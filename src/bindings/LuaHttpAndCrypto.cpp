#include "bindings/LuaHttpAndCrypto.h"
#include "tolua_GameTemplate.h"
#include "CCCrypto.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <curl/curl.h>
#include <openssl/evp.h>

#include "cocos2d.h"
#include "CCLuaEngine.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "tolua++.h"
#include "tolua_fix.h"
}

USING_NS_CC;

namespace {

// ============================================================================
// Hex, Base64 & OpenSSL EVP Digest Helpers
// ============================================================================

std::string bytesToHex(const unsigned char* data, size_t len) {
    if (!data || len == 0) return {};
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

int hexCharVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::string hexToBytes(const std::string& hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = hexCharVal(hex[i]);
        int lo = hexCharVal(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

std::string encodeBase64Impl(const unsigned char* data, size_t len) {
    if (!data || len == 0) return {};
    const size_t outLen = 4 * ((len + 2) / 3);
    std::string out(outLen, '\0');
    int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        data,
        static_cast<int>(len));
    if (written < 0) return {};
    out.resize(static_cast<size_t>(written));
    return out;
}

std::string decodeBase64Impl(const std::string& b64) {
    if (b64.empty()) return {};
    std::string clean;
    clean.reserve(b64.size() + 2);
    for (char c : b64) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean.push_back(c);
        }
    }
    if (clean.empty()) return {};

    const size_t rem = clean.size() % 4;
    if (rem == 1) {
        return {};
    } else if (rem == 2) {
        clean.append("==");
    } else if (rem == 3) {
        clean.push_back('=');
    }

    size_t pad = 0;
    if (clean.size() >= 1 && clean.back() == '=') ++pad;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=') ++pad;

    std::string out((clean.size() / 4) * 3 + 3, '\0');
    int decoded = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(clean.data()),
        static_cast<int>(clean.size()));
    if (decoded < 0) return {};
    size_t actual = static_cast<size_t>(decoded);
    if (pad <= actual) actual -= pad;
    out.resize(actual);
    return out;
}

std::string computeDigest(const EVP_MD* md, const void* data, size_t len, bool raw) {
    unsigned char buf[EVP_MAX_MD_SIZE] = {};
    unsigned int outLen = 0;
    static const unsigned char kEmpty = 0;
    const unsigned char* bytes = data ? static_cast<const unsigned char*>(data) : &kEmpty;
    const size_t actualLen = data ? len : 0;
    if (EVP_Digest(bytes, actualLen, buf, &outLen, md, nullptr) != 1) {
        return {};
    }
    if (raw) {
        return std::string(reinterpret_cast<const char*>(buf), outLen);
    }
    return bytesToHex(buf, outLen);
}

std::string getHttpEnvVar(const char* name) {
    if (!name || !*name) return {};
#ifdef _WIN32
    char buf[4096] = {};
    const DWORD n = ::GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
    if (n > 0 && n < sizeof(buf)) {
        return std::string(buf, static_cast<size_t>(n));
    }
#endif
    if (const char* v = std::getenv(name)) {
        return std::string(v);
    }
    return {};
}

bool isTruthyHttpEnvFlag(std::string val) {
    while (!val.empty() && std::isspace(static_cast<unsigned char>(val.front()))) val.erase(val.begin());
    while (!val.empty() && std::isspace(static_cast<unsigned char>(val.back()))) val.pop_back();
    return val == "1" || val == "true" || val == "TRUE" || val == "yes" || val == "YES";
}

} // namespace

// ============================================================================
// CCCrypto Static C++ Implementation
// ============================================================================

std::string CCCrypto::md5(const void* data, size_t len, bool raw) {
    return computeDigest(EVP_md5(), data, len, raw);
}

std::string CCCrypto::sha1(const void* data, size_t len, bool raw) {
    return computeDigest(EVP_sha1(), data, len, raw);
}

std::string CCCrypto::bin2hex(const void* data, size_t len) {
    return bytesToHex(static_cast<const unsigned char*>(data), len);
}

std::string CCCrypto::hex2bin(const std::string& hex) {
    return hexToBytes(hex);
}

std::string CCCrypto::encodeBase64(const void* data, size_t len) {
    return encodeBase64Impl(static_cast<const unsigned char*>(data), len);
}

std::string CCCrypto::decodeBase64(const std::string& b64) {
    return decodeBase64Impl(b64);
}

namespace gclient {
namespace bindings {

namespace {

constexpr const char* kDigestMetatableName = "GCLIENT.CCCryptoDigest";
constexpr uint32_t kDigestMagic = 0x4F4D4447u; // 'OMDG'

struct LuaDigestUserdata {
    uint32_t magic = 0;
    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;
};

struct HttpRetainGuard {
    CCObject* obj = nullptr;
    explicit HttpRetainGuard(CCObject* o) : obj(o) {
        if (obj) obj->retain();
    }
    ~HttpRetainGuard() {
        if (obj) obj->release();
    }
    HttpRetainGuard(const HttpRetainGuard&) = delete;
    HttpRetainGuard& operator=(const HttpRetainGuard&) = delete;
};

inline int cryptoArgBase(lua_State* L) {
    const int t1 = lua_type(L, 1);
    return (t1 == LUA_TTABLE || t1 == LUA_TUSERDATA) ? 2 : 1;
}

inline size_t clampOptionalLengthArg(lua_State* L, int lenIdx, size_t actualLen) {
    if (lua_type(L, lenIdx) != LUA_TNUMBER) {
        return actualLen;
    }
    const lua_Number reqNum = lua_tonumber(L, lenIdx);
    if (reqNum <= 0) {
        return 0;
    }
    const size_t reqLen = static_cast<size_t>(reqNum);
    return reqLen < actualLen ? reqLen : actualLen;
}

const EVP_MD* resolveDigestAlgorithm(lua_State* L, int idx) {
    const int t = lua_type(L, idx);
    if (t == LUA_TNONE || t == LUA_TNIL) {
        return EVP_md5();
    }
    if (t == LUA_TNUMBER) {
        const int algId = static_cast<int>(lua_tonumber(L, idx));
        if (algId == CCCrypto::EDigestSha1) return EVP_sha1();
        if (algId == CCCrypto::EDigestMD5) return EVP_md5();
        return nullptr;
    }
    if (t == LUA_TSTRING) {
        size_t len = 0;
        const char* s = lua_tolstring(L, idx, &len);
        if (!s || len == 0) {
            return EVP_md5();
        }
        std::string lower(s, len);
        for (char& ch : lower) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        if (lower == "md5") return EVP_md5();
        if (lower == "sha1" || lower == "sha-1") return EVP_sha1();
        if (lower == "sha224" || lower == "sha-224") return EVP_sha224();
        if (lower == "sha256" || lower == "sha-256") return EVP_sha256();
        if (lower == "sha384" || lower == "sha-384") return EVP_sha384();
        if (lower == "sha512" || lower == "sha-512") return EVP_sha512();
        return EVP_get_digestbyname(s);
    }
    return nullptr;
}

LuaDigestUserdata* toDigestUserdata(lua_State* L, int idx) {
    if (lua_type(L, idx) != LUA_TUSERDATA) {
        return nullptr;
    }
    auto* ud = static_cast<LuaDigestUserdata*>(lua_touserdata(L, idx));
    if (!ud || ud->magic != kDigestMagic) {
        return nullptr;
    }
    return ud;
}

int lua_Digest_addBytes(lua_State* L) {
    LuaDigestUserdata* ud = toDigestUserdata(L, 1);
    int dataIdx = 2;
    if (!ud) {
        ud = toDigestUserdata(L, 2);
        dataIdx = 3;
    }
    if (ud && ud->ctx) {
        size_t len = 0;
        const char* data = lua_tolstring(L, dataIdx, &len);
        if (data) {
            len = clampOptionalLengthArg(L, dataIdx + 1, len);
            if (len > 0) {
                EVP_DigestUpdate(ud->ctx, data, len);
            }
        }
    }
    lua_pushvalue(L, dataIdx == 2 ? 1 : 2);
    return 1;
}

int lua_Digest_getDigest(lua_State* L) {
    LuaDigestUserdata* ud = toDigestUserdata(L, 1);
    int rawIdx = 2;
    if (!ud) {
        ud = toDigestUserdata(L, 2);
        rawIdx = 3;
    }
    const bool raw = lua_toboolean(L, rawIdx) != 0;
    if (!ud || !ud->ctx) {
        lua_pushstring(L, "");
        return 1;
    }

    unsigned char buf[EVP_MAX_MD_SIZE] = {};
    unsigned int outLen = 0;
    EVP_MD_CTX* copyCtx = EVP_MD_CTX_new();
    if (!copyCtx) {
        lua_pushstring(L, "");
        return 1;
    }
    const bool ok = (EVP_MD_CTX_copy_ex(copyCtx, ud->ctx) == 1) &&
                    (EVP_DigestFinal_ex(copyCtx, buf, &outLen) == 1);
    EVP_MD_CTX_free(copyCtx);

    if (!ok || outLen == 0) {
        lua_pushstring(L, "");
        return 1;
    }
    if (raw) {
        lua_pushlstring(L, reinterpret_cast<const char*>(buf), outLen);
    } else {
        std::string hex = bytesToHex(buf, outLen);
        lua_pushlstring(L, hex.data(), hex.size());
    }
    return 1;
}

int lua_Digest_reset(lua_State* L) {
    LuaDigestUserdata* ud = toDigestUserdata(L, 1);
    int selfIdx = 1;
    if (!ud) {
        ud = toDigestUserdata(L, 2);
        selfIdx = 2;
    }
    if (ud && ud->ctx && ud->md) {
        EVP_DigestInit_ex(ud->ctx, ud->md, nullptr);
    }
    lua_pushvalue(L, selfIdx);
    return 1;
}

int lua_Digest_gc(lua_State* L) {
    if (LuaDigestUserdata* ud = toDigestUserdata(L, 1)) {
        if (ud->ctx) {
            EVP_MD_CTX_free(ud->ctx);
            ud->ctx = nullptr;
        }
        ud->md = nullptr;
        ud->magic = 0;
    }
    return 0;
}

void pushDigestMetatable(lua_State* L) {
    if (luaL_newmetatable(L, kDigestMetatableName) != 0) {
        lua_pushvalue(L, -1);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, lua_Digest_gc);
        lua_setfield(L, -2, "__gc");
        lua_pushcfunction(L, lua_Digest_addBytes);
        lua_setfield(L, -2, "addBytes");
        lua_pushcfunction(L, lua_Digest_getDigest);
        lua_setfield(L, -2, "getDigest");
        lua_pushcfunction(L, lua_Digest_reset);
        lua_setfield(L, -2, "reset");
    }
}

// ============================================================================
// CCCrypto Lua Bindings
// ============================================================================

int lua_CCCrypto_encodeBase64(lua_State* L) {
    const int base = cryptoArgBase(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    if (data) {
        len = clampOptionalLengthArg(L, base + 1, len);
    }
    std::string enc = CCCrypto::encodeBase64(data, data ? len : 0);
    lua_pushlstring(L, enc.data(), enc.size());
    return 1;
}

int lua_CCCrypto_decodeBase64(lua_State* L) {
    const int base = cryptoArgBase(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    std::string dec = data ? CCCrypto::decodeBase64(std::string(data, len)) : std::string();
    lua_pushlstring(L, dec.data(), dec.size());
    return 1;
}

int lua_CCCrypto_md5(lua_State* L) {
    const int base = cryptoArgBase(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    bool raw = false;
    if (lua_type(L, base + 1) == LUA_TNUMBER) {
        len = clampOptionalLengthArg(L, base + 1, len);
        raw = lua_toboolean(L, base + 2) != 0;
    } else {
        raw = lua_toboolean(L, base + 1) != 0;
    }
    std::string res = CCCrypto::md5(data ? data : "", data ? len : 0, raw);
    lua_pushlstring(L, res.data(), res.size());
    return 1;
}

int lua_CCCrypto_sha1(lua_State* L) {
    const int base = cryptoArgBase(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    bool raw = false;
    if (lua_type(L, base + 1) == LUA_TNUMBER) {
        len = clampOptionalLengthArg(L, base + 1, len);
        raw = lua_toboolean(L, base + 2) != 0;
    } else {
        raw = lua_toboolean(L, base + 1) != 0;
    }
    std::string res = CCCrypto::sha1(data ? data : "", data ? len : 0, raw);
    lua_pushlstring(L, res.data(), res.size());
    return 1;
}

int lua_CCCrypto_bin2hex(lua_State* L) {
    const int base = cryptoArgBase(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    if (data) {
        len = clampOptionalLengthArg(L, base + 1, len);
    }
    std::string hex = data ? CCCrypto::bin2hex(data, len) : std::string();
    lua_pushlstring(L, hex.data(), hex.size());
    return 1;
}

int lua_CCCrypto_hex2bin(lua_State* L) {
    const int base = cryptoArgBase(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    std::string bin = data ? CCCrypto::hex2bin(std::string(data, len)) : std::string();
    lua_pushlstring(L, bin.data(), bin.size());
    return 1;
}

int lua_CCCrypto_createDigest(lua_State* L) {
    const int base = cryptoArgBase(L);
    const EVP_MD* md = resolveDigestAlgorithm(L, base);
    if (!md) {
        lua_pushnil(L);
        return 1;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        lua_pushnil(L);
        return 1;
    }

    auto* ud = static_cast<LuaDigestUserdata*>(lua_newuserdata(L, sizeof(LuaDigestUserdata)));
    if (!ud) {
        EVP_MD_CTX_free(ctx);
        lua_pushnil(L);
        return 1;
    }
    ud->magic = kDigestMagic;
    ud->ctx = ctx;
    ud->md = md;

    pushDigestMetatable(L);
    lua_setmetatable(L, -2);
    return 1;
}

int lua_CCCrypto_addBytes(lua_State* L) {
    return lua_Digest_addBytes(L);
}

int lua_CCCrypto_getDigest(lua_State* L) {
    return lua_Digest_getDigest(L);
}

// ============================================================================
// HTTP Request / Response / Client Classes
// ============================================================================

class WinHttpRequest : public CCObject {
public:
    int requestType = 0; // 0=GET, 1=POST, 2=PUT, 3=DELETE
    std::string url;
    std::string requestData;
    std::string tag;
    std::vector<std::string> headers;
    int timeoutConnect = 30;
    int timeoutRead = 60;
    int timeoutLowSpeed = 0;
    int lowSpeed = 0;
    int responseScriptFunc = 0;
    int bodyDataScriptFunc = 0;
    int headerDataScriptFunc = 0;

    ~WinHttpRequest() override {
        CCScriptEngineProtocol* engine = CCScriptEngineManager::sharedManager()->getScriptEngine();
        if (engine) {
            if (responseScriptFunc != 0) engine->removeScriptHandler(responseScriptFunc);
            if (bodyDataScriptFunc != 0) engine->removeScriptHandler(bodyDataScriptFunc);
            if (headerDataScriptFunc != 0) engine->removeScriptHandler(headerDataScriptFunc);
        }
    }
};

class WinHttpResponse : public CCObject {
public:
    WinHttpRequest* request = nullptr;
    bool succeed = false;
    long responseCode = 0;
    std::string errorBuffer;
    std::string responseData;
    std::string headers;

    ~WinHttpResponse() override {
        CC_SAFE_RELEASE(request);
    }
};

class WinHttpClient : public CCObject {
public:
    static WinHttpClient* getInstance() {
        if (!instance_) {
            instance_ = new WinHttpClient();
        }
        return instance_;
    }

    static void destroyInstance() {
        if (instance_) {
            WinHttpClient* inst = instance_;
            instance_ = nullptr;
            inst->scheduled_ = false;
            if (auto* director = CCDirector::sharedDirector()) {
                if (auto* scheduler = director->getScheduler()) {
                    scheduler->unscheduleAllForTarget(inst);
                }
            }
            inst->shutdownQueueOnMainThread();
            inst->release();
        }
    }

    static void rescheduleIfAlive() {
        if (!instance_) {
            return;
        }
        if (auto* director = CCDirector::sharedDirector()) {
            if (auto* scheduler = director->getScheduler()) {
                scheduler->unscheduleSelector(
                    schedule_selector(WinHttpClient::dispatchCallbacks), instance_);
                instance_->scheduled_ = false;
                instance_->ensureScheduled();
            }
        }
    }

    ~WinHttpClient() override {
        shutdownQueueOnMainThread();
    }

    void enableCookies(const char* cookieFile) {
        std::lock_guard<std::mutex> lock(sharedState_->mutex);
        cookieFile_ = cookieFile ? cookieFile : "";
    }

    void send(WinHttpRequest* req) {
        if (!req) return;
        // Single main-thread retain keeps `req` alive through all queued HeaderChunk,
        // BodyChunk, and ResponseDone events without any off-thread CCObject refcount races!
        req->retain();

        ensureScheduled();

        RequestSnapshot snap;
        snap.requestType = req->requestType;
        snap.url = req->url;
        snap.requestData = req->requestData;
        snap.headers = req->headers;
        snap.timeoutConnect = req->timeoutConnect;
        snap.timeoutRead = req->timeoutRead;
        snap.timeoutLowSpeed = req->timeoutLowSpeed;
        snap.lowSpeed = req->lowSpeed;
        snap.streamBodyChunks = (req->bodyDataScriptFunc != 0);
        snap.streamHeaderChunks = (req->headerDataScriptFunc != 0);
        {
            std::lock_guard<std::mutex> lock(sharedState_->mutex);
            snap.cookieFile = cookieFile_;
        }

        std::shared_ptr<SharedQueueState> state = sharedState_;

        std::thread(&WinHttpClient::runWorker, std::move(state), req, std::move(snap)).detach();
    }

    void dispatchCallbacks(float /*dt*/) {
        std::deque<PendingEvent> batch;
        {
            std::lock_guard<std::mutex> lock(sharedState_->mutex);
            batch.swap(sharedState_->events);
        }
        if (batch.empty()) return;

        // Retain `this` across the entire dispatch loop so Lua callbacks calling
        // CCHttpClient:destroyInstance() cannot free `this` mid-iteration!
        HttpRetainGuard selfGuard(this);

        for (PendingEvent& ev : batch) {
            CCLuaEngine* engine = dynamic_cast<CCLuaEngine*>(
                CCScriptEngineManager::sharedManager()->getScriptEngine());
            lua_State* L = (engine && engine->getLuaStack())
                ? engine->getLuaStack()->getLuaState()
                : nullptr;

            if (ev.type == PendingEvent::HeaderChunk) {
                if (L && ev.req && ev.req->headerDataScriptFunc != 0) {
                    lua_pushlstring(L, ev.data.data(), ev.data.size());
                    engine->getLuaStack()->executeFunctionByHandler(ev.req->headerDataScriptFunc, 1);
                }
            } else if (ev.type == PendingEvent::BodyChunk) {
                if (L && ev.req && ev.req->bodyDataScriptFunc != 0) {
                    lua_pushlstring(L, ev.data.data(), ev.data.size());
                    engine->getLuaStack()->executeFunctionByHandler(ev.req->bodyDataScriptFunc, 1);
                }
            } else if (ev.type == PendingEvent::ResponseDone) {
                auto* resp = new WinHttpResponse();
                resp->request = ev.req; // transfer main-thread retain from send()
                resp->succeed = ev.succeed;
                resp->responseCode = ev.responseCode;
                resp->errorBuffer = std::move(ev.errorBuffer);
                resp->responseData = std::move(ev.data);
                resp->headers = std::move(ev.headers);

                if (L && resp->request && resp->request->responseScriptFunc != 0) {
                    CCObject* baseClient = static_cast<CCObject*>(this);
                    CCObject* baseResp = static_cast<CCObject*>(resp);
                    toluafix_pushusertype_ccobject(
                        L,
                        static_cast<int>(baseClient->m_uID),
                        &baseClient->m_nLuaID,
                        static_cast<void*>(baseClient),
                        "CCHttpClient");
                    toluafix_pushusertype_ccobject(
                        L,
                        static_cast<int>(baseResp->m_uID),
                        &baseResp->m_nLuaID,
                        static_cast<void*>(baseResp),
                        "LuaHttpResponse");
                    engine->getLuaStack()->executeFunctionByHandler(
                        resp->request->responseScriptFunc, 2);
                }
                resp->release();
            }
        }
    }

private:
    struct RequestSnapshot {
        int requestType = 0;
        std::string url;
        std::string requestData;
        std::vector<std::string> headers;
        std::string cookieFile;
        int timeoutConnect = 30;
        int timeoutRead = 60;
        int timeoutLowSpeed = 0;
        int lowSpeed = 0;
        bool streamBodyChunks = false;
        bool streamHeaderChunks = false;
    };

    struct PendingEvent {
        enum Type { HeaderChunk, BodyChunk, ResponseDone } type = ResponseDone;
        WinHttpRequest* req = nullptr;
        bool succeed = false;
        long responseCode = 0;
        std::string errorBuffer;
        std::string data;
        std::string headers;
    };

    struct SharedQueueState {
        std::mutex mutex;
        std::deque<PendingEvent> events;
        bool shuttingDown = false;
    };

    static void runWorker(std::shared_ptr<SharedQueueState> state, WinHttpRequest* req, RequestSnapshot snap) {
        struct StreamCtx {
            SharedQueueState* state;
            WinHttpRequest* req;
            bool streamBodyChunks;
            bool streamHeaderChunks;
            std::string responseData;
            std::string responseHeaders;
        } streamCtx{state.get(), req, snap.streamBodyChunks, snap.streamHeaderChunks, {}, {}};

        bool succeed = false;
        long responseCode = 0;
        std::string errorBuffer;

        CURL* curl = curl_easy_init();
        if (!curl) {
            succeed = false;
            errorBuffer = "curl_easy_init failed";
        } else {
            auto writeCb = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
                auto* ctx = static_cast<StreamCtx*>(userdata);
                const size_t total = size * nmemb;
                if (ctx->streamBodyChunks) {
                    std::lock_guard<std::mutex> lock(ctx->state->mutex);
                    if (!ctx->state->shuttingDown) {
                        PendingEvent ev;
                        ev.type = PendingEvent::BodyChunk;
                        ev.req = ctx->req;
                        ev.data.assign(ptr, total);
                        ctx->state->events.push_back(std::move(ev));
                    }
                } else {
                    ctx->responseData.append(ptr, total);
                }
                return total;
            };

            auto headerCb = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
                auto* ctx = static_cast<StreamCtx*>(userdata);
                const size_t total = size * nmemb;
                ctx->responseHeaders.append(ptr, total);
                if (ctx->streamHeaderChunks) {
                    std::lock_guard<std::mutex> lock(ctx->state->mutex);
                    if (!ctx->state->shuttingDown) {
                        PendingEvent ev;
                        ev.type = PendingEvent::HeaderChunk;
                        ev.req = ctx->req;
                        ev.data.assign(ptr, total);
                        ctx->state->events.push_back(std::move(ev));
                    }
                }
                return total;
            };

            curl_easy_setopt(curl, CURLOPT_URL, snap.url.c_str());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
#ifdef CURLSSLOPT_NATIVE_CA
            curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif
            std::string caBundle = getHttpEnvVar("GCLIENT_CA_BUNDLE");
            if (caBundle.empty()) {
                caBundle = getHttpEnvVar("CURL_CA_BUNDLE");
            }
            if (!caBundle.empty()) {
                curl_easy_setopt(curl, CURLOPT_CAINFO, caBundle.c_str());
            }
            if (isTruthyHttpEnvFlag(getHttpEnvVar("GCLIENT_INSECURE_TLS"))) {
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            }
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, static_cast<long>((std::max)(1, snap.timeoutConnect)));
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>((std::max)(1, snap.timeoutRead)));
            if (snap.lowSpeed > 0 && snap.timeoutLowSpeed > 0) {
                curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, static_cast<long>(snap.lowSpeed));
                curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, static_cast<long>(snap.timeoutLowSpeed));
            }
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &streamCtx);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCb);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &streamCtx);

            if (!snap.cookieFile.empty()) {
                curl_easy_setopt(curl, CURLOPT_COOKIEFILE, snap.cookieFile.c_str());
                curl_easy_setopt(curl, CURLOPT_COOKIEJAR, snap.cookieFile.c_str());
            }

            struct curl_slist* slist = nullptr;
            for (const auto& h : snap.headers) {
                slist = curl_slist_append(slist, h.c_str());
            }
            if (slist) {
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
            }

            if (snap.requestType == 1) {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, snap.requestData.data());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(snap.requestData.size()));
            } else if (snap.requestType == 2) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, snap.requestData.data());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(snap.requestData.size()));
            } else if (snap.requestType == 3) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            }

            char errBuf[CURL_ERROR_SIZE] = {};
            curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errBuf);

            CURLcode rc = curl_easy_perform(curl);
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
            if (rc == CURLE_OK && responseCode >= 200 && responseCode < 400) {
                succeed = true;
            } else {
                succeed = false;
                errorBuffer = errBuf[0] ? errBuf : curl_easy_strerror(rc);
            }

            if (slist) curl_slist_free_all(slist);
            curl_easy_cleanup(curl);
        }

        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (!state->shuttingDown) {
                PendingEvent ev;
                ev.type = PendingEvent::ResponseDone;
                ev.req = req;
                ev.succeed = succeed;
                ev.responseCode = responseCode;
                ev.errorBuffer = std::move(errorBuffer);
                ev.data = std::move(streamCtx.responseData);
                ev.headers = std::move(streamCtx.responseHeaders);
                state->events.push_back(std::move(ev));
            }
        }
    }

    void shutdownQueueOnMainThread() {
        std::deque<PendingEvent> leftover;
        {
            std::lock_guard<std::mutex> lock(sharedState_->mutex);
            sharedState_->shuttingDown = true;
            leftover.swap(sharedState_->events);
        }
        for (PendingEvent& ev : leftover) {
            if (ev.type == PendingEvent::ResponseDone && ev.req) {
                ev.req->release();
                ev.req = nullptr;
            }
        }
    }

    void ensureScheduled() {
        if (!scheduled_) {
            if (auto* director = CCDirector::sharedDirector()) {
                if (auto* scheduler = director->getScheduler()) {
                    scheduled_ = true;
                    scheduler->scheduleSelector(
                        schedule_selector(WinHttpClient::dispatchCallbacks),
                        this,
                        0.0f,
                        false);
                }
            }
        }
    }

    static WinHttpClient* instance_;
    std::shared_ptr<SharedQueueState> sharedState_ = std::make_shared<SharedQueueState>();
    std::string cookieFile_;
    bool scheduled_ = false;
};

WinHttpClient* WinHttpClient::instance_ = nullptr;

// ============================================================================
// Safe RTTI tolua Bindings for HTTP Classes
// ============================================================================

template <typename T>
T* getSafeHttpObject(lua_State* L, int idx, const char* expectedBaseType) {
    static_assert(std::is_base_of<CCObject, T>::value, "T must inherit CCObject");
    if (!L || !expectedBaseType) return nullptr;
    const int absIdx = (idx < 0 && idx > LUA_REGISTRYINDEX) ? (lua_gettop(L) + idx + 1) : idx;
    if (absIdx <= 0 || absIdx > lua_gettop(L)) return nullptr;

    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, expectedBaseType, 0, &err) ||
            tolua_isusertype(L, absIdx, "CCObject", 0, &err)) {
            auto* obj = static_cast<CCObject*>(tolua_tousertype(L, absIdx, nullptr));
            return obj ? dynamic_cast<T*>(obj) : nullptr;
        }
        return nullptr;
    }

    if (lua_type(L, absIdx) == LUA_TTABLE) {
        lua_pushvalue(L, absIdx);
        for (int depth = 0; depth < 4; ++depth) {
            if (!lua_istable(L, -1)) break;
            lua_pushlstring(L, ".c_instance", 11);
            lua_rawget(L, -2);
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                lua_getfield(L, -1, ".c_instance");
            }
            lua_remove(L, -2);
            if (lua_type(L, -1) == LUA_TUSERDATA) {
                T* out = nullptr;
                if (tolua_isusertype(L, -1, expectedBaseType, 0, &err) ||
                    tolua_isusertype(L, -1, "CCObject", 0, &err)) {
                    if (auto* obj = static_cast<CCObject*>(tolua_tousertype(L, -1, nullptr))) {
                        out = dynamic_cast<T*>(obj);
                    }
                }
                lua_pop(L, 1);
                return out;
            }
        }
        lua_pop(L, 1);
    }
    return nullptr;
}

WinHttpRequest* checkReq(lua_State* L, int idx = 1) {
    return getSafeHttpObject<WinHttpRequest>(L, idx, "CCHttpRequest");
}

WinHttpResponse* checkResp(lua_State* L, int idx = 1) {
    return getSafeHttpObject<WinHttpResponse>(L, idx, "CCHttpResponse");
}

WinHttpClient* checkClient(lua_State* L, int idx = 1) {
    return getSafeHttpObject<WinHttpClient>(L, idx, "CCHttpClient");
}

int lua_HttpReq_setRequestType(lua_State* L) {
    if (auto* r = checkReq(L)) r->requestType = static_cast<int>(tolua_tonumber(L, 2, 0));
    return 0;
}
int lua_HttpReq_getRequestType(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushnumber(L, r ? r->requestType : 0);
    return 1;
}
int lua_HttpReq_setUrl(lua_State* L) {
    if (auto* r = checkReq(L)) {
        const char* u = tolua_tostring(L, 2, "");
        r->url = u ? u : "";
    }
    return 0;
}
int lua_HttpReq_getUrl(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushstring(L, r ? r->url.c_str() : "");
    return 1;
}
int lua_HttpReq_setRequestData(lua_State* L) {
    if (auto* r = checkReq(L)) {
        size_t len = 0;
        const char* d = lua_tolstring(L, 2, &len);
        if (d) {
            len = clampOptionalLengthArg(L, 3, len);
            r->requestData.assign(d, len);
        } else {
            r->requestData.clear();
        }
    }
    return 0;
}
int lua_HttpReq_getRequestData(lua_State* L) {
    auto* r = checkReq(L);
    if (r) lua_pushlstring(L, r->requestData.data(), r->requestData.size());
    else lua_pushstring(L, "");
    return 1;
}
int lua_HttpReq_getRequestDataSize(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushnumber(L, r ? static_cast<lua_Number>(r->requestData.size()) : 0);
    return 1;
}
int lua_HttpReq_setTag(lua_State* L) {
    if (auto* r = checkReq(L)) {
        const char* t = tolua_tostring(L, 2, "");
        r->tag = t ? t : "";
    }
    return 0;
}
int lua_HttpReq_getTag(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushstring(L, r ? r->tag.c_str() : "");
    return 1;
}
int lua_HttpReq_getTarget(lua_State* L) {
    lua_pushnil(L);
    return 1;
}
int lua_HttpReq_setTimeoutForConnect(lua_State* L) {
    if (auto* r = checkReq(L)) r->timeoutConnect = static_cast<int>(tolua_tonumber(L, 2, 30));
    return 0;
}
int lua_HttpReq_getTimeoutForConnect(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushnumber(L, r ? r->timeoutConnect : 30);
    return 1;
}
int lua_HttpReq_setTimeoutForRead(lua_State* L) {
    if (auto* r = checkReq(L)) r->timeoutRead = static_cast<int>(tolua_tonumber(L, 2, 60));
    return 0;
}
int lua_HttpReq_getTimeoutForRead(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushnumber(L, r ? r->timeoutRead : 60);
    return 1;
}
int lua_HttpReq_setTimeoutForLowSpeed(lua_State* L) {
    if (auto* r = checkReq(L)) r->timeoutLowSpeed = static_cast<int>(tolua_tonumber(L, 2, 0));
    return 0;
}
int lua_HttpReq_getTimeoutForLowSpeed(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushnumber(L, r ? r->timeoutLowSpeed : 0);
    return 1;
}
int lua_HttpReq_setLowSpeed(lua_State* L) {
    if (auto* r = checkReq(L)) r->lowSpeed = static_cast<int>(tolua_tonumber(L, 2, 0));
    return 0;
}
int lua_HttpReq_getLowSpeed(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushnumber(L, r ? r->lowSpeed : 0);
    return 1;
}

int lua_LuaHttpReq_newRequest(lua_State* L) {
    // Returns caller-owned CCObject (m_uReference == 1, NOT autoreleased) matching
    // Http.lua / Platform.lua / Downloader.lua which call request:release() after send(request).
    auto* req = new WinHttpRequest();
    CCObject* baseReq = static_cast<CCObject*>(req);
    toluafix_pushusertype_ccobject(
        L, static_cast<int>(baseReq->m_uID), &baseReq->m_nLuaID, static_cast<void*>(baseReq), "LuaHttpRequest");
    return 1;
}
int lua_LuaHttpReq_setHeaders(lua_State* L) {
    if (auto* r = checkReq(L)) {
        r->headers.clear();
        if (lua_istable(L, 2)) {
            int n = static_cast<int>(lua_objlen(L, 2));
            for (int i = 1; i <= n; ++i) {
                lua_rawgeti(L, 2, i);
                if (const char* s = lua_tostring(L, -1)) {
                    r->headers.emplace_back(s);
                }
                lua_pop(L, 1);
            }
        }
    }
    return 0;
}
int lua_LuaHttpReq_addHeader(lua_State* L) {
    if (auto* r = checkReq(L)) {
        if (const char* h = tolua_tostring(L, 2, nullptr)) {
            r->headers.emplace_back(h);
        }
    }
    return 0;
}
int lua_LuaHttpReq_getHeaders(lua_State* L) {
    auto* r = checkReq(L);
    lua_newtable(L);
    if (r) {
        for (size_t i = 0; i < r->headers.size(); ++i) {
            lua_pushlstring(L, r->headers[i].data(), r->headers[i].size());
            lua_rawseti(L, -2, static_cast<int>(i + 1));
        }
    }
    return 1;
}
int lua_LuaHttpReq_setResponseScriptFunc(lua_State* L) {
    if (auto* r = checkReq(L)) {
        tolua_Error err;
        if (toluafix_isfunction(L, 2, "LUA_FUNCTION", 0, &err)) {
            if (r->responseScriptFunc != 0) {
                if (auto* eng = CCScriptEngineManager::sharedManager()->getScriptEngine()) {
                    eng->removeScriptHandler(r->responseScriptFunc);
                }
            }
            r->responseScriptFunc = toluafix_ref_function(L, 2, 0);
        }
    }
    return 0;
}
int lua_LuaHttpReq_setBodyDataScriptFunc(lua_State* L) {
    if (auto* r = checkReq(L)) {
        tolua_Error err;
        if (toluafix_isfunction(L, 2, "LUA_FUNCTION", 0, &err)) {
            if (r->bodyDataScriptFunc != 0) {
                if (auto* eng = CCScriptEngineManager::sharedManager()->getScriptEngine()) {
                    eng->removeScriptHandler(r->bodyDataScriptFunc);
                }
            }
            r->bodyDataScriptFunc = toluafix_ref_function(L, 2, 0);
        }
    }
    return 0;
}
int lua_LuaHttpReq_setHeaderDataScriptFunc(lua_State* L) {
    if (auto* r = checkReq(L)) {
        tolua_Error err;
        if (toluafix_isfunction(L, 2, "LUA_FUNCTION", 0, &err)) {
            if (r->headerDataScriptFunc != 0) {
                if (auto* eng = CCScriptEngineManager::sharedManager()->getScriptEngine()) {
                    eng->removeScriptHandler(r->headerDataScriptFunc);
                }
            }
            r->headerDataScriptFunc = toluafix_ref_function(L, 2, 0);
        }
    }
    return 0;
}

int lua_HttpResp_isSucceed(lua_State* L) {
    auto* r = checkResp(L);
    lua_pushboolean(L, (r && r->succeed) ? 1 : 0);
    return 1;
}
int lua_HttpResp_getResponseCode(lua_State* L) {
    auto* r = checkResp(L);
    lua_pushnumber(L, r ? static_cast<lua_Number>(r->responseCode) : 0);
    return 1;
}
int lua_HttpResp_getErrorBuffer(lua_State* L) {
    auto* r = checkResp(L);
    lua_pushstring(L, r ? r->errorBuffer.c_str() : "");
    return 1;
}
int lua_LuaHttpResp_getHeaders(lua_State* L) {
    auto* r = checkResp(L);
    if (r) lua_pushlstring(L, r->headers.data(), r->headers.size());
    else lua_pushstring(L, "");
    return 1;
}
int lua_LuaHttpResp_getHeadersSize(lua_State* L) {
    auto* r = checkResp(L);
    lua_pushnumber(L, r ? static_cast<lua_Number>(r->headers.size()) : 0);
    return 1;
}
int lua_LuaHttpResp_getResponseData(lua_State* L) {
    auto* r = checkResp(L);
    if (r) lua_pushlstring(L, r->responseData.data(), r->responseData.size());
    else lua_pushstring(L, "");
    return 1;
}
int lua_LuaHttpResp_getResponseDataSize(lua_State* L) {
    auto* r = checkResp(L);
    lua_pushnumber(L, r ? static_cast<lua_Number>(r->responseData.size()) : 0);
    return 1;
}
int lua_LuaHttpResp_getRequest(lua_State* L) {
    auto* r = checkResp(L);
    if (r && r->request) {
        CCObject* baseReq = static_cast<CCObject*>(r->request);
        toluafix_pushusertype_ccobject(
            L,
            static_cast<int>(baseReq->m_uID),
            &baseReq->m_nLuaID,
            static_cast<void*>(baseReq),
            "LuaHttpRequest");
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int lua_HttpClient_getInstance(lua_State* L) {
    auto* c = WinHttpClient::getInstance();
    CCObject* baseClient = static_cast<CCObject*>(c);
    toluafix_pushusertype_ccobject(
        L, static_cast<int>(baseClient->m_uID), &baseClient->m_nLuaID, static_cast<void*>(baseClient), "CCHttpClient");
    return 1;
}
int lua_HttpClient_destroyInstance(lua_State* /*L*/) {
    WinHttpClient::destroyInstance();
    return 0;
}
int lua_HttpClient_send(lua_State* L) {
    auto* c = checkClient(L, 1);
    auto* req = checkReq(L, 2);
    if (c && req) c->send(req);
    return 0;
}
int lua_HttpClient_enableCookies(lua_State* L) {
    auto* c = checkClient(L, 1);
    const char* file = tolua_tostring(L, 2, "");
    if (c) c->enableCookies(file);
    return 0;
}

} // namespace

void registerLuaHttpAndCrypto(lua_State* tolua_S) {
    tolua_usertype(tolua_S, "CCHttpRequest");
    tolua_usertype(tolua_S, "CCHttpResponse");
    tolua_usertype(tolua_S, "CCHttpClient");
    tolua_usertype(tolua_S, "LuaHttpRequest");
    tolua_usertype(tolua_S, "LuaHttpResponse");
    tolua_usertype(tolua_S, "CCCrypto");

    tolua_cclass(tolua_S, "CCHttpRequest", "CCHttpRequest", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CCHttpRequest");
    tolua_constant(tolua_S, "kHttpGet", 0.0);
    tolua_constant(tolua_S, "kHttpPost", 1.0);
    tolua_constant(tolua_S, "kHttpPut", 2.0);
    tolua_constant(tolua_S, "kHttpDelete", 3.0);
    tolua_constant(tolua_S, "kHttpUnkown", 4.0);
    tolua_function(tolua_S, "setRequestType", lua_HttpReq_setRequestType);
    tolua_function(tolua_S, "getRequestType", lua_HttpReq_getRequestType);
    tolua_function(tolua_S, "setUrl", lua_HttpReq_setUrl);
    tolua_function(tolua_S, "getUrl", lua_HttpReq_getUrl);
    tolua_function(tolua_S, "setRequestData", lua_HttpReq_setRequestData);
    tolua_function(tolua_S, "getRequestData", lua_HttpReq_getRequestData);
    tolua_function(tolua_S, "getRequestDataSize", lua_HttpReq_getRequestDataSize);
    tolua_function(tolua_S, "setTag", lua_HttpReq_setTag);
    tolua_function(tolua_S, "getTag", lua_HttpReq_getTag);
    tolua_function(tolua_S, "getTarget", lua_HttpReq_getTarget);
    tolua_function(tolua_S, "setTimeoutForConnect", lua_HttpReq_setTimeoutForConnect);
    tolua_function(tolua_S, "getTimeoutForConnect", lua_HttpReq_getTimeoutForConnect);
    tolua_function(tolua_S, "setTimeoutForRead", lua_HttpReq_setTimeoutForRead);
    tolua_function(tolua_S, "getTimeoutForRead", lua_HttpReq_getTimeoutForRead);
    tolua_function(tolua_S, "setTimeoutForLowSpeed", lua_HttpReq_setTimeoutForLowSpeed);
    tolua_function(tolua_S, "getTimeoutForLowSpeed", lua_HttpReq_getTimeoutForLowSpeed);
    tolua_function(tolua_S, "setLowSpeed", lua_HttpReq_setLowSpeed);
    tolua_function(tolua_S, "getLowSpeed", lua_HttpReq_getLowSpeed);
    tolua_endmodule(tolua_S);

    tolua_cclass(tolua_S, "CCHttpResponse", "CCHttpResponse", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CCHttpResponse");
    tolua_function(tolua_S, "isSucceed", lua_HttpResp_isSucceed);
    tolua_function(tolua_S, "getResponseCode", lua_HttpResp_getResponseCode);
    tolua_function(tolua_S, "getErrorBuffer", lua_HttpResp_getErrorBuffer);
    tolua_endmodule(tolua_S);

    tolua_cclass(tolua_S, "CCHttpClient", "CCHttpClient", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CCHttpClient");
    tolua_function(tolua_S, "getInstance", lua_HttpClient_getInstance);
    tolua_function(tolua_S, "destroyInstance", lua_HttpClient_destroyInstance);
    tolua_function(tolua_S, "send", lua_HttpClient_send);
    tolua_function(tolua_S, "enableCookies", lua_HttpClient_enableCookies);
    tolua_endmodule(tolua_S);

    tolua_cclass(tolua_S, "LuaHttpRequest", "LuaHttpRequest", "CCHttpRequest", nullptr);
    tolua_beginmodule(tolua_S, "LuaHttpRequest");
    tolua_function(tolua_S, "newRequest", lua_LuaHttpReq_newRequest);
    tolua_function(tolua_S, "setHeaders", lua_LuaHttpReq_setHeaders);
    tolua_function(tolua_S, "addHeader", lua_LuaHttpReq_addHeader);
    tolua_function(tolua_S, "getHeaders", lua_LuaHttpReq_getHeaders);
    tolua_function(tolua_S, "setResponseScriptFunc", lua_LuaHttpReq_setResponseScriptFunc);
    tolua_function(tolua_S, "setBodyDataScriptFunc", lua_LuaHttpReq_setBodyDataScriptFunc);
    tolua_function(tolua_S, "setHeaderDataScriptFunc", lua_LuaHttpReq_setHeaderDataScriptFunc);
    tolua_endmodule(tolua_S);

    tolua_cclass(tolua_S, "LuaHttpResponse", "LuaHttpResponse", "CCHttpResponse", nullptr);
    tolua_beginmodule(tolua_S, "LuaHttpResponse");
    tolua_function(tolua_S, "getHeaders", lua_LuaHttpResp_getHeaders);
    tolua_function(tolua_S, "getHeadersSize", lua_LuaHttpResp_getHeadersSize);
    tolua_function(tolua_S, "getResponseData", lua_LuaHttpResp_getResponseData);
    tolua_function(tolua_S, "getResponseDataSize", lua_LuaHttpResp_getResponseDataSize);
    tolua_function(tolua_S, "getRequest", lua_LuaHttpResp_getRequest);
    tolua_endmodule(tolua_S);

    tolua_cclass(tolua_S, "CCCrypto", "CCCrypto", "", nullptr);
    tolua_beginmodule(tolua_S, "CCCrypto");
    tolua_constant(tolua_S, "EDigestMD5", 1.0);
    tolua_constant(tolua_S, "EDigestSha1", 2.0);
    tolua_function(tolua_S, "encodeBase64", lua_CCCrypto_encodeBase64);
    tolua_function(tolua_S, "decodeBase64", lua_CCCrypto_decodeBase64);
    tolua_function(tolua_S, "md5", lua_CCCrypto_md5);
    tolua_function(tolua_S, "sha1", lua_CCCrypto_sha1);
    tolua_function(tolua_S, "bin2hex", lua_CCCrypto_bin2hex);
    tolua_function(tolua_S, "createDigest", lua_CCCrypto_createDigest);
    tolua_function(tolua_S, "addBytes", lua_CCCrypto_addBytes);
    tolua_function(tolua_S, "getDigest", lua_CCCrypto_getDigest);
    tolua_function(tolua_S, "hex2bin", lua_CCCrypto_hex2bin);
    tolua_endmodule(tolua_S);
}

} // namespace bindings
} // namespace gclient

void gclient_rescheduleHttpClientCallbacks() {
    gclient::bindings::WinHttpClient::rescheduleIfAlive();
}
