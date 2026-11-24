#include "BtPlatformWin32.h"
#include "platform/VngAuthProvider.h"
#include "assets/BtDecryptHook.h"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace bt {

namespace {

// ---------------------------------------------------------------------------
// Self-contained RFC 1321 MD5 implementation (zero OpenSSL dependency)
// ---------------------------------------------------------------------------
class Md5Hasher {
public:
    Md5Hasher() { reset(); }

    void reset() {
        count_[0] = 0;
        count_[1] = 0;
        state_[0] = 0x67452301u;
        state_[1] = 0xefcdab89u;
        state_[2] = 0x98badcfeu;
        state_[3] = 0x10325476u;
    }

    void update(const uint8_t* input, size_t len) {
        size_t index = static_cast<size_t>((count_[0] >> 3) & 0x3Fu);
        if ((count_[0] += static_cast<uint32_t>(len << 3)) < static_cast<uint32_t>(len << 3)) {
            ++count_[1];
        }
        count_[1] += static_cast<uint32_t>(len >> 29);

        size_t partLen = 64 - index;
        size_t i = 0;
        if (len >= partLen) {
            std::memcpy(&buffer_[index], input, partLen);
            transform(buffer_.data());
            for (i = partLen; i + 63 < len; i += 64) {
                transform(&input[i]);
            }
            index = 0;
        }
        std::memcpy(&buffer_[index], &input[i], len - i);
    }

    std::string finalHex() {
        static const uint8_t kPadding[64] = {0x80};
        uint8_t bits[8];
        encode(bits, count_, 8);

        size_t index = static_cast<size_t>((count_[0] >> 3) & 0x3Fu);
        size_t padLen = (index < 56) ? (56 - index) : (120 - index);
        update(kPadding, padLen);
        update(bits, 8);

        uint8_t digest[16];
        encode(digest, state_, 16);

        static const char kHex[] = "0123456789abcdef";
        std::string out(32, '0');
        for (size_t i = 0; i < 16; ++i) {
            out[i * 2]     = kHex[(digest[i] >> 4) & 0x0F];
            out[i * 2 + 1] = kHex[digest[i] & 0x0F];
        }
        return out;
    }

private:
    static inline uint32_t rotateLeft(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32u - n));
    }

    static void encode(uint8_t* out, const uint32_t* in, size_t len) {
        for (size_t i = 0, j = 0; j < len; ++i, j += 4) {
            out[j]     = static_cast<uint8_t>(in[i] & 0xFFu);
            out[j + 1] = static_cast<uint8_t>((in[i] >> 8) & 0xFFu);
            out[j + 2] = static_cast<uint8_t>((in[i] >> 16) & 0xFFu);
            out[j + 3] = static_cast<uint8_t>((in[i] >> 24) & 0xFFu);
        }
    }

    static void decode(uint32_t* out, const uint8_t* in, size_t len) {
        for (size_t i = 0, j = 0; j < len; ++i, j += 4) {
            out[i] = static_cast<uint32_t>(in[j]) |
                     (static_cast<uint32_t>(in[j + 1]) << 8) |
                     (static_cast<uint32_t>(in[j + 2]) << 16) |
                     (static_cast<uint32_t>(in[j + 3]) << 24);
        }
    }

    void transform(const uint8_t block[64]) {
        static const uint32_t kShift[64] = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };
        static const uint32_t kTable[64] = {
            0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
            0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
            0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
            0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
            0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
            0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
            0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
            0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
            0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
            0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
            0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
            0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
            0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
            0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
            0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
            0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
        };

        uint32_t x[16];
        decode(x, block, 64);

        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];

        for (uint32_t i = 0; i < 64; ++i) {
            uint32_t f = 0;
            uint32_t g = 0;
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            const uint32_t temp = d;
            d = c;
            c = b;
            b = b + rotateLeft(a + f + kTable[i] + x[g], kShift[i]);
            a = temp;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
    }

    uint32_t state_[4]{};
    uint32_t count_[2]{};
    std::array<uint8_t, 64> buffer_{};
};

// ---------------------------------------------------------------------------
// Minimal self-contained JSON parser for config.json / game_config.json & API params
// ---------------------------------------------------------------------------
class MiniJsonParser {
public:
    explicit MiniJsonParser(const std::string& src) : src_(src) {}

    bool parseObjectToConfig(ConfigDocument& outDoc) {
        skipWs();
        if (!consume('{')) return false;
        skipWs();
        if (peek() == '}') {
            ++pos_;
            return true;
        }
        while (pos_ < src_.size()) {
            skipWs();
            std::string key;
            if (!parseString(key)) return false;
            skipWs();
            if (!consume(':')) return false;
            skipWs();

            char ch = peek();
            if (ch == '{') {
                std::map<std::string, std::string> child;
                if (!parseFlatObject(child)) return false;
                outDoc.objects[key] = std::move(child);
            } else {
                std::string scalar;
                if (!parseScalarOrSkip(scalar)) return false;
                outDoc.values[key] = std::move(scalar);
            }

            skipWs();
            if (consume(',')) continue;
            if (consume('}')) return true;
            return false;
        }
        return false;
    }

    bool parseFlatObject(std::map<std::string, std::string>& outMap) {
        skipWs();
        if (!consume('{')) return false;
        skipWs();
        if (peek() == '}') {
            ++pos_;
            return true;
        }
        while (pos_ < src_.size()) {
            skipWs();
            std::string key;
            if (!parseString(key)) return false;
            skipWs();
            if (!consume(':')) return false;
            skipWs();

            std::string value;
            if (!parseScalarOrSkip(value)) return false;
            outMap[key] = std::move(value);

            skipWs();
            if (consume(',')) continue;
            if (consume('}')) return true;
            return false;
        }
        return false;
    }

private:
    static bool parseHex4At(const std::string& s, size_t offset, uint32_t& outCode) {
        if (offset + 4 > s.size()) {
            return false;
        }
        uint32_t acc = 0;
        for (size_t i = 0; i < 4; ++i) {
            const char c = s[offset + i];
            uint32_t digit = 0;
            if (c >= '0' && c <= '9') {
                digit = static_cast<uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                digit = static_cast<uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                digit = static_cast<uint32_t>(c - 'A' + 10);
            } else {
                return false;
            }
            acc = (acc << 4) | digit;
        }
        outCode = acc;
        return true;
    }

    static void appendUtf8Codepoint(std::string& out, uint32_t cp) {
        if (cp >= 0xD800u && cp <= 0xDFFFu) {
            cp = 0xFFFDu;
        }
        if (cp <= 0x7Fu) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FFu) {
            out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else if (cp <= 0xFFFFu) {
            out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else if (cp <= 0x10FFFFu) {
            out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else {
            appendUtf8Codepoint(out, 0xFFFDu);
        }
    }

    void skipWs() {
        while (pos_ < src_.size() &&
               (src_[pos_] == ' ' || src_[pos_] == '\t' || src_[pos_] == '\r' || src_[pos_] == '\n')) {
            ++pos_;
        }
    }

    char peek() const { return pos_ < src_.size() ? src_[pos_] : '\0'; }

    bool consume(char expected) {
        if (pos_ < src_.size() && src_[pos_] == expected) {
            ++pos_;
            return true;
        }
        return false;
    }

    bool parseString(std::string& out) {
        if (!consume('"')) return false;
        out.clear();
        while (pos_ < src_.size()) {
            char c = src_[pos_++];
            if (c == '"') return true;
            if (c == '\\' && pos_ < src_.size()) {
                char esc = src_[pos_++];
                switch (esc) {
                    case '"':  out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/':  out.push_back('/'); break;
                    case 'b':  out.push_back('\b'); break;
                    case 'f':  out.push_back('\f'); break;
                    case 'n':  out.push_back('\n'); break;
                    case 'r':  out.push_back('\r'); break;
                    case 't':  out.push_back('\t'); break;
                    case 'u': {
                        uint32_t code = 0;
                        if (parseHex4At(src_, pos_, code)) {
                            pos_ += 4;
                            if (code >= 0xD800u && code <= 0xDBFFu &&
                                pos_ + 6 <= src_.size() &&
                                src_[pos_] == '\\' && src_[pos_ + 1] == 'u') {
                                uint32_t low = 0;
                                if (parseHex4At(src_, pos_ + 2, low) &&
                                    low >= 0xDC00u && low <= 0xDFFFu) {
                                    pos_ += 6;
                                    const uint32_t fullCp =
                                        0x10000u + (((code - 0xD800u) << 10) | (low - 0xDC00u));
                                    appendUtf8Codepoint(out, fullCp);
                                    break;
                                }
                            }
                            appendUtf8Codepoint(out, code);
                        }
                        break;
                    }
                    default:
                        out.push_back(esc);
                        break;
                }
            } else {
                out.push_back(c);
            }
        }
        return false;
    }

    bool skipComposite(char openCh, char closeCh, std::string& rawCapture) {
        size_t start = pos_;
        int depth = 0;
        bool inStr = false;
        while (pos_ < src_.size()) {
            char c = src_[pos_++];
            if (inStr) {
                if (c == '\\' && pos_ < src_.size()) {
                    ++pos_;
                } else if (c == '"') {
                    inStr = false;
                }
            } else {
                if (c == '"') {
                    inStr = true;
                } else if (c == openCh) {
                    ++depth;
                } else if (c == closeCh) {
                    --depth;
                    if (depth == 0) {
                        rawCapture = src_.substr(start, pos_ - start);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    bool parseScalarOrSkip(std::string& out) {
        char c = peek();
        if (c == '"') {
            return parseString(out);
        }
        if (c == '{') {
            return skipComposite('{', '}', out);
        }
        if (c == '[') {
            return skipComposite('[', ']', out);
        }
        size_t start = pos_;
        while (pos_ < src_.size()) {
            char ch = src_[pos_];
            if (ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                break;
            }
            ++pos_;
        }
        if (pos_ == start) return false;
        out = src_.substr(start, pos_ - start);
        if (out == "null") {
            out.clear();
        }
        return true;
    }

    const std::string& src_;
    size_t pos_ = 0;
};

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out.push_back(c); break;
        }
    }
    return out;
}

size_t curlWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    auto* response = static_cast<std::string*>(userp);
    response->append(static_cast<const char*>(contents), total);
    return total;
}

void ensureCurlGlobalInit() {
    static std::once_flag onceFlag;
    std::call_once(onceFlag, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

#ifdef _WIN32
std::wstring platformUtf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int req = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (req <= 0) return {};
    std::wstring w(static_cast<size_t>(req), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), w.data(), req);
    return w;
}

std::string platformWideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int req = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (req <= 0) return {};
    std::string u(static_cast<size_t>(req), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), u.data(), req, nullptr, nullptr);
    return u;
}

std::filesystem::path platformUtf8Path(const std::string& utf8) {
    return std::filesystem::path(platformUtf8ToWide(utf8));
}
#else
std::filesystem::path platformUtf8Path(const std::string& utf8) {
    return std::filesystem::path(utf8);
}
#endif

std::string generateDefaultWin32Uuid() {
    return VngAuthProvider::resolvePersistentDeviceId();
}

// Internal main-thread queue sentinel used to marshal expired-cache interactive re-login
// onto Platform::tickLoop() instead of calling authProvider_->login() from detached HTTP threads.
constexpr int kInternalRetryInteractiveLoginEventId = -1001;

// ---------------------------------------------------------------------------
// Table-driven capability shim for dropped Android/iOS SDK calls
// ---------------------------------------------------------------------------
const std::array<CapabilityShimEntry, 26> kCapabilityShimTable = {{
    {"pay",                       "billing",  true,  kPay,              kHttpFailed,  "{\"code\":-1,\"msg\":\"Win32: in-app billing unsupported\"}"},
    {"issueDJOrders",             "billing",  true,  kIssueDJOrders,    kHttpFailed,  "{\"code\":-1,\"msg\":\"Win32: DJ orders unsupported\"}"},
    {"shareWeixin",               "social",   true,  kShareBack,        kHttpFailed,  "{\"code\":-1,\"msg\":\"Win32: WeChat sharing unsupported\"}"},
    {"playVideo",                 "media",    true,  kPlayFinish,       kHttpSuccess, "{\"code\":0,\"msg\":\"Win32: video playback skipped\"}"},
    {"openCustomWebView",         "webview",  false, 0,                 kHttpSuccess, "{}"},
    {"closeCustomWebView",        "webview",  false, 0,                 kHttpSuccess, "{}"},
    {"doCustomWebViewAction",     "webview",  false, 0,                 kHttpSuccess, "{}"},
    {"showToolBar",               "sdk_ui",   false, 0,                 kHttpSuccess, "{}"},
    {"hideToolBar",               "sdk_ui",   false, 0,                 kHttpSuccess, "{}"},
    {"enterUserCenter",           "sdk_ui",   false, 0,                 kHttpSuccess, "{}"},
    {"accountSwitch",             "sdk_ui",   false, 0,                 kHttpSuccess, "{}"},
    {"pause",                     "lifecycle",false, 0,                 kHttpSuccess, "{}"},
    {"onPressBack",               "lifecycle",false, 0,                 kHttpSuccess, "{}"},
    {"quit",                      "lifecycle",true,  kQuit,             kHttpSuccess, "{\"code\":0,\"msg\":\"Win32: quit acknowledged\"}"},
    {"sendInformationToPlatform", "tracking", false, 0,                 kHttpSuccess, "{}"},
    {"sendTracking",              "tracking", false, 0,                 kHttpSuccess, "{}"},
    {"retention",                 "tracking", false, 0,                 kHttpSuccess, "{}"},
    {"sendLog",                   "tracking", false, 0,                 kHttpSuccess, "{}"},
    {"sendAdstat",                "tracking", false, 0,                 kHttpSuccess, "{}"},
    {"push",                      "push",     false, 0,                 kHttpSuccess, "{}"},
    {"registerPush",              "push",     false, 0,                 kHttpSuccess, "{}"},
    {"unregisterPush",            "push",     false, 0,                 kHttpSuccess, "{}"},
    {"showMessage",               "ui",       false, 0,                 kHttpSuccess, "{}"},
    {"searchHandleUrl",           "deeplink", false, 0,                 kHttpSuccess, "{}"},
    {"getNetworkCapture",         "diag",     true,  kNetworkCapture,   kHttpSuccess, "{\"code\":0,\"data\":{}}"},
    {"openUrl",                   "browser",  false, 0,                 kHttpSuccess, "{}"},
}};

}  // namespace

// ---------------------------------------------------------------------------
// Platform singleton & lifecycle
// ---------------------------------------------------------------------------
Platform* Platform::getInstance() {
    static Platform instance;
    return &instance;
}

static std::shared_ptr<IAuthProvider> createDefaultAuthProvider() {
#ifdef _WIN32
    char buf[16] = {};
    if (::GetEnvironmentVariableA("GCLIENT_USE_LOCAL_STUB_AUTH", buf, sizeof(buf)) > 0 &&
        std::strcmp(buf, "1") == 0) {
        return std::make_shared<LocalStubAuthProvider>();
    }
#endif
    return std::make_shared<VngAuthProvider>();
}

Platform::Platform()
    : authProvider_(createDefaultAuthProvider()),
      uuid_(generateDefaultWin32Uuid()) {
    ensureCurlGlobalInit();
}

Platform::~Platform() {
    shuttingDown_.store(true);
}

void Platform::setAuthProvider(std::shared_ptr<IAuthProvider> provider) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (provider) {
        authProvider_ = std::move(provider);
    }
}

std::shared_ptr<IAuthProvider> Platform::getAuthProvider() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return authProvider_;
}

void Platform::setDesDecryptor(std::shared_ptr<IDesDecryptor> decryptor) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    desDecryptor_ = std::move(decryptor);
}

void Platform::setLogHandler(LogHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    logHandler_ = std::move(handler);
}

void Platform::setCallbackHandler(CallbackHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    callbackHandler_ = std::move(handler);
}

void Platform::setSyncCallbackHandler(CallbackHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    syncCallbackHandler_ = std::move(handler);
}

void Platform::setWebViewBridgeHandler(WebViewBridgeHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    webViewBridgeHandler_ = std::move(handler);
}

void Platform::dispatchWebViewBridge(const std::string& action,
                                     int x,
                                     int y,
                                     int width,
                                     int height,
                                     const std::string& url) {
    WebViewBridgeHandler handler;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        handler = webViewBridgeHandler_;
    }
    if (handler) {
        handler(action, x, y, width, height, url);
        return;
    }
    if (action == "updateURL" && !url.empty()) {
        openUrl(url);
    }
}

void Platform::setResourceRoot(const std::string& rootPath) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    resourceRoot_ = rootPath;
    if (!resourceRoot_.empty() && resourceRoot_.back() != '/' && resourceRoot_.back() != '\\') {
        resourceRoot_.push_back('/');
    }
}

void Platform::log(const std::string& level, const std::string& message) const {
    LogHandler handler;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        handler = logHandler_;
    }
    if (handler) {
        handler(level, message);
        return;
    }
    std::fprintf(stderr, "[bt::Platform][%s] %s\n", level.c_str(), message.c_str());
}

static std::string getSdkCookieJarPath();

bool Platform::readBinaryFile(const std::string& path, std::vector<uint8_t>& outBytes) const {
    std::ifstream ifs(platformUtf8Path(path), std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        return false;
    }
    const std::streamsize size = ifs.tellg();
    if (size <= 0) {
        return false;
    }
    ifs.seekg(0, std::ios::beg);
    outBytes.resize(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(outBytes.data()), size)) {
        return false;
    }
    size_t len = outBytes.size();
    if (gclient::assets::DecryptBuffer(outBytes.data(), &len, path.c_str(), nullptr)) {
        outBytes.resize(len);
    }
    return true;
}

static std::string readPlatformEnvUtf8(const char* name) {
    if (!name || !*name) {
        return {};
    }
#ifdef _WIN32
    const std::wstring wName = platformUtf8ToWide(name);
    if (!wName.empty()) {
        const DWORD needed = ::GetEnvironmentVariableW(wName.c_str(), nullptr, 0);
        if (needed > 1) {
            std::wstring wBuf(static_cast<size_t>(needed), L'\0');
            const DWORD wLen = ::GetEnvironmentVariableW(wName.c_str(), wBuf.data(), needed);
            if (wLen > 0 && wLen < needed) {
                wBuf.resize(wLen);
                return platformWideToUtf8(wBuf);
            }
        }
    }
#endif
    if (const char* v = std::getenv(name)) {
        return std::string(v);
    }
    return {};
}

static bool isTruthyPlatformEnv(const char* name) {
    std::string v = readPlatformEnvUtf8(name);
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front()))) v.erase(v.begin());
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back()))) v.pop_back();
    return v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES";
}

std::string Platform::resolveConfigPath(const std::string& relativePath) const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (!resourceRoot_.empty()) {
        return resourceRoot_ + relativePath;
    }
    return relativePath;
}

std::vector<std::string> Platform::buildConfigSearchRoots() const {
    std::string rootCopy;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        rootCopy = resourceRoot_;
    }

    auto normalizeRoot = [](std::string r) -> std::string {
        while (!r.empty() && std::isspace(static_cast<unsigned char>(r.front()))) r.erase(r.begin());
        while (!r.empty() && std::isspace(static_cast<unsigned char>(r.back()))) r.pop_back();
        std::replace(r.begin(), r.end(), '\\', '/');
        if (!r.empty() && r.back() != '/') {
            r.push_back('/');
        }
        return r;
    };

    std::vector<std::string> roots;
    auto addUnique = [&](const std::string& raw, bool allowEmpty) {
        std::string norm = allowEmpty && raw.empty() ? std::string() : normalizeRoot(raw);
        if (!allowEmpty && norm.empty()) {
            return;
        }
        if (std::find(roots.begin(), roots.end(), norm) == roots.end()) {
            roots.push_back(std::move(norm));
        }
    };

    addUnique(rootCopy, false);
    addUnique(readPlatformEnvUtf8("GCLIENT_BASE_ASSETS_DIR"), false);
    addUnique(readPlatformEnvUtf8("GCLIENT_ASSETS_DIR"), false);
    addUnique(readPlatformEnvUtf8("GCLIENT_RESOURCES_DIR"), false);
    addUnique("base_assets/", false);
    addUnique("assets/", false);
    addUnique("Resources/", false);
    addUnique("", true);
    return roots;
}

// ---------------------------------------------------------------------------
// Ported from bt::Platform::loadConfig @ 0xc4370 (DES_Decrypt2Buffer "BTPRIKEY")
// ---------------------------------------------------------------------------
ConfigDocument Platform::loadConfig(const std::string& relativePath) const {
    log("debug", "loadConfig: " + relativePath);

    std::string dirCopy;
    std::shared_ptr<IDesDecryptor> decryptor;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        dirCopy = platformDir_;
        decryptor = desDecryptor_;
    }
    if (!dirCopy.empty() && dirCopy.back() != '/' && dirCopy.back() != '\\') {
        dirCopy.push_back('/');
    }

    std::string relNorm = relativePath;
    while (!relNorm.empty() && (relNorm.front() == '/' || relNorm.front() == '\\')) {
        relNorm.erase(relNorm.begin());
    }

    const std::vector<std::string> searchRoots = buildConfigSearchRoots();
    std::vector<uint8_t> rawBytes;
    bool loaded = false;

    for (const std::string& root : searchRoots) {
        if (!dirCopy.empty()) {
            const std::string overridePath = root + dirCopy + relNorm;
            log("debug", "filePath candidate = " + overridePath);
            rawBytes.clear();
            if (readBinaryFile(overridePath, rawBytes) && !rawBytes.empty()) {
                log("release", "filePath = " + overridePath);
                loaded = true;
                break;
            }
        }

        const std::string candidatePath = root + relNorm;
        log("debug", "filename candidate = " + candidatePath);
        rawBytes.clear();
        if (readBinaryFile(candidatePath, rawBytes) && !rawBytes.empty()) {
            log("release", "filename = " + candidatePath);
            loaded = true;
            break;
        }
    }

    ConfigDocument doc;
    if (!loaded || rawBytes.empty()) {
        log("debug", "Failed to readFile " + relativePath);
        return doc;
    }

    std::string jsonText;
    // Detect plaintext JSON directly (convenient for Win32 dev/private-server overrides)
    size_t firstNonWs = 0;
    while (firstNonWs < rawBytes.size() &&
           std::isspace(static_cast<unsigned char>(rawBytes[firstNonWs]))) {
        ++firstNonWs;
    }
    const bool looksPlainJson = (firstNonWs < rawBytes.size() &&
                                 (rawBytes[firstNonWs] == '{' || rawBytes[firstNonWs] == '['));

    if (looksPlainJson) {
        jsonText.assign(reinterpret_cast<const char*>(rawBytes.data()), rawBytes.size());
    } else if (decryptor) {
        if (!decryptor->decrypt(rawBytes.data(), rawBytes.size(), kDefaultConfigDesKey, jsonText)) {
            log("debug", "Failed to DES_Decrypt2Buffer for " + relativePath);
            return doc;
        }
    } else if (rawBytes.size() > 8 && std::memcmp(rawBytes.data(), "F0F0F0F0", 8) == 0 &&
               (rawBytes.size() - 8) % 8 == 0) {
        // Ported from libnew_sdk.so DES_Decrypt2Buffer (LSB-first Char8ToBit64 + exact PC2 table)
        static constexpr int kIp[64] = {
            57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3, 61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
            56,48,40,32,24,16,8,0, 58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6
        };
        static constexpr int kIp1[64] = {
            39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29, 36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27, 34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25, 32,0,40,8,48,16,56,24
        };
        static constexpr int kE[48] = {
            31,0,1,2,3,4, 3,4,5,6,7,8, 7,8,9,10,11,12, 11,12,13,14,15,16,
            15,16,17,18,19,20, 19,20,21,22,23,24, 23,24,25,26,27,28, 27,28,29,30,31,0
        };
        static constexpr int kP[32] = {
            15,6,19,20,28,11,27,16, 0,14,22,25,4,17,30,9, 1,7,23,13,31,26,2,8, 18,12,29,5,21,10,3,24
        };
        static constexpr int kPc1[56] = {
            56,48,40,32,24,16,8, 0,57,49,41,33,25,17, 9,1,58,50,42,34,26, 18,10,2,59,51,43,35,
            62,54,46,38,30,22,14, 6,61,53,45,37,29,21, 13,5,60,52,44,36,28, 20,12,4,27,19,11,3
        };
        static constexpr int kPc2[48] = {
            13,16,10,23,0,4, 2,27,14,5,20,9, 22,18,11,3,25,7, 15,6,26,19,12,1,
            40,51,30,36,46,54, 29,39,50,44,32,46, 43,48,38,55,33,52, 45,41,49,35,28,31
        };
        static constexpr int kShifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
        static constexpr uint8_t kS[8][64] = {
            {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
            {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
            {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
            {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
            {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
            {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
            {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
            {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
        };

        uint8_t keyBits[64]{};
        for (int i = 0; i < 8; ++i) {
            const uint8_t ch = static_cast<uint8_t>(kDefaultConfigDesKey[i]);
            for (int b = 0; b < 8; ++b) keyBits[i * 8 + b] = (ch >> b) & 1;
        }
        uint8_t cd[56]{};
        for (int i = 0; i < 56; ++i) cd[i] = keyBits[kPc1[i]];
        uint8_t subkeys[16][48]{};
        for (int r = 0; r < 16; ++r) {
            const int sh = kShifts[r];
            uint8_t tmp[56];
            std::memcpy(tmp, cd, 56);
            for (int i = 0; i < 28; ++i) {
                cd[i] = tmp[(i + sh) % 28];
                cd[28 + i] = tmp[28 + (i + sh) % 28];
            }
            for (int i = 0; i < 48; ++i) subkeys[r][i] = cd[kPc2[i]];
        }

        const uint8_t* enc = rawBytes.data() + 8;
        const size_t encLen = rawBytes.size() - 8;
        std::vector<uint8_t> dec(encLen);
        for (size_t off = 0; off < encLen; off += 8) {
            uint8_t blkBits[64]{}, ipBits[64]{};
            for (int i = 0; i < 8; ++i) {
                const uint8_t ch = enc[off + i];
                for (int b = 0; b < 8; ++b) blkBits[i * 8 + b] = (ch >> b) & 1;
            }
            for (int i = 0; i < 64; ++i) ipBits[i] = blkBits[kIp[i]];
            uint8_t L[32], R[32];
            std::memcpy(L, ipBits, 32);
            std::memcpy(R, ipBits + 32, 32);
            for (int r = 15; r >= 0; --r) {
                uint8_t ep[48], sb[32], f[32];
                for (int i = 0; i < 48; ++i) ep[i] = R[kE[i]] ^ subkeys[r][i];
                for (int i = 0; i < 8; ++i) {
                    const uint8_t* g = ep + i * 6;
                    const uint8_t val = kS[i][g[0] * 32 + g[5] * 16 + g[1] * 8 + g[2] * 4 + g[3] * 2 + g[4]];
                    sb[i * 4 + 0] = (val >> 3) & 1;
                    sb[i * 4 + 1] = (val >> 2) & 1;
                    sb[i * 4 + 2] = (val >> 1) & 1;
                    sb[i * 4 + 3] = val & 1;
                }
                for (int i = 0; i < 32; ++i) f[i] = sb[kP[i]] ^ L[i];
                std::memcpy(L, R, 32);
                std::memcpy(R, f, 32);
            }
            uint8_t rl[64], outBits[64];
            std::memcpy(rl, R, 32);
            std::memcpy(rl + 32, L, 32);
            for (int i = 0; i < 64; ++i) outBits[i] = rl[kIp1[i]];
            for (int i = 0; i < 8; ++i) {
                uint8_t v = 0;
                for (int b = 0; b < 8; ++b) v |= static_cast<uint8_t>(outBits[i * 8 + b] << b);
                dec[off + i] = v;
            }
        }
        while (!dec.empty() && dec.back() == 0) {
            dec.pop_back();
        }
        jsonText.assign(reinterpret_cast<const char*>(dec.data()), dec.size());
    } else {
        log("release", "Encrypted config detected (" + relativePath +
                       ") but no IDesDecryptor registered; attempting raw parse fallback");
        jsonText.assign(reinterpret_cast<const char*>(rawBytes.data()), rawBytes.size());
    }

    MiniJsonParser parser(jsonText);
    if (!parser.parseObjectToConfig(doc)) {
        log("debug", "Failed to parse JSON config: " + relativePath);
    }
    log("debug", "loadConfig end");
    return doc;
}

// ---------------------------------------------------------------------------
// Ported from bt::Platform::initSDK @ 0xdcbec
// ---------------------------------------------------------------------------
void Platform::initSDK(const std::string& jsonParam, CallbackHandler callback) {
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        initTimestamp_ = static_cast<int64_t>(std::time(nullptr));
        if (callback) {
            callbackHandler_ = std::move(callback);
        }
        if (!jsonParam.empty()) {
            const auto parsed = parseFlatJsonObject(jsonParam);
            auto itDir = parsed.find("platformDir");
            if (itDir != parsed.end() && !itDir->second.empty()) {
                platformDir_ = itDir->second;
            }
        }
        isLoggingIn_ = false;
    }

    log("release", "platformDir: " + platformDir_);
    log("release", std::string("initSDK version: ") + kSdkVersion);

    ConfigDocument pCfg = loadConfig("platform/config.json");
    ConfigDocument gCfg = loadConfig("platform/game_config.json");

    std::map<std::string, std::string> initMap;
    std::shared_ptr<IAuthProvider> provider;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        platformConfig_ = std::move(pCfg);
        gameConfig_ = std::move(gCfg);

        if (platformConfig_.hasKey("debug")) {
            try {
                debugLevel_ = std::stoi(platformConfig_.getString("debug"));
            } catch (...) {
                debugLevel_ = 0;
            }
        }

        payConfig_ = platformConfig_.getObject("pay");
        localizedConfig_ = gameConfig_.getObject("localized");
        initMap = gameConfig_.values;
        for (const auto& kv : platformConfig_.values) {
            initMap[kv.first] = kv.second;
        }
        for (const auto& kv : platformConfig_.getObject("init")) {
            initMap[kv.first] = kv.second;
        }

        if (platformConfig_.hasKey("isSimulation")) {
            isSimulation_ = (platformConfig_.getString("isSimulation") == "1");
            log("release", "isSimulation=" + std::to_string(isSimulation_ ? 1 : 0));
        }
        if (platformConfig_.hasKey("simulateHashHost")) {
            simulationHashHost_ = platformConfig_.getString("simulateHashHost");
            log("release", "_simulationHashHost=" + simulationHashHost_);
        }
        if (platformConfig_.hasKey("isStandAlone")) {
            isStandAlone_ = (platformConfig_.getString("isStandAlone") == "1");
            log("release", "_isStandAlone=" + std::to_string(isStandAlone_ ? 1 : 0));
        }
        if (gameConfig_.hasKey("pushurl")) {
            pushUrl_ = gameConfig_.getString("pushurl");
        }
        if (gameConfig_.hasKey("gn")) {
            gnOverride_ = gameConfig_.getString("gn");
        }

        combinedPl_ = platformConfig_.getString("pl", "vnsg2");
        if (platformConfig_.hasKey("other_pl")) {
            combinedPl_ = platformConfig_.getString("other_pl") + "|" + combinedPl_;
        }

        uuid_ = VngAuthProvider::resolvePersistentDeviceId();
        isInitialized_ = true;
        provider = authProvider_;
    }

    if (provider) {
        const bool ok = provider->initialize(initMap);
        log("release", "AuthProvider '" + provider->providerName() +
                       "' initialize=" + (ok ? "ok" : "failed"));
    }

    log("release", "initSDK end");
    receiveCallBack(kInit, kHttpSuccess, "{\"errornu\":\"0\",\"errordesc\":\"ok\"}");
}

// ---------------------------------------------------------------------------
// Ported from bt::Platform::tickLoop @ 0xc1f6c
// ---------------------------------------------------------------------------
void Platform::tickLoop() {
    bool initialized = false;
    std::shared_ptr<IAuthProvider> provider;
    CallbackHandler mainCb;
    CallbackHandler syncCb;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        initialized = isInitialized_;
        provider = authProvider_;
        mainCb = callbackHandler_;
        syncCb = syncCallbackHandler_;
    }
    if (!initialized) {
        return;
    }

    if (provider) {
        provider->poll();
    }

    std::deque<PendingCallback> batch;
    {
        std::lock_guard<std::mutex> lock(callbackQueueMutex_);
        if (callbackQueue_.empty()) {
            return;
        }
        batch.swap(callbackQueue_);
    }

    for (const auto& item : batch) {
        if (item.eventId == kInternalRetryInteractiveLoginEventId) {
            std::shared_ptr<IAuthProvider> retryProv = getAuthProvider();
            if (retryProv) {
                retryProv->logout(nullptr);
            }
            startLoginAttempt(false);
            if (retryProv) {
                retryProv->poll();
            }
            continue;
        }
        if (mainCb) {
            mainCb(item.eventId, item.statusCode, item.payload);
        }
        if (syncCb) {
            syncCb(item.eventId, item.statusCode, item.payload);
        }
    }
}

void Platform::receiveCallBack(int eventId, int statusCode, const std::string& payload) {
    std::lock_guard<std::mutex> lock(callbackQueueMutex_);
    callbackQueue_.push_back(PendingCallback{eventId, statusCode, payload});
}

void Platform::registeCallBackBySync(CallbackHandler handler) {
    setSyncCallbackHandler(std::move(handler));
}

static bool performSharedHttpGet(const std::string& url,
                                 std::string& outBody,
                                 long& outHttpCode,
                                 std::string& outErr);

static std::string extractJsonScalar(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return {};
    if (json[pos] == '"') {
        ++pos;
        std::string out;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                ++pos;
            }
            out.push_back(json[pos++]);
        }
        return out;
    }
    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' &&
           !std::isspace(static_cast<unsigned char>(json[end]))) {
        ++end;
    }
    return json.substr(pos, end - pos);
}

// ---------------------------------------------------------------------------
// Ported from bt::Platform::login @ 0xca46c & logout
// ---------------------------------------------------------------------------
void Platform::login() {
    startLoginAttempt(true);
}

void Platform::startLoginAttempt(bool allowInteractiveRetryOnExpiredCache) {
    log("debug", "login");

    std::shared_ptr<IAuthProvider> provider;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        if (isSimulation_) {
            log("release", "is simulation, skip login");
            return;
        }
        if (!isInitialized_ || isLoggingIn_) {
            log("release", "not init or loginning");
            return;
        }
        isLoggingIn_ = true;
        provider = authProvider_;
    }

    if (!provider) {
        {
            std::lock_guard<std::recursive_mutex> lock(stateMutex_);
            isLoggingIn_ = false;
        }
        receiveCallBack(kLogin, kHttpFailed,
                        "{\"errornu\":\"1\",\"code\":-1,\"errordesc\":\"No IAuthProvider configured\",\"msg\":\"No IAuthProvider configured\"}");
        return;
    }

    provider->login([this, allowInteractiveRetryOnExpiredCache](const AuthResult& result) {
        if (shuttingDown_.load()) {
            return;
        }
        if (!result.success) {
            {
                std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                isLoggingIn_ = false;
                isLogined_ = false;
                pid_.clear();
                sessionToken_.clear();
            }
            std::ostringstream oss;
            oss << "{\"errornu\":\"1\",\"code\":" << result.errorCode
                << ",\"errordesc\":\"" << jsonEscape(result.errorMessage) << "\"}";
            receiveCallBack(kLogin, kHttpFailed, oss.str());
            return;
        }

        const bool isOfflineGuest =
            VngAuthProvider::isOfflineStubToken(result.session.token);
        if (isOfflineGuest) {
            {
                std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                isLoggingIn_ = false;
                isLogined_ = true;
                pid_ = result.session.pid;
                sessionToken_ = result.session.token;
            }
            std::ostringstream oss;
            oss << "{\"errornu\":\"0\",\"errordesc\":\"ok\",\"uid\":\"" << jsonEscape(result.session.pid)
                << "\",\"pid\":\"" << jsonEscape(result.session.pid)
                << "\",\"token\":\"" << jsonEscape(result.session.token)
                << "\",\"username\":\"" << jsonEscape(result.session.username)
                << "\",\"newuser\":\"0\"}";
            receiveCallBack(kLogin, kHttpSuccess, oss.str());
            return;
        }

        // Exchange VNG userID + sessionID on the game backend's signed /phone/login endpoint
        // (matching bt::Platform::getPidBySession @ 0xd534c in libnew_sdk.so) using the shared
        // CURLSH* cookie handle so PHPSESSID is captured for /phone/gethash/.
        const std::string uuid = getUUID();
        const std::string rawLoginUrl = getHost() + getStandAlone() +
                                        "/login?userid=" + urlEncode(result.session.pid) +
                                        "&sessionid=" + urlEncode(result.session.token) +
                                        getUrlParam() +
                                        "&bind=" + urlEncode(uuid) +
                                        "&uuid=" + urlEncode(uuid) +
                                        "&country=VN";
        const std::string signedLoginUrl = signUrl(rawLoginUrl);
        log("debug", "login exchange url=" + signedLoginUrl);

        std::thread([this, result, signedLoginUrl, allowInteractiveRetryOnExpiredCache]() {
            if (shuttingDown_.load()) {
                return;
            }
            std::string body;
            long httpCode = 0;
            std::string errMsg;
            const bool ok = performSharedHttpGet(signedLoginUrl, body, httpCode, errMsg);
            if (shuttingDown_.load()) {
                return;
            }

            if (!ok) {
                std::shared_ptr<IAuthProvider> prov;
                {
                    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                    isLoggingIn_ = false;
                    isLogined_ = false;
                    pid_.clear();
                    sessionToken_.clear();
                    if (httpCode == 401 || httpCode == 403) {
                        prov = authProvider_;
                    }
                }
                if (prov && result.fromCache && allowInteractiveRetryOnExpiredCache) {
#ifdef _WIN32
                    log("release", "Cached VNG token rejected with HTTP " + std::to_string(httpCode) +
                                   "; marshaling Win32 Sign-In dialog onto main thread");
                    receiveCallBack(kInternalRetryInteractiveLoginEventId, 0, "");
                    return;
#else
                    if (prov->providerName() != "VngAuthProvider") {
                        receiveCallBack(kInternalRetryInteractiveLoginEventId, 0, "");
                        return;
                    }
#endif
                }
                if (prov) {
                    prov->logout(nullptr);
                }
                std::ostringstream oss;
                oss << "{\"errornu\":\"1\",\"code\":" << httpCode
                    << ",\"errordesc\":\"" << jsonEscape(errMsg) << "\"}";
                receiveCallBack(kLogin, kHttpFailed, oss.str());
                return;
            }

            log("debug", "login exchange response: " + body);
            const std::string errNo = extractJsonScalar(body, "errornu");
            const std::string errDesc = extractJsonScalar(body, "errordesc");
            const std::string candPid = !extractJsonScalar(body, "pid").empty()
                                            ? extractJsonScalar(body, "pid")
                                            : extractJsonScalar(body, "uid");
            if ((!errNo.empty() && errNo != "0") || (errNo.empty() && candPid.empty())) {
                std::shared_ptr<IAuthProvider> prov;
                {
                    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                    isLoggingIn_ = false;
                    isLogined_ = false;
                    pid_.clear();
                    sessionToken_.clear();
                    prov = authProvider_;
                }
                if (prov && result.fromCache && allowInteractiveRetryOnExpiredCache) {
#ifdef _WIN32
                    log("release", "Cached VNG session expired (" + errDesc +
                                   "); marshaling cache clear and Win32 Sign-In dialog onto main thread");
                    receiveCallBack(kInternalRetryInteractiveLoginEventId, 0, "");
                    return;
#else
                    if (prov->providerName() != "VngAuthProvider") {
                        receiveCallBack(kInternalRetryInteractiveLoginEventId, 0, "");
                        return;
                    }
#endif
                }
                if (prov) {
                    prov->logout(nullptr);
                }
                const std::string reportedErr = errNo.empty() ? "1" : errNo;
                std::ostringstream oss;
                oss << "{\"errornu\":\"" << jsonEscape(reportedErr)
                    << "\",\"errordesc\":\"" << jsonEscape(errDesc.empty() ? body : errDesc) << "\"}";
                receiveCallBack(kLogin, kHttpFailed, oss.str());
                return;
            }

            std::string resolvedPid = extractJsonScalar(body, "pid");
            if (resolvedPid.empty()) {
                resolvedPid = extractJsonScalar(body, "uid");
            }
            if (resolvedPid.empty()) {
                resolvedPid = result.session.pid;
            }

            {
                std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                isLoggingIn_ = false;
                isLogined_ = true;
                pid_ = resolvedPid;
                sessionToken_ = result.session.token;
            }

            std::ostringstream oss;
            oss << "{\"errornu\":\"0\",\"errordesc\":\"ok\",\"uid\":\"" << jsonEscape(resolvedPid)
                << "\",\"pid\":\"" << jsonEscape(resolvedPid)
                << "\",\"token\":\"" << jsonEscape(result.session.token)
                << "\",\"username\":\"" << jsonEscape(result.session.username)
                << "\",\"newuser\":\"0\"}";
            receiveCallBack(kLogin, kHttpSuccess, oss.str());
        }).detach();
    });
}

void Platform::logout() {
    log("debug", "logout");
    std::shared_ptr<IAuthProvider> provider;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        provider = authProvider_;
        isLogined_ = false;
        isLoggingIn_ = false;
        pid_.clear();
        sessionToken_.clear();
    }
    const std::string cookieJar = getSdkCookieJarPath();
    if (!cookieJar.empty()) {
        std::error_code ec;
        std::filesystem::remove(platformUtf8Path(cookieJar), ec);
    }

    if (provider) {
        provider->logout([this](bool ok) {
            if (shuttingDown_.load()) return;
            receiveCallBack(kLogout, ok ? kHttpSuccess : kHttpFailed, "{\"code\":0}");
        });
    } else {
        receiveCallBack(kLogout, kHttpSuccess, "{\"code\":0}");
    }
}

bool Platform::isLogined() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return isLogined_;
}

// ---------------------------------------------------------------------------
// Ported from getHost / getStandAlone / getKey / getUrlParam / signUrl / compleUrl
// ---------------------------------------------------------------------------
std::string Platform::getHost() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (isDebugEnv_) {
        if (!gameConfig_.hasKey("host_debug")) {
            log("release", "error get host_debug from game_config");
            return "null";
        }
        return gameConfig_.getString("host_debug");
    }
    if (!gameConfig_.hasKey("host")) {
        log("release", "error get host from game_config");
        return "null";
    }
    return gameConfig_.getString("host");
}

std::string Platform::getLogHost() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (isDebugEnv_ && gameConfig_.hasKey("log_host_debug")) {
        return gameConfig_.getString("log_host_debug");
    }
    return gameConfig_.getString("log_host", "null");
}

std::string Platform::getStandAlone() const {
    return "/phone";
}

std::string Platform::getKey() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (!platformConfig_.hasKey("key")) {
        return kDefaultSignKey;
    }
    return platformConfig_.getString("key");
}

std::string Platform::getUrlParam() const {
    std::string param = "&pl=" + getPL() + "&os=" + getOS() + "&gn=" + getGN();
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (platformConfig_.hasKey("other_pl")) {
        param += "&other_pl=" + platformConfig_.getString("other_pl");
    }
    if (gameConfig_.hasKey("language")) {
        param += "&language=" + gameConfig_.getString("language");
    }
    return param;
}

std::string Platform::sortUrlParams(const std::string& url) {
    const size_t qPos = url.find('?');
    const std::string query = (qPos == std::string::npos) ? url : url.substr(qPos + 1);

    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= query.size()) {
        size_t amp = query.find('&', start);
        if (amp == std::string::npos) {
            amp = query.size();
        }
        if (amp > start) {
            parts.emplace_back(query.substr(start, amp - start));
        }
        start = amp + 1;
    }
    std::sort(parts.begin(), parts.end());

    std::string sorted;
    for (size_t i = 0; i < parts.size(); ++i) {
        sorted += parts[i];
    }
    return sorted;
}

std::string Platform::md5Hex(const std::string& data) {
    Md5Hasher hasher;
    hasher.update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return hasher.finalHex();
}

std::string Platform::signUrl(const std::string& url) const {
    return signUrl(url, getKey());
}

std::string Platform::signUrl(const std::string& url, const std::string& customKey) const {
    const int64_t nowSec = static_cast<int64_t>(std::time(nullptr));
    std::string urlWithTime = url + "&time=" + std::to_string(nowSec);
    std::string toSign = sortUrlParams(urlWithTime) + customKey;
    log("debug", "key=" + toSign);
    return urlWithTime + "&sign=" + md5Hex(toSign);
}

std::string Platform::compleUrl(const std::string& url) const {
    std::string out = url;
    std::string sep = (out.find('?') == std::string::npos) ? "?" : "&";

    if (out.find("pl=") == std::string::npos) {
        out += sep + "pl=" + getPL();
        sep = "&";
    }
    if (out.find("os=") == std::string::npos) {
        out += sep + "os=" + getOS();
        sep = "&";
    }
    if (out.find("gn=") == std::string::npos) {
        out += sep + "gn=" + getGN();
        sep = "&";
    }
    if (out.find("uuid=") == std::string::npos) {
        out += sep + "uuid=" + getUUID();
    }
    return signUrl(out);
}

// ---------------------------------------------------------------------------
// Web API calls via libcurl async worker -> receiveCallBack main-thread queue
// ---------------------------------------------------------------------------
std::string Platform::urlEncode(const std::string& raw) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex;
    for (unsigned char c : raw) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            oss << static_cast<char>(c);
        } else {
            oss << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
    }
    return oss.str();
}

std::map<std::string, std::string> Platform::parseFlatJsonObject(const std::string& jsonStr) {
    std::map<std::string, std::string> out;
    if (jsonStr.empty()) return out;
    MiniJsonParser parser(jsonStr);
    parser.parseFlatObject(out);
    return out;
}

std::string Platform::buildQueryFromJson(const std::string& jsonParams) const {
    std::string extra;
    const auto kv = parseFlatJsonObject(jsonParams);
    for (const auto& entry : kv) {
        const std::string encoded = urlEncode(entry.second);
        extra += "&" + entry.first + "=" + encoded;
        log("debug", "key=" + entry.first + ",value=" + encoded);
    }
    return extra;
}

static std::string getSdkCookieJarPath() {
    std::string dir = readPlatformEnvUtf8("GCLIENT_WRITABLE_DIR");
    if (!dir.empty()) {
        if (dir.back() != '/' && dir.back() != '\\') {
#ifdef _WIN32
            dir.push_back('\\');
#else
            dir.push_back('/');
#endif
        }
        return dir + "vng_sdk_cookies.txt";
    }
    return "vng_sdk_cookies.txt";
}

static void configureSharedCurlTls(CURL* curl) {
    if (!curl) return;
#ifdef CURLSSLOPT_NATIVE_CA
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif
    std::string caBundle = readPlatformEnvUtf8("GCLIENT_CA_BUNDLE");
    if (caBundle.empty()) {
        caBundle = readPlatformEnvUtf8("CURL_CA_BUNDLE");
    }
    if (!caBundle.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, caBundle.c_str());
    }
    if (isTruthyPlatformEnv("GCLIENT_INSECURE_TLS")) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

static CURLSH* getSharedCookieHandle() {
    static std::mutex cookieMutex;
    static CURLSH* share = []() -> CURLSH* {
        CURLSH* sh = curl_share_init();
        if (sh) {
            curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
            curl_share_setopt(sh, CURLSHOPT_LOCKFUNC,
                +[](CURL*, curl_lock_data, curl_lock_access, void* userptr) {
                    static_cast<std::mutex*>(userptr)->lock();
                });
            curl_share_setopt(sh, CURLSHOPT_UNLOCKFUNC,
                +[](CURL*, curl_lock_data, void* userptr) {
                    static_cast<std::mutex*>(userptr)->unlock();
                });
            curl_share_setopt(sh, CURLSHOPT_USERDATA, &cookieMutex);
        }
        return sh;
    }();
    return share;
}

static bool performSharedHttpGet(const std::string& url,
                                 std::string& outBody,
                                 long& outHttpCode,
                                 std::string& outErr) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        outErr = "curl_easy_init failed";
        return false;
    }

    const std::string cookieJar = getSdkCookieJarPath();
    char errBuf[CURL_ERROR_SIZE] = {0};
    outBody.clear();
    outHttpCode = 0;

    if (CURLSH* sh = getSharedCookieHandle()) {
        curl_easy_setopt(curl, CURLOPT_SHARE, sh);
    }
    if (!cookieJar.empty()) {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookieJar.c_str());
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookieJar.c_str());
    }
    configureSharedCurlTls(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outBody);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errBuf);

    const CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &outHttpCode);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && outHttpCode >= 200 && outHttpCode < 300) {
        return true;
    }
    outErr = (errBuf[0] != '\0') ? errBuf : curl_easy_strerror(res);
    return false;
}

void Platform::sendHTTPRequest(int eventId, const std::string& url, bool shouldSign) {
    const std::string finalUrl = shouldSign ? signUrl(url) : url;
    log("debug", "sendHTTPRequest event=" + std::to_string(eventId) + " url=" + finalUrl);

    std::thread([this, eventId, finalUrl]() {
        if (shuttingDown_.load()) {
            return;
        }
        std::string responseBody;
        long httpCode = 0;
        std::string errMsg;
        const bool ok = performSharedHttpGet(finalUrl, responseBody, httpCode, errMsg);

        if (shuttingDown_.load()) {
            return;
        }

        if (ok) {
            size_t firstNonWs = 0;
            while (firstNonWs < responseBody.size() &&
                   std::isspace(static_cast<unsigned char>(responseBody[firstNonWs]))) {
                ++firstNonWs;
            }
            const bool looksJson = (firstNonWs < responseBody.size() &&
                                    (responseBody[firstNonWs] == '{' || responseBody[firstNonWs] == '['));
            if (!looksJson) {
                const std::string wrapped =
                    "{\"errornu\":\"0\",\"errordesc\":\"OK\",\"data\":\"" + jsonEscape(responseBody) + "\"}";
                receiveCallBack(eventId, kHttpSuccess, wrapped);
            } else {
                receiveCallBack(eventId, kHttpSuccess, responseBody);
            }
        } else {
            const std::string safeDesc = errMsg.empty()
                ? ("HTTP error " + std::to_string(httpCode))
                : errMsg;
            std::ostringstream oss;
            oss << "{\"errornu\":\"1\""
                << ",\"errordesc\":\"" << jsonEscape(safeDesc) << "\""
                << ",\"code\":" << httpCode
                << ",\"http_code\":" << httpCode
                << ",\"msg\":\"" << jsonEscape(safeDesc) << "\"}";
            receiveCallBack(eventId, kHttpFailed, oss.str());
        }
    }).detach();
}

void Platform::getHash(const std::string& jsonParams) {
    log("debug", "getHash");
    std::string pidCopy;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        pidCopy = pid_;
    }
    if (pidCopy.empty()) {
        log("release", "not login");
        return;
    }

    const std::string extra = buildQueryFromJson(jsonParams);
    const std::string url = getHost() + getStandAlone() +
                            "/gethash/?pid=" + pidCopy +
                            "&uuid=" + getUUID() +
                            getUrlParam() + extra;
    sendHTTPRequest(kGetHash, url, true);
}

void Platform::getHashWithSimulation(const std::string& jsonParams) {
    log("debug", "getHashWithSimulation");
    std::string hostOverride;
    std::string pidCopy;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        hostOverride = simulationHashHost_;
        pidCopy = pid_;
    }
    const std::string baseHost = hostOverride.empty() ? getHost() : hostOverride;
    const std::string extra = buildQueryFromJson(jsonParams);
    const std::string url = baseHost + getStandAlone() +
                            "/gethash/?pid=" + pidCopy +
                            "&uuid=" + getUUID() +
                            getUrlParam() + extra;
    sendHTTPRequest(kGetHash, url, true);
}

void Platform::getServerList(const std::string& jsonParams) {
    log("debug", "getServerList");
    callUniversalWebFunction(kGetServerlist, "serverlist", jsonParams);
}

void Platform::getVersionInfo(const std::string& jsonParams) {
    log("debug", "getVersionInfo");
    callUniversalWebFunction(kGetVersion, "getversion", jsonParams);
}

void Platform::getLoginedServerInfo(const std::string& jsonParams) {
    callUniversalWebFunction(kGetLoginedServerInfo, "loginrole", jsonParams);
}

void Platform::getNotice(const std::string& jsonParams) {
    callUniversalWebFunction(kGetNotice, "notice", jsonParams);
}

void Platform::getSuperNotice(const std::string& jsonParams) {
    callUniversalWebFunction(kGetSuperNotice, "supernotice", jsonParams);
}

void Platform::getAppleReview(const std::string& jsonParams) {
    callUniversalWebFunction(kGetAppleReview, "applereview", jsonParams);
}

void Platform::question(const std::string& jsonParams) {
    callUniversalWebFunction(kQuestion, "question", jsonParams);
}

void Platform::getUserInformation(const std::string& jsonParams) {
    callUniversalWebFunction(kGetUserInformation, "userinfo", jsonParams);
}

void Platform::getBrowseActive(const std::string& jsonParams) {
    callUniversalWebFunction(kGetBrowseActive, "innerbrowse", jsonParams);
}

void Platform::getForceFix(const std::string& jsonParams) {
    callUniversalWebFunction(kGetForceFix, "getforcefix", jsonParams);
}

void Platform::callUniversalWebFunction(int eventId,
                                        const std::string& endpoint,
                                        const std::string& jsonParams) {
    log("debug", "callUniversalWebFunction: " + endpoint);
    const auto kv = parseFlatJsonObject(jsonParams);
    std::string extra;
    for (const auto& entry : kv) {
        const std::string encoded = urlEncode(entry.second);
        extra += "&" + entry.first + "=" + encoded;
        log("debug", "key=" + entry.first + ",value=" + encoded);
    }
    if (kv.find("pid") == kv.end() && endpoint.find("pid=") == std::string::npos) {
        std::string currentPid = getPid();
        if (currentPid.empty()) {
            std::shared_ptr<IAuthProvider> prov = getAuthProvider();
            if (prov && prov->isAuthenticated()) {
                currentPid = prov->currentSession().pid;
            }
        }
        if (!currentPid.empty()) {
            extra += "&pid=" + urlEncode(currentPid);
        }
    }
    const std::string sep = (endpoint.find('?') == std::string::npos) ? "/?uuid=" : "&uuid=";
    const std::string url = getHost() + getStandAlone() + "/" + endpoint +
                            sep + getUUID() +
                            getUrlParam() + extra;
    sendHTTPRequest(eventId, url, true);
}

// ---------------------------------------------------------------------------
// Metadata & environment accessors
// ---------------------------------------------------------------------------
bool Platform::isDebug() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return isDebugEnv_ || debugLevel_ > 0;
}

bool Platform::isAd() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("isAd", "0") == "1";
}

void Platform::setDebugEnv(bool debugEnv) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    isDebugEnv_ = debugEnv;
}

std::string Platform::getUUID() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return uuid_;
}

std::string Platform::getPid() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return pid_;
}

std::string Platform::getIdfa() const {
    return "";
}

std::string Platform::getPL() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("pl", "vnsg2");
}

std::string Platform::getOS() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("os", "android");
}

std::string Platform::getGN() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (!gnOverride_.empty()) {
        return gnOverride_;
    }
    return gameConfig_.getString("gn", "gclient");
}

std::string Platform::getSDKVersion() const {
    return kSdkVersion;
}

std::string Platform::getUserCenterName() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("userCenterName", "Win32");
}

std::string Platform::getDeviceInfo() const {
    return "{\"os\":\"win32\",\"model\":\"PC\",\"brand\":\"Windows\",\"sdk\":\"" +
           std::string(kSdkVersion) + "\"}";
}

std::string Platform::getDeviceFeature() const {
    return "{\"topDangerHeigth\":0,\"bottomDangerHeight\":0,"
           "\"leftDangerWidth\":0,\"rightDangerWidth\":0,"
           "\"safeInsetTop\":0,\"safeInsetBottom\":0,"
           "\"safeInsetLeft\":0,\"safeInsetRight\":0,"
           "\"statusBarHeight\":0,\"navigationBarHeight\":0}";
}

std::string Platform::getLocaleInfo() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return gameConfig_.getString("language", "en_US");
}

void Platform::setSimulationInfo(const std::string& jsonInfo) {
    const auto kv = parseFlatJsonObject(jsonInfo);
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    auto itPid = kv.find("pid");
    if (itPid != kv.end() && !itPid->second.empty()) {
        pid_ = itPid->second;
        isLogined_ = true;
    }
    auto itHost = kv.find("simulateHashHost");
    if (itHost != kv.end() && !itHost->second.empty()) {
        simulationHashHost_ = itHost->second;
    }
}

void Platform::setMainScreenBrightness(float brightness) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    screenBrightness_ = std::max(0.0f, std::min(1.0f, brightness));
}

float Platform::getMainScreenBrightness() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return screenBrightness_;
}

bool Platform::checkMethod(const std::string& methodName) const {
    // Report true ONLY for shimmed/supported methods and false for unknown mobile-only SDK methods.
    return findCapabilityShim(methodName) != nullptr;
}

// ---------------------------------------------------------------------------
// Table-driven capability shim for dropped Android SDK calls
// ---------------------------------------------------------------------------
const CapabilityShimEntry* Platform::findCapabilityShim(const std::string& methodName) {
    for (const auto& entry : kCapabilityShimTable) {
        if (methodName == entry.methodName) {
            return &entry;
        }
    }
    return nullptr;
}

bool Platform::invokeCapabilityShim(const std::string& methodName, const std::string& detail) {
    const CapabilityShimEntry* entry = findCapabilityShim(methodName);
    if (!entry) {
        log("release", "[CapabilityShim][unknown] Dropped call '" + methodName +
                       "' (detail=" + detail + ")");
        return false;
    }

    log("release", std::string("[CapabilityShim][") + entry->category + "] " +
                   entry->methodName + " ignored on Win32" +
                   (detail.empty() ? "" : (" (" + detail + ")")));

    if (entry->emitCallback) {
        receiveCallBack(entry->callbackEventId,
                        entry->defaultStatusCode,
                        entry->defaultPayloadJson ? entry->defaultPayloadJson : "{}");
    }
    return true;
}

void Platform::pay(const std::string& jsonParams) {
    invokeCapabilityShim("pay", jsonParams);
}

void Platform::showToolBar() {
    invokeCapabilityShim("showToolBar");
}

void Platform::hideToolBar() {
    invokeCapabilityShim("hideToolBar");
}

void Platform::enterUserCenter() {
    invokeCapabilityShim("enterUserCenter");
}

void Platform::accountSwitch() {
    logout();
}

void Platform::sendInformationToPlatform(int infoType, const std::string& jsonParams) {
    invokeCapabilityShim("sendInformationToPlatform",
                         "type=" + std::to_string(infoType) + " " + jsonParams);
}

void Platform::pause() {
    invokeCapabilityShim("pause");
}

void Platform::onPressBack() {
    invokeCapabilityShim("onPressBack");
}

void Platform::shareWeixin(const std::string& jsonParams) {
    invokeCapabilityShim("shareWeixin", jsonParams);
}

void Platform::playVideo(const std::string& videoPath) {
    invokeCapabilityShim("playVideo", videoPath);
}

void Platform::openCustomWebView(const std::string& jsonParams) {
    invokeCapabilityShim("openCustomWebView", jsonParams);
}

void Platform::closeCustomWebView() {
    invokeCapabilityShim("closeCustomWebView");
}

void Platform::doCustomWebViewAction(const std::string& jsonParams) {
    invokeCapabilityShim("doCustomWebViewAction", jsonParams);
}

void Platform::quit() {
    invokeCapabilityShim("quit");
}

void Platform::openUrl(const std::string& url) {
    invokeCapabilityShim("openUrl", url);
#ifdef _WIN32
    if (!url.empty() &&
        (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0)) {
        ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
#endif
}

void Platform::sendTracking(const std::string& eventName, const std::string& jsonParams) {
    invokeCapabilityShim("sendTracking", eventName + " " + jsonParams);
}

void Platform::retention(const std::string& jsonParams) {
    invokeCapabilityShim("retention", jsonParams);
}

void Platform::sendLog(const std::string& jsonParams) {
    invokeCapabilityShim("sendLog", jsonParams);
}

void Platform::sendAdstat() {
    invokeCapabilityShim("sendAdstat");
}

void Platform::showMessage(const std::string& title, const std::string& message) {
    invokeCapabilityShim("showMessage", title + ": " + message);
}

void Platform::issueDJOrders() {
    invokeCapabilityShim("issueDJOrders");
}

void Platform::searchHandleUrl() {
    invokeCapabilityShim("searchHandleUrl");
}

void Platform::getNetworkCapture(const std::string& jsonParams) {
    invokeCapabilityShim("getNetworkCapture", jsonParams);
}

void Platform::callUniversalFunction(const std::string& funcName, const std::string& jsonParams) {
    invokeCapabilityShim(funcName.empty() ? "callUniversalFunction" : funcName, jsonParams);
}

void Platform::callUniversalFunctionWithBack(const std::string& funcName,
                                             const std::string& jsonParams) {
    if (!invokeCapabilityShim(funcName, jsonParams)) {
        log("release", "[CapabilityShim][universal] Resolving unknown universal call '" +
                       funcName + "' cleanly without deadlock");
    }
}

void Platform::callUniversalFunctionWithBack(const std::string& funcName,
                                             const std::string& jsonParams,
                                             std::function<void(const std::string&)> callback) {
    callUniversalFunctionWithBack(funcName, jsonParams);
    if (callback) {
        callback("{}");
    }
}

}  // namespace bt
