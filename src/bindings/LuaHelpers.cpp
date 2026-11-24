#include "LuaHelpers.h"
#include "../assets/PlistbLoader.h"
#include "../assets/PbGuiLoader.h"
#include "../assets/XmlbArmatureLoader.h"
#include "../diagnostics/CrashAndTelemetry.h"
#include "cocos-ext.h"
#include "CocoStudio/GUI/UIWidgets/UIRichText.h"
#include "CocoStudio/Json/rapidjson/document.h"
#include "CocoStudio/Json/rapidjson/stringbuffer.h"
#include "CocoStudio/Json/rapidjson/writer.h"
#include "tolua++.h"
#include "tolua_fix.h"

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <set>
#include <type_traits>
#include <typeinfo>
#include <unordered_map>

USING_NS_CC;

namespace {

struct CCObjectRetainGuard {
    cocos2d::CCObject* obj = nullptr;
    explicit CCObjectRetainGuard(cocos2d::CCObject* o) : obj(o) {
        if (obj) {
            obj->retain();
        }
    }
    ~CCObjectRetainGuard() {
        if (obj) {
            obj->release();
        }
    }
    CCObjectRetainGuard(const CCObjectRetainGuard&) = delete;
    CCObjectRetainGuard& operator=(const CCObjectRetainGuard&) = delete;
};

lua_State* getLiveMainLuaState() {
    auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
    if (!mgr || !mgr->getScriptEngine()) {
        return nullptr;
    }
    auto* engine = cocos2d::CCLuaEngine::defaultEngine();
    auto* stack = engine ? engine->getLuaStack() : nullptr;
    return stack ? stack->getLuaState() : nullptr;
}

int toAbsLuaIndex(lua_State* L, int idx) {
    if (!L) return 0;
    if (idx < 0 && idx > LUA_REGISTRYINDEX) {
        return lua_gettop(L) + idx + 1;
    }
    return idx;
}

template <typename T>
void pushCCObject(lua_State* L, T* obj, const char* typeName) {
    static_assert(std::is_base_of<cocos2d::CCObject, T>::value, "T must inherit CCObject");
    if (!obj) {
        lua_pushnil(L);
        return;
    }
    cocos2d::CCObject* baseObj = static_cast<cocos2d::CCObject*>(obj);
    toluafix_pushusertype_ccobject(
        L,
        static_cast<int>(baseObj->m_uID),
        &baseObj->m_nLuaID,
        static_cast<void*>(baseObj),
        typeName ? typeName : "CCObject");
}

cocos2d::CCObject* extractRawCCObject(lua_State* L, int idx) {
    if (!L) return nullptr;
    const int absIdx = toAbsLuaIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) {
        return nullptr;
    }

    tolua_Error err{};
    const int tp = lua_type(L, absIdx);
    if (tp == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, "CCObject", 0, &err)) {
            return static_cast<cocos2d::CCObject*>(tolua_tousertype(L, absIdx, nullptr));
        }
        return nullptr;
    }

    if (tp == LUA_TTABLE) {
        // Unwrap tolua.inherit Lua peer tables (`t[".c_instance"]`).
        lua_pushvalue(L, absIdx);
        for (int depth = 0; depth < 4; ++depth) {
            if (!lua_istable(L, -1)) {
                break;
            }
            lua_pushlstring(L, ".c_instance", 11);
            lua_rawget(L, -2);
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                lua_getfield(L, -1, ".c_instance");
            }
            lua_remove(L, -2);
            if (lua_type(L, -1) == LUA_TUSERDATA) {
                cocos2d::CCObject* obj = nullptr;
                if (tolua_isusertype(L, -1, "CCObject", 0, &err)) {
                    obj = static_cast<cocos2d::CCObject*>(tolua_tousertype(L, -1, nullptr));
                }
                lua_pop(L, 1);
                return obj;
            }
        }
        lua_pop(L, 1);
    }
    return nullptr;
}

template <typename T>
T* getSafeCCObject(lua_State* L, int idx) {
    static_assert(std::is_base_of<cocos2d::CCObject, T>::value, "T must inherit CCObject");
    cocos2d::CCObject* obj = extractRawCCObject(L, idx);
    return obj ? dynamic_cast<T*>(obj) : nullptr;
}

template <typename T>
T* getSafeNamedUsertype(lua_State* L, int idx, const char* typeName) {
    if (!L || !typeName) return nullptr;
    const int absIdx = toAbsLuaIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) {
        return nullptr;
    }
    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, typeName, 0, &err)) {
            return static_cast<T*>(tolua_tousertype(L, absIdx, nullptr));
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
                if (tolua_isusertype(L, -1, typeName, 0, &err)) {
                    out = static_cast<T*>(tolua_tousertype(L, -1, nullptr));
                }
                lua_pop(L, 1);
                return out;
            }
        }
        lua_pop(L, 1);
    }
    return nullptr;
}

std::string normalizeAssetLookupPath(const char* raw) {
    if (!raw || !*raw) return {};
    std::string s(raw);
    std::replace(s.begin(), s.end(), '\\', '/');
    while (!s.empty() && s.front() == '#') {
        s.erase(s.begin());
    }
    return s;
}

cocos2d::CCSpriteFrame* findSpriteFrameWithFallback(const char* name) {
    if (!name || !*name) return nullptr;
    auto* cache = cocos2d::CCSpriteFrameCache::sharedSpriteFrameCache();
    if (!cache) return nullptr;

    if (auto* f = cache->spriteFrameByName(name)) return f;

    const std::string s = normalizeAssetLookupPath(name);
    if (s.empty()) return nullptr;
    if (s != name) {
        if (auto* f = cache->spriteFrameByName(s.c_str())) return f;
    }

    const std::string prefix = "res/jsonUI/";
    if (s.rfind(prefix, 0) == 0) {
        const std::string stripped = s.substr(prefix.size());
        if (!stripped.empty()) {
            if (auto* f = cache->spriteFrameByName(stripped.c_str())) return f;
        }
    }

    const size_t lastSlash = s.find_last_of('/');
    if (lastSlash != std::string::npos && lastSlash + 1 < s.size()) {
        const std::string basename = s.substr(lastSlash + 1);
        if (auto* f = cache->spriteFrameByName(basename.c_str())) return f;
    }

    return nullptr;
}

std::string extractAssetStem(const std::string& candidate) {
    if (candidate.size() > 8 &&
        candidate.compare(candidate.size() - 8, 8, ".pvr.ccz") == 0) {
        return candidate.substr(0, candidate.size() - 8);
    }
    const size_t slashPos = candidate.find_last_of('/');
    const size_t dotPos = candidate.find_last_of('.');
    if (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos)) {
        return candidate.substr(0, dotPos);
    }
    return candidate;
}

cocos2d::CCTexture2D* loadTextureWithExtensionFallback(const char* name) {
    if (!name || !*name) return nullptr;
    auto* texCache = cocos2d::CCTextureCache::sharedTextureCache();
    if (!texCache) return nullptr;

    if (auto* tex = texCache->addImage(name)) {
        return tex;
    }

    const std::string s = normalizeAssetLookupPath(name);
    if (s.empty()) return nullptr;
    if (s != name) {
        if (auto* tex = texCache->addImage(s.c_str())) {
            return tex;
        }
    }

    auto tryAltExtensions = [&](const std::string& candidate) -> cocos2d::CCTexture2D* {
        if (candidate.empty()) return nullptr;
        const std::string stem = extractAssetStem(candidate);
        static const char* const kAltExts[] = {".pvr.ccz", ".pkm", ".webp", ".png", ".jpg"};
        for (const char* ext : kAltExts) {
            const std::string altPath = stem + ext;
            if (auto* tex = texCache->addImage(altPath.c_str())) {
                return tex;
            }
        }
        return nullptr;
    };

    if (auto* tex = tryAltExtensions(s)) {
        return tex;
    }

    const std::string prefix = "res/jsonUI/";
    if (s.rfind(prefix, 0) == 0) {
        const std::string stripped = s.substr(prefix.size());
        if (auto* tex = texCache->addImage(stripped.c_str())) {
            return tex;
        }
        if (auto* tex = tryAltExtensions(stripped)) {
            return tex;
        }
    }

    return nullptr;
}

std::string resolveImagePathWithExtensionFallback(const char* filePath) {
    if (!filePath || !*filePath) return {};
    const std::string norm = normalizeAssetLookupPath(filePath);
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) return norm;

    const std::string exactFull = fu->fullPathForFilename(norm.c_str());
    if (!exactFull.empty() && fu->isFileExist(exactFull)) {
        return norm;
    }

    const std::string stem = extractAssetStem(norm);
    static const char* const kAltExts[] = {".pvr.ccz", ".pkm", ".webp", ".png"};
    for (const char* ext : kAltExts) {
        const std::string cand = stem + ext;
        const std::string full = fu->fullPathForFilename(cand.c_str());
        if (!full.empty() && fu->isFileExist(full)) {
            return cand;
        }
    }
    return norm;
}

cocos2d::CCTexture2D* getOrCreateFallbackWhiteTexture() {
    static cocos2d::CCTexture2D* s_whiteTex = nullptr;
    if (!s_whiteTex) {
        static const unsigned char kWhitePixels[16] = {
            255, 255, 255, 255,  255, 255, 255, 255,
            255, 255, 255, 255,  255, 255, 255, 255
        };
        auto* tex = new cocos2d::CCTexture2D();
        if (tex->initWithData(kWhitePixels,
                              cocos2d::kCCTexture2DPixelFormat_RGBA8888,
                              2,
                              2,
                              cocos2d::CCSize(2.0f, 2.0f))) {
            s_whiteTex = tex;
        } else {
            tex->release();
        }
    }
    return s_whiteTex;
}

} // namespace

// ============================================================================
// CLuaFuncs
// ============================================================================
static CLuaFuncs* s_luaFuncs = nullptr;

CLuaFuncs* CLuaFuncs::sharedLuaFuncs() {
    if (!s_luaFuncs) {
        s_luaFuncs = new CLuaFuncs();
    }
    return s_luaFuncs;
}

CLuaFuncs::~CLuaFuncs() {
    auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
    auto* engine = (mgr && mgr->getScriptEngine()) ? CCLuaEngine::defaultEngine() : nullptr;
    auto* stack = engine ? engine->getLuaStack() : nullptr;
    if (stack) {
        for (const auto& kv : m_handlers) {
            stack->removeScriptHandler(kv.second);
        }
    }
    m_handlers.clear();
}

void CLuaFuncs::addHandler(const char* name, int luaFuncRef) {
    if (!name) return;
    auto it = m_handlers.find(name);
    if (it != m_handlers.end()) {
        if (auto* engine = CCLuaEngine::defaultEngine()) {
            if (auto* stack = engine->getLuaStack()) {
                stack->removeScriptHandler(it->second);
            }
        }
    }
    m_handlers[name] = luaFuncRef;
}

void CLuaFuncs::removeHandler(const char* name) {
    if (!name) return;
    auto it = m_handlers.find(name);
    if (it != m_handlers.end()) {
        if (auto* engine = CCLuaEngine::defaultEngine()) {
            if (auto* stack = engine->getLuaStack()) {
                stack->removeScriptHandler(it->second);
            }
        }
        m_handlers.erase(it);
    }
}

int CLuaFuncs::call(const char* name, const std::list<CCLuaValue>& args) {
    auto it = m_handlers.find(name ? name : "");
    if (it == m_handlers.end()) {
        CCLog("lua function:%s not found in registry", name ? name : "");
        return 0;
    }
    auto* engine = CCLuaEngine::defaultEngine();
    if (!engine) return 0;
    auto* stack = engine->getLuaStack();
    if (!stack) return 0;
    CCObjectRetainGuard selfGuard(this);
    for (const auto& arg : args) {
        stack->pushCCLuaValue(arg);
    }
    return stack->executeFunctionByHandler(it->second, static_cast<int>(args.size()));
}

// ============================================================================
// CTimer
// ============================================================================
static CTimer* s_timer = nullptr;

CTimer* CTimer::sharedTimer() {
    if (!s_timer) {
        s_timer = new CTimer();
        if (auto* director = CCDirector::sharedDirector()) {
            if (auto* scheduler = director->getScheduler()) {
                scheduler->scheduleUpdateForTarget(s_timer, 0, false);
            }
        }
    }
    return s_timer;
}

CTimer::~CTimer() {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
    auto* engine = (mgr && mgr->getScriptEngine()) ? CCLuaEngine::defaultEngine() : nullptr;
    auto* stack = engine ? engine->getLuaStack() : nullptr;
    if (stack) {
        for (const auto& ev : m_events) {
            stack->removeScriptHandler(ev.luaFuncRef);
        }
    }
    m_events.clear();
}

void CTimer::addEvent(int delaySeconds, int luaFuncRef) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.push_back({std::time(nullptr) + delaySeconds, luaFuncRef});
}

void CTimer::update(float /*dt*/) {
    std::vector<int> ready;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const std::time_t now = std::time(nullptr);
        auto it = m_events.begin();
        while (it != m_events.end()) {
            if (it->fireAt <= now) {
                ready.push_back(it->luaFuncRef);
                it = m_events.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (ready.empty()) {
        return;
    }
    auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
    if (!mgr || !mgr->getScriptEngine()) {
        return;
    }
    auto* engine = CCLuaEngine::defaultEngine();
    if (!engine) return;
    auto* stack = engine->getLuaStack();
    if (!stack) return;

    CCObjectRetainGuard selfGuard(this);
    for (int ref : ready) {
        stack->executeFunctionByHandler(ref, 0);
        stack->removeScriptHandler(ref);
    }
}

// ============================================================================
// CCStrokeLabel
// ============================================================================
CCStrokeLabel* CCStrokeLabel::create(const char* text, const char* fontName, int fontSize) {
    auto* p = new CCStrokeLabel();
    if (!p) {
        return nullptr;
    }
    const char* safeText = text ? text : "";
    const char* safeFont = fontName ? fontName : "";
    const float safeFontSize = static_cast<float>(fontSize > 0 ? fontSize : 20);
    if (p->initWithString(safeText, safeFont, safeFontSize) ||
        (safeFont[0] != '\0' && p->initWithString(safeText, "", safeFontSize)) ||
        p->init()) {
        p->autorelease();
        return p;
    }
    CC_SAFE_DELETE(p);
    return nullptr;
}

void CCStrokeLabel::setStroke(unsigned int strokeSize, ccColor4B color) {
    enableStroke(ccc3(color.r, color.g, color.b), static_cast<float>(strokeSize), true);
}

void CCStrokeLabel::setContrast(float /*contrast*/) {
    // Optional shader contrast tweak; safe no-op on Win32.
}

// ============================================================================
// SpriteBlur
// ============================================================================
SpriteBlur* SpriteBlur::create(const char* filename) {
    auto* p = new SpriteBlur();
    if (!p) {
        return nullptr;
    }

    if (filename && filename[0] != '\0') {
        if (auto* frame = findSpriteFrameWithFallback(filename)) {
            if (p->initWithSpriteFrame(frame)) {
                p->initProgram();
                p->autorelease();
                return p;
            }
        }
        if (auto* tex = loadTextureWithExtensionFallback(filename)) {
            CCRect rect = CCRectZero;
            rect.size = tex->getContentSize();
            if (p->initWithTexture(tex, rect)) {
                p->autorelease();
                return p;
            }
        }
        if (p->initWithFile(filename)) {
            p->initProgram();
            p->autorelease();
            return p;
        }
    }

    if (auto* whiteTex = getOrCreateFallbackWhiteTexture()) {
        if (p->initWithTexture(whiteTex, cocos2d::CCRect(0.0f, 0.0f, 2.0f, 2.0f))) {
            p->autorelease();
            return p;
        }
    }

    if (p->init()) {
        p->initProgram();
        p->autorelease();
        return p;
    }

    CC_SAFE_DELETE(p);
    return nullptr;
}

SpriteBlur* SpriteBlur::createWithTexture(CCTexture2D* texture) {
    auto* p = new SpriteBlur();
    if (!p) {
        return nullptr;
    }
    CCTexture2D* effectiveTex = texture ? texture : getOrCreateFallbackWhiteTexture();
    if (effectiveTex) {
        CCRect rect = CCRectZero;
        rect.size = effectiveTex->getContentSize();
        if (p->initWithTexture(effectiveTex, rect)) {
            p->autorelease();
            return p;
        }
    }
    if (p->init()) {
        p->initProgram();
        p->autorelease();
        return p;
    }
    CC_SAFE_DELETE(p);
    return nullptr;
}

bool SpriteBlur::initWithTexture(CCTexture2D* texture, const CCRect& rect) {
    if (!CCSprite::initWithTexture(texture, rect)) return false;
    initProgram();
    return true;
}

void SpriteBlur::initProgram() {
    if (auto* cache = CCShaderCache::sharedShaderCache()) {
        setShaderProgram(cache->programForKey(kCCShader_PositionTextureColor));
    }
}

void SpriteBlur::setBlurSize(float size) { m_blurSize = size; }
void SpriteBlur::listenBack2Foreground(CCObject* /*obj*/) { initProgram(); }
void SpriteBlur::draw() { CCSprite::draw(); }

namespace {

void pushRapidJsonValue(lua_State* L, const rapidjson::Value& v) {
    if (v.IsNull()) {
        lua_pushlightuserdata(L, nullptr);
    } else if (v.IsBool()) {
        lua_pushboolean(L, v.GetBool() ? 1 : 0);
    } else if (v.IsInt64()) {
        lua_pushnumber(L, static_cast<lua_Number>(v.GetInt64()));
    } else if (v.IsUint64()) {
        lua_pushnumber(L, static_cast<lua_Number>(v.GetUint64()));
    } else if (v.IsNumber()) {
        lua_pushnumber(L, static_cast<lua_Number>(v.GetDouble()));
    } else if (v.IsString()) {
        lua_pushlstring(L, v.GetString(), v.GetStringLength());
    } else if (v.IsArray()) {
        lua_createtable(L, static_cast<int>(v.Size()), 0);
        for (rapidjson::SizeType i = 0; i < v.Size(); ++i) {
            pushRapidJsonValue(L, v[i]);
            lua_rawseti(L, -2, static_cast<int>(i + 1));
        }
    } else if (v.IsObject()) {
        lua_newtable(L);
        for (auto it = v.MemberonBegin(); it != v.MemberonEnd(); ++it) {
            lua_pushlstring(L, it->name.GetString(), it->name.GetStringLength());
            pushRapidJsonValue(L, it->value);
            lua_rawset(L, -3);
        }
    } else {
        lua_pushnil(L);
    }
}

void writeLuaValueToJson(lua_State* L, int idx, rapidjson::Writer<rapidjson::StringBuffer>& w, int depth) {
    if (depth > 64) {
        w.Null();
        return;
    }
    if (idx < 0) idx = lua_gettop(L) + idx + 1;
    const int t = lua_type(L, idx);
    switch (t) {
    case LUA_TNIL:
        w.Null();
        break;
    case LUA_TLIGHTUSERDATA:
        if (lua_touserdata(L, idx) == nullptr) w.Null();
        else w.String("userdata");
        break;
    case LUA_TBOOLEAN:
        w.Bool(lua_toboolean(L, idx) != 0);
        break;
    case LUA_TNUMBER: {
        const double d = static_cast<double>(lua_tonumber(L, idx));
        if (std::isfinite(d) && std::floor(d) == d && d >= -9007199254740991.0 && d <= 9007199254740991.0) {
            w.Int64(static_cast<int64_t>(d));
        } else {
            w.Double(d);
        }
        break;
    }
    case LUA_TSTRING: {
        size_t len = 0;
        const char* s = lua_tolstring(L, idx, &len);
        w.String(s ? s : "", static_cast<rapidjson::SizeType>(len));
        break;
    }
    case LUA_TTABLE: {
        size_t maxIdx = 0;
        size_t count = 0;
        bool isArray = true;
        lua_pushnil(L);
        while (lua_next(L, idx) != 0) {
            lua_pop(L, 1);
            if (lua_type(L, -1) == LUA_TNUMBER) {
                const double k = static_cast<double>(lua_tonumber(L, -1));
                if (k >= 1.0 && std::floor(k) == k) {
                    const size_t ki = static_cast<size_t>(k);
                    if (ki > maxIdx) maxIdx = ki;
                    ++count;
                    continue;
                }
            }
            isArray = false;
            lua_pop(L, 1);
            break;
        }
        if (isArray && (count == 0 || maxIdx == count)) {
            w.StartArray();
            for (size_t i = 1; i <= maxIdx; ++i) {
                lua_rawgeti(L, idx, static_cast<int>(i));
                writeLuaValueToJson(L, -1, w, depth + 1);
                lua_pop(L, 1);
            }
            w.EndArray();
        } else {
            w.StartObject();
            lua_pushnil(L);
            while (lua_next(L, idx) != 0) {
                if (lua_type(L, -2) == LUA_TSTRING) {
                    size_t klen = 0;
                    const char* k = lua_tolstring(L, -2, &klen);
                    w.String(k ? k : "", static_cast<rapidjson::SizeType>(klen));
                    writeLuaValueToJson(L, -1, w, depth + 1);
                } else if (lua_type(L, -2) == LUA_TNUMBER) {
                    lua_pushvalue(L, -2);
                    const char* ks = lua_tostring(L, -1);
                    w.String(ks ? ks : "");
                    lua_pop(L, 1);
                    writeLuaValueToJson(L, -1, w, depth + 1);
                }
                lua_pop(L, 1);
            }
            w.EndObject();
        }
        break;
    }
    default:
        w.Null();
        break;
    }
}

int lua_cjson_decode(lua_State* L) {
    size_t len = 0;
    const char* str = luaL_checklstring(L, 1, &len);
    std::string buf(str, len);
    rapidjson::Document doc;
    doc.Parse<0>(buf.c_str());
    if (doc.HasParseError()) {
        return luaL_error(L, "cjson.decode failed: %s", doc.GetParseError() ? doc.GetParseError() : "parse error");
    }
    pushRapidJsonValue(L, doc);
    return 1;
}

int lua_cjson_encode(lua_State* L) {
    luaL_checkany(L, 1);
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writeLuaValueToJson(L, 1, writer, 0);
    lua_pushlstring(L, sb.GetString(), sb.Size());
    return 1;
}

int luaopen_cjson(lua_State* L) {
    lua_newtable(L);
    lua_pushcfunction(L, &lua_cjson_decode);
    lua_setfield(L, -2, "decode");
    lua_pushcfunction(L, &lua_cjson_encode);
    lua_setfield(L, -2, "encode");
    lua_pushlightuserdata(L, nullptr);
    lua_setfield(L, -2, "null");
    return 1;
}

} // namespace

extern "C" {
#include "lua.h"
int luaopen_lua_extensions(lua_State* L) {
    if (!L) return 0;
    lua_getglobal(L, "package");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "preload");
        if (lua_istable(L, -1)) {
            lua_pushcfunction(L, &luaopen_cjson);
            lua_setfield(L, -2, "cjson");
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    return 0;
}
}

namespace {

std::string resolveWidgetLuaTypeName(cocos2d::ui::Widget* w) {
    if (!w) return "Widget";
    std::string desc = w->getDescription();
    if (desc.empty()) {
        return "Widget";
    }
    if (desc == "Panel") {
        return "Layout";
    }
    return desc;
}

const char* resolveRendererLuaTypeName(cocos2d::CCNode* node) {
    if (!node) return "CCNode";
    if (dynamic_cast<cocos2d::extension::CCScale9Sprite*>(node) != nullptr) {
        return "CCScale9Sprite";
    }
    if (dynamic_cast<cocos2d::CCLabelTTF*>(node) != nullptr) {
        return "CCLabelTTF";
    }
    if (dynamic_cast<cocos2d::CCSprite*>(node) != nullptr) {
        return "CCSprite";
    }
    return "CCNode";
}

cocos2d::CCDictionary* getOrCreateWidgetScriptDict(cocos2d::ui::Widget* widget) {
    if (!widget) return nullptr;
    auto* dict = dynamic_cast<cocos2d::CCDictionary*>(widget->getScriptObjectDict());
    if (!dict) {
        dict = new cocos2d::CCDictionary();
        widget->setScriptObjectDict(dict);
        dict->release();
    }
    return dict;
}

bool tryReadLuaColor3B(lua_State* L, int idx, cocos2d::ccColor3B& outColor) {
    if (!L) return false;
    const int absIdx = toAbsLuaIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) {
        return false;
    }

    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, "ccColor3B", 0, &err) ||
            tolua_isusertype(L, absIdx, "const ccColor3B", 0, &err)) {
            if (auto* c = static_cast<cocos2d::ccColor3B*>(tolua_tousertype(L, absIdx, nullptr))) {
                outColor = *c;
                return true;
            }
        }
        if (tolua_isusertype(L, absIdx, "ccColor4B", 0, &err) ||
            tolua_isusertype(L, absIdx, "const ccColor4B", 0, &err)) {
            if (auto* c4 = static_cast<cocos2d::ccColor4B*>(tolua_tousertype(L, absIdx, nullptr))) {
                outColor = cocos2d::ccc3(c4->r, c4->g, c4->b);
                return true;
            }
        }
        return false;
    }

    if (lua_type(L, absIdx) == LUA_TTABLE) {
        auto readChannel = [&](const char* key, int arrIdx) -> GLubyte {
            lua_getfield(L, absIdx, key);
            if (lua_isnumber(L, -1)) {
                const int v = static_cast<int>(lua_tointeger(L, -1));
                lua_pop(L, 1);
                return static_cast<GLubyte>((std::max)(0, (std::min)(255, v)));
            }
            lua_pop(L, 1);
            lua_rawgeti(L, absIdx, arrIdx);
            if (lua_isnumber(L, -1)) {
                const int v = static_cast<int>(lua_tointeger(L, -1));
                lua_pop(L, 1);
                return static_cast<GLubyte>((std::max)(0, (std::min)(255, v)));
            }
            lua_pop(L, 1);
            return 255;
        };
        outColor = cocos2d::ccc3(readChannel("r", 1), readChannel("g", 2), readChannel("b", 3));
        return true;
    }
    return false;
}

cocos2d::ccColor3B readLuaColor3B(lua_State* L, int idx) {
    cocos2d::ccColor3B c = cocos2d::ccc3(255, 255, 255);
    (void)tryReadLuaColor3B(L, idx, c);
    return c;
}

bool readLuaPoint(lua_State* L, int idx, cocos2d::CCPoint& outPt) {
    if (!L) return false;
    const int absIdx = toAbsLuaIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) {
        return false;
    }

    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, "CCPoint", 0, &err) ||
            tolua_isusertype(L, absIdx, "const CCPoint", 0, &err)) {
            if (auto* p = static_cast<cocos2d::CCPoint*>(tolua_tousertype(L, absIdx, nullptr))) {
                outPt = *p;
                return true;
            }
        }
        return false;
    }
    if (lua_type(L, absIdx) == LUA_TNUMBER &&
        absIdx + 1 <= lua_gettop(L) &&
        lua_type(L, absIdx + 1) == LUA_TNUMBER) {
        outPt.x = static_cast<float>(lua_tonumber(L, absIdx));
        outPt.y = static_cast<float>(lua_tonumber(L, absIdx + 1));
        return true;
    }
    if (lua_type(L, absIdx) == LUA_TTABLE) {
        lua_getfield(L, absIdx, "x");
        const float x = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        lua_getfield(L, absIdx, "y");
        const float y = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        outPt = cocos2d::CCPoint(x, y);
        return true;
    }
    return false;
}

bool readLuaSize(lua_State* L, int idx, cocos2d::CCSize& outSize) {
    if (!L) return false;
    const int absIdx = toAbsLuaIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) {
        return false;
    }

    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, "CCSize", 0, &err) ||
            tolua_isusertype(L, absIdx, "const CCSize", 0, &err)) {
            if (auto* s = static_cast<cocos2d::CCSize*>(tolua_tousertype(L, absIdx, nullptr))) {
                outSize = *s;
                return true;
            }
        }
        return false;
    }
    if (lua_type(L, absIdx) == LUA_TNUMBER &&
        absIdx + 1 <= lua_gettop(L) &&
        lua_type(L, absIdx + 1) == LUA_TNUMBER) {
        outSize.width = static_cast<float>(lua_tonumber(L, absIdx));
        outSize.height = static_cast<float>(lua_tonumber(L, absIdx + 1));
        return true;
    }
    if (lua_type(L, absIdx) == LUA_TTABLE) {
        lua_getfield(L, absIdx, "width");
        const float w = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        lua_getfield(L, absIdx, "height");
        const float h = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        outSize = cocos2d::CCSize(w, h);
        return true;
    }
    return false;
}

bool readLuaRect(lua_State* L, int idx, cocos2d::CCRect& outRect) {
    if (!L) return false;
    const int absIdx = toAbsLuaIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) {
        return false;
    }

    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, "CCRect", 0, &err) ||
            tolua_isusertype(L, absIdx, "const CCRect", 0, &err)) {
            if (auto* r = static_cast<cocos2d::CCRect*>(tolua_tousertype(L, absIdx, nullptr))) {
                outRect = *r;
                return true;
            }
        }
        return false;
    }
    if (lua_type(L, absIdx) == LUA_TTABLE) {
        lua_getfield(L, absIdx, "x");
        const float x = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        lua_getfield(L, absIdx, "y");
        const float y = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        lua_getfield(L, absIdx, "width");
        const float w = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        lua_getfield(L, absIdx, "height");
        const float h = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        outRect = cocos2d::CCRect(x, y, w, h);
        return true;
    }
    return false;
}

int callOriginalMethod(lua_State* L) {
    const int nargs = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        return 0;
    }
    for (int i = 1; i <= nargs; ++i) {
        lua_pushvalue(L, i);
    }
    lua_call(L, nargs, LUA_MULTRET);
    return lua_gettop(L) - nargs;
}

// ============================================================================
// Tracked Lua CCScheduler Script Entries (for safe BTUtil::unscheduleAll)
// ============================================================================
std::mutex g_luaScriptEntriesMutex;
std::set<int> g_activeLuaScriptEntries;

int hook_CCScheduler_scheduleScriptFunc(lua_State* L) {
    const int nret = callOriginalMethod(L);
    if (nret >= 1 && lua_isnumber(L, -1)) {
        const int entryId = static_cast<int>(lua_tointeger(L, -1));
        if (entryId != 0) {
            std::lock_guard<std::mutex> lock(g_luaScriptEntriesMutex);
            g_activeLuaScriptEntries.insert(entryId);
        }
    }
    return nret;
}

int hook_CCScheduler_unscheduleScriptEntry(lua_State* L) {
    if (lua_isnumber(L, 2)) {
        const int entryId = static_cast<int>(lua_tointeger(L, 2));
        std::lock_guard<std::mutex> lock(g_luaScriptEntriesMutex);
        g_activeLuaScriptEntries.erase(entryId);
    }
    return callOriginalMethod(L);
}

// ============================================================================
// CCFileUtils:isFileExist Binary/Compressed Extension Fallback Hook
// ============================================================================
int hook_CCFileUtils_isFileExist(lua_State* L) {
    if (lua_type(L, 2) != LUA_TSTRING) {
        lua_pushboolean(L, 0);
        return 1;
    }
    const char* rawPath = lua_tostring(L, 2);
    if (!rawPath || rawPath[0] == '\0') {
        lua_pushboolean(L, 0);
        return 1;
    }

    if (lua_isfunction(L, lua_upvalueindex(1))) {
        lua_pushvalue(L, lua_upvalueindex(1));
        lua_pushvalue(L, 1);
        lua_pushvalue(L, 2);
        lua_call(L, 2, 1);
        if (lua_toboolean(L, -1) != 0) {
            return 1;
        }
        lua_pop(L, 1);
    }

    auto* fu = getSafeNamedUsertype<cocos2d::CCFileUtils>(L, 1, "CCFileUtils");
    if (!fu) {
        fu = cocos2d::CCFileUtils::sharedFileUtils();
    }
    if (!fu) {
        lua_pushboolean(L, 0);
        return 1;
    }

    const std::string norm = normalizeAssetLookupPath(rawPath);
    if (norm.empty()) {
        lua_pushboolean(L, 0);
        return 1;
    }

    auto existsViaFileUtils = [&](const std::string& rel) -> bool {
        if (rel.empty()) return false;
        const std::string full = fu->fullPathForFilename(rel.c_str());
        return !full.empty() && fu->isFileExist(full);
    };

    if (existsViaFileUtils(norm)) {
        lua_pushboolean(L, 1);
        return 1;
    }

    const std::string stem = extractAssetStem(norm);
    static const char* const kBinaryAltExts[] = {
        ".pkm",
        ".pvr.ccz",
        ".webp",
        ".plistb",
        ".xmlb",
        ".pb",
        ".jsonb",
    };
    for (const char* altExt : kBinaryAltExts) {
        if (existsViaFileUtils(stem + altExt)) {
            lua_pushboolean(L, 1);
            return 1;
        }
    }

    const std::string jsonUiPrefix = "res/jsonUI/";
    if (norm.rfind(jsonUiPrefix, 0) == 0) {
        const std::string stripped = norm.substr(jsonUiPrefix.size());
        if (existsViaFileUtils(stripped)) {
            lua_pushboolean(L, 1);
            return 1;
        }
        const std::string strippedStem = extractAssetStem(stripped);
        for (const char* altExt : kBinaryAltExts) {
            if (existsViaFileUtils(strippedStem + altExt)) {
                lua_pushboolean(L, 1);
                return 1;
            }
        }
    }

    lua_pushboolean(L, 0);
    return 1;
}

// ============================================================================
// Asset Loader Hooks (Plistb, PbGui, SceneReader)
// ============================================================================
int hook_addSpriteFramesWithFile(lua_State* L) {
    auto* self = getSafeNamedUsertype<CCSpriteFrameCache>(L, 1, "CCSpriteFrameCache");
    if (!self) {
        self = CCSpriteFrameCache::sharedSpriteFrameCache();
    }
    const char* plist = lua_tostring(L, 2);
    if (self && plist && plist[0] != '\0') {
        CCTexture2D* tex = nullptr;
        if (lua_gettop(L) >= 3) {
            if (lua_type(L, 3) == LUA_TSTRING) {
                const char* texPath = lua_tostring(L, 3);
                if (texPath && texPath[0] != '\0') {
                    tex = loadTextureWithExtensionFallback(texPath);
                }
            } else {
                tex = getSafeCCObject<CCTexture2D>(L, 3);
            }
        }
        if (gclient::assets::PlistbLoader::AddSpriteFramesWithBinary(plist, tex, self)) {
            return 0;
        }
    }
    return callOriginalMethod(L);
}

int hook_widgetFromJsonFile(lua_State* L) {
    const char* fileName = lua_tostring(L, 2);
    if (fileName && fileName[0] != '\0') {
        if (cocos2d::ui::Widget* w = gclient::assets::PbGuiLoader::WidgetFromPbFile(fileName)) {
            const std::string luaType = resolveWidgetLuaTypeName(w);
            pushCCObject(L, w, luaType.c_str());
            return 1;
        }
    }
    const int nret = callOriginalMethod(L);
    if (nret >= 1) {
        if (auto* w = getSafeCCObject<cocos2d::ui::Widget>(L, -1)) {
            const std::string luaType = resolveWidgetLuaTypeName(w);
            lua_pop(L, 1);
            pushCCObject(L, w, luaType.c_str());
        }
    }
    return nret;
}

int hook_createNodeWithSceneFile(lua_State* L) {
    const char* fileName = lua_tostring(L, 2);
    if (fileName && fileName[0] != '\0') {
        if (CCNode* n = gclient::assets::PbGuiLoader::SceneFromPbFile(fileName)) {
            pushCCObject(L, n, "CCNode");
            return 1;
        }
    }
    return callOriginalMethod(L);
}

// ============================================================================
// DeferredArmatureAsyncCallback — resolves live main lua_State* at tick time
// (NEVER caches a coroutine lua_State* that may be GC'd before next tick!).
// ============================================================================
class DeferredArmatureAsyncCallback;
std::vector<DeferredArmatureAsyncCallback*> g_pendingArmatureCallbacks;

class DeferredArmatureAsyncCallback : public cocos2d::CCObject {
public:
    explicit DeferredArmatureAsyncCallback(int funcRef)
        : m_funcRef(funcRef) {}

    ~DeferredArmatureAsyncCallback() override {
        unregisterPending();
        releaseLuaRef();
    }

    void scheduleSelf() {
        if (std::find(g_pendingArmatureCallbacks.begin(),
                      g_pendingArmatureCallbacks.end(),
                      this) == g_pendingArmatureCallbacks.end()) {
            g_pendingArmatureCallbacks.push_back(this);
        }
        ensureOnScheduler();
    }

    void ensureOnScheduler() {
        if (m_funcRef == LUA_NOREF || m_funcRef == LUA_REFNIL) {
            return;
        }
        if (auto* director = cocos2d::CCDirector::sharedDirector()) {
            if (auto* scheduler = director->getScheduler()) {
                scheduler->unscheduleSelector(
                    schedule_selector(DeferredArmatureAsyncCallback::onTick), this);
                scheduler->scheduleSelector(
                    schedule_selector(DeferredArmatureAsyncCallback::onTick),
                    this,
                    0.0f,
                    false);
            }
        }
    }

    void onTick(float /*dt*/) {
        CCObjectRetainGuard selfGuard(this);
        unregisterPending();
        if (auto* director = cocos2d::CCDirector::sharedDirector()) {
            if (auto* scheduler = director->getScheduler()) {
                scheduler->unscheduleSelector(
                    schedule_selector(DeferredArmatureAsyncCallback::onTick), this);
            }
        }
        invokeLuaCallback();
    }

private:
    void unregisterPending() {
        g_pendingArmatureCallbacks.erase(
            std::remove(g_pendingArmatureCallbacks.begin(),
                        g_pendingArmatureCallbacks.end(),
                        this),
            g_pendingArmatureCallbacks.end());
    }

    void releaseLuaRef() {
        if (m_funcRef != LUA_NOREF && m_funcRef != LUA_REFNIL) {
            const int ref = m_funcRef;
            m_funcRef = LUA_NOREF;
            if (lua_State* liveL = getLiveMainLuaState()) {
                luaL_unref(liveL, LUA_REGISTRYINDEX, ref);
            }
        }
    }

    void invokeLuaCallback() {
        if (m_funcRef == LUA_NOREF || m_funcRef == LUA_REFNIL) {
            return;
        }

        const int ref = m_funcRef;
        m_funcRef = LUA_NOREF;

        lua_State* liveL = getLiveMainLuaState();
        if (!liveL) {
            return;
        }

        int errFuncIdx = 0;
        lua_getglobal(liveL, "__G__TRACKBACK__");
        if (lua_isfunction(liveL, -1)) {
            errFuncIdx = lua_gettop(liveL);
        } else {
            lua_pop(liveL, 1);
        }

        lua_rawgeti(liveL, LUA_REGISTRYINDEX, ref);
        luaL_unref(liveL, LUA_REGISTRYINDEX, ref);

        if (lua_isfunction(liveL, -1)) {
            lua_pushnumber(liveL, 1.0);
            if (lua_pcall(liveL, 1, 0, errFuncIdx) != 0) {
                const char* err = lua_tostring(liveL, -1);
                gclient::diagnostics::CrashAndTelemetry::log(
                    gclient::diagnostics::LogLevel::Error,
                    "XmlbAsync",
                    "Deferred callback error: %s",
                    err ? err : "(null)");
                lua_pop(liveL, 1);
            }
        } else {
            lua_pop(liveL, 1);
        }

        if (errFuncIdx != 0) {
            lua_remove(liveL, errFuncIdx);
        }
    }

    int m_funcRef = LUA_NOREF;
};

bool loadArmatureAssetsWithBinaryFallback(const char* imagePath,
                                          const char* plistPath,
                                          const char* configPath) {
    cocos2d::CCTexture2D* tex = nullptr;
    if (imagePath && imagePath[0] != '\0') {
        tex = loadTextureWithExtensionFallback(imagePath);
    }
    if (plistPath && plistPath[0] != '\0') {
        gclient::assets::PlistbLoader::AddSpriteFramesWithBinary(plistPath, tex);
    }
    if (configPath && configPath[0] != '\0') {
        if (gclient::assets::XmlbArmatureLoader::AddDataFromXmlbFile(imagePath, plistPath, configPath)) {
            return true;
        }
    }
    return false;
}

bool hasPlainArmatureConfigOnDisk(const char* configPath) {
    if (!configPath || !*configPath) return false;
    const std::string norm = normalizeAssetLookupPath(configPath);
    if (norm.size() >= 5 && norm.compare(norm.size() - 5, 5, ".xmlb") == 0) {
        return false;
    }
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) return false;
    const std::string full = fu->fullPathForFilename(norm.c_str());
    return !full.empty() && fu->isFileExist(full);
}

int hook_addArmatureFileInfo(lua_State* L) {
    const int nargs = lua_gettop(L);
    const char* imagePath = nullptr;
    const char* plistPath = nullptr;
    const char* configPath = nullptr;

    if (nargs >= 4 && lua_type(L, 2) == LUA_TSTRING &&
        lua_type(L, 3) == LUA_TSTRING && lua_type(L, 4) == LUA_TSTRING) {
        imagePath = lua_tostring(L, 2);
        plistPath = lua_tostring(L, 3);
        configPath = lua_tostring(L, 4);
    } else if (nargs >= 2 && lua_type(L, 2) == LUA_TSTRING) {
        configPath = lua_tostring(L, 2);
    }
    if (loadArmatureAssetsWithBinaryFallback(imagePath, plistPath, configPath)) {
        return 0;
    }
    if (!hasPlainArmatureConfigOnDisk(configPath)) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "Armature",
            "addArmatureFileInfo: config '%s' not found; skipping unguarded reader",
            configPath ? configPath : "(null)");
        return 0;
    }
    return callOriginalMethod(L);
}

int hook_addArmatureFileInfoAsync(lua_State* L) {
    const int nargs = lua_gettop(L);
    const char* imagePath = nullptr;
    const char* plistPath = nullptr;
    const char* configPath = nullptr;
    int cbIdx = 0;

    if (nargs >= 5 && lua_type(L, 2) == LUA_TSTRING &&
        lua_type(L, 3) == LUA_TSTRING && lua_type(L, 4) == LUA_TSTRING) {
        imagePath = lua_tostring(L, 2);
        plistPath = lua_tostring(L, 3);
        configPath = lua_tostring(L, 4);
        if (nargs >= 6 && lua_isfunction(L, 6)) {
            cbIdx = 6;
        } else if (lua_isfunction(L, 5)) {
            cbIdx = 5;
        }
    } else if (nargs >= 3 && lua_type(L, 2) == LUA_TSTRING) {
        configPath = lua_tostring(L, 2);
        if (nargs >= 4 && lua_isfunction(L, 4)) {
            cbIdx = 4;
        } else if (lua_isfunction(L, 3)) {
            cbIdx = 3;
        }
    }

    // NEVER delegate to stock worker-thread CCDataReaderHelper::addDataFromFileAsync,
    // which races CCFileUtils/CCTextureCache/OpenGL off-thread and crashes on .xmlb/missing files.
    bool loaded = loadArmatureAssetsWithBinaryFallback(imagePath, plistPath, configPath);
    if (!loaded && hasPlainArmatureConfigOnDisk(configPath)) {
        if (auto* mgr = cocos2d::extension::CCArmatureDataManager::sharedArmatureDataManager()) {
            if (imagePath && plistPath) {
                const std::string resImg = resolveImagePathWithExtensionFallback(imagePath);
                mgr->addArmatureFileInfo(resImg.c_str(), plistPath, configPath);
            } else {
                mgr->addArmatureFileInfo(configPath);
            }
            loaded = true;
        }
    }
    if (!loaded) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "XmlbAsync",
            "addArmatureFileInfoAsync: asset '%s' unavailable; firing safe completion tick",
            configPath ? configPath : "(null)");
    }

    if (cbIdx > 0 && lua_isfunction(L, cbIdx)) {
        lua_pushvalue(L, cbIdx);
        const int funcRef = luaL_ref(L, LUA_REGISTRYINDEX);
        auto* task = new DeferredArmatureAsyncCallback(funcRef);
        auto* director = cocos2d::CCDirector::sharedDirector();
        auto* scheduler = director ? director->getScheduler() : nullptr;
        if (scheduler) {
            task->scheduleSelf();
            if (task->retainCount() > 1) {
                task->release();
            }
        } else {
            task->onTick(0.0f);
            task->release();
        }
    }
    return 0;
}

int hook_CCArmatureAnimation_setMovementLoopByName(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCArmatureAnimation>(L, 1);
    const char* movementName = lua_tostring(L, 2);
    const bool loop = lua_toboolean(L, 3) != 0;
    if (self && movementName && movementName[0] != '\0') {
        if (cocos2d::extension::CCAnimationData* animData = self->getAnimationData()) {
            if (cocos2d::extension::CCMovementData* movData = animData->getMovement(movementName)) {
                movData->loop = loop;
            }
        }
    }
    return 0;
}

// ============================================================================
// Safe GLSL Pre-Compilation & CCGLProgram Shader Hook
// (Prevents stock CCGLProgram::compileShader from calling abort() on Win32!)
// ============================================================================
struct Scale9SpriteAccessor : public cocos2d::extension::CCScale9Sprite {
    static cocos2d::CCSpriteBatchNode* scale9Img(const cocos2d::extension::CCScale9Sprite* obj) {
        return obj ? obj->*(&Scale9SpriteAccessor::_scale9Image) : nullptr;
    }
};

std::string buildDesktopCompatibleGlsl(const char* rawSource) {
    if (!rawSource) return {};
    std::string src(rawSource);

    // Strip standalone GLES `precision <qual> <type>;` statements and define lowp/mediump/highp
    // empty macros when GL_ES is not defined so desktop OpenGL 2.1 drivers never reject GLES shaders.
    std::string cleaned;
    cleaned.reserve(src.size() + 96);

    size_t pos = 0;
    std::string versionDirective;
    while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\r' || src[pos] == '\n')) {
        ++pos;
    }
    if (src.compare(pos, 8, "#version") == 0) {
        const size_t nl = src.find('\n', pos);
        if (nl != std::string::npos) {
            versionDirective = src.substr(pos, nl - pos + 1);
            pos = nl + 1;
        } else {
            versionDirective = src.substr(pos) + "\n";
            pos = src.size();
        }
    }

    if (!versionDirective.empty()) {
        cleaned += versionDirective;
    }
    cleaned += "#ifndef GL_ES\n#define lowp\n#define mediump\n#define highp\n#endif\n";

    while (pos < src.size()) {
        const size_t lineEnd = src.find('\n', pos);
        const std::string line = (lineEnd == std::string::npos)
            ? src.substr(pos)
            : src.substr(pos, lineEnd - pos + 1);

        size_t trim = 0;
        while (trim < line.size() && (line[trim] == ' ' || line[trim] == '\t')) {
            ++trim;
        }
        if (line.compare(trim, 9, "precision") == 0 &&
            trim + 9 < line.size() &&
            (line[trim + 9] == ' ' || line[trim + 9] == '\t')) {
            // Skip standalone `precision ...;` line on desktop GL
        } else {
            cleaned += line;
        }

        if (lineEnd == std::string::npos) {
            break;
        }
        pos = lineEnd + 1;
    }
    return cleaned;
}

bool probeCompileGlslShader(GLenum shaderType, const char* source, std::string& outLog) {
    if (!source || !*source) {
        outLog = "empty shader source";
        return false;
    }
    static const char* const kCocosBuiltinUniformPreamble =
        "uniform mat4 CC_PMatrix;\n"
        "uniform mat4 CC_MVMatrix;\n"
        "uniform mat4 CC_MVPMatrix;\n"
        "uniform vec4 CC_Time;\n"
        "uniform vec4 CC_SinTime;\n"
        "uniform vec4 CC_CosTime;\n"
        "uniform vec4 CC_Random01;\n"
        "//CC INCLUDES END\n\n";

    const GLuint shader = glCreateShader(shaderType);
    if (shader == 0) {
        outLog = "glCreateShader returned 0 (no active GL context)";
        return false;
    }

    // If `#version` appears at start of source, desktop GLSL requires `#version` before uniforms;
    // match stock CCGLProgram::compileShader's exact 2-chunk source array so if our probe succeeds,
    // CCGLProgram::compileShader is guaranteed to succeed as well without calling abort()!
    const GLchar* chunks[2] = {
        kCocosBuiltinUniformPreamble,
        source,
    };
    glShaderSource(shader, 2, chunks, nullptr);
    glCompileShader(shader);

    GLint compiled = GL_FALSE;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (compiled != GL_TRUE) {
        GLint logLen = 0;
        glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &logLen);
        if (logLen > 1) {
            std::string logBuf(static_cast<size_t>(logLen), '\0');
            GLsizei written = 0;
            glGetShaderInfoLog(shader, logLen, &written, &logBuf[0]);
            if (written > 0) {
                logBuf.resize(static_cast<size_t>(written));
            }
            outLog = std::move(logBuf);
        } else {
            outLog = "GL_COMPILE_STATUS == GL_FALSE";
        }
        glDeleteShader(shader);
        return false;
    }

    glDeleteShader(shader);
    return true;
}

void applyProgramToTargetAndRenderer(cocos2d::CCNode* node, cocos2d::CCGLProgram* prog) {
    if (!node || !prog) return;
    node->setShaderProgram(prog);
    if (auto* s9 = dynamic_cast<cocos2d::extension::CCScale9Sprite*>(node)) {
        if (auto* batch = Scale9SpriteAccessor::scale9Img(s9)) {
            batch->setShaderProgram(prog);
        }
    }
    if (auto* widget = dynamic_cast<cocos2d::ui::Widget*>(node)) {
        if (dynamic_cast<cocos2d::CCSprite*>(node) == nullptr) {
            if (cocos2d::CCNode* vr = widget->getVirtualRenderer()) {
                if (vr != node) {
                    vr->setShaderProgram(prog);
                    if (auto* vrS9 = dynamic_cast<cocos2d::extension::CCScale9Sprite*>(vr)) {
                        if (auto* batch = Scale9SpriteAccessor::scale9Img(vrS9)) {
                            batch->setShaderProgram(prog);
                        }
                    }
                }
            }
        }
    }
}

int hook_setShaderWithVertexShaderByteArray(lua_State* L) {
    auto* node = getSafeCCObject<CCNode>(L, 1);
    const char* vsh = lua_tostring(L, 2);
    const char* fsh = lua_tostring(L, 3);
    bool ok = false;

    if (node && vsh && *vsh && fsh && *fsh) {
        std::string finalVsh(vsh);
        std::string finalFsh(fsh);
        std::string vErr;
        std::string fErr;

        bool vValid = probeCompileGlslShader(GL_VERTEX_SHADER, finalVsh.c_str(), vErr);
        if (!vValid) {
            const std::string compatVsh = buildDesktopCompatibleGlsl(vsh);
            if (probeCompileGlslShader(GL_VERTEX_SHADER, compatVsh.c_str(), vErr)) {
                finalVsh = compatVsh;
                vValid = true;
            }
        }

        bool fValid = false;
        if (vValid) {
            fValid = probeCompileGlslShader(GL_FRAGMENT_SHADER, finalFsh.c_str(), fErr);
            if (!fValid) {
                const std::string compatFsh = buildDesktopCompatibleGlsl(fsh);
                if (probeCompileGlslShader(GL_FRAGMENT_SHADER, compatFsh.c_str(), fErr)) {
                    finalFsh = compatFsh;
                    fValid = true;
                }
            }
        }

        if (!vValid || !fValid) {
            gclient::diagnostics::CrashAndTelemetry::log(
                gclient::diagnostics::LogLevel::Warn,
                "Shader",
                "Rejected invalid custom GLSL shader before CCGLProgram::compileShader (vOk=%d fOk=%d vErr='%s' fErr='%s')",
                vValid ? 1 : 0,
                fValid ? 1 : 0,
                vErr.c_str(),
                fErr.c_str());
        } else {
            auto* prog = new CCGLProgram();
            if (prog->initWithVertexShaderByteArray(finalVsh.c_str(), finalFsh.c_str())) {
                prog->addAttribute(kCCAttributeNamePosition, kCCVertexAttrib_Position);
                prog->addAttribute(kCCAttributeNameColor, kCCVertexAttrib_Color);
                prog->addAttribute(kCCAttributeNameTexCoord, kCCVertexAttrib_TexCoords);
                const bool linked = prog->link();
                GLint linkStatus = GL_FALSE;
                const GLuint programId = prog->getProgram();
                if (linked && programId != 0) {
                    glGetProgramiv(programId, GL_LINK_STATUS, &linkStatus);
                }
                if (linkStatus == GL_TRUE) {
                    prog->use();
                    prog->updateUniforms();
                    const GLint uTexLoc = glGetUniformLocation(programId, "u_texture");
                    if (uTexLoc >= 0) {
                        glUniform1i(uTexLoc, 0);
                    }
                    applyProgramToTargetAndRenderer(node, prog);
                    ok = true;
                } else {
                    gclient::diagnostics::CrashAndTelemetry::log(
                        gclient::diagnostics::LogLevel::Warn,
                        "Shader",
                        "Custom GLSL program failed GL_LINK_STATUS check (program=%u)",
                        static_cast<unsigned int>(programId));
                }
            }
            prog->release();
        }
    }

    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

int hook_CCDirector_getCurrentTime(lua_State* L) {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const double sec = std::chrono::duration<double>(now).count();
    lua_pushnumber(L, static_cast<lua_Number>(sec));
    return 1;
}

// ============================================================================
// Null-Safe Scene-Graph & Action Hooks (CCNode / Widget addChild, addNode, runAction)
// ============================================================================
int hook_CCNode_addChild(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::CCNode>(L, 1);
    auto* child = getSafeCCObject<cocos2d::CCNode>(L, 2);
    if (!self) {
        return 0;
    }
    if (!child || child == self) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "SceneGraph",
            "Ignored invalid CCNode:addChild(child=%p) on self=%p (%s)",
            static_cast<void*>(child),
            static_cast<void*>(self),
            typeid(*self).name());
        return 0;
    }
    if (child->getParent() != nullptr) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "SceneGraph",
            "Ignored CCNode:addChild for child=%p (%s) that already has parent=%p",
            static_cast<void*>(child),
            typeid(*child).name(),
            static_cast<void*>(child->getParent()));
        return 0;
    }

    const int argc = lua_gettop(L);
    if (auto* selfWidget = dynamic_cast<cocos2d::ui::Widget*>(self)) {
        // If Lua invoked CCNode.addChild(widget, node) explicitly, preserve CCNode::addChild;
        // if invoked on a Widget without Widget metatable override, route non-Widgets to addNode.
        if (dynamic_cast<cocos2d::ui::Widget*>(child) == nullptr) {
            if (argc == 2) {
                selfWidget->addNode(child);
            } else if (argc == 3) {
                selfWidget->addNode(child, static_cast<int>(lua_tointeger(L, 3)));
            } else {
                selfWidget->addNode(
                    child,
                    static_cast<int>(lua_tointeger(L, 3)),
                    static_cast<int>(lua_tointeger(L, 4)));
            }
            return 0;
        }
    }

    if (argc == 2) {
        self->addChild(child);
    } else if (argc == 3) {
        self->addChild(child, static_cast<int>(lua_tointeger(L, 3)));
    } else {
        self->addChild(
            child,
            static_cast<int>(lua_tointeger(L, 3)),
            static_cast<int>(lua_tointeger(L, 4)));
    }
    return 0;
}

int hook_Widget_addChild(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    auto* child = getSafeCCObject<cocos2d::CCNode>(L, 2);
    if (!self) {
        return 0;
    }
    if (!child || child == self) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "SceneGraph",
            "Ignored invalid Widget:addChild(child=%p) on widget=%p (%s)",
            static_cast<void*>(child),
            static_cast<void*>(self),
            self->getDescription().c_str());
        return 0;
    }
    if (child->getParent() != nullptr) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "SceneGraph",
            "Ignored Widget:addChild for child=%p (%s) that already has parent=%p",
            static_cast<void*>(child),
            typeid(*child).name(),
            static_cast<void*>(child->getParent()));
        return 0;
    }

    const int argc = lua_gettop(L);
    if (auto* childWidget = dynamic_cast<cocos2d::ui::Widget*>(child)) {
        if (argc == 2) {
            self->addChild(childWidget);
        } else if (argc == 3) {
            self->addChild(childWidget, static_cast<int>(lua_tointeger(L, 3)));
        } else {
            self->addChild(
                childWidget,
                static_cast<int>(lua_tointeger(L, 3)),
                static_cast<int>(lua_tointeger(L, 4)));
        }
    } else {
        // Route non-Widget CCNode* (CCSprite, SpineLuaAnimation, CCArmature, CCLabelTTF)
        // to Widget::addNode so _widgetChildren is never corrupted with non-Widget pointers!
        if (argc == 2) {
            self->addNode(child);
        } else if (argc == 3) {
            self->addNode(child, static_cast<int>(lua_tointeger(L, 3)));
        } else {
            self->addNode(
                child,
                static_cast<int>(lua_tointeger(L, 3)),
                static_cast<int>(lua_tointeger(L, 4)));
        }
    }
    return 0;
}

int hook_Widget_addNode(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    auto* node = getSafeCCObject<cocos2d::CCNode>(L, 2);
    if (!self) {
        return 0;
    }
    if (!node || node == self) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "SceneGraph",
            "Ignored invalid Widget:addNode(node=%p) on widget=%p (%s)",
            static_cast<void*>(node),
            static_cast<void*>(self),
            self->getDescription().c_str());
        return 0;
    }
    if (node->getParent() != nullptr) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "SceneGraph",
            "Ignored Widget:addNode for node=%p (%s) that already has parent=%p",
            static_cast<void*>(node),
            typeid(*node).name(),
            static_cast<void*>(node->getParent()));
        return 0;
    }

    const int argc = lua_gettop(L);
    if (argc == 2) {
        self->addNode(node);
    } else if (argc == 3) {
        self->addNode(node, static_cast<int>(lua_tointeger(L, 3)));
    } else {
        self->addNode(
            node,
            static_cast<int>(lua_tointeger(L, 3)),
            static_cast<int>(lua_tointeger(L, 4)));
    }
    return 0;
}

int hook_CCNode_runAction(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::CCNode>(L, 1);
    auto* action = getSafeCCObject<cocos2d::CCAction>(L, 2);
    if (!self || !action) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "SceneGraph",
            "Ignored CCNode:runAction with null self=%p or action=%p",
            static_cast<void*>(self),
            static_cast<void*>(action));
        lua_pushnil(L);
        return 1;
    }
    cocos2d::CCAction* ret = self->runAction(action);
    pushCCObject(L, ret, "CCAction");
    return 1;
}

// ============================================================================
// Safe RTTI CocoStudio Widget / Label / Button / ImageView Hooks
// ============================================================================
int hook_ImageView_isScale9Enabled(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::ImageView>(L, 1);
    tolua_pushboolean(L, (self && self->isScale9Enabled()) ? 1 : 0);
    return 1;
}

int hook_LoadingBar_isScale9Enabled(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::LoadingBar>(L, 1);
    tolua_pushboolean(L, (self && self->isScale9Enabled()) ? 1 : 0);
    return 1;
}

int hook_Button_isScale9Enabled(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Button>(L, 1);
    tolua_pushboolean(L, (self && self->isScale9Enabled()) ? 1 : 0);
    return 1;
}

int hook_Slider_isScale9Enabled(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Slider>(L, 1);
    tolua_pushboolean(L, (self && self->isScale9Enabled()) ? 1 : 0);
    return 1;
}

int hook_Layout_isBackGroundImageScale9Enabled(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Layout>(L, 1);
    tolua_pushboolean(L, (self && self->isBackGroundImageScale9Enabled()) ? 1 : 0);
    return 1;
}

struct LayoutAccessor : public cocos2d::ui::Layout {
    static cocos2d::CCNode* bgImg(const cocos2d::ui::Layout* obj) {
        return obj ? obj->*(&LayoutAccessor::_backGroundImage) : nullptr;
    }
};

int hook_Layout_getBackGroundImage(lua_State* L) {
    auto* layout = getSafeCCObject<cocos2d::ui::Layout>(L, 1);
    CCNode* img = LayoutAccessor::bgImg(layout);
    pushCCObject(L, img, resolveRendererLuaTypeName(img));
    return 1;
}

struct ImageViewAccessor : public cocos2d::ui::ImageView {
    static cocos2d::CCNode* imgRenderer(const cocos2d::ui::ImageView* obj) {
        return obj ? obj->*(&ImageViewAccessor::_imageRenderer) : nullptr;
    }
    static const std::string& textureFile(const cocos2d::ui::ImageView* obj) {
        static const std::string kEmpty;
        return obj ? obj->*(&ImageViewAccessor::_textureFile) : kEmpty;
    }
};

int hook_ImageView_getScale9Image(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::ImageView>(L, 1);
    CCNode* img = ImageViewAccessor::imgRenderer(self);
    pushCCObject(L, img, resolveRendererLuaTypeName(img));
    return 1;
}

int hook_ImageView_getTexture(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::ImageView>(L, 1);
    if (self) {
        const std::string& tex = ImageViewAccessor::textureFile(self);
        lua_pushlstring(L, tex.data(), tex.size());
    } else {
        lua_pushstring(L, "");
    }
    return 1;
}

int hook_ImageView_getCapInsets(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::ImageView>(L, 1);
    const cocos2d::CCRect r = self ? self->getCapInsets() : cocos2d::CCRectZero;
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCRect(r), "CCRect");
    return 1;
}

class ButtonTitleOffsetState : public cocos2d::CCObject {
public:
    float offsetX = 0.0f;
    float offsetY = 0.0f;
};

struct ButtonAccessor : public cocos2d::ui::Button {
    static cocos2d::CCNode* normalRenderer(const cocos2d::ui::Button* obj) {
        return obj ? obj->*(&ButtonAccessor::_buttonNormalRenderer) : nullptr;
    }
    static cocos2d::CCLabelTTF* titleRenderer(const cocos2d::ui::Button* obj) {
        return obj ? obj->*(&ButtonAccessor::_titleRenderer) : nullptr;
    }
};

cocos2d::CCSize effectiveButtonSize(cocos2d::ui::Button* btn) {
    if (!btn) return cocos2d::CCSizeZero;
    cocos2d::CCSize sz = btn->getSize();
    if (sz.width == 0.0f && sz.height == 0.0f) {
        sz = btn->getContentSize();
    }
    return sz;
}

int hook_Button_getScale9Image(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Button>(L, 1);
    CCNode* img = ButtonAccessor::normalRenderer(self);
    pushCCObject(L, img, resolveRendererLuaTypeName(img));
    return 1;
}

int hook_Button_enableTitleStroke(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Button>(L, 1);
    cocos2d::ccColor3B color = cocos2d::ccc3(0, 0, 0);
    const bool hasColor = tryReadLuaColor3B(L, 2, color);
    const float strokeSize = lua_isnumber(L, 3) ? static_cast<float>(lua_tonumber(L, 3)) : 1.0f;
    const bool mustUpdate = lua_isboolean(L, 4) ? (lua_toboolean(L, 4) != 0) : true;
    if (auto* tr = ButtonAccessor::titleRenderer(self); tr && hasColor) {
        tr->enableStroke(color, strokeSize, mustUpdate);
    }
    return 0;
}

int hook_Button_disableTitleStroke(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Button>(L, 1);
    const bool mustUpdate = lua_isboolean(L, 2) ? (lua_toboolean(L, 2) != 0) : true;
    if (auto* tr = ButtonAccessor::titleRenderer(self)) {
        tr->disableStroke(mustUpdate);
    }
    return 0;
}

int hook_Button_setTitleOffsetPosition(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Button>(L, 1);
    cocos2d::CCPoint offset = cocos2d::CCPointZero;
    auto* tr = ButtonAccessor::titleRenderer(self);
    if (!self || !tr || !readLuaPoint(L, 2, offset)) {
        return 0;
    }
    if (cocos2d::CCDictionary* dict = getOrCreateWidgetScriptDict(self)) {
        auto* state = dynamic_cast<ButtonTitleOffsetState*>(dict->objectForKey("gclientBtnTitleOffset"));
        if (!state) {
            state = new ButtonTitleOffsetState();
            dict->setObject(state, "gclientBtnTitleOffset");
            state->release();
        }
        state->offsetX = offset.x;
        state->offsetY = offset.y;
    }
    const cocos2d::CCSize btnSize = effectiveButtonSize(self);
    const cocos2d::CCPoint anchor = self->getAnchorPoint();
    tr->setPosition(cocos2d::CCPoint(
        btnSize.width * (0.5f - anchor.x) + offset.x,
        btnSize.height * (0.5f - anchor.y) + offset.y));
    return 0;
}

int hook_Button_setTitleOffsetY(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Button>(L, 1);
    auto* tr = ButtonAccessor::titleRenderer(self);
    if (!self || !tr) {
        return 0;
    }
    const float offsetY = static_cast<float>(lua_tonumber(L, 2));
    float offsetX = 0.0f;
    if (cocos2d::CCDictionary* dict = getOrCreateWidgetScriptDict(self)) {
        auto* state = dynamic_cast<ButtonTitleOffsetState*>(dict->objectForKey("gclientBtnTitleOffset"));
        if (!state) {
            state = new ButtonTitleOffsetState();
            dict->setObject(state, "gclientBtnTitleOffset");
            state->release();
        }
        offsetX = state->offsetX;
        state->offsetY = offsetY;
    }
    const cocos2d::CCSize btnSize = effectiveButtonSize(self);
    const cocos2d::CCPoint anchor = self->getAnchorPoint();
    tr->setPosition(cocos2d::CCPoint(
        btnSize.width * (0.5f - anchor.x) + offsetX,
        btnSize.height * (0.5f - anchor.y) + offsetY));
    return 0;
}

struct LabelAccessor : public cocos2d::ui::Label {
    static cocos2d::CCLabelTTF* labelRenderer(const cocos2d::ui::Label* obj) {
        return obj ? obj->*(&LabelAccessor::_labelRenderer) : nullptr;
    }
};

int hook_Label_enableStroke(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Label>(L, 1);
    cocos2d::ccColor3B color = cocos2d::ccc3(0, 0, 0);
    const bool hasColor = tryReadLuaColor3B(L, 2, color);
    const float strokeSize = lua_isnumber(L, 3) ? static_cast<float>(lua_tonumber(L, 3)) : 1.0f;
    const bool mustUpdate = lua_isboolean(L, 4) ? (lua_toboolean(L, 4) != 0) : true;
    if (auto* lr = LabelAccessor::labelRenderer(self); lr && hasColor) {
        lr->enableStroke(color, strokeSize, mustUpdate);
    }
    return 0;
}

int hook_Label_disableStroke(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Label>(L, 1);
    const bool mustUpdate = lua_isboolean(L, 2) ? (lua_toboolean(L, 2) != 0) : true;
    if (auto* lr = LabelAccessor::labelRenderer(self)) {
        lr->disableStroke(mustUpdate);
    }
    return 0;
}

int hook_Label_enableShadow(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Label>(L, 1);
    cocos2d::CCSize offset = cocos2d::CCSizeZero;
    const bool hasOffset = readLuaSize(L, 2, offset);
    const float opacity = lua_isnumber(L, 3) ? static_cast<float>(lua_tonumber(L, 3)) : 0.5f;
    const float blur = lua_isnumber(L, 4) ? static_cast<float>(lua_tonumber(L, 4)) : 0.0f;
    const bool mustUpdate = lua_isboolean(L, 5) ? (lua_toboolean(L, 5) != 0) : true;
    if (auto* lr = LabelAccessor::labelRenderer(self); lr && hasOffset) {
        lr->enableShadow(offset, opacity, blur, mustUpdate);
    }
    return 0;
}

int hook_Label_getTextHeight(lua_State* L) {
    auto* node = getSafeCCObject<cocos2d::CCNode>(L, 1);
    float height = 0.0f;
    if (node) {
        height = node->getContentSize().height;
        if (height <= 0.0f) {
            if (auto* widget = dynamic_cast<cocos2d::ui::Widget*>(node)) {
                height = widget->getSize().height;
                if (height <= 0.0f) {
                    if (cocos2d::CCNode* vr = widget->getVirtualRenderer()) {
                        height = vr->getContentSize().height;
                    }
                }
            }
        }
    }
    tolua_pushnumber(L, static_cast<lua_Number>(height));
    return 1;
}

class LabelAtlasGapState : public cocos2d::CCObject {
public:
    float gap = 0.0f;
};

int hook_LabelAtlas_setItemGap(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::LabelAtlas>(L, 1);
    const float gap = lua_isnumber(L, 2) ? static_cast<float>(lua_tonumber(L, 2)) : 0.0f;
    if (self) {
        if (cocos2d::CCDictionary* dict = getOrCreateWidgetScriptDict(self)) {
            auto* st = dynamic_cast<LabelAtlasGapState*>(dict->objectForKey("gclientLabelAtlasGap"));
            if (!st) {
                st = new LabelAtlasGapState();
                dict->setObject(st, "gclientLabelAtlasGap");
                st->release();
            }
            st->gap = gap;
        }
    }
    return 0;
}

int hook_LabelAtlas_getItemGap(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::LabelAtlas>(L, 1);
    float gap = 0.0f;
    if (self) {
        if (auto* dict = dynamic_cast<cocos2d::CCDictionary*>(self->getScriptObjectDict())) {
            if (auto* st = dynamic_cast<LabelAtlasGapState*>(dict->objectForKey("gclientLabelAtlasGap"))) {
                gap = st->gap;
            }
        }
    }
    tolua_pushnumber(L, static_cast<lua_Number>(gap));
    return 1;
}

int hook_Widget_clippingParentAreaContainPoint(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    cocos2d::CCPoint pt = cocos2d::CCPointZero;
    if (!self || !readLuaPoint(L, 2, pt)) {
        tolua_pushboolean(L, 0);
        return 1;
    }
    tolua_pushboolean(L, self->clippingParentAreaContainPoint(pt) ? 1 : 0);
    return 1;
}

// ============================================================================
// ScrollView / ListView / PageView BabelTime Extensions (with UAF-Safe Chained Target)
// ============================================================================
class ScrollViewMoveState : public cocos2d::CCObject {
public:
    bool enabled = true;
    cocos2d::ui::SCROLLVIEW_DIR savedDir = cocos2d::ui::SCROLLVIEW_DIR_VERTICAL;
    bool hasSavedDir = false;
};

struct ScrollViewAccessor : public cocos2d::ui::ScrollView {
    static void clearPressed(cocos2d::ui::ScrollView* obj) {
        if (obj) {
            obj->*(&ScrollViewAccessor::_bePressed) = false;
        }
    }
};

struct WidgetTouchAccessor : public cocos2d::ui::Widget {
    static cocos2d::CCObject* touchListener(const cocos2d::ui::Widget* obj) {
        return obj ? obj->*(&WidgetTouchAccessor::_touchEventListener) : nullptr;
    }
    static cocos2d::ui::SEL_TouchEvent touchSelector(const cocos2d::ui::Widget* obj) {
        return obj ? obj->*(&WidgetTouchAccessor::_touchEventSelector) : nullptr;
    }
};

class ScrollViewTouchListenerProxy : public cocos2d::CCObject {
public:
    ~ScrollViewTouchListenerProxy() override {
        clearLuaHandler();
        releaseChainedTarget();
    }

    void setLuaHandler(int handler) {
        clearLuaHandler();
        m_luaHandler = handler;
    }

    void setChainedListener(cocos2d::CCObject* prevTarget,
                            cocos2d::ui::SEL_TouchEvent prevSelector,
                            cocos2d::CCObject* ownerWidget) {
        if (prevTarget == this) {
            return;
        }
        // Retain external listener (e.g., LuaCocoStudioEventListener previously in m_pUserObject)
        // BEFORE Widget::addTouchEventListener overwrites it, while avoiding a retain cycle if
        // prevTarget == ownerWidget (since ownerWidget owns _scriptObjectDict -> this).
        if (prevTarget && prevTarget != ownerWidget) {
            prevTarget->retain();
        }
        releaseChainedTarget();
        m_chainedTarget = prevTarget;
        m_chainedSelector = prevTarget ? prevSelector : nullptr;
        m_chainedRetained = (prevTarget != nullptr && prevTarget != ownerWidget);
    }

    void onTouchEvent(cocos2d::CCObject* sender, cocos2d::ui::TouchEventType eventType) {
        CCObjectRetainGuard selfGuard(this);
        CCObjectRetainGuard senderGuard(sender);

        if (m_chainedTarget && m_chainedSelector) {
            cocos2d::CCObject* target = m_chainedTarget;
            const cocos2d::ui::SEL_TouchEvent sel = m_chainedSelector;
            CCObjectRetainGuard targetGuard(target);
            (target->*sel)(sender, eventType);
        }
        if (m_luaHandler == 0) return;

        auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
        if (!mgr || !mgr->getScriptEngine()) return;
        auto* engine = cocos2d::CCLuaEngine::defaultEngine();
        auto* stack = engine ? engine->getLuaStack() : nullptr;
        if (!stack) return;

        if (lua_State* L = stack->getLuaState()) {
            std::string senderType = "CCObject";
            if (auto* w = dynamic_cast<cocos2d::ui::Widget*>(sender)) {
                senderType = resolveWidgetLuaTypeName(w);
            }
            pushCCObject(L, sender, senderType.c_str());
            lua_pushinteger(L, static_cast<lua_Integer>(eventType));
            stack->executeFunctionByHandler(m_luaHandler, 2);
            stack->clean();
        } else {
            stack->pushInt(static_cast<int>(eventType));
            stack->executeFunctionByHandler(m_luaHandler, 1);
            stack->clean();
        }
    }

private:
    void releaseChainedTarget() {
        if (m_chainedTarget && m_chainedRetained) {
            m_chainedTarget->release();
        }
        m_chainedTarget = nullptr;
        m_chainedSelector = nullptr;
        m_chainedRetained = false;
    }

    void clearLuaHandler() {
        if (m_luaHandler != 0) {
            auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
            if (mgr && mgr->getScriptEngine()) {
                if (auto* engine = cocos2d::CCLuaEngine::defaultEngine()) {
                    if (auto* stack = engine->getLuaStack()) {
                        stack->removeScriptHandler(m_luaHandler);
                    }
                }
            }
            m_luaHandler = 0;
        }
    }

    int m_luaHandler = 0;
    cocos2d::CCObject* m_chainedTarget = nullptr;
    cocos2d::ui::SEL_TouchEvent m_chainedSelector = nullptr;
    bool m_chainedRetained = false;
};

int hook_ScrollView_setTouchMovedEnabled(lua_State* L) {
    auto* widget = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    if (!widget) return 0;
    const bool enabled = lua_toboolean(L, 2) != 0;

    ScrollViewMoveState* state = nullptr;
    if (cocos2d::CCDictionary* dict = getOrCreateWidgetScriptDict(widget)) {
        state = dynamic_cast<ScrollViewMoveState*>(dict->objectForKey("gclientTouchMoveState"));
        if (!state) {
            state = new ScrollViewMoveState();
            dict->setObject(state, "gclientTouchMoveState");
            state->release();
        }
    }

    if (auto* sv = dynamic_cast<cocos2d::ui::ScrollView*>(widget)) {
        if (!enabled) {
            const cocos2d::ui::SCROLLVIEW_DIR curDir = sv->getDirection();
            if (curDir != cocos2d::ui::SCROLLVIEW_DIR_NONE && state) {
                state->savedDir = curDir;
                state->hasSavedDir = true;
            }
            ScrollViewAccessor::clearPressed(sv);
            sv->setDirection(cocos2d::ui::SCROLLVIEW_DIR_NONE);
        } else if (state && state->hasSavedDir &&
                   sv->getDirection() == cocos2d::ui::SCROLLVIEW_DIR_NONE) {
            sv->setDirection(state->savedDir);
        }
    }

    if (state) {
        state->enabled = enabled;
    }
    return 0;
}

int hook_ScrollView_isTouchMovedEnabled(lua_State* L) {
    auto* widget = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    bool enabled = true;
    if (widget) {
        if (auto* dict = dynamic_cast<cocos2d::CCDictionary*>(widget->getScriptObjectDict())) {
            if (auto* state = dynamic_cast<ScrollViewMoveState*>(dict->objectForKey("gclientTouchMoveState"))) {
                enabled = state->enabled;
            }
        }
    }
    tolua_pushboolean(L, enabled ? 1 : 0);
    return 1;
}

int hook_ScrollView_setTouchEndSmoothMove(lua_State* L) {
    auto* sv = getSafeCCObject<cocos2d::ui::ScrollView>(L, 1);
    const bool enabled = lua_toboolean(L, 2) != 0;
    if (sv) {
        sv->setInertiaScrollEnabled(enabled);
    }
    return 0;
}

int hook_ScrollView_getScrollToPercentVertical(lua_State* L) {
    auto* sv = getSafeCCObject<cocos2d::ui::ScrollView>(L, 1);
    float pct = 0.0f;
    if (sv && sv->getInnerContainer()) {
        const cocos2d::CCSize viewSize = sv->getSize();
        const cocos2d::CCSize innerSize = sv->getInnerContainerSize();
        const float minY = viewSize.height - innerSize.height;
        const float h = -minY;
        if (h > 1e-5f) {
            const float y = sv->getInnerContainer()->getPosition().y;
            pct = ((y - minY) / h) * 100.0f;
            pct = (std::max)(0.0f, (std::min)(100.0f, pct));
        }
    }
    tolua_pushnumber(L, static_cast<lua_Number>(pct));
    return 1;
}

int hook_ScrollView_getScrollToPercentHorizontal(lua_State* L) {
    auto* sv = getSafeCCObject<cocos2d::ui::ScrollView>(L, 1);
    float pct = 0.0f;
    if (sv && sv->getInnerContainer()) {
        const cocos2d::CCSize viewSize = sv->getSize();
        const cocos2d::CCSize innerSize = sv->getInnerContainerSize();
        const float w = innerSize.width - viewSize.width;
        if (w > 1e-5f) {
            const float x = sv->getInnerContainer()->getPosition().x;
            pct = (-x / w) * 100.0f;
            pct = (std::max)(0.0f, (std::min)(100.0f, pct));
        }
    }
    tolua_pushnumber(L, static_cast<lua_Number>(pct));
    return 1;
}

int hook_ScrollView_addTouchEventListenerScrollView(lua_State* L) {
    auto* widget = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    if (!widget) return 0;

    const int fnIdx = lua_isfunction(L, 3) ? 3 : (lua_isfunction(L, 2) ? 2 : 0);
    cocos2d::CCDictionary* dict = getOrCreateWidgetScriptDict(widget);
    if (!dict) return 0;

    auto* proxy = dynamic_cast<ScrollViewTouchListenerProxy*>(dict->objectForKey("scrollViewTouchEvent"));
    if (fnIdx == 0) {
        if (proxy) {
            proxy->setLuaHandler(0);
        }
        return 0;
    }

    const int handler = toluafix_ref_function(L, fnIdx, 0);
    cocos2d::CCObject* curTarget = WidgetTouchAccessor::touchListener(widget);
    cocos2d::ui::SEL_TouchEvent curSel = WidgetTouchAccessor::touchSelector(widget);

    if (!proxy) {
        proxy = new ScrollViewTouchListenerProxy();
        proxy->setChainedListener(curTarget, curSel, widget);
        dict->setObject(proxy, "scrollViewTouchEvent");
        proxy->release();
    } else if (curTarget != proxy) {
        proxy->setChainedListener(curTarget, curSel, widget);
    }
    proxy->setLuaHandler(handler);
    widget->addTouchEventListener(proxy, static_cast<cocos2d::ui::SEL_TouchEvent>(&ScrollViewTouchListenerProxy::onTouchEvent));
    return 0;
}

int hook_ScrollView_getScrollViewTouchStartPos(lua_State* L) {
    auto* widget = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    const cocos2d::CCPoint pt = widget ? widget->getTouchStartPos() : cocos2d::CCPointZero;
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCPoint(pt), "CCPoint");
    return 1;
}

int hook_ScrollView_getScrollViewTouchMovePos(lua_State* L) {
    auto* widget = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    const cocos2d::CCPoint pt = widget ? widget->getTouchMovePos() : cocos2d::CCPointZero;
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCPoint(pt), "CCPoint");
    return 1;
}

int hook_ScrollView_getScrollViewTouchEndPos(lua_State* L) {
    auto* widget = getSafeCCObject<cocos2d::ui::Widget>(L, 1);
    const cocos2d::CCPoint pt = widget ? widget->getTouchEndPos() : cocos2d::CCPointZero;
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCPoint(pt), "CCPoint");
    return 1;
}

struct LoadingBarAccessor : public cocos2d::ui::LoadingBar {
    static cocos2d::CCNode* barRenderer(const cocos2d::ui::LoadingBar* obj) {
        return obj ? obj->*(&LoadingBarAccessor::_barRenderer) : nullptr;
    }
    static const std::string& textureFile(const cocos2d::ui::LoadingBar* obj) {
        static const std::string kEmpty;
        return obj ? obj->*(&LoadingBarAccessor::_textureFile) : kEmpty;
    }
};

int hook_LoadingBar_getScale9Image(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::LoadingBar>(L, 1);
    CCNode* img = LoadingBarAccessor::barRenderer(self);
    pushCCObject(L, img, resolveRendererLuaTypeName(img));
    return 1;
}

int hook_LoadingBar_getTexture(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::LoadingBar>(L, 1);
    if (self) {
        const std::string& tex = LoadingBarAccessor::textureFile(self);
        lua_pushlstring(L, tex.data(), tex.size());
    } else {
        lua_pushstring(L, "");
    }
    return 1;
}

int hook_LoadingBar_getCapInsets(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::LoadingBar>(L, 1);
    const cocos2d::CCRect r = self ? self->getCapInsets() : cocos2d::CCRectZero;
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCRect(r), "CCRect");
    return 1;
}

int hook_CCScale9Sprite_getScale9Image(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCScale9Sprite>(L, 1);
    CCSpriteBatchNode* img = Scale9SpriteAccessor::scale9Img(self);
    pushCCObject(L, img, "CCSpriteBatchNode");
    return 1;
}

// ============================================================================
// Null-Safe CCSprite & CCScale9Sprite Creation Hooks
// ============================================================================
cocos2d::CCSprite* createFallbackWhiteSprite(const cocos2d::CCRect* optRect = nullptr) {
    if (auto* whiteTex = getOrCreateFallbackWhiteTexture()) {
        return optRect
            ? cocos2d::CCSprite::createWithTexture(whiteTex, *optRect)
            : cocos2d::CCSprite::createWithTexture(whiteTex);
    }
    return cocos2d::CCSprite::create();
}

cocos2d::extension::CCScale9Sprite* createFallbackWhiteScale9Sprite(
    const cocos2d::CCRect& capInsets = cocos2d::CCRectZero) {
    if (auto* whiteTex = getOrCreateFallbackWhiteTexture()) {
        const cocos2d::CCRect whiteRect = cocos2d::CCRect(0.0f, 0.0f, 2.0f, 2.0f);
        if (auto* frame = cocos2d::CCSpriteFrame::createWithTexture(whiteTex, whiteRect)) {
            if (auto* sp = cocos2d::extension::CCScale9Sprite::createWithSpriteFrame(frame, capInsets)) {
                return sp;
            }
        }
    }
    return cocos2d::extension::CCScale9Sprite::create();
}

int hook_CCSprite_create(lua_State* L) {
    const int argc = lua_gettop(L);
    const bool hasStrArg2 = (argc >= 2 && lua_type(L, 2) == LUA_TSTRING);
    const char* rawStr2 = hasStrArg2 ? lua_tostring(L, 2) : nullptr;
    const std::string strArg2 = rawStr2 ? rawStr2 : "";
    const bool isEmptyStr = (hasStrArg2 && strArg2.empty());

    if (!isEmptyStr && !(argc >= 2 && lua_isnil(L, 2)) && lua_isfunction(L, lua_upvalueindex(1))) {
        lua_pushvalue(L, lua_upvalueindex(1));
        for (int i = 1; i <= argc; ++i) lua_pushvalue(L, i);
        lua_call(L, argc, 1);
        if (!lua_isnil(L, -1)) return 1;
        lua_pop(L, 1);
    }

    if (hasStrArg2) {
        cocos2d::CCRect parsedRect = cocos2d::CCRectZero;
        const bool hasRect = (argc >= 3) && readLuaRect(L, 3, parsedRect);
        const cocos2d::CCRect* optRect = hasRect ? &parsedRect : nullptr;

        if (!isEmptyStr) {
            if (auto* frame = findSpriteFrameWithFallback(strArg2.c_str())) {
                if (auto* sp = cocos2d::CCSprite::createWithSpriteFrame(frame)) {
                    pushCCObject(L, sp, "CCSprite");
                    return 1;
                }
            }
            if (auto* tex = loadTextureWithExtensionFallback(strArg2.c_str())) {
                cocos2d::CCSprite* sp = optRect
                    ? cocos2d::CCSprite::createWithTexture(tex, *optRect)
                    : cocos2d::CCSprite::createWithTexture(tex);
                if (sp) {
                    pushCCObject(L, sp, "CCSprite");
                    return 1;
                }
            }
        }

        pushCCObject(L, createFallbackWhiteSprite(optRect), "CCSprite");
        return 1;
    }

    pushCCObject(L, cocos2d::CCSprite::create(), "CCSprite");
    return 1;
}

int hook_CCSprite_createWithSpriteFrameName(lua_State* L) {
    const char* frameName = (lua_gettop(L) >= 2 && lua_type(L, 2) == LUA_TSTRING)
        ? lua_tostring(L, 2)
        : nullptr;
    if (frameName && frameName[0] != '\0') {
        if (auto* frame = findSpriteFrameWithFallback(frameName)) {
            if (auto* sp = cocos2d::CCSprite::createWithSpriteFrame(frame)) {
                pushCCObject(L, sp, "CCSprite");
                return 1;
            }
        }
        if (auto* tex = loadTextureWithExtensionFallback(frameName)) {
            if (auto* sp = cocos2d::CCSprite::createWithTexture(tex)) {
                pushCCObject(L, sp, "CCSprite");
                return 1;
            }
        }
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "Sprite",
            "CCSprite:createWithSpriteFrameName missing '%s'; using 2x2 fallback texture",
            frameName);
    }
    pushCCObject(L, createFallbackWhiteSprite(nullptr), "CCSprite");
    return 1;
}

int hook_CCSprite_createWithSpriteFrame(lua_State* L) {
    if (auto* frame = getSafeCCObject<cocos2d::CCSpriteFrame>(L, 2)) {
        if (auto* sp = cocos2d::CCSprite::createWithSpriteFrame(frame)) {
            pushCCObject(L, sp, "CCSprite");
            return 1;
        }
    }
    pushCCObject(L, createFallbackWhiteSprite(nullptr), "CCSprite");
    return 1;
}

int hook_CCScale9Sprite_create(lua_State* L) {
    const int argc = lua_gettop(L);
    int strIdx = 0;
    if (argc >= 2 && lua_type(L, 2) == LUA_TSTRING) {
        strIdx = 2;
    } else if (argc >= 3 && lua_type(L, 3) == LUA_TSTRING) {
        strIdx = 3;
    }
    const char* rawStrArg = (strIdx > 0) ? lua_tostring(L, strIdx) : nullptr;
    const std::string strArg = rawStrArg ? rawStrArg : "";
    const bool isEmptyStr = (strIdx > 0 && strArg.empty());

    if (!isEmptyStr && !(argc >= 2 && lua_isnil(L, 2)) && lua_isfunction(L, lua_upvalueindex(1))) {
        lua_pushvalue(L, lua_upvalueindex(1));
        for (int i = 1; i <= argc; ++i) lua_pushvalue(L, i);
        lua_call(L, argc, 1);
        if (!lua_isnil(L, -1)) return 1;
        lua_pop(L, 1);
    }

    if (strIdx > 0) {
        cocos2d::CCRect capInsets = cocos2d::CCRectZero;
        if (strIdx == 3) {
            (void)readLuaRect(L, 2, capInsets);
        } else if (argc >= 4) {
            (void)readLuaRect(L, 4, capInsets);
        } else if (argc == 3) {
            (void)readLuaRect(L, 3, capInsets);
        }

        if (!isEmptyStr) {
            if (auto* frame = findSpriteFrameWithFallback(strArg.c_str())) {
                if (auto* sp = cocos2d::extension::CCScale9Sprite::createWithSpriteFrame(frame, capInsets)) {
                    pushCCObject(L, sp, "CCScale9Sprite");
                    return 1;
                }
            }
            if (auto* tex = loadTextureWithExtensionFallback(strArg.c_str())) {
                cocos2d::CCRect texRect = cocos2d::CCRectZero;
                texRect.size = tex->getContentSize();
                if (strIdx == 2 && argc >= 4) {
                    (void)readLuaRect(L, 3, texRect);
                }
                if (auto* frame = cocos2d::CCSpriteFrame::createWithTexture(tex, texRect)) {
                    if (auto* sp = cocos2d::extension::CCScale9Sprite::createWithSpriteFrame(frame, capInsets)) {
                        pushCCObject(L, sp, "CCScale9Sprite");
                        return 1;
                    }
                }
            }
        }

        pushCCObject(L, createFallbackWhiteScale9Sprite(capInsets), "CCScale9Sprite");
        return 1;
    }

    pushCCObject(L, createFallbackWhiteScale9Sprite(), "CCScale9Sprite");
    return 1;
}

int hook_CCScale9Sprite_createWithSpriteFrameName(lua_State* L) {
    const int argc = lua_gettop(L);
    const char* frameName = (argc >= 2 && lua_type(L, 2) == LUA_TSTRING)
        ? lua_tostring(L, 2)
        : nullptr;
    cocos2d::CCRect capInsets = cocos2d::CCRectZero;
    if (argc >= 3) {
        (void)readLuaRect(L, 3, capInsets);
    }
    if (frameName && frameName[0] != '\0') {
        if (auto* frame = findSpriteFrameWithFallback(frameName)) {
            if (auto* sp = cocos2d::extension::CCScale9Sprite::createWithSpriteFrame(frame, capInsets)) {
                pushCCObject(L, sp, "CCScale9Sprite");
                return 1;
            }
        }
        if (auto* tex = loadTextureWithExtensionFallback(frameName)) {
            cocos2d::CCRect texRect = cocos2d::CCRectZero;
            texRect.size = tex->getContentSize();
            if (auto* frame = cocos2d::CCSpriteFrame::createWithTexture(tex, texRect)) {
                if (auto* sp = cocos2d::extension::CCScale9Sprite::createWithSpriteFrame(frame, capInsets)) {
                    pushCCObject(L, sp, "CCScale9Sprite");
                    return 1;
                }
            }
        }
    }
    pushCCObject(L, createFallbackWhiteScale9Sprite(capInsets), "CCScale9Sprite");
    return 1;
}

int hook_CCScale9Sprite_createWithSpriteFrame(lua_State* L) {
    const int argc = lua_gettop(L);
    cocos2d::CCRect capInsets = cocos2d::CCRectZero;
    if (argc >= 3) {
        (void)readLuaRect(L, 3, capInsets);
    }
    if (auto* frame = getSafeCCObject<cocos2d::CCSpriteFrame>(L, 2)) {
        if (auto* sp = cocos2d::extension::CCScale9Sprite::createWithSpriteFrame(frame, capInsets)) {
            pushCCObject(L, sp, "CCScale9Sprite");
            return 1;
        }
    }
    pushCCObject(L, createFallbackWhiteScale9Sprite(capInsets), "CCScale9Sprite");
    return 1;
}

// ============================================================================
// GClientRichText — Crash-Proof Replacement for Stock UIRichText::formatText()
// Fixes:
//  1) Stock formarRenderers() dereferencing NULL dynamic_cast<CCRGBAProtocol*> on Widget/CCNode
//  2) Stock handleImageRenderer() dereferencing NULL CCSprite* on sprite frames / .pkm / missing icons
//  3) Stock handleTextRenderer() UTF-8 mid-codepoint slicing & infinite recursion when _leftSpaceWidth <= 0
//  4) BroadcastView.lua tolua.cast(richText:getVirtualRenderer(), "CCLabelTTF"):enableStroke(...)
// ============================================================================
struct RichElementAccessor : public cocos2d::ui::RichElement {
    static cocos2d::ui::RichElementType type(const cocos2d::ui::RichElement* e) {
        return e->*(&RichElementAccessor::_type);
    }
    static int tag(const cocos2d::ui::RichElement* e) {
        return e->*(&RichElementAccessor::_tag);
    }
    static const cocos2d::ccColor3B& color(const cocos2d::ui::RichElement* e) {
        return e->*(&RichElementAccessor::_color);
    }
    static GLubyte opacity(const cocos2d::ui::RichElement* e) {
        return e->*(&RichElementAccessor::_opacity);
    }
};

struct RichElementTextAccessor : public cocos2d::ui::RichElementText {
    static const std::string& text(const cocos2d::ui::RichElementText* e) {
        return e->*(&RichElementTextAccessor::_text);
    }
    static const std::string& fontName(const cocos2d::ui::RichElementText* e) {
        return e->*(&RichElementTextAccessor::_fontName);
    }
    static float fontSize(const cocos2d::ui::RichElementText* e) {
        return e->*(&RichElementTextAccessor::_fontSize);
    }
};

struct RichElementImageAccessor : public cocos2d::ui::RichElementImage {
    static const std::string& filePath(const cocos2d::ui::RichElementImage* e) {
        return e->*(&RichElementImageAccessor::_filePath);
    }
};

struct RichElementCustomNodeAccessor : public cocos2d::ui::RichElementCustomNode {
    static cocos2d::CCNode* customNode(const cocos2d::ui::RichElementCustomNode* e) {
        return e->*(&RichElementCustomNodeAccessor::_customNode);
    }
};

std::vector<size_t> collectUtf8CodepointOffsets(const std::string& utf8) {
    std::vector<size_t> offsets;
    offsets.reserve(utf8.size() + 1);
    size_t i = 0;
    const size_t n = utf8.size();
    while (i < n) {
        offsets.push_back(i);
        const unsigned char c = static_cast<unsigned char>(utf8[i]);
        size_t step = 1;
        if ((c & 0x80u) == 0u) {
            step = 1;
        } else if ((c & 0xE0u) == 0xC0u) {
            step = 2;
        } else if ((c & 0xF0u) == 0xE0u) {
            step = 3;
        } else if ((c & 0xF8u) == 0xF0u) {
            step = 4;
        }
        // Validate continuation bytes so malformed sequences still step cleanly >= 1 byte.
        for (size_t k = 1; k < step; ++k) {
            if (i + k >= n || (static_cast<unsigned char>(utf8[i + k]) & 0xC0u) != 0x80u) {
                step = k;
                break;
            }
        }
        if (step == 0) {
            step = 1;
        }
        i += step;
    }
    offsets.push_back(n);
    return offsets;
}

void applySafeRichColorAndOpacity(cocos2d::CCNode* renderer,
                                  const cocos2d::ccColor3B& color,
                                  GLubyte opacity) {
    if (!renderer) return;
    if (auto* rgba = dynamic_cast<cocos2d::CCRGBAProtocol*>(renderer)) {
        rgba->setColor(color);
        rgba->setOpacity(opacity);
    } else if (auto* widget = dynamic_cast<cocos2d::ui::Widget*>(renderer)) {
        widget->setColor(color);
        widget->setOpacity(opacity);
    }
}

cocos2d::CCLabelTTF* createSafeRichLabel(const std::string& str,
                                         const std::string& fontName,
                                         float fontSize) {
    const float safeSize = (fontSize > 0.0f) ? fontSize : 20.0f;
    cocos2d::CCLabelTTF* lbl = cocos2d::CCLabelTTF::create(str.c_str(), fontName.c_str(), safeSize);
    if (!lbl && !fontName.empty()) {
        lbl = cocos2d::CCLabelTTF::create(str.c_str(), "", safeSize);
    }
    if (!lbl) {
        lbl = new cocos2d::CCLabelTTF();
        if (lbl && lbl->init()) {
            lbl->autorelease();
        } else {
            CC_SAFE_DELETE(lbl);
        }
    }
    return lbl;
}

cocos2d::CCSprite* createSafeRichImageSprite(const std::string& filePath) {
    if (!filePath.empty()) {
        if (auto* frame = findSpriteFrameWithFallback(filePath.c_str())) {
            if (auto* sp = cocos2d::CCSprite::createWithSpriteFrame(frame)) {
                return sp;
            }
        }
        if (auto* tex = loadTextureWithExtensionFallback(filePath.c_str())) {
            if (auto* sp = cocos2d::CCSprite::createWithTexture(tex)) {
                return sp;
            }
        }
    }
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Warn,
        "RichText",
        "RichElementImage '%s' missing; using 2x2 fallback white texture",
        filePath.c_str());
    return createFallbackWhiteSprite(nullptr);
}

class GClientRichText : public cocos2d::ui::RichText {
public:
    static GClientRichText* create() {
        auto* widget = new GClientRichText();
        if (widget && widget->init()) {
            widget->autorelease();
            return widget;
        }
        CC_SAFE_DELETE(widget);
        return nullptr;
    }

    void markFormatDirty() {
        _formatTextDirty = true;
    }

    void visit() override {
        if (!m_bVisible) {
            return;
        }
        if (_formatTextDirty) {
            safeFormatText();
        }
        // Call Widget::visit() directly (skipping RichText::visit() in libExtensions.dll)
        // AND _formatTextDirty is already false so stock RichText::formatText() NEVER runs!
        cocos2d::ui::Widget::visit();
    }

    const cocos2d::CCSize& getContentSize() const override {
        if (_formatTextDirty) {
            const_cast<GClientRichText*>(this)->safeFormatText();
        }
        if (_elementRenderersContainer) {
            return _elementRenderersContainer->getContentSize();
        }
        return cocos2d::CCSizeZero;
    }

    void setAnchorPoint(const cocos2d::CCPoint& pt) override {
        cocos2d::ui::Widget::setAnchorPoint(pt);
        if (_elementRenderersContainer) {
            _elementRenderersContainer->setAnchorPoint(pt);
        }
    }

    void setSize(const cocos2d::CCSize& size) override {
        _formatTextDirty = true;
        cocos2d::ui::Widget::setSize(size);
    }

    void ignoreContentAdaptWithSize(bool ignore) override {
        if (_ignoreSize != ignore) {
            _formatTextDirty = true;
            cocos2d::ui::Widget::ignoreContentAdaptWithSize(ignore);
        }
    }

    void strokeChildLabels(const cocos2d::ccColor3B& strokeColor,
                           float strokeSize,
                           bool mustUpdate = true) {
        m_strokeEnabled = true;
        m_strokeColor = strokeColor;
        m_strokeSize = strokeSize;
        if (_formatTextDirty) {
            safeFormatText();
            return;
        }
        applyStrokeAndShadowToCurrentChildren(mustUpdate);
    }

    void disableChildStrokes(bool mustUpdate = true) {
        m_strokeEnabled = false;
        if (!_elementRenderersContainer) return;
        cocos2d::CCArray* children = _elementRenderersContainer->getChildren();
        if (!children) return;
        const unsigned int count = children->count();
        for (unsigned int i = 0; i < count; ++i) {
            if (auto* ttf = dynamic_cast<cocos2d::CCLabelTTF*>(children->objectAtIndex(i))) {
                ttf->disableStroke(mustUpdate);
            }
        }
    }

    void shadowChildLabels(const cocos2d::CCSize& shadowOffset,
                           float shadowOpacity,
                           float shadowBlur,
                           bool mustUpdate = true) {
        m_shadowEnabled = true;
        m_shadowOffset = shadowOffset;
        m_shadowOpacity = shadowOpacity;
        m_shadowBlur = shadowBlur;
        if (_formatTextDirty) {
            safeFormatText();
            return;
        }
        applyStrokeAndShadowToCurrentChildren(mustUpdate);
    }

    void safeFormatText() {
        if (m_inSafeFormat) {
            return;
        }
        if (!_formatTextDirty) {
            return;
        }

        m_inSafeFormat = true;
        _formatTextDirty = false;

        if (!_elementRenderersContainer) {
            _elementRenderersContainer = cocos2d::CCNode::create();
            if (_elementRenderersContainer) {
                _elementRenderersContainer->setAnchorPoint(getAnchorPoint());
                cocos2d::CCNode::addChild(_elementRenderersContainer, 0, -1);
            }
        }

        if (!_elementRenderersContainer) {
            m_inSafeFormat = false;
            return;
        }

        _elementRenderersContainer->removeAllChildren();
        for (cocos2d::CCArray* rowArr : _elementRenders) {
            if (rowArr) {
                rowArr->removeAllObjects();
                delete rowArr;
            }
        }
        _elementRenders.clear();

        struct StyledEntry {
            cocos2d::CCNode* node = nullptr;
            cocos2d::ccColor3B color{255, 255, 255};
            GLubyte opacity = 255;
            int tag = -1;
            bool applyColor = true;
        };

        std::vector<std::vector<StyledEntry>> rows(1);
        const bool wrapEnabled = (!_ignoreSize && _customSize.width > 0.0f);
        _leftSpaceWidth = wrapEnabled ? _customSize.width : FLT_MAX;

        auto startNewRow = [&]() {
            rows.emplace_back();
            _leftSpaceWidth = wrapEnabled ? _customSize.width : FLT_MAX;
        };

        auto decorateLabelIfNeeded = [&](cocos2d::CCLabelTTF* lbl) {
            if (!lbl) return;
            if (m_strokeEnabled) {
                lbl->enableStroke(m_strokeColor, m_strokeSize, true);
            }
            if (m_shadowEnabled) {
                lbl->enableShadow(m_shadowOffset, m_shadowOpacity, m_shadowBlur, true);
            }
        };

        auto nodeDisplayWidth = [](cocos2d::CCNode* n) -> float {
            if (!n) return 0.0f;
            return n->getContentSize().width * std::fabs(n->getScaleX());
        };
        auto nodeDisplayHeight = [](cocos2d::CCNode* n) -> float {
            if (!n) return 0.0f;
            return n->getContentSize().height * std::fabs(n->getScaleY());
        };

        const unsigned int elemCount = _richElements ? _richElements->count() : 0u;
        for (unsigned int i = 0; i < elemCount; ++i) {
            auto* elem = dynamic_cast<cocos2d::ui::RichElement*>(_richElements->objectAtIndex(i));
            if (!elem) continue;

            const cocos2d::ui::RichElementType elemType = RichElementAccessor::type(elem);
            const int elemTag = RichElementAccessor::tag(elem);
            const cocos2d::ccColor3B elemColor = RichElementAccessor::color(elem);
            const GLubyte elemOpacity = RichElementAccessor::opacity(elem);

            if (elemType == cocos2d::ui::RICH_TEXT) {
                auto* elText = dynamic_cast<cocos2d::ui::RichElementText*>(elem);
                if (!elText) continue;
                const std::string& fullStr = RichElementTextAccessor::text(elText);
                const std::string& fontName = RichElementTextAccessor::fontName(elText);
                const float fontSize = RichElementTextAccessor::fontSize(elText);

                if (fullStr.empty()) {
                    continue;
                }

                // Split on explicit '\n' newlines first (stripping optional '\r').
                size_t segStart = 0;
                while (segStart <= fullStr.size()) {
                    const size_t nlPos = fullStr.find('\n', segStart);
                    std::string seg = (nlPos == std::string::npos)
                        ? fullStr.substr(segStart)
                        : fullStr.substr(segStart, nlPos - segStart);
                    if (!seg.empty() && seg.back() == '\r') {
                        seg.pop_back();
                    }

                    if (!seg.empty()) {
                        if (!wrapEnabled) {
                            if (cocos2d::CCLabelTTF* lbl = createSafeRichLabel(seg, fontName, fontSize)) {
                                decorateLabelIfNeeded(lbl);
                                rows.back().push_back(StyledEntry{lbl, elemColor, elemOpacity, elemTag, true});
                            }
                        } else {
                            const std::vector<size_t> cp = collectUtf8CodepointOffsets(seg);
                            const size_t totalCp = cp.size() > 0 ? (cp.size() - 1) : 0;
                            size_t curCp = 0;

                            while (curCp < totalCp) {
                                const std::string rem = seg.substr(cp[curCp]);
                                cocos2d::CCLabelTTF* fullLbl = createSafeRichLabel(rem, fontName, fontSize);
                                if (!fullLbl) {
                                    break;
                                }
                                decorateLabelIfNeeded(fullLbl);
                                const float fullW = fullLbl->getContentSize().width;
                                if (fullW <= _leftSpaceWidth) {
                                    _leftSpaceWidth -= fullW;
                                    rows.back().push_back(StyledEntry{fullLbl, elemColor, elemOpacity, elemTag, true});
                                    break;
                                }

                                const size_t remCp = totalCp - curCp;
                                const std::string firstChar = seg.substr(cp[curCp], cp[curCp + 1] - cp[curCp]);
                                cocos2d::CCLabelTTF* oneLbl = createSafeRichLabel(firstChar, fontName, fontSize);
                                if (oneLbl) {
                                    decorateLabelIfNeeded(oneLbl);
                                }
                                const float oneW = oneLbl ? oneLbl->getContentSize().width : 0.0f;

                                if (oneW > _leftSpaceWidth) {
                                    if (!rows.back().empty()) {
                                        startNewRow();
                                        continue;
                                    }
                                    // Guaranteed >= 1 codepoint progress even when _customSize.width < 1 glyph!
                                    if (oneLbl) {
                                        rows.back().push_back(
                                            StyledEntry{oneLbl, elemColor, elemOpacity, elemTag, true});
                                    }
                                    curCp += 1;
                                    if (curCp < totalCp) {
                                        startNewRow();
                                    }
                                    continue;
                                }

                                // Binary-search largest codepoint prefix [1..remCp] fitting _leftSpaceWidth.
                                size_t lo = 1;
                                size_t hi = remCp;
                                size_t best = 1;
                                while (lo <= hi) {
                                    const size_t mid = lo + (hi - lo) / 2;
                                    const std::string sub = seg.substr(cp[curCp], cp[curCp + mid] - cp[curCp]);
                                    cocos2d::CCLabelTTF* probeLbl = createSafeRichLabel(sub, fontName, fontSize);
                                    if (probeLbl) {
                                        decorateLabelIfNeeded(probeLbl);
                                    }
                                    const float probeW = probeLbl ? probeLbl->getContentSize().width : 0.0f;
                                    if (probeW <= _leftSpaceWidth) {
                                        best = mid;
                                        lo = mid + 1;
                                    } else {
                                        if (mid == 0) break;
                                        hi = mid - 1;
                                    }
                                }

                                const std::string fitStr = seg.substr(cp[curCp], cp[curCp + best] - cp[curCp]);
                                if (cocos2d::CCLabelTTF* fitLbl = createSafeRichLabel(fitStr, fontName, fontSize)) {
                                    decorateLabelIfNeeded(fitLbl);
                                    _leftSpaceWidth -= fitLbl->getContentSize().width;
                                    rows.back().push_back(
                                        StyledEntry{fitLbl, elemColor, elemOpacity, elemTag, true});
                                }
                                curCp += best;
                                if (curCp < totalCp) {
                                    startNewRow();
                                }
                            }
                        }
                    }

                    if (nlPos == std::string::npos) {
                        break;
                    }
                    startNewRow();
                    segStart = nlPos + 1;
                }
            } else if (elemType == cocos2d::ui::RICH_IMAGE) {
                auto* elImg = dynamic_cast<cocos2d::ui::RichElementImage*>(elem);
                if (!elImg) continue;
                cocos2d::CCSprite* sp = createSafeRichImageSprite(RichElementImageAccessor::filePath(elImg));
                if (!sp) continue;

                const float w = nodeDisplayWidth(sp);
                if (wrapEnabled && !rows.back().empty() && _leftSpaceWidth < w) {
                    startNewRow();
                }
                _leftSpaceWidth -= w;
                rows.back().push_back(StyledEntry{sp, elemColor, elemOpacity, elemTag, true});
            } else if (elemType == cocos2d::ui::RICH_CUSTOM) {
                auto* elCustom = dynamic_cast<cocos2d::ui::RichElementCustomNode*>(elem);
                if (!elCustom) continue;
                cocos2d::CCNode* customNode = RichElementCustomNodeAccessor::customNode(elCustom);
                if (!customNode || customNode == this || customNode == _elementRenderersContainer) {
                    continue;
                }
                if (customNode->getParent() != nullptr) {
                    customNode->retain();
                    customNode->removeFromParentAndCleanup(false);
                    customNode->autorelease();
                }

                const float w = nodeDisplayWidth(customNode);
                if (wrapEnabled && !rows.back().empty() && _leftSpaceWidth < w) {
                    startNewRow();
                }
                _leftSpaceWidth -= w;
                rows.back().push_back(StyledEntry{customNode, elemColor, elemOpacity, elemTag, true});
            }
        }

        // Remove trailing empty row if multiple rows exist and last row has no items.
        while (rows.size() > 1 && rows.back().empty()) {
            rows.pop_back();
        }

        std::vector<float> rowHeights(rows.size(), 0.0f);
        std::vector<float> rowWidths(rows.size(), 0.0f);
        float maxRowWidth = 0.0f;
        float totalRowsHeight = 0.0f;

        for (size_t r = 0; r < rows.size(); ++r) {
            float rw = 0.0f;
            float rh = 0.0f;
            for (const StyledEntry& entry : rows[r]) {
                rw += nodeDisplayWidth(entry.node);
                rh = (std::max)(rh, nodeDisplayHeight(entry.node));
            }
            rowWidths[r] = rw;
            rowHeights[r] = rh;
            maxRowWidth = (std::max)(maxRowWidth, rw);
            totalRowsHeight += rh;
        }
        if (rows.size() > 1) {
            totalRowsHeight += _verticalSpace * static_cast<float>(rows.size() - 1);
        }

        cocos2d::CCSize containerSize;
        if (_ignoreSize) {
            containerSize = cocos2d::CCSize(maxRowWidth, totalRowsHeight);
            _size = containerSize;
        } else {
            const float outW = (_customSize.width > 0.0f) ? _customSize.width : maxRowWidth;
            const float outH = (_customSize.height > 0.0f) ? _customSize.height : totalRowsHeight;
            containerSize = cocos2d::CCSize(outW, outH);
            _size = _customSize;
        }

        float nextPosY = containerSize.height;
        for (size_t r = 0; r < rows.size(); ++r) {
            nextPosY -= rowHeights[r];
            float nextPosX = 0.0f;
            for (const StyledEntry& entry : rows[r]) {
                cocos2d::CCNode* renderer = entry.node;
                if (!renderer) continue;
                renderer->setAnchorPoint(cocos2d::CCPointZero);
                renderer->setPosition(cocos2d::CCPoint(nextPosX, nextPosY));
                if (entry.applyColor) {
                    applySafeRichColorAndOpacity(renderer, entry.color, entry.opacity);
                }
                _elementRenderersContainer->addChild(renderer, 1, entry.tag);
                nextPosX += nodeDisplayWidth(renderer);
            }
            nextPosY -= _verticalSpace;
        }

        _elementRenderersContainer->setContentSize(containerSize);
        _elementRenderersContainer->setAnchorPoint(getAnchorPoint());
        _elementRenderersContainer->setPosition(cocos2d::CCPointZero);

        m_inSafeFormat = false;
    }

private:
    void applyStrokeAndShadowToCurrentChildren(bool mustUpdate) {
        if (!_elementRenderersContainer) return;
        cocos2d::CCArray* children = _elementRenderersContainer->getChildren();
        if (!children) return;
        const unsigned int count = children->count();
        for (unsigned int i = 0; i < count; ++i) {
            if (auto* ttf = dynamic_cast<cocos2d::CCLabelTTF*>(children->objectAtIndex(i))) {
                if (m_strokeEnabled) {
                    ttf->enableStroke(m_strokeColor, m_strokeSize, mustUpdate);
                }
                if (m_shadowEnabled) {
                    ttf->enableShadow(m_shadowOffset, m_shadowOpacity, m_shadowBlur, mustUpdate);
                }
            }
        }
    }

    bool m_inSafeFormat = false;
    bool m_strokeEnabled = false;
    cocos2d::ccColor3B m_strokeColor{0, 0, 0};
    float m_strokeSize = 1.0f;
    bool m_shadowEnabled = false;
    cocos2d::CCSize m_shadowOffset{0.0f, 0.0f};
    float m_shadowOpacity = 0.5f;
    float m_shadowBlur = 0.0f;
};

// ============================================================================
// Safe RTTI CCLabelTTF Stroke/Shadow Hooks
// Safely handles BroadcastView.lua `tolua.cast(richText:getVirtualRenderer(), "CCLabelTTF"):enableStroke(...)`!
// ============================================================================
int hook_CCLabelTTF_enableStroke(lua_State* L) {
    cocos2d::CCObject* obj = extractRawCCObject(L, 1);
    if (!obj) {
        return 0;
    }

    cocos2d::ccColor3B color = cocos2d::ccc3(0, 0, 0);
    if (!tryReadLuaColor3B(L, 2, color)) {
        return 0;
    }
    const float strokeSize = lua_isnumber(L, 3) ? static_cast<float>(lua_tonumber(L, 3)) : 1.0f;
    const bool mustUpdate = lua_isboolean(L, 4) ? (lua_toboolean(L, 4) != 0) : true;

    if (auto* ttf = dynamic_cast<cocos2d::CCLabelTTF*>(obj)) {
        ttf->enableStroke(color, strokeSize, mustUpdate);
    } else if (auto* rt = dynamic_cast<GClientRichText*>(obj)) {
        rt->strokeChildLabels(color, strokeSize, mustUpdate);
    } else if (auto* lbl = dynamic_cast<cocos2d::ui::Label*>(obj)) {
        if (auto* vr = dynamic_cast<cocos2d::CCLabelTTF*>(lbl->getVirtualRenderer())) {
            vr->enableStroke(color, strokeSize, mustUpdate);
        }
    } else if (auto* node = dynamic_cast<cocos2d::CCNode*>(obj)) {
        if (auto* parentRt = dynamic_cast<GClientRichText*>(node->getParent())) {
            parentRt->strokeChildLabels(color, strokeSize, mustUpdate);
        }
    }
    return 0;
}

int hook_CCLabelTTF_disableStroke(lua_State* L) {
    cocos2d::CCObject* obj = extractRawCCObject(L, 1);
    if (!obj) {
        return 0;
    }
    const bool mustUpdate = lua_isboolean(L, 2) ? (lua_toboolean(L, 2) != 0) : true;

    if (auto* ttf = dynamic_cast<cocos2d::CCLabelTTF*>(obj)) {
        ttf->disableStroke(mustUpdate);
    } else if (auto* rt = dynamic_cast<GClientRichText*>(obj)) {
        rt->disableChildStrokes(mustUpdate);
    } else if (auto* lbl = dynamic_cast<cocos2d::ui::Label*>(obj)) {
        if (auto* vr = dynamic_cast<cocos2d::CCLabelTTF*>(lbl->getVirtualRenderer())) {
            vr->disableStroke(mustUpdate);
        }
    } else if (auto* node = dynamic_cast<cocos2d::CCNode*>(obj)) {
        if (auto* parentRt = dynamic_cast<GClientRichText*>(node->getParent())) {
            parentRt->disableChildStrokes(mustUpdate);
        }
    }
    return 0;
}

int hook_CCLabelTTF_enableShadow(lua_State* L) {
    cocos2d::CCObject* obj = extractRawCCObject(L, 1);
    if (!obj) {
        return 0;
    }

    cocos2d::CCSize offset = cocos2d::CCSizeZero;
    if (!readLuaSize(L, 2, offset)) {
        return 0;
    }
    const float opacity = lua_isnumber(L, 3) ? static_cast<float>(lua_tonumber(L, 3)) : 0.5f;
    const float blur = lua_isnumber(L, 4) ? static_cast<float>(lua_tonumber(L, 4)) : 0.0f;
    const bool mustUpdate = lua_isboolean(L, 5) ? (lua_toboolean(L, 5) != 0) : true;

    if (auto* ttf = dynamic_cast<cocos2d::CCLabelTTF*>(obj)) {
        ttf->enableShadow(offset, opacity, blur, mustUpdate);
    } else if (auto* rt = dynamic_cast<GClientRichText*>(obj)) {
        rt->shadowChildLabels(offset, opacity, blur, mustUpdate);
    } else if (auto* lbl = dynamic_cast<cocos2d::ui::Label*>(obj)) {
        if (auto* vr = dynamic_cast<cocos2d::CCLabelTTF*>(lbl->getVirtualRenderer())) {
            vr->enableShadow(offset, opacity, blur, mustUpdate);
        }
    } else if (auto* node = dynamic_cast<cocos2d::CCNode*>(obj)) {
        if (auto* parentRt = dynamic_cast<GClientRichText*>(node->getParent())) {
            parentRt->shadowChildLabels(offset, opacity, blur, mustUpdate);
        }
    }
    return 0;
}

// ============================================================================
// RichText & RichElement* Lua Bindings (cocos2d::ui::* + GClientRichText)
// ============================================================================
int lua_RichElementText_create(lua_State* L) {
    const int base = (lua_type(L, 1) == LUA_TNUMBER) ? 1 : 2;
    const int tag = static_cast<int>(lua_tointeger(L, base));
    const cocos2d::ccColor3B color = readLuaColor3B(L, base + 1);
    const int rawOpacity = lua_isnumber(L, base + 2) ? static_cast<int>(lua_tointeger(L, base + 2)) : 255;
    const GLubyte opacity = static_cast<GLubyte>((std::max)(0, (std::min)(255, rawOpacity)));
    const char* text = lua_tostring(L, base + 3);
    const char* fontName = lua_tostring(L, base + 4);
    const float fontSize = lua_isnumber(L, base + 5) ? static_cast<float>(lua_tonumber(L, base + 5)) : 20.0f;

    auto* elem = cocos2d::ui::RichElementText::create(
        tag,
        color,
        opacity,
        text ? text : "",
        fontName ? fontName : "",
        fontSize > 0.0f ? fontSize : 20.0f);
    pushCCObject(L, elem, "RichElementText");
    return 1;
}

int lua_RichElementImage_create(lua_State* L) {
    const int base = (lua_type(L, 1) == LUA_TNUMBER) ? 1 : 2;
    const int tag = static_cast<int>(lua_tointeger(L, base));
    const cocos2d::ccColor3B color = readLuaColor3B(L, base + 1);
    const int rawOpacity = lua_isnumber(L, base + 2) ? static_cast<int>(lua_tointeger(L, base + 2)) : 255;
    const GLubyte opacity = static_cast<GLubyte>((std::max)(0, (std::min)(255, rawOpacity)));
    const char* filePath = lua_tostring(L, base + 3);
    const std::string resolved = resolveImagePathWithExtensionFallback(filePath ? filePath : "");

    auto* elem = cocos2d::ui::RichElementImage::create(
        tag,
        color,
        opacity,
        resolved.c_str());
    pushCCObject(L, elem, "RichElementImage");
    return 1;
}

int lua_RichElementCustomNode_create(lua_State* L) {
    const int base = (lua_type(L, 1) == LUA_TNUMBER) ? 1 : 2;
    const int tag = static_cast<int>(lua_tointeger(L, base));
    const cocos2d::ccColor3B color = readLuaColor3B(L, base + 1);
    const int rawOpacity = lua_isnumber(L, base + 2) ? static_cast<int>(lua_tointeger(L, base + 2)) : 255;
    const GLubyte opacity = static_cast<GLubyte>((std::max)(0, (std::min)(255, rawOpacity)));
    auto* customNode = getSafeCCObject<cocos2d::CCNode>(L, base + 3);
    if (!customNode) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "RichText",
            "RichElementCustomNode:create received null/non-CCNode customNode (tag=%d); falling back to CCNode::create()",
            tag);
        customNode = cocos2d::CCNode::create();
    }
    if (!customNode) {
        lua_pushnil(L);
        return 1;
    }

    auto* elem = cocos2d::ui::RichElementCustomNode::create(tag, color, opacity, customNode);
    pushCCObject(L, elem, "RichElementCustomNode");
    return 1;
}

int lua_RichText_create(lua_State* L) {
    auto* rt = GClientRichText::create();
    pushCCObject(L, rt, "RichText");
    return 1;
}

int lua_RichText_insertElement(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    auto* elem = getSafeCCObject<cocos2d::ui::RichElement>(L, 2);
    int index = static_cast<int>(lua_tointeger(L, 3));
    if (self && elem) {
        if (index < 0) index = 0;
        self->insertElement(elem, index);
    }
    return 0;
}

int lua_RichText_pushBackElement(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    auto* elem = getSafeCCObject<cocos2d::ui::RichElement>(L, 2);
    if (self && elem) {
        self->pushBackElement(elem);
    }
    return 0;
}

int lua_RichText_removeElement(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    if (!self) return 0;
    if (lua_type(L, 2) == LUA_TNUMBER) {
        const int idx = static_cast<int>(lua_tointeger(L, 2));
        if (idx >= 0) {
            self->removeElement(idx);
        }
    } else if (auto* elem = getSafeCCObject<cocos2d::ui::RichElement>(L, 2)) {
        self->removeElement(elem);
    }
    return 0;
}

int lua_RichText_setVerticalSpace(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    const float space = static_cast<float>(lua_tonumber(L, 2));
    if (self) {
        self->setVerticalSpace(space);
        if (auto* gc = dynamic_cast<GClientRichText*>(self)) {
            gc->markFormatDirty();
        }
    }
    return 0;
}

int lua_RichText_formatText(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    if (self) {
        if (auto* gc = dynamic_cast<GClientRichText*>(self)) {
            gc->markFormatDirty();
            gc->safeFormatText();
        } else {
            self->formatText();
        }
    }
    return 0;
}

int lua_RichText_ignoreContentAdaptWithSize(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    const bool ignore = lua_toboolean(L, 2) != 0;
    if (self) {
        self->ignoreContentAdaptWithSize(ignore);
    }
    return 0;
}

int lua_RichText_isIgnoreContentAdaptWithSize(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    tolua_pushboolean(L, (self && self->isIgnoreContentAdaptWithSize()) ? 1 : 0);
    return 1;
}

int lua_RichText_setAnchorPoint(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    cocos2d::CCPoint pt = cocos2d::CCPointZero;
    if (self && readLuaPoint(L, 2, pt)) {
        self->setAnchorPoint(pt);
    }
    return 0;
}

int lua_RichText_setSize(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    cocos2d::CCSize sz = cocos2d::CCSizeZero;
    if (self && readLuaSize(L, 2, sz)) {
        self->setSize(sz);
    }
    return 0;
}

int lua_RichText_getSize(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    const cocos2d::CCSize sz = self ? self->getSize() : cocos2d::CCSizeZero;
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCSize(sz), "CCSize");
    return 1;
}

int lua_RichText_getContentSize(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    if (self) {
        if (auto* gc = dynamic_cast<GClientRichText*>(self)) {
            gc->safeFormatText();
        } else {
            self->formatText();
        }
    }
    const cocos2d::CCSize sz = self ? self->getContentSize() : cocos2d::CCSizeZero;
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCSize(sz), "CCSize");
    return 1;
}

int lua_RichText_getVirtualRendererSize(lua_State* L) {
    return lua_RichText_getContentSize(L);
}

int lua_RichText_getDescription(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::ui::RichText>(L, 1);
    const std::string desc = self ? self->getDescription() : "RichText";
    lua_pushlstring(L, desc.data(), desc.size());
    return 1;
}

void registerRichTextBindingsInternal(lua_State* L) {
    if (!L) return;
    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);

    tolua_usertype(L, "RichElement");
    tolua_usertype(L, "RichElementText");
    tolua_usertype(L, "RichElementImage");
    tolua_usertype(L, "RichElementCustomNode");
    tolua_usertype(L, "RichText");

    tolua_cclass(L, "RichElement", "RichElement", "CCObject", nullptr);
    tolua_beginmodule(L, "RichElement");
    tolua_endmodule(L);

    tolua_cclass(L, "RichElementText", "RichElementText", "RichElement", nullptr);
    tolua_beginmodule(L, "RichElementText");
    tolua_function(L, "create", lua_RichElementText_create);
    tolua_endmodule(L);

    tolua_cclass(L, "RichElementImage", "RichElementImage", "RichElement", nullptr);
    tolua_beginmodule(L, "RichElementImage");
    tolua_function(L, "create", lua_RichElementImage_create);
    tolua_endmodule(L);

    tolua_cclass(L, "RichElementCustomNode", "RichElementCustomNode", "RichElement", nullptr);
    tolua_beginmodule(L, "RichElementCustomNode");
    tolua_function(L, "create", lua_RichElementCustomNode_create);
    tolua_endmodule(L);

    tolua_cclass(L, "RichText", "RichText", "Widget", nullptr);
    tolua_beginmodule(L, "RichText");
    tolua_function(L, "create", lua_RichText_create);
    tolua_function(L, "insertElement", lua_RichText_insertElement);
    tolua_function(L, "pushBackElement", lua_RichText_pushBackElement);
    tolua_function(L, "removeElement", lua_RichText_removeElement);
    tolua_function(L, "setVerticalSpace", lua_RichText_setVerticalSpace);
    tolua_function(L, "formatText", lua_RichText_formatText);
    tolua_function(L, "ignoreContentAdaptWithSize", lua_RichText_ignoreContentAdaptWithSize);
    tolua_function(L, "isIgnoreContentAdaptWithSize", lua_RichText_isIgnoreContentAdaptWithSize);
    tolua_function(L, "setAnchorPoint", lua_RichText_setAnchorPoint);
    tolua_function(L, "setSize", lua_RichText_setSize);
    tolua_function(L, "setContentSize", lua_RichText_setSize);
    tolua_function(L, "getSize", lua_RichText_getSize);
    tolua_function(L, "getContentSize", lua_RichText_getContentSize);
    tolua_function(L, "getVirtualRendererSize", lua_RichText_getVirtualRendererSize);
    tolua_function(L, "getDescription", lua_RichText_getDescription);
    tolua_function(L, "enableStroke", hook_CCLabelTTF_enableStroke);
    tolua_function(L, "disableStroke", hook_CCLabelTTF_disableStroke);
    tolua_function(L, "enableShadow", hook_CCLabelTTF_enableShadow);
    tolua_endmodule(L);

    tolua_endmodule(L);
}

// ============================================================================
// SpineLuaAnimation (GClientSkeletonAnimation) — .json/.jsonb Fallback,
// Pre-Validated Atlas/SkeletonData, Inert Dummy Node, & UAF-Safe Event Dispatch
// ============================================================================
struct CachedSpineEntry {
    std::string jsonPath;
    std::string atlasPath;
    float scale = 1.0f;
};
static std::unordered_map<std::string, CachedSpineEntry> g_spineCache;

struct SpineEventKeyframe {
    float time = 0.0f;
    std::string name;
    int intValue = 0;
    float floatValue = 0.0f;
    std::string stringValue;
};

using SpineAnimEventMap = std::unordered_map<std::string, std::vector<SpineEventKeyframe>>;
static std::unordered_map<std::string, std::shared_ptr<const SpineAnimEventMap>> g_spineEventTimelinesCache;

std::string resolveSpineJsonPath(const char* rawJsonPath) {
    if (!rawJsonPath || !*rawJsonPath) return {};
    const std::string norm = normalizeAssetLookupPath(rawJsonPath);
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) return norm;

    auto checkCandidate = [&](const std::string& cand) -> std::string {
        if (cand.empty()) return {};
        const std::string full = fu->fullPathForFilename(cand.c_str());
        if (!full.empty() && fu->isFileExist(full)) {
            return full;
        }
        return {};
    };

    if (std::string exact = checkCandidate(norm); !exact.empty()) {
        return exact;
    }

    const std::string stem = extractAssetStem(norm);
    static const char* const kJsonAlts[] = {".jsonb", ".json"};
    for (const char* ext : kJsonAlts) {
        if (std::string alt = checkCandidate(stem + ext); !alt.empty()) {
            return alt;
        }
    }
    return {};
}

std::string resolveSpineAtlasPath(const char* rawAtlasPath) {
    if (!rawAtlasPath || !*rawAtlasPath) return {};
    const std::string norm = normalizeAssetLookupPath(rawAtlasPath);
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) return norm;

    auto checkCandidate = [&](const std::string& cand) -> std::string {
        if (cand.empty()) return {};
        const std::string full = fu->fullPathForFilename(cand.c_str());
        if (!full.empty() && fu->isFileExist(full)) {
            return full;
        }
        return {};
    };

    if (std::string exact = checkCandidate(norm); !exact.empty()) {
        return exact;
    }

    const std::string stem = extractAssetStem(norm);
    static const char* const kAtlasAlts[] = {".atlas", ".atlas.txt", ".txt"};
    for (const char* ext : kAtlasAlts) {
        if (std::string alt = checkCandidate(stem + ext); !alt.empty()) {
            return alt;
        }
    }
    return {};
}

std::shared_ptr<const SpineAnimEventMap> getOrLoadSpineEventTimelines(const std::string& jsonPathOrRaw) {
    std::string resolvedKey = resolveSpineJsonPath(jsonPathOrRaw.c_str());
    if (resolvedKey.empty()) {
        resolvedKey = jsonPathOrRaw;
    }

    auto cachedIt = g_spineEventTimelinesCache.find(resolvedKey);
    if (cachedIt != g_spineEventTimelinesCache.end() && cachedIt->second) {
        return cachedIt->second;
    }

    auto animMap = std::make_shared<SpineAnimEventMap>();
    if (!resolvedKey.empty()) {
        if (auto* fu = cocos2d::CCFileUtils::sharedFileUtils()) {
            unsigned long sz = 0;
            unsigned char* raw = fu->getFileData(resolvedKey.c_str(), "rb", &sz);
            if (raw && sz > 0) {
                std::string jsonStr(reinterpret_cast<const char*>(raw), static_cast<size_t>(sz));
                delete[] raw;

                rapidjson::Document doc;
                doc.Parse<0>(jsonStr.c_str());
                if (!doc.HasParseError() && doc.IsObject()) {
                    std::unordered_map<std::string, SpineEventKeyframe> defaults;
                    if (doc.HasMember("events") && doc["events"].IsObject()) {
                        const auto& evDefs = doc["events"];
                        for (auto it = evDefs.MemberonBegin(); it != evDefs.MemberonEnd(); ++it) {
                            if (!it->name.IsString() || !it->value.IsObject()) continue;
                            SpineEventKeyframe def;
                            def.name = it->name.GetString();
                            if (it->value.HasMember("int") && it->value["int"].IsInt()) {
                                def.intValue = it->value["int"].GetInt();
                            }
                            if (it->value.HasMember("float") && it->value["float"].IsNumber()) {
                                def.floatValue = static_cast<float>(it->value["float"].GetDouble());
                            }
                            if (it->value.HasMember("string") && it->value["string"].IsString()) {
                                def.stringValue = it->value["string"].GetString();
                            }
                            defaults[def.name] = std::move(def);
                        }
                    }

                    if (doc.HasMember("animations") && doc["animations"].IsObject()) {
                        const auto& anims = doc["animations"];
                        for (auto ait = anims.MemberonBegin(); ait != anims.MemberonEnd(); ++ait) {
                            if (!ait->name.IsString() || !ait->value.IsObject()) continue;
                            if (!ait->value.HasMember("events") || !ait->value["events"].IsArray()) continue;
                            const auto& evArr = ait->value["events"];
                            std::vector<SpineEventKeyframe> list;
                            list.reserve(evArr.Size());
                            for (rapidjson::SizeType k = 0; k < evArr.Size(); ++k) {
                                const auto& item = evArr[k];
                                if (!item.IsObject() || !item.HasMember("name") || !item["name"].IsString()) {
                                    continue;
                                }
                                SpineEventKeyframe kf;
                                kf.name = item["name"].GetString();
                                auto defIt = defaults.find(kf.name);
                                if (defIt != defaults.end()) {
                                    kf.intValue = defIt->second.intValue;
                                    kf.floatValue = defIt->second.floatValue;
                                    kf.stringValue = defIt->second.stringValue;
                                }
                                if (item.HasMember("time") && item["time"].IsNumber()) {
                                    kf.time = static_cast<float>(item["time"].GetDouble());
                                }
                                if (item.HasMember("int") && item["int"].IsInt()) {
                                    kf.intValue = item["int"].GetInt();
                                }
                                if (item.HasMember("float") && item["float"].IsNumber()) {
                                    kf.floatValue = static_cast<float>(item["float"].GetDouble());
                                }
                                if (item.HasMember("string") && item["string"].IsString()) {
                                    kf.stringValue = item["string"].GetString();
                                }
                                list.push_back(std::move(kf));
                            }
                            std::stable_sort(list.begin(), list.end(),
                                             [](const SpineEventKeyframe& a, const SpineEventKeyframe& b) {
                                                 return a.time < b.time;
                                             });
                            if (!list.empty()) {
                                (*animMap)[ait->name.GetString()] = std::move(list);
                            }
                        }
                    }
                }
            } else {
                delete[] raw;
            }
        }
    }

    std::shared_ptr<const SpineAnimEventMap> constMap = animMap;
    g_spineEventTimelinesCache[resolvedKey] = constMap;
    return constMap;
}

// Binary-compatible attachment layouts matching tools/patch_cocos2dx.py MeshAttachment (type == 2)
// and SkinnedMeshAttachment (type == 3), while compiling cleanly against unpatched stock 2.2.6 headers.
struct GClientCompatMeshAttachment {
    cocos2d::extension::Attachment super;
    void* rendererObject;
    float regionU, regionV, regionU2, regionV2;
    int regionRotate;
    float regionOffsetX, regionOffsetY;
    float regionWidth, regionHeight;
    float regionOriginalWidth, regionOriginalHeight;
    float r, g, b, a;
    float* vertices;
    int verticesCount;
    float* regionUVs;
    float* uvs;
    int* triangles;
    int trianglesCount;
    int hullLength;
    float width, height;
};

struct GClientCompatSkinnedMeshAttachment {
    cocos2d::extension::Attachment super;
    void* rendererObject;
    float regionU, regionV, regionU2, regionV2;
    int regionRotate;
    float regionOffsetX, regionOffsetY;
    float regionWidth, regionHeight;
    float regionOriginalWidth, regionOriginalHeight;
    float r, g, b, a;
    int* bones;
    int bonesCount;
    float* weights;
    int weightsCount;
    float* regionUVs;
    float* uvs;
    int uvsCount;
    int* triangles;
    int trianglesCount;
    int hullLength;
    float width, height;
};

constexpr int kSpineAttachmentMesh = 2;
constexpr int kSpineAttachmentSkinnedMesh = 3;

cocos2d::CCRect computeSpineBoundingBoxInParent(cocos2d::extension::CCSkeleton* self) {
    if (!self) {
        return cocos2d::CCRectZero;
    }
    const cocos2d::CCPoint pos = self->getPosition();
    if (!self->skeleton || self->skeleton->slotCount <= 0 || !self->skeleton->slots) {
        return cocos2d::CCRect(pos.x, pos.y, 0.0f, 0.0f);
    }

    float minX = FLT_MAX;
    float minY = FLT_MAX;
    float maxX = -FLT_MAX;
    float maxY = -FLT_MAX;
    bool hasVertices = false;

    for (int i = 0; i < self->skeleton->slotCount; ++i) {
        cocos2d::extension::Slot* slot = self->skeleton->drawOrder
            ? self->skeleton->drawOrder[i]
            : self->skeleton->slots[i];
        if (!slot || !slot->bone || !slot->attachment) {
            continue;
        }

        static_assert(sizeof(slot->attachment->type) == sizeof(int), "Spine AttachmentType size mismatch");
        int attType = 0;
        std::memcpy(&attType, &slot->attachment->type, sizeof(attType));
        if (attType == static_cast<int>(cocos2d::extension::ATTACHMENT_REGION)) {
            float vertices[8] = {};
            auto* region = reinterpret_cast<cocos2d::extension::RegionAttachment*>(slot->attachment);
            cocos2d::extension::RegionAttachment_computeVertices(
                region, self->skeleton->x, self->skeleton->y, slot->bone, vertices);
            for (int v = 0; v < 8; v += 2) {
                minX = (std::min)(minX, vertices[v]);
                minY = (std::min)(minY, vertices[v + 1]);
                maxX = (std::max)(maxX, vertices[v]);
                maxY = (std::max)(maxY, vertices[v + 1]);
                hasVertices = true;
            }
        } else if (attType == kSpineAttachmentMesh) {
            const auto* mesh = reinterpret_cast<const GClientCompatMeshAttachment*>(slot->attachment);
            if (mesh->vertices && mesh->verticesCount >= 2) {
                const cocos2d::extension::Bone* bone = slot->bone;
                const float x = self->skeleton->x + bone->worldX;
                const float y = self->skeleton->y + bone->worldY;
                const float m00 = bone->m00;
                const float m01 = bone->m01;
                const float m10 = bone->m10;
                const float m11 = bone->m11;
                for (int v = 0; v + 1 < mesh->verticesCount; v += 2) {
                    const float vx = mesh->vertices[v];
                    const float vy = mesh->vertices[v + 1];
                    const float wx = vx * m00 + vy * m01 + x;
                    const float wy = vx * m10 + vy * m11 + y;
                    minX = (std::min)(minX, wx);
                    minY = (std::min)(minY, wy);
                    maxX = (std::max)(maxX, wx);
                    maxY = (std::max)(maxY, wy);
                    hasVertices = true;
                }
            }
        } else if (attType == kSpineAttachmentSkinnedMesh) {
            const auto* mesh = reinterpret_cast<const GClientCompatSkinnedMeshAttachment*>(slot->attachment);
            if (mesh->bones && mesh->bonesCount > 0 && mesh->weights &&
                mesh->weightsCount >= 3 && self->skeleton->bones) {
                const float sx = self->skeleton->x;
                const float sy = self->skeleton->y;
                int v = 0;
                int b = 0;
                while (v < mesh->bonesCount) {
                    const int boneInfluenceCount = mesh->bones[v++];
                    if (boneInfluenceCount <= 0 || v + boneInfluenceCount > mesh->bonesCount) {
                        break;
                    }
                    float wx = 0.0f;
                    float wy = 0.0f;
                    const int endV = v + boneInfluenceCount;
                    bool validVertex = true;
                    for (; v < endV; ++v, b += 3) {
                        const int boneIdx = mesh->bones[v];
                        if (boneIdx < 0 || boneIdx >= self->skeleton->boneCount ||
                            b + 2 >= mesh->weightsCount) {
                            validVertex = false;
                            break;
                        }
                        const cocos2d::extension::Bone* bone = self->skeleton->bones[boneIdx];
                        if (!bone) {
                            validVertex = false;
                            break;
                        }
                        const float vx = mesh->weights[b];
                        const float vy = mesh->weights[b + 1];
                        const float weight = mesh->weights[b + 2];
                        wx += (vx * bone->m00 + vy * bone->m01 + bone->worldX) * weight;
                        wy += (vx * bone->m10 + vy * bone->m11 + bone->worldY) * weight;
                    }
                    if (!validVertex) {
                        break;
                    }
                    wx += sx;
                    wy += sy;
                    minX = (std::min)(minX, wx);
                    minY = (std::min)(minY, wy);
                    maxX = (std::max)(maxX, wx);
                    maxY = (std::max)(maxY, wy);
                    hasVertices = true;
                }
            }
        }
    }

    if (!hasVertices) {
        return cocos2d::CCRect(pos.x, pos.y, 0.0f, 0.0f);
    }

    const float scaleX = self->getScaleX();
    const float scaleY = self->getScaleY();
    const float x1 = minX * scaleX;
    const float x2 = maxX * scaleX;
    const float y1 = minY * scaleY;
    const float y2 = maxY * scaleY;
    const float outMinX = (std::min)(x1, x2);
    const float outMaxX = (std::max)(x1, x2);
    const float outMinY = (std::min)(y1, y2);
    const float outMaxY = (std::max)(y1, y2);
    return cocos2d::CCRect(
        pos.x + outMinX, pos.y + outMinY, outMaxX - outMinX, outMaxY - outMinY);
}

void releaseSpineLuaHandler(int& handler) {
    if (handler != 0) {
        auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
        if (mgr && mgr->getScriptEngine()) {
            if (auto* engine = CCLuaEngine::defaultEngine()) {
                if (auto* stack = engine->getLuaStack()) {
                    stack->removeScriptHandler(handler);
                }
            }
        }
        handler = 0;
    }
}

void invokeSpineLuaHandler(int handler, int trackIndex, int loopCount, bool hasLoopCount) {
    if (handler == 0) return;
    auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
    if (!mgr || !mgr->getScriptEngine()) return;
    auto* engine = CCLuaEngine::defaultEngine();
    auto* stack = engine ? engine->getLuaStack() : nullptr;
    if (!stack) return;
    stack->pushInt(trackIndex);
    int argc = 1;
    if (hasLoopCount) {
        stack->pushInt(loopCount);
        argc = 2;
    }
    stack->executeFunctionByHandler(handler, argc);
    stack->clean();
}

void invokeSpineEventHandler(int handler,
                             int trackIndex,
                             const char* animName,
                             const SpineEventKeyframe& ev) {
    if (handler == 0) return;
    auto* mgr = cocos2d::CCScriptEngineManager::sharedManager();
    if (!mgr || !mgr->getScriptEngine()) return;
    auto* engine = CCLuaEngine::defaultEngine();
    auto* stack = engine ? engine->getLuaStack() : nullptr;
    if (!stack) return;

    if (lua_State* L = stack->getLuaState()) {
        lua_pushinteger(L, static_cast<lua_Integer>(trackIndex));

        lua_newtable(L);
        lua_pushstring(L, "event");
        lua_setfield(L, -2, "type");
        lua_pushinteger(L, static_cast<lua_Integer>(trackIndex));
        lua_setfield(L, -2, "trackIndex");
        lua_pushstring(L, animName ? animName : "");
        lua_setfield(L, -2, "animation");
        lua_pushlstring(L, ev.name.data(), ev.name.size());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(ev.intValue));
        lua_setfield(L, -2, "intValue");
        lua_pushnumber(L, static_cast<lua_Number>(ev.floatValue));
        lua_setfield(L, -2, "floatValue");
        lua_pushlstring(L, ev.stringValue.data(), ev.stringValue.size());
        lua_setfield(L, -2, "stringValue");
        lua_pushnumber(L, static_cast<lua_Number>(ev.time));
        lua_setfield(L, -2, "time");

        lua_newtable(L);
        lua_pushlstring(L, ev.name.data(), ev.name.size());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(ev.intValue));
        lua_setfield(L, -2, "intValue");
        lua_pushnumber(L, static_cast<lua_Number>(ev.floatValue));
        lua_setfield(L, -2, "floatValue");
        lua_pushlstring(L, ev.stringValue.data(), ev.stringValue.size());
        lua_setfield(L, -2, "stringValue");
        lua_pushnumber(L, static_cast<lua_Number>(ev.time));
        lua_setfield(L, -2, "time");
        lua_pushvalue(L, -1);
        lua_setfield(L, -3, "eventData");
        lua_setfield(L, -2, "data");

        lua_pushlstring(L, ev.name.data(), ev.name.size());
        lua_pushinteger(L, static_cast<lua_Integer>(ev.intValue));
        lua_pushnumber(L, static_cast<lua_Number>(ev.floatValue));
        lua_pushlstring(L, ev.stringValue.data(), ev.stringValue.size());

        stack->executeFunctionByHandler(handler, 6);
        stack->clean();
    } else {
        stack->pushInt(trackIndex);
        stack->pushString(ev.name.c_str(), static_cast<int>(ev.name.size()));
        stack->executeFunctionByHandler(handler, 2);
        stack->clean();
    }
}

cocos2d::extension::SkeletonData* getSharedDummySkeletonData() {
    static cocos2d::extension::SkeletonData* s_dummyData = nullptr;
    static cocos2d::extension::BoneData* s_dummyBones[1] = {nullptr};
    if (!s_dummyData) {
        s_dummyData = cocos2d::extension::SkeletonData_create();
        s_dummyBones[0] = cocos2d::extension::BoneData_create("root", nullptr);
        if (s_dummyData && s_dummyBones[0]) {
            s_dummyBones[0]->scaleX = 1.0f;
            s_dummyBones[0]->scaleY = 1.0f;
            s_dummyData->boneCount = 1;
            s_dummyData->bones = s_dummyBones;
        }
    }
    return s_dummyData;
}

class GClientSkeletonAnimation : public cocos2d::extension::CCSkeletonAnimation {
public:
    static GClientSkeletonAnimation* createDummy(const char* reason,
                                               const char* jsonArg,
                                               const char* atlasArg) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "Spine",
            "Creating inert dummy SpineLuaAnimation (%s): json='%s' atlas='%s'",
            reason ? reason : "invalid",
            jsonArg ? jsonArg : "(null)",
            atlasArg ? atlasArg : "(null)");
        auto* dummy = new GClientSkeletonAnimation();
        dummy->autorelease();
        return dummy;
    }

    static GClientSkeletonAnimation* createWithFile(const char* skeletonDataFile,
                                                  const char* atlasFile,
                                                  float scale = 1.0f) {
        if (!skeletonDataFile || !*skeletonDataFile || !atlasFile || !*atlasFile) {
            return createDummy("empty path argument", skeletonDataFile, atlasFile);
        }

        const std::string resolvedJson = resolveSpineJsonPath(skeletonDataFile);
        const std::string resolvedAtlas = resolveSpineAtlasPath(atlasFile);
        if (resolvedJson.empty() || resolvedAtlas.empty()) {
            return createDummy("missing .json/.jsonb or .atlas file", skeletonDataFile, atlasFile);
        }

        // Pre-validate Atlas and SkeletonData (boneCount > 0) BEFORE invoking CCSkeleton ctor,
        // because stock CCSkeleton ctor dereferences NULL skeletonData and bones[0] under NDEBUG!
        cocos2d::extension::Atlas* atlas =
            cocos2d::extension::Atlas_readAtlasFile(resolvedAtlas.c_str());
        if (!atlas) {
            return createDummy("Atlas_readAtlasFile returned NULL",
                               resolvedJson.c_str(),
                               resolvedAtlas.c_str());
        }

        cocos2d::extension::SkeletonJson* json = cocos2d::extension::SkeletonJson_create(atlas);
        if (!json) {
            cocos2d::extension::Atlas_dispose(atlas);
            return createDummy("SkeletonJson_create returned NULL",
                               resolvedJson.c_str(),
                               resolvedAtlas.c_str());
        }
        json->scale = (scale > 0.0f) ? scale : 1.0f;

        cocos2d::extension::SkeletonData* skeletonData =
            cocos2d::extension::SkeletonJson_readSkeletonDataFile(json, resolvedJson.c_str());
        const std::string parseError = (json->error != nullptr) ? json->error : "";
        cocos2d::extension::SkeletonJson_dispose(json);

        if (!skeletonData || skeletonData->boneCount <= 0 || !skeletonData->bones || !skeletonData->bones[0]) {
            if (skeletonData) {
                cocos2d::extension::SkeletonData_dispose(skeletonData);
            }
            cocos2d::extension::Atlas_dispose(atlas);
            return createDummy(
                parseError.empty() ? "SkeletonData invalid or boneCount == 0" : parseError.c_str(),
                resolvedJson.c_str(),
                resolvedAtlas.c_str());
        }

        auto* node = new GClientSkeletonAnimation(skeletonData, atlas, resolvedJson);
        if (!node->skeleton) {
            delete node;
            return createDummy("Skeleton_create returned NULL",
                               resolvedJson.c_str(),
                               resolvedAtlas.c_str());
        }
        node->autorelease();
        return node;
    }

    // Valid pre-validated constructor: CCSkeletonAnimation(skeletonData) sets ownsSkeletonData=false
    // and initializes states[0] safely; GClientSkeletonAnimation owns skeletonData and atlas cleanly.
    GClientSkeletonAnimation(cocos2d::extension::SkeletonData* validatedData,
                           cocos2d::extension::Atlas* validatedAtlas,
                           const std::string& resolvedJsonPath)
        : CCSkeletonAnimation(validatedData),
          resolvedJsonPath_(resolvedJsonPath),
          timelines_(getOrLoadSpineEventTimelines(resolvedJsonPath)),
          ownedSkeletonData_(validatedData),
          ownedAtlas_(validatedAtlas),
          isDummy_(false) {}

    // Inert dummy constructor: uses shared 1-bone static SkeletonData during base ctor so
    // CCSkeletonAnimation::initialize() never dereferences NULL, then detaches `this->skeleton = nullptr`
    // during runtime and restores `dummySkeleton_` in ~GClientSkeletonAnimation() so ~CCSkeleton()
    // never calls Skeleton_dispose(nullptr)!
    GClientSkeletonAnimation()
        : CCSkeletonAnimation(getSharedDummySkeletonData()),
          isDummy_(true) {
        dummySkeleton_ = this->skeleton;
        this->skeleton = nullptr;
        this->rootBone = nullptr;
        unscheduleUpdate();
    }

    ~GClientSkeletonAnimation() override {
        releaseSpineLuaHandler(startHandler_);
        releaseSpineLuaHandler(endHandler_);
        releaseSpineLuaHandler(completeHandler_);
        releaseSpineLuaHandler(eventHandler_);
        if (isDummy_ && this->skeleton == nullptr && dummySkeleton_ != nullptr) {
            this->skeleton = dummySkeleton_;
            dummySkeleton_ = nullptr;
        }
        if (ownedSkeletonData_) {
            cocos2d::extension::SkeletonData_dispose(ownedSkeletonData_);
            ownedSkeletonData_ = nullptr;
        }
        if (ownedAtlas_) {
            cocos2d::extension::Atlas_dispose(ownedAtlas_);
            ownedAtlas_ = nullptr;
        }
    }

    bool isDummy() const { return isDummy_ || skeleton == nullptr; }

    void setStartHandler(int h) { releaseSpineLuaHandler(startHandler_); startHandler_ = h; }
    void setEndHandler(int h) { releaseSpineLuaHandler(endHandler_); endHandler_ = h; }
    void setCompleteHandler(int h) { releaseSpineLuaHandler(completeHandler_); completeHandler_ = h; }
    void setEventHandler(int h) { releaseSpineLuaHandler(eventHandler_); eventHandler_ = h; }

    void queueEvent(int trackIndex,
                    const char* eventName,
                    int intVal = 0,
                    float floatVal = 0.0f,
                    const char* strVal = "") {
        QueuedEvent q;
        q.trackIndex = trackIndex;
        q.keyframe.name = eventName ? eventName : "";
        q.keyframe.intValue = intVal;
        q.keyframe.floatValue = floatVal;
        q.keyframe.stringValue = strVal ? strVal : "";
        queuedEvents_.push_back(std::move(q));
    }

    void resetTrackTracking(int stateIdx) {
        if (stateIdx < 0) return;
        if (static_cast<size_t>(stateIdx) >= tracked_.size()) {
            tracked_.resize(static_cast<size_t>(stateIdx) + 1);
        }
        tracked_[stateIdx].anim = nullptr;
        tracked_[stateIdx].prevTime = 0.0f;
        tracked_[stateIdx].loopCount = 0;
        tracked_[stateIdx].ended = false;
        tracked_[stateIdx].generation = ++generationCounter_;
    }

    void draw() override {
        if (!skeleton || isDummy_) {
            return;
        }
        CCSkeletonAnimation::draw();
    }

    cocos2d::CCRect boundingBox() override {
        if (!skeleton || isDummy_) {
            const cocos2d::CCPoint pos = getPosition();
            return cocos2d::CCRect(pos.x, pos.y, 0.0f, 0.0f);
        }
        return computeSpineBoundingBoxInParent(this);
    }

    void update(float deltaTime) override {
        if (!skeleton || isDummy_) {
            return;
        }
        CCObjectRetainGuard selfGuard(this);

        // 1. Pre-update track transition detection (safe against callbacks mutating states/tracked_).
        const size_t initialStateCount = states.size();
        if (tracked_.size() < initialStateCount) {
            tracked_.resize(initialStateCount);
        }
        for (size_t i = 0; i < initialStateCount; ++i) {
            if (i >= states.size() || !skeleton) {
                break;
            }
            if (i >= tracked_.size()) {
                tracked_.resize(states.size());
            }
            auto* st = states[i];
            const auto* anim = st ? st->animation : nullptr;
            if (anim != tracked_[i].anim) {
                const bool shouldFireEnd = (tracked_[i].anim != nullptr && !tracked_[i].ended);
                const bool shouldFireStart = (anim != nullptr);
                const uint64_t gen = ++generationCounter_;
                tracked_[i].anim = anim;
                tracked_[i].prevTime = st ? st->time : 0.0f;
                tracked_[i].loopCount = 0;
                tracked_[i].ended = false;
                tracked_[i].generation = gen;

                if (shouldFireEnd && endHandler_ != 0) {
                    invokeSpineLuaHandler(endHandler_, static_cast<int>(i), 0, false);
                }
                if (shouldFireStart && startHandler_ != 0 &&
                    i < states.size() && i < tracked_.size() &&
                    tracked_[i].anim == anim && tracked_[i].generation == gen) {
                    invokeSpineLuaHandler(startHandler_, static_cast<int>(i), 0, false);
                }
            } else if (st) {
                tracked_[i].prevTime = st->time;
            }
        }

        if (!skeleton || isDummy_) {
            return;
        }

        // 2. Advance Spine C animation timelines & world transforms.
        CCSkeletonAnimation::update(deltaTime);

        // Hold a shared_ptr on the stack so lua_Spine_removeAllSkeletonData() inside an event
        // callback can NEVER UAF the timeline map or keyframe vectors!
        std::shared_ptr<const SpineAnimEventMap> animEvents = timelines_;
        if (!animEvents && eventHandler_ != 0 && !resolvedJsonPath_.empty()) {
            animEvents = getOrLoadSpineEventTimelines(resolvedJsonPath_);
            timelines_ = animEvents;
        }

        // 3. Dispatch manually queued events safely.
        if (eventHandler_ != 0 && !queuedEvents_.empty()) {
            std::vector<QueuedEvent> pending;
            pending.swap(queuedEvents_);
            for (const auto& q : pending) {
                std::string animName;
                if (q.trackIndex >= 0 && static_cast<size_t>(q.trackIndex) < states.size()) {
                    const auto* st = states[static_cast<size_t>(q.trackIndex)];
                    if (st && st->animation && st->animation->name) {
                        animName = st->animation->name;
                    }
                }
                invokeSpineEventHandler(eventHandler_, q.trackIndex, animName.c_str(), q.keyframe);
            }
        }

        // 4. Snapshot post-update track states BEFORE firing Lua callbacks so callbacks calling
        //    setAnimation / addAnimation / clearTrack / clearTracks never cause OOB or UAF reads.
        struct TrackSnapshot {
            int trackIndex = 0;
            const cocos2d::extension::Animation* anim = nullptr;
            std::string animName;
            float duration = 0.0f;
            float prevTime = 0.0f;
            float curTime = 0.0f;
            bool loop = false;
            bool wasEnded = false;
            uint64_t generation = 0;
        };

        if (tracked_.size() < states.size()) {
            tracked_.resize(states.size());
        }
        std::vector<TrackSnapshot> snapshots;
        snapshots.reserve(states.size());
        for (size_t i = 0; i < states.size(); ++i) {
            auto* st = states[i];
            if (!st || !st->animation) continue;
            if (tracked_[i].anim != st->animation) {
                tracked_[i].anim = st->animation;
                tracked_[i].prevTime = 0.0f;
                tracked_[i].loopCount = 0;
                tracked_[i].ended = false;
                tracked_[i].generation = ++generationCounter_;
            }
            TrackSnapshot snap;
            snap.trackIndex = static_cast<int>(i);
            snap.anim = st->animation;
            snap.animName = st->animation->name ? st->animation->name : "";
            snap.duration = st->animation->duration;
            snap.prevTime = tracked_[i].prevTime;
            snap.curTime = st->time;
            snap.loop = (st->loop != 0);
            snap.wasEnded = tracked_[i].ended;
            snap.generation = tracked_[i].generation;
            snapshots.push_back(std::move(snap));
        }

        auto isSnapshotStillCurrent = [&](const TrackSnapshot& snap) -> bool {
            const size_t idx = static_cast<size_t>(snap.trackIndex);
            return skeleton != nullptr &&
                   idx < states.size() &&
                   idx < tracked_.size() &&
                   states[idx] != nullptr &&
                   states[idx]->animation == snap.anim &&
                   tracked_[idx].anim == snap.anim &&
                   tracked_[idx].generation == snap.generation;
        };

        for (const TrackSnapshot& snap : snapshots) {
            if (!isSnapshotStillCurrent(snap)) {
                continue;
            }

            if (eventHandler_ != 0 && animEvents && !snap.animName.empty() && snap.curTime > snap.prevTime) {
                auto evIt = animEvents->find(snap.animName);
                if (evIt != animEvents->end() && !evIt->second.empty()) {
                    const auto& evList = evIt->second;
                    if (snap.loop && snap.duration > 0.0f) {
                        const int prevLoop = static_cast<int>(std::floor(snap.prevTime / snap.duration));
                        const int curLoop = static_cast<int>(std::floor(snap.curTime / snap.duration));
                        const float prevMod = std::fmod(snap.prevTime, snap.duration);
                        const float curMod = std::fmod(snap.curTime, snap.duration);
                        if (curLoop == prevLoop) {
                            for (const auto& ev : evList) {
                                if (!isSnapshotStillCurrent(snap) || eventHandler_ == 0) break;
                                const bool match = (snap.prevTime == 0.0f)
                                    ? (ev.time >= 0.0f && ev.time <= curMod)
                                    : (ev.time > prevMod && ev.time <= curMod);
                                if (match) {
                                    invokeSpineEventHandler(
                                        eventHandler_, snap.trackIndex, snap.animName.c_str(), ev);
                                }
                            }
                        } else {
                            for (const auto& ev : evList) {
                                if (!isSnapshotStillCurrent(snap) || eventHandler_ == 0) break;
                                const bool match = (snap.prevTime == 0.0f)
                                    ? (ev.time >= 0.0f && ev.time <= snap.duration)
                                    : (ev.time > prevMod && ev.time <= snap.duration);
                                if (match) {
                                    invokeSpineEventHandler(
                                        eventHandler_, snap.trackIndex, snap.animName.c_str(), ev);
                                }
                            }
                            for (int full = prevLoop + 1; full < curLoop; ++full) {
                                if (!isSnapshotStillCurrent(snap) || eventHandler_ == 0) break;
                                for (const auto& ev : evList) {
                                    if (!isSnapshotStillCurrent(snap) || eventHandler_ == 0) break;
                                    invokeSpineEventHandler(
                                        eventHandler_, snap.trackIndex, snap.animName.c_str(), ev);
                                }
                            }
                            for (const auto& ev : evList) {
                                if (!isSnapshotStillCurrent(snap) || eventHandler_ == 0) break;
                                if (ev.time >= 0.0f && ev.time <= curMod) {
                                    invokeSpineEventHandler(
                                        eventHandler_, snap.trackIndex, snap.animName.c_str(), ev);
                                }
                            }
                        }
                    } else if (!snap.wasEnded) {
                        for (const auto& ev : evList) {
                            if (!isSnapshotStillCurrent(snap) || eventHandler_ == 0) break;
                            const bool match = (snap.prevTime == 0.0f)
                                ? (ev.time >= 0.0f && ev.time <= snap.curTime)
                                : (ev.time > snap.prevTime && ev.time <= snap.curTime);
                            if (match) {
                                invokeSpineEventHandler(
                                    eventHandler_, snap.trackIndex, snap.animName.c_str(), ev);
                            }
                        }
                    }
                }
            }

            if (!isSnapshotStillCurrent(snap)) {
                continue;
            }

            const size_t idx = static_cast<size_t>(snap.trackIndex);
            if (snap.duration > 0.0f) {
                if (snap.loop) {
                    const int completed = static_cast<int>(std::floor(snap.curTime / snap.duration));
                    while (isSnapshotStillCurrent(snap) && completed > tracked_[idx].loopCount) {
                        const int lc = ++tracked_[idx].loopCount;
                        if (completeHandler_ != 0) {
                            invokeSpineLuaHandler(completeHandler_, snap.trackIndex, lc, true);
                        }
                    }
                } else if (!tracked_[idx].ended && snap.curTime >= snap.duration) {
                    tracked_[idx].loopCount = 1;
                    tracked_[idx].ended = true;
                    if (completeHandler_ != 0) {
                        invokeSpineLuaHandler(completeHandler_, snap.trackIndex, 1, true);
                    }
                    if (isSnapshotStillCurrent(snap) && endHandler_ != 0) {
                        invokeSpineLuaHandler(endHandler_, snap.trackIndex, 0, false);
                    }
                }
            }

            if (isSnapshotStillCurrent(snap)) {
                tracked_[idx].prevTime = snap.curTime;
            }
        }
    }

private:
    struct TrackState {
        const cocos2d::extension::Animation* anim = nullptr;
        float prevTime = 0.0f;
        int loopCount = 0;
        bool ended = false;
        uint64_t generation = 0;
    };
    struct QueuedEvent {
        int trackIndex = 0;
        SpineEventKeyframe keyframe;
    };

    std::string resolvedJsonPath_;
    std::shared_ptr<const SpineAnimEventMap> timelines_;
    cocos2d::extension::SkeletonData* ownedSkeletonData_ = nullptr;
    cocos2d::extension::Atlas* ownedAtlas_ = nullptr;
    cocos2d::extension::Skeleton* dummySkeleton_ = nullptr;
    bool isDummy_ = false;
    uint64_t generationCounter_ = 0;
    std::vector<TrackState> tracked_;
    std::vector<QueuedEvent> queuedEvents_;
    int startHandler_ = 0;
    int endHandler_ = 0;
    int completeHandler_ = 0;
    int eventHandler_ = 0;
};

int lua_Spine_hasSkeletonData(lua_State* L) {
    const char* modelId = lua_tostring(L, 2);
    lua_pushboolean(L, (modelId && g_spineCache.count(modelId) > 0) ? 1 : 0);
    return 1;
}

int lua_Spine_setSkeletonDataToCache(lua_State* L) {
    const char* modelId = lua_tostring(L, 2);
    const char* jsonPath = lua_tostring(L, 3);
    const char* atlasPath = lua_tostring(L, 4);
    const float scale = lua_isnumber(L, 5) ? static_cast<float>(lua_tonumber(L, 5)) : 1.0f;
    if (modelId && jsonPath && atlasPath) {
        const std::string resolvedJson = resolveSpineJsonPath(jsonPath);
        const std::string resolvedAtlas = resolveSpineAtlasPath(atlasPath);
        g_spineCache[modelId] = CachedSpineEntry{
            resolvedJson.empty() ? std::string(jsonPath) : resolvedJson,
            resolvedAtlas.empty() ? std::string(atlasPath) : resolvedAtlas,
            scale
        };
    }
    return 0;
}

int lua_Spine_createFromCache(lua_State* L) {
    const char* modelId = lua_tostring(L, 2);
    if (!modelId) {
        auto* dummy = GClientSkeletonAnimation::createDummy("createFromCache(nil)", nullptr, nullptr);
        pushCCObject(L, dummy, "SpineLuaAnimation");
        return 1;
    }
    auto it = g_spineCache.find(modelId);
    if (it == g_spineCache.end()) {
        auto* dummy = GClientSkeletonAnimation::createDummy("modelId not in g_spineCache", modelId, nullptr);
        pushCCObject(L, dummy, "SpineLuaAnimation");
        return 1;
    }
    auto* anim = GClientSkeletonAnimation::createWithFile(
        it->second.jsonPath.c_str(), it->second.atlasPath.c_str(), it->second.scale);
    pushCCObject(L, anim, "SpineLuaAnimation");
    return 1;
}

int lua_Spine_createWithFile(lua_State* L) {
    const char* jsonPath = lua_tostring(L, 2);
    const char* atlasPath = lua_tostring(L, 3);
    const float scale = lua_isnumber(L, 4) ? static_cast<float>(lua_tonumber(L, 4)) : 1.0f;
    auto* anim = GClientSkeletonAnimation::createWithFile(jsonPath, atlasPath, scale);
    pushCCObject(L, anim, "SpineLuaAnimation");
    return 1;
}

int lua_Spine_removeSkeletonData(lua_State* L) {
    const char* modelId = lua_tostring(L, 2);
    if (modelId) {
        g_spineCache.erase(modelId);
    }
    return 0;
}

int lua_Spine_removeAllSkeletonData(lua_State* /*L*/) {
    g_spineCache.clear();
    g_spineEventTimelinesCache.clear();
    return 0;
}

int lua_Spine_getAnimationCount(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const int count = (self && self->skeleton && self->skeleton->data)
        ? self->skeleton->data->animationCount
        : 0;
    lua_pushinteger(L, count);
    return 1;
}

int lua_Spine_getAnimationName(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const int idx = static_cast<int>(lua_tointeger(L, 2));
    if (self && self->skeleton && self->skeleton->data &&
        self->skeleton->data->animations &&
        idx >= 0 && idx < self->skeleton->data->animationCount &&
        self->skeleton->data->animations[idx]) {
        lua_pushstring(L, self->skeleton->data->animations[idx]->name
            ? self->skeleton->data->animations[idx]->name
            : "");
    } else {
        lua_pushstring(L, "");
    }
    return 1;
}

int lua_Spine_setAnimation(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const int track = static_cast<int>(lua_tointeger(L, 2));
    const char* name = lua_tostring(L, 3);
    const bool loop = lua_toboolean(L, 4) != 0;
    if (self && name && self->skeleton && self->skeleton->data &&
        cocos2d::extension::SkeletonData_findAnimation(self->skeleton->data, name)) {
        const std::string animName(name);
        const int stateIdx = (track >= 0) ? track : 0;
        while (static_cast<int>(self->states.size()) <= stateIdx) {
            self->addAnimationState();
        }
        self->setAnimation(animName.c_str(), loop, stateIdx);
        if (auto* gc = dynamic_cast<GClientSkeletonAnimation*>(self)) {
            gc->resetTrackTracking(stateIdx);
        }
        lua_newtable(L);
        lua_pushlstring(L, animName.data(), animName.size());
        lua_setfield(L, -2, "animationName");
        lua_pushinteger(L, stateIdx);
        lua_setfield(L, -2, "trackIndex");
        lua_pushboolean(L, loop ? 1 : 0);
        lua_setfield(L, -2, "loop");
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int lua_Spine_addAnimation(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const int track = static_cast<int>(lua_tointeger(L, 2));
    const char* name = lua_tostring(L, 3);
    const bool loop = lua_toboolean(L, 4) != 0;
    const float delay = lua_isnumber(L, 5) ? static_cast<float>(lua_tonumber(L, 5)) : 0.0f;
    if (self && name && self->skeleton && self->skeleton->data &&
        cocos2d::extension::SkeletonData_findAnimation(self->skeleton->data, name)) {
        const std::string animName(name);
        const int stateIdx = (track >= 0) ? track : 0;
        while (static_cast<int>(self->states.size()) <= stateIdx) {
            self->addAnimationState();
        }
        self->addAnimation(animName.c_str(), loop, delay, stateIdx);
        lua_newtable(L);
        lua_pushlstring(L, animName.data(), animName.size());
        lua_setfield(L, -2, "animationName");
        lua_pushinteger(L, stateIdx);
        lua_setfield(L, -2, "trackIndex");
        lua_pushboolean(L, loop ? 1 : 0);
        lua_setfield(L, -2, "loop");
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int lua_Spine_setMix(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const char* from = lua_tostring(L, 2);
    const char* to = lua_tostring(L, 3);
    const float dur = static_cast<float>(lua_tonumber(L, 4));
    const int stateIdx = lua_isnumber(L, 5) ? (std::max)(0, static_cast<int>(lua_tointeger(L, 5))) : 0;
    if (self && self->skeleton && self->skeleton->data && from && to) {
        while (static_cast<int>(self->states.size()) <= stateIdx) {
            self->addAnimationState();
        }
        self->setMix(from, to, dur, stateIdx);
    }
    return 0;
}

int lua_Spine_clearTrack(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const int trackIdx = lua_isnumber(L, 2) ? static_cast<int>(lua_tointeger(L, 2)) : 0;
    if (self && self->skeleton && trackIdx >= 0 && trackIdx < static_cast<int>(self->states.size())) {
        self->clearAnimation(trackIdx);
        if (auto* gc = dynamic_cast<GClientSkeletonAnimation*>(self)) {
            gc->resetTrackTracking(trackIdx);
        }
    }
    return 0;
}

int lua_Spine_clearTracks(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self && self->skeleton) {
        auto* gc = dynamic_cast<GClientSkeletonAnimation*>(self);
        const int count = static_cast<int>(self->states.size());
        for (int i = 0; i < count; ++i) {
            self->clearAnimation(i);
            if (gc) {
                gc->resetTrackTracking(i);
            }
        }
    }
    return 0;
}

int lua_Spine_setToSetupPose(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self && self->skeleton) {
        self->setToSetupPose();
    }
    return 0;
}

int lua_Spine_setBonesToSetupPose(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self && self->skeleton) {
        self->setBonesToSetupPose();
    }
    return 0;
}

int lua_Spine_setSlotsToSetupPose(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self && self->skeleton) {
        self->setSlotsToSetupPose();
    }
    return 0;
}

int lua_Spine_updateWorldTransform(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self && self->skeleton) {
        self->updateWorldTransform();
    }
    return 0;
}

int lua_Spine_setTimeScale(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self) {
        self->timeScale = static_cast<float>(lua_tonumber(L, 2));
    }
    return 0;
}

int lua_Spine_getCurrent(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const int trackIdx = lua_isnumber(L, 2) ? (std::max)(0, static_cast<int>(lua_tointeger(L, 2))) : 0;
    if (self && self->skeleton && trackIdx < static_cast<int>(self->states.size()) &&
        self->states[trackIdx] && self->states[trackIdx]->animation) {
        const auto* st = self->states[trackIdx];
        lua_newtable(L);
        lua_pushstring(L, st->animation->name ? st->animation->name : "");
        lua_setfield(L, -2, "animationName");
        lua_pushinteger(L, trackIdx);
        lua_setfield(L, -2, "trackIndex");
        lua_pushboolean(L, st->loop ? 1 : 0);
        lua_setfield(L, -2, "loop");
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int lua_Spine_pause(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self) self->pauseSchedulerAndActions();
    return 0;
}

int lua_Spine_resume(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    if (self) self->resumeSchedulerAndActions();
    return 0;
}

int lua_Spine_setSkin(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const char* skinName = lua_tostring(L, 2);
    const bool ok = (self && self->skeleton && skinName) ? (self->setSkin(skinName) != 0) : false;
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

int lua_Spine_findBone(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const char* boneName = lua_tostring(L, 2);
    if (self && self->skeleton && boneName && boneName[0] != '\0') {
        if (cocos2d::extension::Bone* bone = self->findBone(boneName)) {
            lua_newtable(L);
            lua_pushnumber(L, static_cast<lua_Number>(bone->x));
            lua_setfield(L, -2, "x");
            lua_pushnumber(L, static_cast<lua_Number>(bone->y));
            lua_setfield(L, -2, "y");
            lua_pushnumber(L, static_cast<lua_Number>(bone->worldX));
            lua_setfield(L, -2, "worldX");
            lua_pushnumber(L, static_cast<lua_Number>(bone->worldY));
            lua_setfield(L, -2, "worldY");
            lua_pushnumber(L, static_cast<lua_Number>(bone->rotation));
            lua_setfield(L, -2, "rotation");
            lua_pushnumber(L, static_cast<lua_Number>(bone->scaleX));
            lua_setfield(L, -2, "scaleX");
            lua_pushnumber(L, static_cast<lua_Number>(bone->scaleY));
            lua_setfield(L, -2, "scaleY");
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

int lua_Spine_setAttachment(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const char* slotName = lua_tostring(L, 2);
    const char* attName = lua_isstring(L, 3) ? lua_tostring(L, 3) : nullptr;
    const bool ok = (self && self->skeleton && slotName)
        ? (self->setAttachment(slotName, attName) != 0)
        : false;
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

int lua_Spine_boundingBox(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const cocos2d::CCRect box = computeSpineBoundingBoxInParent(self);
    tolua_pushusertype_and_takeownership(L, new cocos2d::CCRect(box), "CCRect");
    return 1;
}

int lua_Spine_triggerEvent(lua_State* L) {
    if (auto* self = getSafeCCObject<GClientSkeletonAnimation>(L, 1)) {
        const int trackIdx = lua_isnumber(L, 2) ? static_cast<int>(lua_tointeger(L, 2)) : 0;
        const char* eventName = lua_tostring(L, 3);
        const int intVal = lua_isnumber(L, 4) ? static_cast<int>(lua_tointeger(L, 4)) : 0;
        const float floatVal = lua_isnumber(L, 5) ? static_cast<float>(lua_tonumber(L, 5)) : 0.0f;
        const char* strVal = lua_tostring(L, 6);
        if (eventName && eventName[0] != '\0') {
            self->queueEvent(trackIdx, eventName, intVal, floatVal, strVal ? strVal : "");
        }
    }
    return 0;
}

int extractSpineLuaHandler(lua_State* L) {
    const int fnIdx = lua_isfunction(L, 3) ? 3 : (lua_isfunction(L, 2) ? 2 : 0);
    if (fnIdx == 0) return 0;
    return toluafix_ref_function(L, fnIdx, 0);
}

int lua_Spine_setStartListener(lua_State* L) {
    if (auto* self = getSafeCCObject<GClientSkeletonAnimation>(L, 1)) {
        self->setStartHandler(extractSpineLuaHandler(L));
    }
    return 0;
}

int lua_Spine_setEndListener(lua_State* L) {
    if (auto* self = getSafeCCObject<GClientSkeletonAnimation>(L, 1)) {
        self->setEndHandler(extractSpineLuaHandler(L));
    }
    return 0;
}

int lua_Spine_setCompleteListener(lua_State* L) {
    if (auto* self = getSafeCCObject<GClientSkeletonAnimation>(L, 1)) {
        self->setCompleteHandler(extractSpineLuaHandler(L));
    }
    return 0;
}

int lua_Spine_update(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::extension::CCSkeletonAnimation>(L, 1);
    const float dt = lua_isnumber(L, 2) ? static_cast<float>(lua_tonumber(L, 2)) : 0.0f;
    if (self) {
        self->update(dt);
    }
    return 0;
}

int lua_Spine_setEventListener(lua_State* L) {
    if (auto* self = getSafeCCObject<GClientSkeletonAnimation>(L, 1)) {
        self->setEventHandler(extractSpineLuaHandler(L));
    }
    return 0;
}

int lua_CCDrawNode_create(lua_State* L) {
    auto* node = cocos2d::CCDrawNode::create();
    pushCCObject(L, node, "CCDrawNode");
    return 1;
}

int lua_CCDrawNode_drawSegment(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::CCDrawNode>(L, 1);
    cocos2d::CCPoint from = cocos2d::CCPointZero;
    cocos2d::CCPoint to = cocos2d::CCPointZero;
    if (!self || !readLuaPoint(L, 2, from) || !readLuaPoint(L, 3, to)) {
        return 0;
    }
    const float radius = lua_isnumber(L, 4) ? static_cast<float>(lua_tonumber(L, 4)) : 1.0f;
    cocos2d::ccColor4F color = cocos2d::ccc4f(1.0f, 1.0f, 1.0f, 1.0f);
    if (auto* c = static_cast<cocos2d::ccColor4F*>(tolua_tousertype(L, 5, nullptr))) {
        color = *c;
    }
    self->drawSegment(from, to, radius, color);
    return 0;
}

int lua_CCDrawNode_drawDot(lua_State* L) {
    auto* self = getSafeCCObject<cocos2d::CCDrawNode>(L, 1);
    cocos2d::CCPoint pos = cocos2d::CCPointZero;
    if (!self || !readLuaPoint(L, 2, pos)) {
        return 0;
    }
    const float radius = lua_isnumber(L, 3) ? static_cast<float>(lua_tonumber(L, 3)) : 1.0f;
    cocos2d::ccColor4F color = cocos2d::ccc4f(1.0f, 1.0f, 1.0f, 1.0f);
    if (auto* c = static_cast<cocos2d::ccColor4F*>(tolua_tousertype(L, 4, nullptr))) {
        color = *c;
    }
    self->drawDot(pos, radius, color);
    return 0;
}

int lua_CCDrawNode_clear(lua_State* L) {
    if (auto* self = getSafeCCObject<cocos2d::CCDrawNode>(L, 1)) {
        self->clear();
    }
    return 0;
}

void registerDrawNodeBindings(lua_State* L) {
    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);
    tolua_usertype(L, "CCDrawNode");
    tolua_cclass(L, "CCDrawNode", "CCDrawNode", "CCNode", nullptr);
    tolua_beginmodule(L, "CCDrawNode");
    tolua_function(L, "create", lua_CCDrawNode_create);
    tolua_function(L, "drawSegment", lua_CCDrawNode_drawSegment);
    tolua_function(L, "drawDot", lua_CCDrawNode_drawDot);
    tolua_function(L, "clear", lua_CCDrawNode_clear);
    tolua_endmodule(L);
    tolua_endmodule(L);
}

void registerSpineBindings(lua_State* L) {
    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);
    tolua_usertype(L, "SpineLuaAnimation");
    tolua_cclass(L, "SpineLuaAnimation", "SpineLuaAnimation", "CCNodeRGBA", nullptr);
    tolua_beginmodule(L, "SpineLuaAnimation");
    tolua_function(L, "hasSkeletonData", lua_Spine_hasSkeletonData);
    tolua_function(L, "setSkeletonDataToCache", lua_Spine_setSkeletonDataToCache);
    tolua_function(L, "createFromCache", lua_Spine_createFromCache);
    tolua_function(L, "createWithFile", lua_Spine_createWithFile);
    tolua_function(L, "removeSkeletonData", lua_Spine_removeSkeletonData);
    tolua_function(L, "removeAllSkeletonData", lua_Spine_removeAllSkeletonData);
    tolua_function(L, "getAnimationCount", lua_Spine_getAnimationCount);
    tolua_function(L, "getAnimationName", lua_Spine_getAnimationName);
    tolua_function(L, "setAnimation", lua_Spine_setAnimation);
    tolua_function(L, "addAnimation", lua_Spine_addAnimation);
    tolua_function(L, "setMix", lua_Spine_setMix);
    tolua_function(L, "clearTrack", lua_Spine_clearTrack);
    tolua_function(L, "clearTracks", lua_Spine_clearTracks);
    tolua_function(L, "setToSetupPose", lua_Spine_setToSetupPose);
    tolua_function(L, "setBonesToSetupPose", lua_Spine_setBonesToSetupPose);
    tolua_function(L, "setSlotsToSetupPose", lua_Spine_setSlotsToSetupPose);
    tolua_function(L, "updateWorldTransform", lua_Spine_updateWorldTransform);
    tolua_function(L, "setTimeScale", lua_Spine_setTimeScale);
    tolua_function(L, "getCurrent", lua_Spine_getCurrent);
    tolua_function(L, "pause", lua_Spine_pause);
    tolua_function(L, "resume", lua_Spine_resume);
    tolua_function(L, "setSkin", lua_Spine_setSkin);
    tolua_function(L, "findBone", lua_Spine_findBone);
    tolua_function(L, "setAttachment", lua_Spine_setAttachment);
    tolua_function(L, "boundingBox", lua_Spine_boundingBox);
    tolua_function(L, "getBoundingBox", lua_Spine_boundingBox);
    tolua_function(L, "update", lua_Spine_update);
    tolua_function(L, "triggerEvent", lua_Spine_triggerEvent);
    tolua_function(L, "setLuaStartListener", lua_Spine_setStartListener);
    tolua_function(L, "setLuaEndListener", lua_Spine_setEndListener);
    tolua_function(L, "setLuaCompleteListener", lua_Spine_setCompleteListener);
    tolua_function(L, "setLuaEventListener", lua_Spine_setEventListener);
    tolua_function(L, "setStartListener", lua_Spine_setStartListener);
    tolua_function(L, "setEndListener", lua_Spine_setEndListener);
    tolua_function(L, "setCompleteListener", lua_Spine_setCompleteListener);
    tolua_function(L, "setEventListener", lua_Spine_setEventListener);
    tolua_endmodule(L);
    tolua_endmodule(L);

    lua_newtable(L);
    lua_getglobal(L, "SpineLuaAnimation");
    lua_pushvalue(L, -1);
    lua_setfield(L, -3, "SpineLuaAnimation");
    lua_setfield(L, -2, "SkeletonAnimation");
    lua_setglobal(L, "spine");
}

void wrapMetatableMethod(lua_State* L, const char* typeName, const char* methodName, lua_CFunction wrapper) {
    luaL_getmetatable(L, typeName);
    if (lua_istable(L, -1)) {
        lua_pushstring(L, methodName);
        lua_rawget(L, -2); // push original (or nil) as upvalue 1 without invoking __index
        lua_pushstring(L, methodName);
        lua_pushvalue(L, -2); // dup original
        lua_remove(L, -3);    // stack: mt, key, original
        lua_pushcclosure(L, wrapper, 1);
        lua_rawset(L, -3);
    }
    lua_pop(L, 1);
}

void wrapScrollContainerHooks(lua_State* L, const char* typeName) {
    wrapMetatableMethod(L, typeName, "addChild", &hook_Widget_addChild);
    wrapMetatableMethod(L, typeName, "addNode", &hook_Widget_addNode);
    wrapMetatableMethod(L, typeName, "getBackGroundImage", &hook_Layout_getBackGroundImage);
    wrapMetatableMethod(L, typeName, "isBackGroundImageScale9Enabled", &hook_Layout_isBackGroundImageScale9Enabled);
    wrapMetatableMethod(L, typeName, "setTouchMovedEnabled", &hook_ScrollView_setTouchMovedEnabled);
    wrapMetatableMethod(L, typeName, "isTouchMovedEnabled", &hook_ScrollView_isTouchMovedEnabled);
    wrapMetatableMethod(L, typeName, "setTouchEndSmoothMove", &hook_ScrollView_setTouchEndSmoothMove);
    wrapMetatableMethod(L, typeName, "getScrollToPercentVertical", &hook_ScrollView_getScrollToPercentVertical);
    wrapMetatableMethod(L, typeName, "getScrollToPercentHorizontal", &hook_ScrollView_getScrollToPercentHorizontal);
    wrapMetatableMethod(L, typeName, "addTouchEventListenerScrollView", &hook_ScrollView_addTouchEventListenerScrollView);
    wrapMetatableMethod(L, typeName, "getScrollViewTouchStartPos", &hook_ScrollView_getScrollViewTouchStartPos);
    wrapMetatableMethod(L, typeName, "getScrollViewTouchMovePos", &hook_ScrollView_getScrollViewTouchMovePos);
    wrapMetatableMethod(L, typeName, "getScrollViewTouchEndPos", &hook_ScrollView_getScrollViewTouchEndPos);
}

} // namespace

void UnscheduleAllLuaScriptEntries() {
    std::vector<int> entries;
    {
        std::lock_guard<std::mutex> lock(g_luaScriptEntriesMutex);
        entries.assign(g_activeLuaScriptEntries.begin(), g_activeLuaScriptEntries.end());
        g_activeLuaScriptEntries.clear();
    }
    if (entries.empty()) {
        return;
    }
    if (auto* director = cocos2d::CCDirector::sharedDirector()) {
        if (auto* scheduler = director->getScheduler()) {
            for (int entryId : entries) {
                scheduler->unscheduleScriptEntry(entryId);
            }
        }
    }
}

void RescheduleLuaHelpersCallbacks() {
    const std::vector<DeferredArmatureAsyncCallback*> snapshot = g_pendingArmatureCallbacks;
    for (DeferredArmatureAsyncCallback* cb : snapshot) {
        if (cb) {
            cb->ensureOnScheduler();
        }
    }
}

void RegisterRichTextBindings(lua_State* L) {
    registerRichTextBindingsInternal(L);
}

void RegisterAssetLoaderHooks(lua_State* L) {
    if (!L) return;

    wrapMetatableMethod(L, "CCFileUtils", "isFileExist", &hook_CCFileUtils_isFileExist);
    wrapMetatableMethod(L, "CCScheduler", "scheduleScriptFunc", &hook_CCScheduler_scheduleScriptFunc);
    wrapMetatableMethod(L, "CCScheduler", "unscheduleScriptEntry", &hook_CCScheduler_unscheduleScriptEntry);

    wrapMetatableMethod(L, "CCSpriteFrameCache", "addSpriteFramesWithFile", &hook_addSpriteFramesWithFile);
    wrapMetatableMethod(L, "CCSpriteFrameCache", "addSpriteFramesWithBinary", &hook_addSpriteFramesWithFile);
    wrapMetatableMethod(L, "GUIReader", "widgetFromJsonFile", &hook_widgetFromJsonFile);
    wrapMetatableMethod(L, "GUIReader", "widgetFromPbFile", &hook_widgetFromJsonFile);
    wrapMetatableMethod(L, "SceneReader", "createNodeWithSceneFile", &hook_createNodeWithSceneFile);

    wrapMetatableMethod(L, "CCArmatureDataManager", "addArmatureFileInfo", &hook_addArmatureFileInfo);
    wrapMetatableMethod(L, "CCArmatureDataManager", "addArmatureFileInfoAsync", &hook_addArmatureFileInfoAsync);
    wrapMetatableMethod(L, "CCArmatureAnimation", "setMovementLoopByName", &hook_CCArmatureAnimation_setMovementLoopByName);

    wrapMetatableMethod(L, "CCNode", "addChild", &hook_CCNode_addChild);
    wrapMetatableMethod(L, "CCNode", "runAction", &hook_CCNode_runAction);
    wrapMetatableMethod(L, "CCNode", "setShaderWithVertexShaderByteArray", &hook_setShaderWithVertexShaderByteArray);
    wrapMetatableMethod(L, "CCDirector", "getCurrentTime", &hook_CCDirector_getCurrentTime);

    wrapMetatableMethod(L, "Widget", "addChild", &hook_Widget_addChild);
    wrapMetatableMethod(L, "Widget", "addNode", &hook_Widget_addNode);
    wrapMetatableMethod(L, "Widget", "clippingParentAreaContainPoint", &hook_Widget_clippingParentAreaContainPoint);

    wrapMetatableMethod(L, "ImageView", "isScale9Enabled", &hook_ImageView_isScale9Enabled);
    wrapMetatableMethod(L, "ImageView", "getScale9Image", &hook_ImageView_getScale9Image);
    wrapMetatableMethod(L, "ImageView", "getTexture", &hook_ImageView_getTexture);
    wrapMetatableMethod(L, "ImageView", "getCapInsets", &hook_ImageView_getCapInsets);

    wrapMetatableMethod(L, "Button", "isScale9Enabled", &hook_Button_isScale9Enabled);
    wrapMetatableMethod(L, "Button", "getScale9Image", &hook_Button_getScale9Image);
    wrapMetatableMethod(L, "Button", "enableTitleStroke", &hook_Button_enableTitleStroke);
    wrapMetatableMethod(L, "Button", "disableTitleStroke", &hook_Button_disableTitleStroke);
    wrapMetatableMethod(L, "Button", "setTitleOffsetPosition", &hook_Button_setTitleOffsetPosition);
    wrapMetatableMethod(L, "Button", "setTitleOffsetY", &hook_Button_setTitleOffsetY);

    wrapMetatableMethod(L, "Slider", "isScale9Enabled", &hook_Slider_isScale9Enabled);

    wrapMetatableMethod(L, "Label", "enableStroke", &hook_Label_enableStroke);
    wrapMetatableMethod(L, "Label", "disableStroke", &hook_Label_disableStroke);
    wrapMetatableMethod(L, "Label", "enableShadow", &hook_Label_enableShadow);
    wrapMetatableMethod(L, "Label", "getTextHeight", &hook_Label_getTextHeight);
    wrapMetatableMethod(L, "Widget", "getTextHeight", &hook_Label_getTextHeight);
    wrapMetatableMethod(L, "CCNode", "getTextHeight", &hook_Label_getTextHeight);

    wrapMetatableMethod(L, "LabelAtlas", "setItemGap", &hook_LabelAtlas_setItemGap);
    wrapMetatableMethod(L, "LabelAtlas", "getItemGap", &hook_LabelAtlas_getItemGap);

    wrapMetatableMethod(L, "CCLabelTTF", "enableStroke", &hook_CCLabelTTF_enableStroke);
    wrapMetatableMethod(L, "CCLabelTTF", "disableStroke", &hook_CCLabelTTF_disableStroke);
    wrapMetatableMethod(L, "CCLabelTTF", "enableShadow", &hook_CCLabelTTF_enableShadow);
    wrapMetatableMethod(L, "CCLabelTTF", "getTextHeight", &hook_Label_getTextHeight);

    wrapMetatableMethod(L, "LoadingBar", "isScale9Enabled", &hook_LoadingBar_isScale9Enabled);
    wrapMetatableMethod(L, "LoadingBar", "getScale9Image", &hook_LoadingBar_getScale9Image);
    wrapMetatableMethod(L, "LoadingBar", "getTexture", &hook_LoadingBar_getTexture);
    wrapMetatableMethod(L, "LoadingBar", "getCapInsets", &hook_LoadingBar_getCapInsets);

    wrapMetatableMethod(L, "CCScale9Sprite", "getScale9Image", &hook_CCScale9Sprite_getScale9Image);
    wrapMetatableMethod(L, "CCScale9Sprite", "create", &hook_CCScale9Sprite_create);
    wrapMetatableMethod(L, "CCScale9Sprite", "createWithSpriteFrameName", &hook_CCScale9Sprite_createWithSpriteFrameName);
    wrapMetatableMethod(L, "CCScale9Sprite", "createWithSpriteFrame", &hook_CCScale9Sprite_createWithSpriteFrame);

    wrapMetatableMethod(L, "CCSprite", "create", &hook_CCSprite_create);
    wrapMetatableMethod(L, "CCSprite", "createWithSpriteFrameName", &hook_CCSprite_createWithSpriteFrameName);
    wrapMetatableMethod(L, "CCSprite", "createWithSpriteFrame", &hook_CCSprite_createWithSpriteFrame);

    wrapMetatableMethod(L, "Layout", "addChild", &hook_Widget_addChild);
    wrapMetatableMethod(L, "Layout", "addNode", &hook_Widget_addNode);
    wrapMetatableMethod(L, "Layout", "getBackGroundImage", &hook_Layout_getBackGroundImage);
    wrapMetatableMethod(L, "Layout", "isBackGroundImageScale9Enabled", &hook_Layout_isBackGroundImageScale9Enabled);
    wrapScrollContainerHooks(L, "ScrollView");
    wrapScrollContainerHooks(L, "ListView");
    wrapScrollContainerHooks(L, "PageView");

    registerRichTextBindingsInternal(L);
    wrapMetatableMethod(L, "RichText", "getTextHeight", &hook_Label_getTextHeight);
    registerDrawNodeBindings(L);
    registerSpineBindings(L);
}
