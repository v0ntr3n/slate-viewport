#include "tolua_Platform.h"
#include "BtPlatformWin32.h"
#include "../diagnostics/CrashAndTelemetry.h"

#if defined(GCLIENT_USE_COCOS2DX)
#include "CCLuaEngine.h"
#endif

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

namespace {

// ---------------------------------------------------------------------------
// Lua callback bridge (main-thread dispatch from bt::Platform::tickLoop)
// ---------------------------------------------------------------------------
struct LuaCallbackRegistry {
    lua_State* fallbackState = nullptr;
    int primaryHandlerRef = LUA_NOREF;
    int syncHandlerRef = LUA_NOREF;
};

LuaCallbackRegistry& getLuaCallbacks() {
    static LuaCallbackRegistry reg;
    return reg;
}

// Resolves the live main lua_State* via CCLuaEngine::defaultEngine() so callbacks never
// dereference a dead/GC'd coroutine lua_State* (such as MainLoading's startup coroutine).
// Falls back to fallbackState only in standalone unit tests where CCLuaEngine is uninitialized.
lua_State* resolveLiveMainLuaState(lua_State* fallbackState) {
#if defined(GCLIENT_USE_COCOS2DX)
    if (auto* engine = cocos2d::CCLuaEngine::defaultEngine()) {
        if (auto* stack = engine->getLuaStack()) {
            if (lua_State* mainL = stack->getLuaState()) {
                return mainL;
            }
        }
    }
#endif
    return fallbackState;
}

void invokeLuaHandler(lua_State* L, int funcRef, int eventId, int statusCode, const std::string& payload) {
    (void)statusCode;
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "tolua_Platform",
        "invokeLuaHandler event=%d funcRef=%d payload=%s",
        eventId,
        funcRef,
        payload.c_str());
    if (!L || funcRef == LUA_NOREF || funcRef == LUA_REFNIL) {
        return;
    }
    lua_getglobal(L, "debug");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "traceback");
        lua_remove(L, -2);
    } else {
        lua_pop(L, 1);
        lua_pushnil(L);
    }
    const int errfuncIdx = lua_isfunction(L, -1) ? lua_gettop(L) : 0;
    if (errfuncIdx == 0) {
        lua_pop(L, 1);
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, funcRef);
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, errfuncIdx ? 2 : 1);
        return;
    }
    lua_pushinteger(L, eventId);
    lua_pushlstring(L, payload.data(), payload.size());
    if (lua_pcall(L, 2, 0, errfuncIdx) != 0) {
        const char* err = lua_tostring(L, -1);
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Error,
            "tolua_Platform",
            "Lua callback error (event=%d): %s",
            eventId,
            err ? err : "<unknown>");
        gclient::diagnostics::CrashAndTelemetry::flushLogs();
        lua_pop(L, 1);
    }
    if (errfuncIdx != 0) {
        lua_remove(L, errfuncIdx);
    }
}

void invokeInlineLuaCallbackJson(lua_State* L, int fnIdx, const char* jsonStr) {
    if (!L || !lua_isfunction(L, fnIdx)) {
        return;
    }
    const char* safeJson = jsonStr ? jsonStr : "{}";
    lua_getglobal(L, "debug");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "traceback");
        lua_remove(L, -2);
    } else {
        lua_pop(L, 1);
        lua_pushnil(L);
    }
    const int errfuncIdx = lua_isfunction(L, -1) ? lua_gettop(L) : 0;
    if (errfuncIdx == 0) {
        lua_pop(L, 1);
    }
    lua_pushvalue(L, fnIdx);
    lua_pushstring(L, safeJson);
    if (lua_pcall(L, 1, 0, errfuncIdx) != 0) {
        const char* err = lua_tostring(L, -1);
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Error,
            "tolua_Platform",
            "Inline Lua callback error: %s",
            err ? err : "<unknown>");
        gclient::diagnostics::CrashAndTelemetry::flushLogs();
        lua_pop(L, 1);
    }
    if (errfuncIdx != 0) {
        lua_remove(L, errfuncIdx);
    }
}

// Helper: supports both `Platform:method(a, b)` (colon syntax, self at index 1)
// and `Platform.method(a, b)` (dot syntax).
int firstArgIndex(lua_State* L) {
    if (lua_gettop(L) >= 1 && (lua_istable(L, 1) || lua_isuserdata(L, 1))) {
        return 2;
    }
    return 1;
}

std::string optStringArg(lua_State* L, int idx, const char* fallback = "") {
    if (idx <= lua_gettop(L) && lua_isstring(L, idx)) {
        size_t len = 0;
        const char* s = lua_tolstring(L, idx, &len);
        return s ? std::string(s, len) : std::string(fallback);
    }
    return std::string(fallback);
}

int optIntArg(lua_State* L, int idx, int fallback = 0) {
    if (idx <= lua_gettop(L) && lua_isnumber(L, idx)) {
        return static_cast<int>(lua_tointeger(L, idx));
    }
    return fallback;
}

bool optBoolArg(lua_State* L, int idx, bool fallback = false) {
    if (idx <= lua_gettop(L)) {
        if (lua_isboolean(L, idx)) return lua_toboolean(L, idx) != 0;
        if (lua_isnumber(L, idx)) return lua_tonumber(L, idx) != 0.0;
    }
    return fallback;
}

float optFloatArg(lua_State* L, int idx, float fallback = 1.0f) {
    if (idx <= lua_gettop(L) && lua_isnumber(L, idx)) {
        return static_cast<float>(lua_tonumber(L, idx));
    }
    return fallback;
}

int readTableIntAt(lua_State* L, int tblIdx, int arrayIndex, int fallback = 0) {
    if (tblIdx <= 0 || tblIdx > lua_gettop(L) || !lua_istable(L, tblIdx)) {
        return fallback;
    }
    lua_rawgeti(L, tblIdx, arrayIndex);
    int val = fallback;
    if (lua_isnumber(L, -1)) {
        val = static_cast<int>(lua_tointeger(L, -1));
    }
    lua_pop(L, 1);
    return val;
}

std::string readTableStringAt(lua_State* L, int tblIdx, int arrayIndex, const char* fieldFallback = nullptr) {
    if (tblIdx <= 0 || tblIdx > lua_gettop(L) || !lua_istable(L, tblIdx)) {
        return {};
    }
    lua_rawgeti(L, tblIdx, arrayIndex);
    if (lua_isstring(L, -1)) {
        size_t len = 0;
        const char* s = lua_tolstring(L, -1, &len);
        std::string out = s ? std::string(s, len) : std::string();
        lua_pop(L, 1);
        return out;
    }
    lua_pop(L, 1);
    if (fieldFallback) {
        lua_getfield(L, tblIdx, fieldFallback);
        if (lua_isstring(L, -1)) {
            size_t len = 0;
            const char* s = lua_tolstring(L, -1, &len);
            std::string out = s ? std::string(s, len) : std::string();
            lua_pop(L, 1);
            return out;
        }
        lua_pop(L, 1);
    }
    return {};
}

bool isNumericBridgeMethod(const std::string& methodName) {
    return methodName == "getBatteryLevel" ||
           methodName == "getAvailMemory" ||
           methodName == "getTotalMemory" ||
           methodName == "getFreeDiskSpace" ||
           methodName == "getNetworkType" ||
           methodName == "getNetworkStatus" ||
           methodName == "getVersionCode" ||
           methodName == "getSignalStrength";
}

// ---------------------------------------------------------------------------
// Android (CCLuaJavaBridge / luaj) & iOS (CCLuaObjcBridge / luaoc) bridges
// ---------------------------------------------------------------------------
int lua_MobileBridge_callStaticMethod(lua_State* L) {
    const int top = lua_gettop(L);
    const int base = firstArgIndex(L);
    const std::string className = optStringArg(L, base, "");
    const std::string methodName = optStringArg(L, base + 1, "");

    int argsIdx = 0;
    std::string sig;
    if (base + 2 <= top) {
        if (lua_istable(L, base + 2)) {
            argsIdx = base + 2;
            sig = optStringArg(L, base + 3, "");
        } else if (lua_isstring(L, base + 2) && base + 3 > top) {
            sig = optStringArg(L, base + 2, "");
        } else {
            sig = optStringArg(L, base + 3, "");
        }
    }

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "LuaBridge",
        "callStaticMethod class='%s' method='%s' sig='%s'",
        className.c_str(),
        methodName.c_str(),
        sig.c_str());

    // Route org/go3k/utilities/ZYWebView (and iOS ZYWebView) to native Win32 bridge
    if (className.find("ZYWebView") != std::string::npos) {
        if (methodName == "displayWebView" || methodName == "showWebView") {
            const int x = readTableIntAt(L, argsIdx, 1, 0);
            const int y = readTableIntAt(L, argsIdx, 2, 0);
            const int w = readTableIntAt(L, argsIdx, 3, 0);
            const int h = readTableIntAt(L, argsIdx, 4, 0);
            bt::Platform::getInstance()->dispatchWebViewBridge("displayWebView", x, y, w, h, "");
        } else if (methodName == "updateURL" || methodName == "openURL" || methodName == "loadUrl") {
            const std::string url = readTableStringAt(L, argsIdx, 1, "url");
            bt::Platform::getInstance()->dispatchWebViewBridge("updateURL", 0, 0, 0, 0, url);
        } else if (methodName == "removeWebView" || methodName == "closeWebView" || methodName == "hideWebView") {
            bt::Platform::getInstance()->dispatchWebViewBridge("removeWebView", 0, 0, 0, 0, "");
        }
    }

    lua_pushboolean(L, 1);

    // Match JNI return type descriptor after ')' when present
    const size_t closeParen = sig.find(')');
    if (closeParen != std::string::npos && closeParen + 1 < sig.size()) {
        const char retType = sig[closeParen + 1];
        switch (retType) {
            case 'I':
            case 'J':
            case 'S':
            case 'B':
                lua_pushinteger(L, 0);
                return 2;
            case 'F':
            case 'D':
                lua_pushnumber(L, 0.0);
                return 2;
            case 'Z':
                lua_pushboolean(L, 0);
                return 2;
            default:
                lua_pushstring(L, "");
                return 2;
        }
    }

    if (isNumericBridgeMethod(methodName)) {
        lua_pushinteger(L, 0);
        return 2;
    }

    lua_pushstring(L, "");
    return 2;
}

int lua_MobileBridge_retainLuaFunction(lua_State* L) {
    const int base = firstArgIndex(L);
    if (base <= lua_gettop(L) && lua_isfunction(L, base)) {
        lua_pushvalue(L, base);
        const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
        lua_pushinteger(L, ref);
        return 1;
    }
    lua_pushinteger(L, optIntArg(L, base, 0));
    return 1;
}

int lua_MobileBridge_releaseLuaFunction(lua_State* L) {
    const int base = firstArgIndex(L);
    const int ref = optIntArg(L, base, LUA_NOREF);
    if (ref != LUA_NOREF && ref != LUA_REFNIL && ref > 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
    }
    return 0;
}

void registerMobileLuaBridges(lua_State* L) {
    if (!L) return;

    // 1. Register CCLuaJavaBridge
    lua_newtable(L);
    lua_pushcfunction(L, lua_MobileBridge_callStaticMethod);
    lua_setfield(L, -2, "callStaticMethod");
    lua_pushcfunction(L, lua_MobileBridge_retainLuaFunction);
    lua_setfield(L, -2, "retainLuaFunction");
    lua_pushcfunction(L, lua_MobileBridge_retainLuaFunction);
    lua_setfield(L, -2, "retainLuaFunctionById");
    lua_pushcfunction(L, lua_MobileBridge_releaseLuaFunction);
    lua_setfield(L, -2, "releaseLuaFunction");
    lua_setglobal(L, "CCLuaJavaBridge");

    // Expose global `luaj` if not already set
    lua_getglobal(L, "luaj");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushcfunction(L, lua_MobileBridge_callStaticMethod);
        lua_setfield(L, -2, "callStaticMethod");
        lua_setglobal(L, "luaj");
    } else {
        lua_pop(L, 1);
    }

    // 2. Register CCLuaObjcBridge
    lua_newtable(L);
    lua_pushcfunction(L, lua_MobileBridge_callStaticMethod);
    lua_setfield(L, -2, "callStaticMethod");
    lua_pushcfunction(L, lua_MobileBridge_retainLuaFunction);
    lua_setfield(L, -2, "retainLuaFunctionById");
    lua_pushcfunction(L, lua_MobileBridge_releaseLuaFunction);
    lua_setfield(L, -2, "releaseLuaFunctionById");
    lua_setglobal(L, "CCLuaObjcBridge");

    // Expose global `luaoc` if not already set
    lua_getglobal(L, "luaoc");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushcfunction(L, lua_MobileBridge_callStaticMethod);
        lua_setfield(L, -2, "callStaticMethod");
        lua_setglobal(L, "luaoc");
    } else {
        lua_pop(L, 1);
    }
}

// ---------------------------------------------------------------------------
// All 69 Platform Lua method bindings (matching 01_libcocos2dlua_startup_and_bindings.c)
// ---------------------------------------------------------------------------
int lua_Platform_getInstance(lua_State* L) {
    lua_getglobal(L, "Platform");
    return 1;
}

int lua_Platform_tickLoop(lua_State* /*L*/) {
    bt::Platform::getInstance()->tickLoop();
    return 0;
}

int lua_Platform_initSDK(lua_State* L) {
    const int base = firstArgIndex(L);
    const std::string jsonParam = optStringArg(L, base, "");

    auto& reg = getLuaCallbacks();
    if (reg.fallbackState == nullptr) {
        reg.fallbackState = L;
    }

    // Accept Lua callback function either as 2nd arg or 1st arg if param omitted
    int fnIdx = -1;
    if (base + 1 <= lua_gettop(L) && lua_isfunction(L, base + 1)) {
        fnIdx = base + 1;
    } else if (base <= lua_gettop(L) && lua_isfunction(L, base)) {
        fnIdx = base;
    }

    if (fnIdx > 0) {
        if (reg.primaryHandlerRef != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, reg.primaryHandlerRef);
            reg.primaryHandlerRef = LUA_NOREF;
        }
        lua_pushvalue(L, fnIdx);
        reg.primaryHandlerRef = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "tolua_Platform",
        "lua_Platform_initSDK called (fnIdx=%d, json=%s)",
        fnIdx,
        jsonParam.c_str());
    bt::Platform::getInstance()->initSDK(
        jsonParam,
        [](int eventId, int statusCode, const std::string& payload) {
            auto& r = getLuaCallbacks();
            lua_State* liveL = resolveLiveMainLuaState(r.fallbackState);
            invokeLuaHandler(liveL, r.primaryHandlerRef, eventId, statusCode, payload);
        });
    return 0;
}

int lua_Platform_login(lua_State* /*L*/) {
    bt::Platform::getInstance()->login();
    return 0;
}

int lua_Platform_logout(lua_State* /*L*/) {
    bt::Platform::getInstance()->logout();
    return 0;
}

int lua_Platform_pay(lua_State* L) {
    bt::Platform::getInstance()->pay(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_showToolBar(lua_State* /*L*/) {
    bt::Platform::getInstance()->showToolBar();
    return 0;
}

int lua_Platform_hideToolBar(lua_State* /*L*/) {
    bt::Platform::getInstance()->hideToolBar();
    return 0;
}

int lua_Platform_enterUserCenter(lua_State* /*L*/) {
    bt::Platform::getInstance()->enterUserCenter();
    return 0;
}

int lua_Platform_accountSwitch(lua_State* /*L*/) {
    bt::Platform::getInstance()->accountSwitch();
    return 0;
}

int lua_Platform_sendInformationToPlatform(lua_State* L) {
    const int base = firstArgIndex(L);
    const int infoType = optIntArg(L, base, 0);
    const std::string jsonParams = optStringArg(L, base + 1, "{}");
    bt::Platform::getInstance()->sendInformationToPlatform(infoType, jsonParams);
    return 0;
}

int lua_Platform_getUserCenterName(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getUserCenterName();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_pause(lua_State* /*L*/) {
    bt::Platform::getInstance()->pause();
    return 0;
}

int lua_Platform_onPressBack(lua_State* /*L*/) {
    bt::Platform::getInstance()->onPressBack();
    return 0;
}

int lua_Platform_getServerList(lua_State* L) {
    bt::Platform::getInstance()->getServerList(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getHash(lua_State* L) {
    bt::Platform::getInstance()->getHash(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getHashWithSimulation(lua_State* L) {
    bt::Platform::getInstance()->getHashWithSimulation(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getVersionInfo(lua_State* L) {
    bt::Platform::getInstance()->getVersionInfo(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getLoginedServerInfo(lua_State* L) {
    bt::Platform::getInstance()->getLoginedServerInfo(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getNotice(lua_State* L) {
    bt::Platform::getInstance()->getNotice(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getAppleReview(lua_State* L) {
    bt::Platform::getInstance()->getAppleReview(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_question(lua_State* L) {
    bt::Platform::getInstance()->question(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_shareWeixin(lua_State* L) {
    bt::Platform::getInstance()->shareWeixin(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_playVideo(lua_State* L) {
    bt::Platform::getInstance()->playVideo(optStringArg(L, firstArgIndex(L), ""));
    return 0;
}

int lua_Platform_openCustomWebView(lua_State* L) {
    bt::Platform::getInstance()->openCustomWebView(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_closeCustomWebView(lua_State* /*L*/) {
    bt::Platform::getInstance()->closeCustomWebView();
    return 0;
}

int lua_Platform_quit(lua_State* /*L*/) {
    bt::Platform::getInstance()->quit();
    return 0;
}

int lua_Platform_doCustomWebViewAction(lua_State* L) {
    bt::Platform::getInstance()->doCustomWebViewAction(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_openUrl(lua_State* L) {
    bt::Platform::getInstance()->openUrl(optStringArg(L, firstArgIndex(L), ""));
    return 0;
}

int lua_Platform_isDebug(lua_State* L) {
    lua_pushboolean(L, bt::Platform::getInstance()->isDebug() ? 1 : 0);
    return 1;
}

int lua_Platform_isAd(lua_State* L) {
    lua_pushboolean(L, bt::Platform::getInstance()->isAd() ? 1 : 0);
    return 1;
}

int lua_Platform_getUUID(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getUUID();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getPid(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getPid();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getIdfa(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getIdfa();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getPL(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getPL();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getOS(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getOS();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getGN(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getGN();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getUrlParam(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getUrlParam();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getLogHost(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getLogHost();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getSDKVersion(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getSDKVersion();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getHost(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getHost();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getStandAlone(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getStandAlone();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_sendTracking(lua_State* L) {
    const int base = firstArgIndex(L);
    bt::Platform::getInstance()->sendTracking(
        optStringArg(L, base, ""),
        optStringArg(L, base + 1, "{}"));
    return 0;
}

int lua_Platform_retention(lua_State* L) {
    bt::Platform::getInstance()->retention(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_sendLog(lua_State* L) {
    bt::Platform::getInstance()->sendLog(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getDeviceInfo(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getDeviceInfo();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getDeviceFeature(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getDeviceFeature();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_getSuperNotice(lua_State* L) {
    bt::Platform::getInstance()->getSuperNotice(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_setSimulationInfo(lua_State* L) {
    bt::Platform::getInstance()->setSimulationInfo(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getUserInformation(lua_State* L) {
    bt::Platform::getInstance()->getUserInformation(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getBrowseActive(lua_State* L) {
    bt::Platform::getInstance()->getBrowseActive(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_sendAdstat(lua_State* /*L*/) {
    bt::Platform::getInstance()->sendAdstat();
    return 0;
}

int lua_Platform_callUniversalFunction(lua_State* L) {
    const int base = firstArgIndex(L);
    bt::Platform::getInstance()->callUniversalFunction(
        optStringArg(L, base, ""),
        optStringArg(L, base + 1, "{}"));
    return 0;
}

int lua_Platform_showMessage(lua_State* L) {
    const int base = firstArgIndex(L);
    bt::Platform::getInstance()->showMessage(
        optStringArg(L, base, ""),
        optStringArg(L, base + 1, ""));
    return 0;
}

int lua_Platform_isLogined(lua_State* L) {
    lua_pushboolean(L, bt::Platform::getInstance()->isLogined() ? 1 : 0);
    return 1;
}

int lua_Platform_checkMethod(lua_State* L) {
    const bool ok = bt::Platform::getInstance()->checkMethod(optStringArg(L, firstArgIndex(L), ""));
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

int lua_Platform_callUniversalWebFunction(lua_State* L) {
    const int base = firstArgIndex(L);
    const int eventId = optIntArg(L, base, 0);
    const std::string endpoint = optStringArg(L, base + 1, "");
    const std::string jsonParams = optStringArg(L, base + 2, "{}");
    bt::Platform::getInstance()->callUniversalWebFunction(eventId, endpoint, jsonParams);
    return 0;
}

int lua_Platform_setDebugEnv(lua_State* L) {
    bt::Platform::getInstance()->setDebugEnv(optBoolArg(L, firstArgIndex(L), false));
    return 0;
}

int lua_Platform_issueDJOrders(lua_State* /*L*/) {
    bt::Platform::getInstance()->issueDJOrders();
    return 0;
}

int lua_Platform_getForceFix(lua_State* L) {
    bt::Platform::getInstance()->getForceFix(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

// Overloaded signUrl (registered twice in original tolua_Platform_open:
//   signUrl(url) and signUrl(url, customKey))
int lua_Platform_signUrl_dispatch(lua_State* L) {
    const int base = firstArgIndex(L);
    const std::string url = optStringArg(L, base, "");
    std::string signedUrl;
    if (base + 1 <= lua_gettop(L) && lua_isstring(L, base + 1)) {
        const std::string customKey = optStringArg(L, base + 1, "");
        signedUrl = bt::Platform::getInstance()->signUrl(url, customKey);
    } else {
        signedUrl = bt::Platform::getInstance()->signUrl(url);
    }
    lua_pushlstring(L, signedUrl.data(), signedUrl.size());
    return 1;
}

int lua_Platform_setMainScreenBrightness(lua_State* L) {
    bt::Platform::getInstance()->setMainScreenBrightness(optFloatArg(L, firstArgIndex(L), 1.0f));
    return 0;
}

int lua_Platform_getMainScreenBrightness(lua_State* L) {
    lua_pushnumber(L, static_cast<lua_Number>(bt::Platform::getInstance()->getMainScreenBrightness()));
    return 1;
}

int lua_Platform_searchHandleUrl(lua_State* /*L*/) {
    bt::Platform::getInstance()->searchHandleUrl();
    return 0;
}

int lua_Platform_callUniversalFunctionWithBack(lua_State* L) {
    const int top = lua_gettop(L);
    const int base = firstArgIndex(L);
    const std::string funcName = (base <= top && lua_isstring(L, base))
        ? optStringArg(L, base, "")
        : std::string();
    const std::string jsonParams = (base + 1 <= top && lua_isstring(L, base + 1))
        ? optStringArg(L, base + 1, "{}")
        : std::string("{}");

    int callbackIdx = -1;
    for (int i = base; i <= top; ++i) {
        if (lua_isfunction(L, i)) {
            callbackIdx = i;
            break;
        }
    }

    bt::Platform::getInstance()->callUniversalFunctionWithBack(funcName, jsonParams);

    if (callbackIdx > 0) {
        invokeInlineLuaCallbackJson(L, callbackIdx, "{}");
    }

    lua_pushstring(L, "{}");
    return 1;
}

int lua_Platform_getNetworkCapture(lua_State* L) {
    bt::Platform::getInstance()->getNetworkCapture(optStringArg(L, firstArgIndex(L), "{}"));
    return 0;
}

int lua_Platform_getLocaleInfo(lua_State* L) {
    const std::string s = bt::Platform::getInstance()->getLocaleInfo();
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int lua_Platform_registeCallBackBySync(lua_State* L) {
    const int base = firstArgIndex(L);
    auto& reg = getLuaCallbacks();
    if (reg.fallbackState == nullptr) {
        reg.fallbackState = L;
    }

    if (base <= lua_gettop(L) && lua_isfunction(L, base)) {
        if (reg.syncHandlerRef != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, reg.syncHandlerRef);
            reg.syncHandlerRef = LUA_NOREF;
        }
        lua_pushvalue(L, base);
        reg.syncHandlerRef = luaL_ref(L, LUA_REGISTRYINDEX);

        bt::Platform::getInstance()->registeCallBackBySync(
            [](int eventId, int statusCode, const std::string& payload) {
                auto& r = getLuaCallbacks();
                lua_State* liveL = resolveLiveMainLuaState(r.fallbackState);
                invokeLuaHandler(liveL, r.syncHandlerRef, eventId, statusCode, payload);
            });
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Constant & method registration tables
// ---------------------------------------------------------------------------
struct LuaConstEntry {
    const char* name;
    lua_Number value;
};

// All constants from tolua_Platform_open in 01_libcocos2dlua_startup_and_bindings.c
const LuaConstEntry kPlatformConstants[] = {
    {"kCreateNewRole",        0.0},
    {"kEnterTheGameHall",     1.0},
    {"kLevelUp",              2.0},
    {"kInit",                 1.0},
    {"kLogin",                2.0},
    {"kGetServerlist",        3.0},
    {"kGetHash",              4.0},
    {"kGetVersion",           5.0},
    {"kPay",                  6.0},
    {"kQuit",                 7.0},
    {"kLogout",               8.0},
    {"kCrash",                9.0},
    {"kDiffAccount",          10.0},
    {"kShareBack",            11.0},
    {"kPlayFinish",           12.0},
    {"kLowMemory",            13.0},
    {"kHandleOpenURL",        14.0},
    {"kShowLogoFinish",       15.0},
    {"kGetLoginedServerInfo", 16.0},
    {"kGetNotice",            17.0},
    {"kQuestion",             18.0},
    {"kGetAppleReview",       19.0},
    {"kGetSuperNotice",       20.0},
    {"kGetUserInformation",   21.0},
    {"kGetBrowseActive",      22.0},
    {"kIssueDJOrders",        24.0},
    {"kGetForceFix",          25.0},
    {"kHandleUrl",            26.0},
    {"kNetworkCapture",       31.0},
    {"kPermissionResult",     32.0},
    {"kHttpSuccess",          0.0},
    {"kHttpFailed",           1.0},
    {"kATTAuthorizedResult",  35.0},
};

struct LuaMethodEntry {
    const char* name;
    lua_CFunction fn;
};

// All 69 Platform tolua_function entries from 01_libcocos2dlua_startup_and_bindings.c
// (including both signUrl overloads unified into lua_Platform_signUrl_dispatch)
const LuaMethodEntry kPlatformMethods[] = {
    {"getInstance",                   lua_Platform_getInstance},
    {"tickLoop",                      lua_Platform_tickLoop},
    {"initSDK",                       lua_Platform_initSDK},
    {"login",                         lua_Platform_login},
    {"logout",                        lua_Platform_logout},
    {"pay",                           lua_Platform_pay},
    {"showToolBar",                   lua_Platform_showToolBar},
    {"hideToolBar",                   lua_Platform_hideToolBar},
    {"enterUserCenter",               lua_Platform_enterUserCenter},
    {"accountSwitch",                 lua_Platform_accountSwitch},
    {"sendInformationToPlatform",     lua_Platform_sendInformationToPlatform},
    {"getUserCenterName",             lua_Platform_getUserCenterName},
    {"pause",                         lua_Platform_pause},
    {"onPressBack",                   lua_Platform_onPressBack},
    {"getServerList",                 lua_Platform_getServerList},
    {"getHash",                       lua_Platform_getHash},
    {"getHashWithSimulation",         lua_Platform_getHashWithSimulation},
    {"getVersionInfo",                lua_Platform_getVersionInfo},
    {"getLoginedServerInfo",          lua_Platform_getLoginedServerInfo},
    {"getNotice",                     lua_Platform_getNotice},
    {"getAppleReview",                lua_Platform_getAppleReview},
    {"question",                      lua_Platform_question},
    {"shareWeixin",                   lua_Platform_shareWeixin},
    {"playVideo",                     lua_Platform_playVideo},
    {"openCustomWebView",             lua_Platform_openCustomWebView},
    {"closeCustomWebView",            lua_Platform_closeCustomWebView},
    {"quit",                          lua_Platform_quit},
    {"doCustomWebViewAction",         lua_Platform_doCustomWebViewAction},
    {"openUrl",                       lua_Platform_openUrl},
    {"isDebug",                       lua_Platform_isDebug},
    {"isAd",                          lua_Platform_isAd},
    {"getUUID",                       lua_Platform_getUUID},
    {"getPid",                        lua_Platform_getPid},
    {"getIdfa",                       lua_Platform_getIdfa},
    {"getPL",                         lua_Platform_getPL},
    {"getOS",                         lua_Platform_getOS},
    {"getGN",                         lua_Platform_getGN},
    {"getUrlParam",                   lua_Platform_getUrlParam},
    {"getLogHost",                    lua_Platform_getLogHost},
    {"getSDKVersion",                 lua_Platform_getSDKVersion},
    {"getHost",                       lua_Platform_getHost},
    {"getStandAlone",                 lua_Platform_getStandAlone},
    {"sendTracking",                  lua_Platform_sendTracking},
    {"retention",                     lua_Platform_retention},
    {"sendLog",                       lua_Platform_sendLog},
    {"getDeviceInfo",                 lua_Platform_getDeviceInfo},
    {"getDeviceFeature",              lua_Platform_getDeviceFeature},
    {"getSuperNotice",                lua_Platform_getSuperNotice},
    {"setSimulationInfo",             lua_Platform_setSimulationInfo},
    {"getUserInformation",            lua_Platform_getUserInformation},
    {"getBrowseActive",               lua_Platform_getBrowseActive},
    {"sendAdstat",                    lua_Platform_sendAdstat},
    {"callUniversalFunction",         lua_Platform_callUniversalFunction},
    {"showMessage",                   lua_Platform_showMessage},
    {"isLogined",                     lua_Platform_isLogined},
    {"checkMethod",                   lua_Platform_checkMethod},
    {"callUniversalWebFunction",      lua_Platform_callUniversalWebFunction},
    {"setDebugEnv",                   lua_Platform_setDebugEnv},
    {"issueDJOrders",                 lua_Platform_issueDJOrders},
    {"getForceFix",                   lua_Platform_getForceFix},
    {"signUrl",                       lua_Platform_signUrl_dispatch},
    {"setMainScreenBrightness",       lua_Platform_setMainScreenBrightness},
    {"getMainScreenBrightness",       lua_Platform_getMainScreenBrightness},
    {"searchHandleUrl",               lua_Platform_searchHandleUrl},
    {"callUniversalFunctionWithBack", lua_Platform_callUniversalFunctionWithBack},
    {"getNetworkCapture",             lua_Platform_getNetworkCapture},
    {"getLocaleInfo",                 lua_Platform_getLocaleInfo},
    {"registeCallBackBySync",         lua_Platform_registeCallBackBySync},
};

// ---------------------------------------------------------------------------
// Generic safe logged stub helpers for PluginManager & NotificationManager
// ---------------------------------------------------------------------------
int lua_StubNoOpClosure(lua_State* L) {
    const char* moduleName = lua_tostring(L, lua_upvalueindex(1));
    const char* methodName = lua_tostring(L, lua_upvalueindex(2));
    std::fprintf(stderr, "[tolua_Stub][%s] Dropped call '%s' safely ignored on Win32 (argc=%d)\n",
                 moduleName ? moduleName : "Unknown",
                 methodName ? methodName : "unknown",
                 lua_gettop(L));
    return 0;
}

int lua_StubFallbackIndex(lua_State* L) {
    const char* moduleName = lua_tostring(L, lua_upvalueindex(1));
    const char* key = lua_tostring(L, 2);
    lua_pushstring(L, moduleName ? moduleName : "Stub");
    lua_pushstring(L, key ? key : "<unknown>");
    lua_pushcclosure(L, lua_StubNoOpClosure, 2);
    return 1;
}

int lua_PluginManager_getInstance(lua_State* L) {
    lua_getglobal(L, "PluginManager");
    return 1;
}

int lua_PluginManager_loadPlugin(lua_State* L) {
    const std::string name = optStringArg(L, firstArgIndex(L), "");
    std::fprintf(stderr, "[tolua_PluginManager] loadPlugin('%s') -> Win32 stub\n", name.c_str());
    lua_getglobal(L, "PluginManager");
    return 1;
}

int lua_PluginManager_callString(lua_State* L) {
    const std::string name = optStringArg(L, firstArgIndex(L), "");
    std::fprintf(stderr, "[tolua_PluginManager] callStringFuncWithParam('%s') -> \"{}\"\n", name.c_str());
    lua_pushstring(L, "{}");
    return 1;
}

int lua_PluginManager_callInt(lua_State* L) {
    const std::string name = optStringArg(L, firstArgIndex(L), "");
    std::fprintf(stderr, "[tolua_PluginManager] callIntFuncWithParam('%s') -> 0\n", name.c_str());
    lua_pushinteger(L, 0);
    return 1;
}

int lua_PluginManager_callBool(lua_State* L) {
    const std::string name = optStringArg(L, firstArgIndex(L), "");
    std::fprintf(stderr, "[tolua_PluginManager] callBoolFuncWithParam('%s') -> false\n", name.c_str());
    lua_pushboolean(L, 0);
    return 1;
}

int lua_NotificationManager_getInstance(lua_State* L) {
    lua_getglobal(L, "NotificationManager");
    return 1;
}

int lua_NotificationManager_getDeviceToken(lua_State* L) {
    std::fprintf(stderr, "[tolua_NotificationManager] getDeviceToken() -> \"\"\n");
    lua_pushstring(L, "");
    return 1;
}

void attachFallbackMetatable(lua_State* L, int tableIdx, const char* moduleName) {
    lua_newtable(L);
    lua_pushstring(L, moduleName);
    lua_pushcclosure(L, lua_StubFallbackIndex, 1);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, tableIdx);
}

}  // namespace

// ---------------------------------------------------------------------------
// Public entry points matching PluginsLuaLoder::loder
// ---------------------------------------------------------------------------
int tolua_Platform_open(lua_State* L) {
    if (!L) return 0;

    // Bind main lua_State* fallback on open (and reset stale registry refs if VM changed in tests).
    {
        auto& reg = getLuaCallbacks();
        if (reg.fallbackState != L) {
            reg.fallbackState = L;
            reg.primaryHandlerRef = LUA_NOREF;
            reg.syncHandlerRef = LUA_NOREF;
        }
    }

    // Register global k* constants
    for (const auto& c : kPlatformConstants) {
        lua_pushnumber(L, c.value);
        lua_setglobal(L, c.name);
    }

    // Register CallBack usertype table
    luaL_newmetatable(L, "CallBack");
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_setglobal(L, "CallBack");

    // Register Platform class table & metatable
    luaL_newmetatable(L, "Platform");
    for (const auto& m : kPlatformMethods) {
        lua_pushcfunction(L, m.fn);
        lua_setfield(L, -2, m.name);
    }
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_setglobal(L, "Platform");

    // Register Android/iOS bridges (CCLuaJavaBridge / luaj / CCLuaObjcBridge / luaoc)
    registerMobileLuaBridges(L);

    return 1;
}

int tolua_PluginManager_open(lua_State* L) {
    if (!L) return 0;

    lua_newtable(L);
    const int tbl = lua_gettop(L);

    lua_pushcfunction(L, lua_PluginManager_getInstance);
    lua_setfield(L, tbl, "getInstance");
    lua_pushcfunction(L, lua_PluginManager_loadPlugin);
    lua_setfield(L, tbl, "loadPlugin");
    lua_pushcfunction(L, lua_PluginManager_callString);
    lua_setfield(L, tbl, "callStringFuncWithParam");
    lua_pushcfunction(L, lua_PluginManager_callInt);
    lua_setfield(L, tbl, "callIntFuncWithParam");
    lua_pushcfunction(L, lua_PluginManager_callBool);
    lua_setfield(L, tbl, "callBoolFuncWithParam");

    attachFallbackMetatable(L, tbl, "PluginManager");
    lua_setglobal(L, "PluginManager");
    return 1;
}

int tolua_NotificationManager_open(lua_State* L) {
    if (!L) return 0;

    lua_newtable(L);
    const int tbl = lua_gettop(L);

    lua_pushcfunction(L, lua_NotificationManager_getInstance);
    lua_setfield(L, tbl, "getInstance");
    lua_pushcfunction(L, lua_NotificationManager_getDeviceToken);
    lua_setfield(L, tbl, "getDeviceToken");

    attachFallbackMetatable(L, tbl, "NotificationManager");
    lua_setglobal(L, "NotificationManager");
    return 1;
}

int tolua_GCLIENT_Plugins_open(lua_State* L) {
    tolua_Platform_open(L);
    tolua_PluginManager_open(L);
    tolua_NotificationManager_open(L);
    return 1;
}
