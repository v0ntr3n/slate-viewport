// ============================================================================
// Win32 Client Win32 Port — AppDelegate Implementation
// Reconstructed from libcocos2dlua.so AppDelegate::applicationDidFinishLaunching
// (0x2a25d8) and adapted for unmodified Cocos2d-x 2.2.6 Win32 overlay architecture.
// ============================================================================

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#endif

#include "AppDelegate.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include "CCLuaEngine.h"
#include "SimpleAudioEngine.h"

#include "diagnostics/CrashAndTelemetry.h"

#include "assets/BTAssetDecryptor.h"
#include "assets/BtDecryptHook.h"
#include "bindings/BTUtil.h"
#include "bindings/LuaBindingsRegistry.h"
#include "bindings/LuaHelpers.h"
#include "net/CNetwork.h"
#include "platform/BTPlatform.h"
#include "ui/ZYWebViewWin32.h"

namespace gclient {

namespace {

std::string g_configuredWritableDir;
bool g_validateAssetsOnly = false;

constexpr float kDesignWidth = 1136.0f;
constexpr float kDesignHeight = 640.0f;
constexpr double kTargetAnimationInterval = 0.0333333333; // 30 FPS

template <typename T, typename = void>
struct HasClearLuaStateNoArg : std::false_type {};
template <typename T>
struct HasClearLuaStateNoArg<T, std::void_t<decltype(T::clearLuaState())>> : std::true_type {};

template <typename T = diagnostics::CrashAndTelemetry>
void clearTelemetryLuaStateBeforeTeardown() {
    if constexpr (HasClearLuaStateNoArg<T>::value) {
        T::clearLuaState();
    }
}

template <typename T, typename = void>
struct HasGetFrameSize : std::false_type {};
template <typename T>
struct HasGetFrameSize<T, std::void_t<decltype(std::declval<T*>()->getFrameSize())>> : std::true_type {};

template <typename T>
bool isEglViewZeroOrMinimized(T* eglView) {
    if (!eglView) {
        return true;
    }
    if constexpr (HasGetFrameSize<T>::value) {
        const cocos2d::CCSize frameSz = eglView->getFrameSize();
        if (frameSz.width < 1.0f || frameSz.height < 1.0f ||
            !std::isfinite(frameSz.width) || !std::isfinite(frameSz.height)) {
            return true;
        }
    }
    return false;
}

template <typename T>
void ensureNonZeroEglFrameSize(T* eglView, int fallbackW, int fallbackH) {
    if (!eglView) {
        return;
    }
    if constexpr (HasGetFrameSize<T>::value) {
        const cocos2d::CCSize frameSz = eglView->getFrameSize();
        if (frameSz.width < 1.0f || frameSz.height < 1.0f ||
            !std::isfinite(frameSz.width) || !std::isfinite(frameSz.height)) {
            const float safeW = static_cast<float>(fallbackW > 0 ? fallbackW : 1136);
            const float safeH = static_cast<float>(fallbackH > 0 ? fallbackH : 640);
            eglView->setFrameSize(safeW, safeH);
        }
    }
}

bool isEnvFlagEnabled(const char* name) {
    if (!name || !*name) {
        return false;
    }
    std::string val;
#ifdef _WIN32
    char buf[32] = {};
    const DWORD len = ::GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
    if (len > 0 && len < sizeof(buf)) {
        val.assign(buf, len);
    }
#endif
    if (val.empty()) {
        if (const char* raw = std::getenv(name)) {
            val = raw;
        }
    }
    return val == "1" || val == "true" || val == "TRUE" || val == "yes" || val == "YES";
}

class AlertDialogGate {
public:
    static constexpr std::size_t kMaxPopupsPerProcess = 3;

    bool shouldDisplayPopup(const std::string& messageText,
                            bool validateAssetsOnly,
                            bool suppressMessageBoxEnv,
                            bool headlessEnv) {
        if (validateAssetsOnly || suppressMessageBoxEnv || headlessEnv) {
            return false;
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_seenMessages.find(messageText) != m_seenMessages.end()) {
            return false;
        }
        if (m_shownCount >= kMaxPopupsPerProcess) {
            return false;
        }
        m_seenMessages.insert(messageText);
        ++m_shownCount;
        return true;
    }

private:
    std::mutex m_mutex;
    std::unordered_set<std::string> m_seenMessages;
    std::size_t m_shownCount = 0;
};

AlertDialogGate& sharedAlertDialogGate() {
    static AlertDialogGate s_gate;
    return s_gate;
}

#ifdef _WIN32
std::wstring utf8ToWideAlert(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int req = ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (req <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(req), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), req);
    return wide;
}

void showAsyncWin32Alert(std::string title, std::string message) {
    std::thread([t = std::move(title), m = std::move(message)]() {
        static std::mutex s_dialogMutex;
        std::lock_guard<std::mutex> lock(s_dialogMutex);
        const std::wstring wideTitle = utf8ToWideAlert(t.empty() ? "Win32 Client" : t);
        const std::wstring wideMsg = utf8ToWideAlert(m);
        ::MessageBoxW(
            nullptr,
            wideMsg.c_str(),
            wideTitle.empty() ? L"Win32 Client" : wideTitle.c_str(),
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    }).detach();
}
#endif

void appendSearchLayer(std::vector<std::string>& searchPaths,
                       std::unordered_set<std::string>& seen,
                       std::string layerRoot) {
    std::replace(layerRoot.begin(), layerRoot.end(), '\\', '/');
    while (layerRoot.size() > 1 && layerRoot.back() == '/') {
        if (layerRoot.size() == 3 && layerRoot[1] == ':') {
            break;
        }
        layerRoot.pop_back();
    }
    if (layerRoot.empty()) {
        return;
    }

    const std::string prefix = (layerRoot.back() == '/') ? layerRoot : (layerRoot + "/");
    const std::string subpaths[] = {
        layerRoot,
        prefix + "scripts",
        prefix + "database",
        prefix + "res",
        prefix + "res/database",
        prefix + "res/jsonUI",
    };
    for (const std::string& p : subpaths) {
        if (seen.insert(p).second) {
            searchPaths.push_back(p);
        }
    }
}

void maybeShowWin32AlertPopup(const std::string& titleStr, const std::string& msgStr, bool showAlert) {
#ifdef _WIN32
    if (showAlert) {
        showAsyncWin32Alert(titleStr, msgStr);
    }
#else
    (void)titleStr;
    (void)msgStr;
    (void)showAlert;
#endif
}

} // namespace

// ----------------------------------------------------------------------------
// FrameTicker: CCObject bridge scheduled on CCScheduler (replaces loom::tick)
// ----------------------------------------------------------------------------
class AppDelegate::FrameTicker final : public cocos2d::CCObject {
public:
    void onTick(float dt) {
        if (bt::Platform* platform = bt::Platform::getInstance()) {
            platform->tickLoop();
        }
        if (gclient::net::CNetwork* network = gclient::net::CNetwork::sharedNetwork()) {
            network->update(dt);
        }
        diagnostics::CrashAndTelemetry::recordFrame(dt);
        static int s_frame = 0;
        if (++s_frame == 60) {
            auto* scene = cocos2d::CCDirector::sharedDirector()->getRunningScene();
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Info,
                "AppDelegate",
                "Frame 60: runningScene=%p children=%u",
                static_cast<void*>(scene),
                scene ? scene->getChildrenCount() : 0u);
        } else if (s_frame == 90) {
            if (const char* shotName = std::getenv("GCLIENT_SCREENSHOT_NAME")) {
                auto* director = cocos2d::CCDirector::sharedDirector();
                auto* eglView = cocos2d::CCEGLView::sharedOpenGLView();
                if (director && !isEglViewZeroOrMinimized(eglView)) {
                    if (auto* scene = director->getRunningScene()) {
                        const auto winSize = director->getWinSize();
                        if (std::isfinite(winSize.width) && std::isfinite(winSize.height) &&
                            winSize.width >= 1.0f && winSize.height >= 1.0f) {
                            if (auto* rt = cocos2d::CCRenderTexture::create(
                                    static_cast<int>(winSize.width), static_cast<int>(winSize.height))) {
                                rt->begin();
                                scene->visit();
                                rt->end();
                                rt->saveToFile(shotName, cocos2d::kCCImageFormatPNG);
                                diagnostics::CrashAndTelemetry::log(
                                    diagnostics::LogLevel::Info, "AppDelegate", "Saved screenshot %s", shotName);
                            }
                        }
                    }
                }
            }
        }
    }
};

static int gclientLuaLoader(lua_State* L) {
    std::string modName = luaL_checkstring(L, 1);
    if (modName.size() >= 4 && modName.substr(modName.size() - 4) == ".lua") {
        modName.resize(modName.size() - 4);
    }
    std::replace(modName.begin(), modName.end(), '.', '/');
    const std::string relFile = modName + ".lua";

    unsigned long sz = 0;
    unsigned char* buf = cocos2d::CCFileUtils::sharedFileUtils()->getFileData(relFile.c_str(), "rb", &sz);
    if (!buf || sz == 0) {
        delete[] buf;
        lua_pushfstring(L, "\n\t[gclientLuaLoader] cannot find '%s'", relFile.c_str());
        return 1;
    }

    const char* code = reinterpret_cast<const char*>(buf);
    size_t codeLen = static_cast<size_t>(sz);
    if (codeLen >= 3 &&
        static_cast<unsigned char>(code[0]) == 0xEF &&
        static_cast<unsigned char>(code[1]) == 0xBB &&
        static_cast<unsigned char>(code[2]) == 0xBF) {
        code += 3;
        codeLen -= 3;
    }

    const std::string chunkName = "@" + relFile;
    const int loadStatus = luaL_loadbuffer(L, code, codeLen, chunkName.c_str());
    delete[] buf;
    if (loadStatus != 0) {
        return lua_error(L);
    }
    return 1;
}

// ----------------------------------------------------------------------------
// AppDelegate lifecycle
// ----------------------------------------------------------------------------
AppDelegate::AppDelegate(const AppConfig& config)
    : m_config(config)
{
    g_validateAssetsOnly = m_config.validateAssetsOnly;
}

AppDelegate::~AppDelegate() {
    unscheduleNativeLoops();
    // Clear CrashAndTelemetry's cached lua_State* BEFORE Lua engine teardown so
    // background/telemetry collectors never touch a closed lua_State*!
    clearTelemetryLuaStateBeforeTeardown();
    cocos2d::CCScriptEngineManager::purgeSharedManager();
    CocosDenshion::SimpleAudioEngine::end();
}

void AppDelegate::configureFileUtils() {
    cocos2d::CCFileUtils* fileUtils = cocos2d::CCFileUtils::sharedFileUtils();

    if (!m_config.writableDir.empty()) {
        std::error_code ec;
#ifdef _WIN32
        std::filesystem::create_directories(utf8ToWideAlert(m_config.writableDir), ec);
#else
        std::filesystem::create_directories(m_config.writableDir, ec);
#endif
    }

    auto normPath = [](std::string p) {
        std::replace(p.begin(), p.end(), '\\', '/');
        return p;
    };

    std::vector<std::string> searchPaths;
    std::unordered_set<std::string> seenPaths;

    if (!m_config.writableDir.empty()) {
        std::string w = normPath(m_config.writableDir);
        if (!w.empty() && w.back() != '/') w.push_back('/');
        g_configuredWritableDir = w;
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", utf8ToWideAlert(w).c_str());
#endif
        appendSearchLayer(searchPaths, seenPaths, w + "Resources");
    }
    if (!m_config.hotfixDir.empty()) {
        appendSearchLayer(searchPaths, seenPaths, m_config.hotfixDir);
    }
    if (!m_config.resourcesDir.empty()) {
        const std::string normRes = normPath(m_config.resourcesDir);
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_RESOURCES_DIR", utf8ToWideAlert(normRes).c_str());
#endif
        appendSearchLayer(searchPaths, seenPaths, normRes);
    }
    if (!m_config.baseAssetsDir.empty()) {
        const std::string normBase = normPath(m_config.baseAssetsDir);
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_BASE_ASSETS_DIR", utf8ToWideAlert(normBase).c_str());
#endif
        appendSearchLayer(searchPaths, seenPaths, normBase);
    }

    fileUtils->setSearchPaths(searchPaths);

    if (bt::Platform* platform = bt::Platform::getInstance()) {
        if (!m_config.baseAssetsDir.empty()) {
            platform->setResourceRoot(normPath(m_config.baseAssetsDir));
        } else if (!m_config.resourcesDir.empty()) {
            platform->setResourceRoot(normPath(m_config.resourcesDir));
        }
        platform->setLogHandler([](const std::string& level, const std::string& message) {
            const auto lvl = (level == "error") ? diagnostics::LogLevel::Error : diagnostics::LogLevel::Info;
            diagnostics::CrashAndTelemetry::log(lvl, "bt::Platform", "%s", message.c_str());
        });
        platform->setWebViewBridgeHandler(
            [](const std::string& action, int x, int y, int width, int height, const std::string& url) {
                auto* webView = gclient::ui::ZYWebViewWin32::getInstance();
                if (!webView) return;
                if (action == "displayWebView") {
                    webView->displayWebView(x, y, width, height);
                } else if (action == "updateURL") {
                    webView->updateURL(url);
                } else if (action == "removeWebView") {
                    webView->removeWebView();
                }
            });
    }

    fileUtils->setDecrypt(&bt_decrypt);
    gclient::assets::InstallBtDecryptHook(fileUtils);
}

void AppDelegate::registerLuaBindings(lua_State* L) {
    tolua_extensions_ccb_open(L);
    tolua_GameTemplate_open(L);
    luaopen_lua_extensions(L);
    luaopen_amf3_extensions(L);
#ifdef GCLIENT_ENABLE_LUAPROFILER
    luaopen_luaprofiler(L);
#endif
    tolua_BTUtil_open(L);

    tolua_Platform_open(L);
    tolua_PluginManager_open(L);
    tolua_NotificationManager_open(L);

    RegisterAssetLoaderHooks(L);

    const lua_CFunction logErrFn = [](lua_State* L) -> int {
        const char* msg = lua_tostring(L, 1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "LuaErr",
            "%s",
            msg ? msg : "(null)");
        diagnostics::CrashAndTelemetry::flushLogs();
        return 0;
    };
    lua_pushcfunction(L, logErrFn);
    lua_setglobal(L, "__GCLIENT_LOG_ERR__");

    const lua_CFunction logInfoFn = [](lua_State* L) -> int {
        const int nargs = lua_gettop(L);
        std::string out;
        lua_getglobal(L, "tostring");
        const bool hasToString = lua_isfunction(L, -1);
        for (int i = 1; i <= nargs; ++i) {
            if (i > 1) {
                out.push_back('\t');
            }
            if (hasToString) {
                lua_pushvalue(L, -1);
                lua_pushvalue(L, i);
                if (lua_pcall(L, 1, 1, 0) == 0) {
                    const char* s = lua_tostring(L, -1);
                    out.append(s ? s : "nil");
                } else {
                    out.append("<tostring-err>");
                }
                lua_pop(L, 1);
            } else {
                const char* s = lua_tostring(L, i);
                out.append(s ? s : "nil");
            }
        }
        lua_pop(L, 1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Info,
            "Lua",
            "%s",
            out.c_str());
        return 0;
    };
    lua_pushcfunction(L, logInfoFn);
    lua_setglobal(L, "__GCLIENT_LOG_INFO__");

    // Avoid duplicate print/release_print/CCLuaLog mirroring when CrashAndTelemetry::installLuaHooks
    // already installed __GCLIENT_NATIVE_PRINT__ mirrors: preserve initial CrashAndTelemetry-mirrored
    // closures without double-wrapping, and guard reassigned print handlers with `_in_print` so
    // nested calls (`CCLuaLog(...) -> print(...)`) log at most once per call!
    static constexpr const char* kLuaBootstrapShim =
        "do "
        "local _gmt = getmetatable(_G) or {} "
        "local _old_ni = _gmt.__newindex "
        "local _old_idx = _gmt.__index "
        "local _hooks = {} "
        "local _already_mirrored = {} "
        "local _in_tb = false "
        "local _in_print = false "
        "local function _get_tb(lvl) "
        "  if type(debug) == 'table' and type(debug.traceback) == 'function' then "
        "    return debug.traceback('', lvl or 2) "
        "  end "
        "  return '' "
        "end "
        "local function _wrap_tb(fn) "
        "  return function(msg) "
        "    local full = tostring(msg) .. '\\n' .. tostring(_get_tb(2)) "
        "    if not _in_tb then "
        "      _in_tb = true "
        "      __GCLIENT_LOG_ERR__(full) "
        "      if type(fn) == 'function' then "
        "        local ok, res = pcall(fn, msg) "
        "        _in_tb = false "
        "        if not ok then "
        "          __GCLIENT_LOG_ERR__('TRACKBACK_HANDLER_ERR:' .. tostring(res)) "
        "        else "
        "          return res "
        "        end "
        "      else "
        "        _in_tb = false "
        "      end "
        "    end "
        "    return full "
        "  end "
        "end "
        "local _native_print = rawget(_G, '__GCLIENT_NATIVE_PRINT__') "
        "if type(_native_print) == 'function' then _already_mirrored[_native_print] = true end "
        "local function _wrap_print(fn) "
        "  if type(fn) == 'function' and _already_mirrored[fn] then return fn end "
        "  local orig = (type(fn) == 'function' and fn ~= __GCLIENT_LOG_INFO__) and fn or nil "
        "  local w "
        "  w = function(...) "
        "    if _in_print then "
        "      if orig then return orig(...) end "
        "      return "
        "    end "
        "    _in_print = true "
        "    __GCLIENT_LOG_INFO__(...) "
        "    if orig then "
        "      local ok, r1, r2 = pcall(orig, ...) "
        "      _in_print = false "
        "      if not ok then error(r1, 0) end "
        "      return r1, r2 "
        "    end "
        "    _in_print = false "
        "  end "
        "  _already_mirrored[w] = true "
        "  return w "
        "end "
        "local function _wrap_existing_mirrored(fn) "
        "  local w "
        "  w = function(...) "
        "    if _in_print then return end "
        "    _in_print = true "
        "    local ok, r1, r2 = pcall(fn, ...) "
        "    _in_print = false "
        "    if not ok then error(r1, 0) end "
        "    return r1, r2 "
        "  end "
        "  _already_mirrored[fn] = true "
        "  _already_mirrored[w] = true "
        "  return w "
        "end "
        "local _init_tb = rawget(_G, '__G__TRACKBACK__') "
        "local _native_tb = rawget(_G, '__GCLIENT_NATIVE_TRACKBACK__') "
        "rawset(_G, '__G__TRACKBACK__', nil) "
        "_hooks.__G__TRACKBACK__ = _wrap_tb((_init_tb ~= _native_tb) and _init_tb or nil) "
        "local _pnames = {'print', 'release_print', 'CCLuaLog'} "
        "for i = 1, #_pnames do "
        "  local pn = _pnames[i] "
        "  local cur = rawget(_G, pn) "
        "  rawset(_G, pn, nil) "
        "  if _native_print ~= nil and type(cur) == 'function' then "
        "    _hooks[pn] = _wrap_existing_mirrored(cur) "
        "  else "
        "    _hooks[pn] = _wrap_print(cur) "
        "  end "
        "end "
        "_gmt.__index = function(t, k) "
        "  local h = _hooks[k] "
        "  if h ~= nil then return h end "
        "  if type(_old_idx) == 'function' then return _old_idx(t, k) "
        "  elseif type(_old_idx) == 'table' then return _old_idx[k] end "
        "  return nil "
        "end "
        "_gmt.__newindex = function(t, k, v) "
        "  if k == '__G__TRACKBACK__' then "
        "    _hooks.__G__TRACKBACK__ = _wrap_tb(v) "
        "    return "
        "  elseif k == 'print' or k == 'release_print' or k == 'CCLuaLog' then "
        "    _hooks[k] = _wrap_print(v) "
        "    return "
        "  elseif k == 'g' and type(v) == 'table' then "
        "    local mt = getmetatable(v) or {} "
        "    mt.__newindex = function(gt, gk, gv) "
        "      if gk == 'isRefresh' then gv = true end "
        "      rawset(gt, gk, gv) "
        "    end "
        "    setmetatable(v, mt) "
        "  end "
        "  if _old_ni then _old_ni(t, k, v) else rawset(t, k, v) end "
        "end "
        "setmetatable(_G, _gmt) "
        "local _r = require "
        "require = function(n) "
        "  local res = _r(n) "
        "  if (n == 'config.Config' or n == 'config/Config') and type(res) == 'table' and res.currentOS == nil then "
        "    res.currentOS = 'android' "
        "  end "
        "  return res "
        "end "
        "if type(io) == 'table' and type(io.open) == 'function' then "
        "  local _io_open = io.open "
        "  io.open = function(path, mode) "
        "    if mode == nil then mode = 'rb' "
        "    elseif type(mode) == 'string' and not mode:find('b', 1, true) then mode = mode .. 'b' end "
        "    return _io_open(path, mode) "
        "  end "
        "end "
        "local _xp = xpcall "
        "xpcall = function(f, eh, ...) "
        "  local wrapped_eh = function(m) "
        "    if eh ~= _hooks.__G__TRACKBACK__ then "
        "      __GCLIENT_LOG_ERR__('ORIG:' .. tostring(m) .. '\\n' .. tostring(_get_tb(2))) "
        "    end "
        "    if type(eh) == 'function' then "
        "      local ok2, e2 = pcall(eh, m) "
        "      if not ok2 then __GCLIENT_LOG_ERR__('EH_ERR:' .. tostring(e2)) end "
        "      return e2 "
        "    end "
        "    return m "
        "  end "
        "  if select('#', ...) > 0 then return _xp(f, wrapped_eh, ...) end "
        "  return _xp(f, wrapped_eh) "
        "end "
        "end";

    if (luaL_dostring(L, kLuaBootstrapShim) != 0) {
        const char* err = lua_tostring(L, -1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AppDelegate",
            "Config shim error: %s",
            err ? err : "(null)");
        lua_pop(L, 1);
    }

    g_validateAssetsOnly = m_config.validateAssetsOnly;
    const lua_CFunction ccMessageBoxFn = [](lua_State* L) -> int {
        const char* msg = lua_tostring(L, 1);
        const char* title = lua_tostring(L, 2);
        const std::string msgStr = msg ? msg : "(null)";
        const std::string titleStr = (title && title[0] != '\0') ? title : "Win32 Client";

        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "CCMessageBox",
            "[%s] %s",
            titleStr.c_str(),
            msgStr.c_str());
        diagnostics::CrashAndTelemetry::flushLogs();

        const std::string dedupKey = titleStr + "\n" + msgStr;
        const bool showAlert = sharedAlertDialogGate().shouldDisplayPopup(
            dedupKey,
            g_validateAssetsOnly,
            isEnvFlagEnabled("GCLIENT_SUPPRESS_MESSAGEBOX"),
            isEnvFlagEnabled("GCLIENT_HEADLESS"));
        maybeShowWin32AlertPopup(titleStr, msgStr, showAlert);
        return 0;
    };
    lua_pushcfunction(L, ccMessageBoxFn);
    lua_setglobal(L, "CCMessageBox");

    luaL_getmetatable(L, "CCFileUtils");
    if (lua_istable(L, -1)) {
        const lua_CFunction removeSearchPathFn = [](lua_State* L) -> int {
            tolua_Error err{};
            auto* self = (lua_type(L, 1) == LUA_TUSERDATA &&
                          tolua_isusertype(L, 1, "CCFileUtils", 0, &err))
                ? static_cast<cocos2d::CCFileUtils*>(tolua_tousertype(L, 1, nullptr))
                : cocos2d::CCFileUtils::sharedFileUtils();
            const char* target = lua_tostring(L, 2);
            if (self && target) {
                std::string targetStr(target);
                auto paths = self->getSearchPaths();
                paths.erase(
                    std::remove_if(paths.begin(), paths.end(), [&](const std::string& p) {
                        return p == targetStr || (!targetStr.empty() && p == targetStr + "/");
                    }),
                    paths.end());
                self->setSearchPaths(paths);
            }
            return 0;
        };
        lua_pushcfunction(L, removeSearchPathFn);
        lua_setfield(L, -2, "removeSearchPath");

        lua_getfield(L, -1, "getWritablePath");
        if (lua_isfunction(L, -1)) {
            const lua_CFunction getWritablePathClosure = [](lua_State* L) -> int {
                if (!g_configuredWritableDir.empty()) {
                    lua_pushlstring(L, g_configuredWritableDir.data(), g_configuredWritableDir.size());
                    return 1;
                }
                lua_pushvalue(L, lua_upvalueindex(1));
                lua_pushvalue(L, 1);
                lua_call(L, 1, 1);
                const char* p = lua_tostring(L, -1);
                if (p && *p) {
                    std::string s(p);
                    std::replace(s.begin(), s.end(), '\\', '/');
                    if (s.back() != '/') s.push_back('/');
                    lua_pop(L, 1);
                    lua_pushlstring(L, s.data(), s.size());
                }
                return 1;
            };
            lua_pushcclosure(L, getWritablePathClosure, 1);
            lua_setfield(L, -2, "getWritablePath");
        } else {
            lua_pop(L, 1);
        }

        std::vector<std::string> initialPaths;
        if (auto* fu = cocos2d::CCFileUtils::sharedFileUtils()) {
            initialPaths = fu->getSearchPaths();
        }
        lua_newtable(L);
        for (size_t i = 0; i < initialPaths.size(); ++i) {
            lua_pushlstring(L, initialPaths[i].data(), initialPaths[i].size());
            lua_rawseti(L, -2, static_cast<int>(i + 1));
        }
        lua_getfield(L, -2, "removeAllPaths");
        const lua_CFunction removeAllPathsClosure = [](lua_State* L) -> int {
            if (lua_isfunction(L, lua_upvalueindex(2))) {
                lua_pushvalue(L, lua_upvalueindex(2));
                lua_pushvalue(L, 1);
                lua_call(L, 1, 0);
            }
            tolua_Error err{};
            auto* self = (lua_type(L, 1) == LUA_TUSERDATA &&
                          tolua_isusertype(L, 1, "CCFileUtils", 0, &err))
                ? static_cast<cocos2d::CCFileUtils*>(tolua_tousertype(L, 1, nullptr))
                : cocos2d::CCFileUtils::sharedFileUtils();
            if (self) {
                int n = static_cast<int>(lua_objlen(L, lua_upvalueindex(1)));
                for (int i = 1; i <= n; ++i) {
                    lua_rawgeti(L, lua_upvalueindex(1), i);
                    if (const char* p = lua_tostring(L, -1)) {
                        self->addSearchPath(p);
                    }
                    lua_pop(L, 1);
                }
            }
            return 0;
        };
        lua_pushcclosure(L, removeAllPathsClosure, 2);
        lua_setfield(L, -2, "removeAllPaths");

        lua_getfield(L, -1, "fullPathForFilename");
        if (lua_isfunction(L, -1)) {
            const lua_CFunction fullPathClosure = [](lua_State* L) -> int {
                tolua_Error err{};
                auto* self = (lua_type(L, 1) == LUA_TUSERDATA &&
                              tolua_isusertype(L, 1, "CCFileUtils", 0, &err))
                    ? static_cast<cocos2d::CCFileUtils*>(tolua_tousertype(L, 1, nullptr))
                    : cocos2d::CCFileUtils::sharedFileUtils();
                const char* rel = lua_tostring(L, 2);
                if (self && rel && rel[0] != '\0') {
                    for (const auto& base : self->getSearchPaths()) {
                        if (base.empty()) continue;
                        std::string cand = base;
                        if (cand.back() != '/' && cand.back() != '\\') cand.push_back('/');
                        cand += rel;
                        std::error_code ec;
                        if (std::filesystem::is_directory(cand, ec)) {
                            std::replace(cand.begin(), cand.end(), '\\', '/');
                            lua_pushlstring(L, cand.data(), cand.size());
                            return 1;
                        }
                    }
                }
                lua_pushvalue(L, lua_upvalueindex(1));
                lua_pushvalue(L, 1);
                lua_pushvalue(L, 2);
                lua_call(L, 2, 1);
                return 1;
            };
            lua_pushcclosure(L, fullPathClosure, 1);
            lua_setfield(L, -2, "fullPathForFilename");
        } else {
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    lua_getglobal(L, "package");
    if (lua_istable(L, -1)) {
        lua_pushstring(L, "");
        lua_setfield(L, -2, "path");
        lua_getfield(L, -1, "loaders");
        if (lua_istable(L, -1)) {
            const lua_CFunction loaderFn = &gclientLuaLoader;
            lua_pushcfunction(L, loaderFn);
            lua_rawseti(L, -2, 2);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

void AppDelegate::scheduleNativeLoops() {
    if (m_ticker == nullptr) {
        m_ticker = new FrameTicker();
    }

    auto bindNativeSchedulers = [this]() {
        if (m_ticker == nullptr) {
            return;
        }
        if (cocos2d::CCDirector* director = cocos2d::CCDirector::sharedDirector()) {
            if (cocos2d::CCScheduler* scheduler = director->getScheduler()) {
                using cocos2d::SEL_SCHEDULE;
                scheduler->unscheduleSelector(schedule_selector(FrameTicker::onTick), m_ticker);
                scheduler->scheduleSelector(
                    schedule_selector(FrameTicker::onTick),
                    m_ticker,
                    0.0f,
                    false);
                if (CTimer* timer = CTimer::sharedTimer()) {
                    scheduler->unscheduleAllForTarget(timer);
                    scheduler->scheduleUpdateForTarget(timer, 0, false);
                }
            }
        }
        gclient_rescheduleHttpClientCallbacks();
        RescheduleLuaHelpersCallbacks();
    };

    bindNativeSchedulers();
    BTUtil::setPostUnscheduleAllHook([bindNativeSchedulers]() {
        UnscheduleAllLuaScriptEntries();
        bindNativeSchedulers();
    });
}

void AppDelegate::unscheduleNativeLoops() {
    BTUtil::setPostUnscheduleAllHook(nullptr);
    if (m_ticker == nullptr) {
        return;
    }
    if (cocos2d::CCDirector* director = cocos2d::CCDirector::sharedDirector()) {
        if (cocos2d::CCScheduler* scheduler = director->getScheduler()) {
            scheduler->unscheduleAllForTarget(m_ticker);
        }
    }
    m_ticker->release();
    m_ticker = nullptr;
}

bool AppDelegate::runAssetValidation() {
    namespace fs = std::filesystem;

    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Running --validate-assets check against '%s'",
        m_config.resourcesDir.c_str());

    cocos2d::CCFileUtils* fileUtils = cocos2d::CCFileUtils::sharedFileUtils();
    const std::string mainScriptPath = fileUtils->fullPathForFilename("scripts/main.lua");

    if (mainScriptPath.empty() || !fs::exists(mainScriptPath)) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Missing entry script 'scripts/main.lua' under resources dir '%s'",
            m_config.resourcesDir.c_str());
        return false;
    }

    unsigned long dataSize = 0;
    unsigned char* data = fileUtils->getFileData(mainScriptPath.c_str(), "rb", &dataSize);
    if (data == nullptr || dataSize == 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Failed to read or decrypt '%s'",
            mainScriptPath.c_str());
        delete[] data;
        return false;
    }

    delete[] data;
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Validated '%s' (%lu bytes decrypted/loaded successfully)",
        mainScriptPath.c_str(),
        dataSize);
    return true;
}

bool AppDelegate::applicationDidFinishLaunching() {
    // 1. Initialize CCDirector & CCEGLView with 1136x640 design resolution and 30 FPS cap.
    cocos2d::CCDirector* pDirector = cocos2d::CCDirector::sharedDirector();
    cocos2d::CCEGLView* pEGLView = cocos2d::CCEGLView::sharedOpenGLView();
    pDirector->setOpenGLView(pEGLView);

    // Guard against 0x0 frame size (e.g., launched minimized) BEFORE kResolutionFixedWidth
    // computes designHeight = frameHeight / (frameWidth / 1136), which otherwise yields NaN!
    ensureNonZeroEglFrameSize(pEGLView, m_config.windowWidth, m_config.windowHeight);

    // ResolutionPolicy(4) in Cocos2d-x 2.2.6 == kResolutionFixedWidth.
    pEGLView->setDesignResolutionSize(kDesignWidth, kDesignHeight, kResolutionFixedWidth);
    pDirector->setAnimationInterval(kTargetAnimationInterval);

    // 2. Configure CCFileUtils search paths, writable path isolation, and bt_decrypt hook.
    configureFileUtils();

    // 3. Handle headless --validate-assets mode if requested on CLI.
    if (m_config.validateAssetsOnly) {
        m_assetValidationOk = runAssetValidation();
        pDirector->end();
        return false;
    }

    // 4. Honor --mute CLI flag before Lua scripts initialize audio.
    if (m_config.muteAudio) {
        auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine();
        audio->setBackgroundMusicVolume(0.0f);
        audio->setEffectsVolume(0.0f);
    }

    // 5. Initialize Lua engine and attach global debug.traceback() error hook.
    cocos2d::CCLuaEngine* pEngine = cocos2d::CCLuaEngine::defaultEngine();
    cocos2d::CCScriptEngineManager::sharedManager()->setScriptEngine(pEngine);

    lua_State* L = pEngine->getLuaStack()->getLuaState();
    diagnostics::CrashAndTelemetry::installLuaHooks(L);

    // 6. Register all native tolua++ / Lua extension modules.
    registerLuaBindings(L);

    // 7. Schedule native per-frame loops (bt::Platform::tickLoop, CNetwork::update, telemetry) + BTUtil hook.
    scheduleNativeLoops();

    // 8. Boot Lua game entry point.
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AppDelegate",
        "Executing Lua entry point: require \"scripts/main\"");

    const int status = pEngine->executeString("require \"scripts/main\"");
#ifdef _WIN32
    if (status == 0) {
        char autoScript[4096] = {};
        const DWORD len = ::GetEnvironmentVariableA("GCLIENT_AUTOTEST_SCRIPT", autoScript, sizeof(autoScript));
        if (len > 0 && len < sizeof(autoScript)) {
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Info, "AutoTest", "Loading autotest script: %s", autoScript);
            if (luaL_dofile(L, autoScript) != 0) {
                const char* err = lua_tostring(L, -1);
                diagnostics::CrashAndTelemetry::log(
                    diagnostics::LogLevel::Error, "AutoTest", "Script error: %s", err ? err : "(null)");
                lua_pop(L, 1);
            }
        }
    }
#endif
    {
        lua_getglobal(L, "cjson");
        const bool hasCjson = !lua_isnil(L, -1);
        lua_pop(L, 1);
        lua_getglobal(L, "g");
        bool hasLoginProxy = false;
        std::string curOS = "<nil>";
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "loginProxy");
            hasLoginProxy = !lua_isnil(L, -1);
            lua_pop(L, 1);
            lua_getfield(L, -1, "config");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "currentOS");
                if (lua_isstring(L, -1)) curOS = lua_tostring(L, -1);
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Info,
            "AppDelegate",
            "Lua DIAG: hasCjson=%d curOS=%s hasLoginProxy=%d",
            hasCjson ? 1 : 0,
            curOS.c_str(),
            hasLoginProxy ? 1 : 0);
    }
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AppDelegate",
        "After require scripts/main: status=%d runningScene=%p",
        status,
        static_cast<void*>(pDirector->getRunningScene()));
    if (status != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal,
            "AppDelegate",
            "Lua bootstrap failed (status=%d) while executing require \"scripts/main\"",
            status);
        diagnostics::CrashAndTelemetry::flushLogs();
        return false;
    }

    return true;
}

void AppDelegate::applicationDidEnterBackground() {
    cocos2d::CCDirector::sharedDirector()->stopAnimation();
    CocosDenshion::SimpleAudioEngine::sharedEngine()->pauseBackgroundMusic();
    CocosDenshion::SimpleAudioEngine::sharedEngine()->pauseAllEffects();
    diagnostics::CrashAndTelemetry::flushLogs();
}

void AppDelegate::applicationWillEnterForeground() {
    cocos2d::CCDirector* director = cocos2d::CCDirector::sharedDirector();
    cocos2d::CCEGLView* eglView = cocos2d::CCEGLView::sharedOpenGLView();
    if (isEglViewZeroOrMinimized(eglView)) {
        // Window is still minimized (0x0 client surface); defer GL animation resume
        // until restored to a valid non-zero client size.
        return;
    }
    const cocos2d::CCSize winSz = director->getWinSize();
    if (!std::isfinite(winSz.width) || !std::isfinite(winSz.height) ||
        winSz.width < 1.0f || winSz.height < 1.0f) {
        eglView->setDesignResolutionSize(kDesignWidth, kDesignHeight, kResolutionFixedWidth);
    }
    director->startAnimation();
    if (!m_config.muteAudio) {
        CocosDenshion::SimpleAudioEngine::sharedEngine()->resumeBackgroundMusic();
        CocosDenshion::SimpleAudioEngine::sharedEngine()->resumeAllEffects();
    }
}

} // namespace gclient
