// ============================================================================
// Win32 Client Win32 Port — Application Entry Point
// Handles DPI awareness, CLI parsing, lock-based persistent profile slots,
// crash/telemetry installation, and Cocos2d-x Win32 message loop bootstrap.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <fcntl.h>
#include <stdlib.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cocos2d.h"
#include "CCEGLView.h"

#include "AppDelegate.h"
#include "diagnostics/CrashAndTelemetry.h"
#include "ui/Win32DesktopBridge.h"

namespace {

namespace fs = std::filesystem;

HANDLE g_profileLockHandle = INVALID_HANDLE_VALUE;

void releaseProfileSlotLock() {
    if (g_profileLockHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(g_profileLockHandle);
        g_profileLockHandle = INVALID_HANDLE_VALUE;
    }
}

std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    const int required = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }
    std::string utf8(static_cast<std::size_t>(required), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        utf8.data(), required, nullptr, nullptr);
    return utf8;
}

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int required = ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
        nullptr, 0);
    if (required <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
        wide.data(), required);
    return wide;
}

void enableDpiAwareness() {
    // Prefer Per-Monitor V2 on Windows 10 1703+; fall back to SetProcessDPIAware.
    HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
    if (user32 != nullptr) {
        using SetDpiCtxFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto setDpiCtx = reinterpret_cast<SetDpiCtxFn>(
            ::GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (setDpiCtx != nullptr &&
            setDpiCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
            return;
        }
    }
    ::SetProcessDPIAware();
}

fs::path getExecutableDirectory() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        DWORD len = ::GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) {
            return fs::current_path();
        }
        if (len < buffer.size()) {
            buffer.resize(len);
            break;
        }
        buffer.resize(buffer.size() * 2);
    }
    return fs::path(buffer).parent_path();
}

fs::path getDefaultBaseProfileRoot() {
    PWSTR localAppData = nullptr;
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData)) &&
        localAppData != nullptr) {
        fs::path root = fs::path(localAppData) / L"GCLIENT";
        ::CoTaskMemFree(localAppData);
        return root;
    }
    if (localAppData != nullptr) {
        ::CoTaskMemFree(localAppData);
    }
    return getExecutableDirectory() / L"userdata";
}

bool parsePositiveInt(const std::string& text, int minVal, int maxVal, int& outValue) {
    if (text.empty()) {
        return false;
    }
    char* endPtr = nullptr;
    long parsed = std::strtol(text.c_str(), &endPtr, 10);
    if (endPtr == text.c_str() || *endPtr != '\0') {
        return false;
    }
    if (parsed < minVal || parsed > maxVal) {
        return false;
    }
    outValue = static_cast<int>(parsed);
    return true;
}

fs::path readEnvDir(const wchar_t* wideName, const char* narrowName) {
#ifdef _WIN32
    const DWORD required = ::GetEnvironmentVariableW(wideName, nullptr, 0);
    if (required > 1) {
        std::wstring buffer(static_cast<std::size_t>(required), L'\0');
        const DWORD copied = ::GetEnvironmentVariableW(wideName, buffer.data(), required);
        if (copied > 0 && copied < required) {
            buffer.resize(copied);
            return fs::path(buffer);
        }
    }
#else
    (void)wideName;
#endif
    if (const char* raw = std::getenv(narrowName)) {
        if (raw[0] != '\0') {
            return fs::path(utf8ToWide(raw));
        }
    }
    return {};
}

bool hasNonEmptyEnvVarW(const wchar_t* wideName) {
    return ::GetEnvironmentVariableW(wideName, nullptr, 0) > 1;
}

std::string normalizeDiscoveredPath(const fs::path& dir) {
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(dir, ec);
    if (ec || canon.empty()) {
        ec.clear();
        canon = fs::absolute(dir, ec);
    }
    return wideToUtf8((canon.empty() ? dir : canon).wstring());
}

bool hasPlatformConfigAssets(const fs::path& dir) {
    std::error_code ec;
    if (dir.empty() || !fs::is_directory(dir, ec)) {
        return false;
    }
    return fs::is_regular_file(dir / L"platform" / L"config.json", ec) ||
           fs::is_regular_file(dir / L"platform" / L"game_config.json", ec);
}

bool hasValidGameAssets(const fs::path& dir) {
    std::error_code ec;
    if (dir.empty() || !fs::is_directory(dir, ec)) {
        return false;
    }
    return hasPlatformConfigAssets(dir) ||
           fs::is_regular_file(dir / L"scripts" / L"main.lua", ec);
}

bool hasValidResourcesDir(const fs::path& dir) {
    std::error_code ec;
    if (dir.empty() || !fs::is_directory(dir, ec)) {
        return false;
    }
    return fs::is_regular_file(dir / L"scripts" / L"main.lua", ec) ||
           fs::is_directory(dir / L"database", ec);
}

std::vector<fs::path> collectSearchRoots(const fs::path& exeDir) {
    std::vector<fs::path> roots;
    if (!exeDir.empty()) {
        roots.push_back(exeDir);
    }
    std::error_code ec;
    const fs::path cwd = fs::current_path(ec);
    if (!ec && !cwd.empty() && (roots.empty() || cwd != roots.front())) {
        roots.push_back(cwd);
    }
    return roots;
}

std::string autoDiscoverBaseAssetsDir(const fs::path& exeDir) {
    // 1. Honor explicit environment variables: GCLIENT_BASE_ASSETS_DIR first, then GCLIENT_ASSETS_DIR.
    const std::pair<const wchar_t*, const char*> envVars[] = {
        { L"GCLIENT_BASE_ASSETS_DIR", "GCLIENT_BASE_ASSETS_DIR" },
        { L"GCLIENT_ASSETS_DIR",      "GCLIENT_ASSETS_DIR" },
    };
    for (const auto& [wideName, narrowName] : envVars) {
        const fs::path envDir = readEnvDir(wideName, narrowName);
        if (!envDir.empty() && hasValidGameAssets(envDir)) {
            return normalizeDiscoveredPath(envDir);
        }
    }

    const std::vector<fs::path> roots = collectSearchRoots(exeDir);

    // 2. Pass 1: Search candidate base-asset directories across all roots and depths (0..7)
    //    for platform/config.json or platform/game_config.json FIRST so Resources/scripts/main.lua
    //    never shadows base_assets/.
    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path candidates[] = {
                cur / L"base_assets",
                cur / L"assets",
                cur / L"win64-client" / L"assets",
                cur / L"GClient" / L"win64-client" / L"assets",
            };
            for (const auto& cand : candidates) {
                if (hasPlatformConfigAssets(cand)) {
                    return normalizeDiscoveredPath(cand);
                }
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    // Allow merged single-folder Resources/ layouts ONLY when Resources/ holds platform/*.json.
    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path mergedRes = cur / L"Resources";
            if (hasPlatformConfigAssets(mergedRes)) {
                return normalizeDiscoveredPath(mergedRes);
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    // 3. Pass 2: Fall back to hasValidGameAssets (scripts/main.lua) on base-asset candidates ONLY
    //    if no directory with platform/*.json exists anywhere (never matching Resources/ here).
    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path candidates[] = {
                cur / L"base_assets",
                cur / L"assets",
                cur / L"win64-client" / L"assets",
                cur / L"GClient" / L"win64-client" / L"assets",
            };
            for (const auto& cand : candidates) {
                if (hasValidGameAssets(cand)) {
                    return normalizeDiscoveredPath(cand);
                }
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    return {};
}

std::string autoDiscoverResourcesDir(const fs::path& exeDir) {
    const fs::path envRes = readEnvDir(L"GCLIENT_RESOURCES_DIR", "GCLIENT_RESOURCES_DIR");
    std::error_code ec;
    if (!envRes.empty() && fs::is_directory(envRes, ec)) {
        return normalizeDiscoveredPath(envRes);
    }

    const fs::path defaultRes = exeDir / L"Resources";
    ec.clear();
    if (!exeDir.empty() && fs::is_directory(defaultRes, ec)) {
        return normalizeDiscoveredPath(defaultRes);
    }

    const std::vector<fs::path> roots = collectSearchRoots(exeDir);
    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path candidates[] = {
                cur / L"Resources",
                cur / L"win64-client" / L"Resources",
                cur / L"GClient" / L"win64-client" / L"Resources",
            };
            for (const auto& cand : candidates) {
                if (hasValidResourcesDir(cand)) {
                    return normalizeDiscoveredPath(cand);
                }
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    return wideToUtf8(defaultRes.wstring());
}

gclient::AppConfig parseCommandLine() {
    gclient::AppConfig cfg;
    const fs::path exeDir = getExecutableDirectory();
    cfg.resourcesDir = autoDiscoverResourcesDir(exeDir);
    cfg.baseAssetsDir = autoDiscoverBaseAssetsDir(exeDir);

    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return cfg;
    }

    bool explicitResourcesDir = false;
    bool explicitBaseAssetsDir = false;

    auto takeValue = [&](int& idx, const std::string& arg, const std::string& prefix, std::string& out) -> bool {
        if (arg == prefix) {
            if (idx + 1 < argc) {
                out = wideToUtf8(argv[++idx]);
                return true;
            }
            return false;
        }
        const std::string eqPrefix = prefix + "=";
        if (arg.rfind(eqPrefix, 0) == 0) {
            out = arg.substr(eqPrefix.size());
            return true;
        }
        return false;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = wideToUtf8(argv[i]);
        std::string val;

        if (takeValue(i, arg, "--resources-dir", val)) {
            cfg.resourcesDir = val;
            explicitResourcesDir = true;
        } else if (takeValue(i, arg, "--base-assets-dir", val)) {
            cfg.baseAssetsDir = val;
            explicitBaseAssetsDir = true;
        } else if (takeValue(i, arg, "--profile-dir", val)) {
            cfg.profileDir = val;
        } else if (takeValue(i, arg, "--width", val)) {
            parsePositiveInt(val, 320, 7680, cfg.windowWidth);
        } else if (takeValue(i, arg, "--height", val)) {
            parsePositiveInt(val, 240, 4320, cfg.windowHeight);
        } else if (arg == "--mute") {
            cfg.muteAudio = true;
        } else if (arg == "--validate-assets") {
            cfg.validateAssetsOnly = true;
        }
    }

    ::LocalFree(argv);

    if (!explicitBaseAssetsDir && cfg.baseAssetsDir.empty() && !cfg.resourcesDir.empty()) {
        const fs::path resParent = fs::path(utf8ToWide(cfg.resourcesDir)).parent_path();
        if (!resParent.empty()) {
            cfg.baseAssetsDir = autoDiscoverBaseAssetsDir(resParent);
        }
    }
    if (!explicitResourcesDir && !cfg.baseAssetsDir.empty()) {
        std::error_code ec;
        if (!fs::is_directory(fs::path(utf8ToWide(cfg.resourcesDir)), ec)) {
            const fs::path baseParent = fs::path(utf8ToWide(cfg.baseAssetsDir)).parent_path();
            if (!baseParent.empty()) {
                cfg.resourcesDir = autoDiscoverResourcesDir(baseParent);
            }
        }
    }

    return cfg;
}

bool isValidSavedSessionJson(const fs::path& candidate) {
    std::error_code ec;
    if (!fs::is_regular_file(candidate, ec)) {
        return false;
    }
    std::ifstream ifs(candidate, std::ios::binary);
    if (!ifs.is_open()) {
        return false;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    const std::string json = oss.str();
    if (json.find("\"pid\"") == std::string::npos ||
        json.find("\"token\"") == std::string::npos) {
        return false;
    }
    if (json.find("win32_guest_token") != std::string::npos ||
        json.find("local_stub_session_token") != std::string::npos) {
        return false;
    }
    return true;
}

void migrateLegacyPidInstanceSessionIfNeeded(const fs::path& baseRoot, const fs::path& destSessionFile) {
    std::error_code ec;
    if (fs::is_regular_file(destSessionFile, ec)) {
        return;
    }
    const fs::path instancesDir = baseRoot / L"instances";
    if (!fs::is_directory(instancesDir, ec)) {
        return;
    }

    fs::path newestPath;
    fs::file_time_type newestTime{};
    bool found = false;

    for (const auto& entry : fs::directory_iterator(instancesDir, ec)) {
        if (!entry.is_directory(ec)) {
            continue;
        }
        const fs::path candidates[] = {
            entry.path() / L"writable" / L"vng_session.json",
            entry.path() / L"vng_session.json",
        };
        for (const auto& cand : candidates) {
            if (!isValidSavedSessionJson(cand)) {
                continue;
            }
            const auto mtime = fs::last_write_time(cand, ec);
            if (!ec && (!found || mtime > newestTime)) {
                newestTime = mtime;
                newestPath = cand;
                found = true;
            }
        }
    }

    if (found && !newestPath.empty()) {
        if (destSessionFile.has_parent_path()) {
            fs::create_directories(destSessionFile.parent_path(), ec);
        }
        fs::copy_file(newestPath, destSessionFile, fs::copy_options::overwrite_existing, ec);
    }
}

bool tryLockSlotDirectory(const fs::path& slotDir, HANDLE& outLockHandle) {
    std::error_code ec;
    fs::create_directories(slotDir, ec);
    if (ec) {
        return false;
    }
    const fs::path lockFile = slotDir / L".instance.lock";
    HANDLE h = ::CreateFileW(
        lockFile.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // Exclusive share mode: released automatically by the OS if the process exits or crashes.
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    outLockHandle = h;
    return true;
}

bool prepareIsolatedStorage(gclient::AppConfig& cfg) {
    const DWORD pid = ::GetCurrentProcessId();
    const fs::path baseRoot = getDefaultBaseProfileRoot();

    fs::path profileRoot;
    fs::path sessionFile;
    fs::path uuidFile;

    if (!cfg.profileDir.empty()) {
        // Explicit --profile-dir on CLI: isolate session, UUID, and writable state inside it.
        profileRoot = fs::path(utf8ToWide(cfg.profileDir));
        sessionFile = profileRoot / L"vng_session.json";
        uuidFile    = profileRoot / L"device_uuid.txt";
    } else if (const fs::path envProfile = readEnvDir(L"GCLIENT_PROFILE_DIR", "GCLIENT_PROFILE_DIR");
               !envProfile.empty()) {
        profileRoot = envProfile;
        sessionFile = profileRoot / L"vng_session.json";
        uuidFile    = profileRoot / L"device_uuid.txt";
    } else if (cfg.validateAssetsOnly) {
        // Headless --validate-assets check: never block a live game window's slot lock.
        profileRoot = baseRoot / L"instances" / (L"pid_" + std::to_wstring(pid));
        sessionFile = baseRoot / L"vng_session.json";
        uuidFile    = baseRoot / L"device_uuid.txt";
    } else {
        // Acquire persistent slot 1 ("profiles/default") for normal single-window play so
        // saved VNG tokens, last-selected server, SDK cookies, and writable caches persist
        // across restarts; concurrent windows automatically claim "profiles/instance_2..64".
        const fs::path primarySlot = baseRoot / L"profiles" / L"default";
        if (tryLockSlotDirectory(primarySlot, g_profileLockHandle)) {
            profileRoot = primarySlot;
            sessionFile = baseRoot / L"vng_session.json";
            uuidFile    = baseRoot / L"device_uuid.txt";
            migrateLegacyPidInstanceSessionIfNeeded(baseRoot, sessionFile);
        } else {
            bool acquiredSecondary = false;
            for (int slot = 2; slot <= 64; ++slot) {
                const fs::path slotDir = baseRoot / L"profiles" / (L"instance_" + std::to_wstring(slot));
                if (tryLockSlotDirectory(slotDir, g_profileLockHandle)) {
                    profileRoot = slotDir;
                    sessionFile = slotDir / L"vng_session.json";
                    uuidFile    = slotDir / L"device_uuid.txt";
                    acquiredSecondary = true;
                    break;
                }
            }
            if (!acquiredSecondary) {
                profileRoot = baseRoot / L"instances" / (L"pid_" + std::to_wstring(pid));
                sessionFile = profileRoot / L"vng_session.json";
                uuidFile    = profileRoot / L"device_uuid.txt";
            }
        }
    }

    std::error_code ec;
    profileRoot = fs::weakly_canonical(profileRoot, ec);
    if (ec) {
        ec.clear();
        profileRoot = fs::absolute(profileRoot, ec);
    }

    const fs::path writableDir = profileRoot / L"writable";
    const fs::path hotfixDir   = writableDir / L"hotfix";
    const fs::path cacheDir    = writableDir / L"cache";
    const fs::path logsDir     = profileRoot / L"logs";
    const fs::path dumpsDir    = profileRoot / L"dumps";

    const fs::path dirs[] = { profileRoot, writableDir, hotfixDir, cacheDir, logsDir, dumpsDir };
    for (const auto& dir : dirs) {
        fs::create_directories(dir, ec);
        if (ec) {
            return false;
        }
    }

    cfg.profileDir  = wideToUtf8(profileRoot.wstring());
    cfg.writableDir = wideToUtf8(writableDir.wstring());
    cfg.hotfixDir   = wideToUtf8(hotfixDir.wstring());
    cfg.logsDir     = wideToUtf8(logsDir.wstring());
    cfg.dumpsDir    = wideToUtf8(dumpsDir.wstring());

    // Expose resolved profile, writable, session, and device UUID paths via wide UTF-16 env vars.
    ::SetEnvironmentVariableW(L"GCLIENT_PROFILE_DIR", profileRoot.c_str());
    ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", writableDir.c_str());
    if (!sessionFile.empty() && !hasNonEmptyEnvVarW(L"GCLIENT_SESSION_FILE")) {
        ::SetEnvironmentVariableW(L"GCLIENT_SESSION_FILE", sessionFile.c_str());
    }
    if (!uuidFile.empty() && !hasNonEmptyEnvVarW(L"GCLIENT_UUID_FILE")) {
        ::SetEnvironmentVariableW(L"GCLIENT_UUID_FILE", uuidFile.c_str());
    }

    return true;
}

} // namespace

int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    // Ensure CRT file I/O defaults to binary mode (prevents 0x1A / CRLF corruption in Lua io.open).
    _set_fmode(_O_BINARY);

    // 1. Enable DPI awareness prior to any window or OpenGL surface creation.
    enableDpiAwareness();

    // 2. Parse CLI flags (--resources-dir, --base-assets-dir, --profile-dir, --width, --height, --mute, --validate-assets).
    gclient::AppConfig config = parseCommandLine();

    // 3. Provision lock-isolated persistent profile & writable storage directories.
    if (!prepareIsolatedStorage(config)) {
        releaseProfileSlotLock();
        ::MessageBoxW(
            nullptr,
            L"Failed to create isolated profile/writable directories for Win32 Client.",
            L"Win32 Client Startup Error",
            MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    // 4. Install Win32 unhandled exception minidump writer and PID-isolated rotating logger.
    gclient::diagnostics::DiagnosticsConfig diagConfig;
    diagConfig.logDirectory = config.logsDir;
    diagConfig.dumpDirectory = config.dumpsDir;
    diagConfig.appName = "gclient";
    gclient::diagnostics::CrashAndTelemetry::install(diagConfig);

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "Main",
        "Starting Win32 Client Win32 (PID=%lu, res=%dx%d, mute=%d, validateAssets=%d, resources='%s', baseAssets='%s', profile='%s')",
        static_cast<unsigned long>(::GetCurrentProcessId()),
        config.windowWidth,
        config.windowHeight,
        config.muteAudio ? 1 : 0,
        config.validateAssetsOnly ? 1 : 0,
        config.resourcesDir.c_str(),
        config.baseAssetsDir.c_str(),
        config.profileDir.c_str());

    // 5. Instantiate AppDelegate BEFORE CCEGLView::setFrameSize so WM_SIZE during window creation
    // finds a valid CCApplication::sharedApplication() instance.
    gclient::AppDelegate app(config);

    // 6. Create Cocos2d-x Win32 EGL view, attach Win32DesktopBridge, and launch AppDelegate.
    cocos2d::CCEGLView* eglView = cocos2d::CCEGLView::sharedOpenGLView();
    eglView->setViewName("Win32 Client");
    eglView->setFrameSize(
        static_cast<float>(config.windowWidth),
        static_cast<float>(config.windowHeight));
#ifdef _WIN32
    gclient::ui::Win32DesktopBridge::instance().attachToWindow(eglView->getHWnd());
#endif

    int exitCode = cocos2d::CCApplication::sharedApplication()->run();

#ifdef _WIN32
    gclient::ui::Win32DesktopBridge::instance().detach();
#endif

    if (config.validateAssetsOnly) {
        exitCode = app.assetValidationSucceeded() ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "Main",
        "Win32 Client shutting down with exit code %d",
        exitCode);
    gclient::diagnostics::CrashAndTelemetry::shutdown();
    releaseProfileSlotLock();

    return exitCode;
}
