// ============================================================================
// Win32 Client Win32 Port — Crash Handling, Rotating Logger & 30 FPS Telemetry
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "diagnostics/CrashAndTelemetry.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>
#include <crtdbg.h>
#else
#include <chrono>
#include <ctime>
#include <thread>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

namespace gclient::diagnostics {

namespace {

namespace fs = std::filesystem;

constexpr std::size_t kFrameWindowSize = 150; // 5 seconds at 30 FPS
constexpr double kSlowFrameThresholdMs = 40.0;

struct DiagnosticsState {
    std::mutex logMutex;
    std::mutex metricsMutex;

    DiagnosticsConfig config;
    std::atomic<bool> installed{false};
    std::atomic<bool> dumpInProgress{false};

    unsigned long pid = 0;
    FILE* logFile = nullptr;
    std::size_t currentLogBytes = 0;
    std::string activeLogPath;

#ifdef _WIN32
    DWORD mainThreadId = 0;
    // Pre-allocated crash-safe wide buffers (zero heap allocation in crash handler)
    wchar_t activeLogPathWide[MAX_PATH] = {};
    wchar_t dumpDirWide[MAX_PATH] = {};
    wchar_t appNameWide[64] = {};

    LPTOP_LEVEL_EXCEPTION_FILTER prevExceptionFilter = nullptr;
#endif
    std::terminate_handler prevTerminateHandler = nullptr;

    std::atomic<lua_State*> luaState{nullptr};

    // Frame-time ring buffer
    std::array<double, kFrameWindowSize> frameTimesMs{};
    std::size_t frameCursor = 0;
    std::size_t frameCountWindow = 0;
    double elapsedSinceFlushSec = 0.0;
    uint64_t totalFrames = 0;
    uint64_t slowFrames = 0;
    FrameTelemetrySnapshot latestSnapshot{};
};

DiagnosticsState& state() {
    static DiagnosticsState s;
    return s;
}

thread_local bool s_inLuaMirrorLog = false;

struct ScopedLuaMirrorGuard {
    bool prev;
    ScopedLuaMirrorGuard() noexcept : prev(s_inLuaMirrorLog) {
        s_inLuaMirrorLog = true;
    }
    ~ScopedLuaMirrorGuard() noexcept {
        s_inLuaMirrorLog = prev;
    }
};

#ifdef _WIN32
std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), needed);
    return wide;
}

std::string wideToUtf8(const wchar_t* wide) {
    if (wide == nullptr || *wide == L'\0') {
        return {};
    }
    const int len = static_cast<int>(std::wcslen(wide));
    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, wide, len, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wide, len, utf8.data(), needed, nullptr, nullptr);
    return utf8;
}

void wideToUtf8Fixed(const wchar_t* wide, char* outBuf, std::size_t outSize) noexcept {
    if (outBuf == nullptr || outSize == 0) {
        return;
    }
    outBuf[0] = '\0';
    if (wide == nullptr || *wide == L'\0') {
        return;
    }
    const int written = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        wide,
        -1,
        outBuf,
        static_cast<int>(outSize),
        nullptr,
        nullptr);
    if (written <= 0) {
        outBuf[0] = '\0';
    } else {
        outBuf[outSize - 1] = '\0';
    }
}
#endif

const char* levelToTag(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
    }
    return "INFO ";
}

void formatTimestamp(char* outBuf, std::size_t outSize) {
#ifdef _WIN32
    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    std::snprintf(
        outBuf,
        outSize,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    const std::time_t tt = system_clock::to_time_t(now);
    std::tm tmLocal{};
    localtime_r(&tt, &tmLocal);
    std::snprintf(
        outBuf,
        outSize,
        "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        tmLocal.tm_year + 1900, tmLocal.tm_mon + 1, tmLocal.tm_mday,
        tmLocal.tm_hour, tmLocal.tm_min, tmLocal.tm_sec,
        static_cast<int>(ms.count()));
#endif
}

bool openLogFileLocked(DiagnosticsState& s) {
    if (s.logFile != nullptr) {
        std::fclose(s.logFile);
        s.logFile = nullptr;
    }
#ifdef _WIN32
    const std::wstring wpath = utf8ToWide(s.activeLogPath);
    ::wcsncpy_s(s.activeLogPathWide, _countof(s.activeLogPathWide), wpath.c_str(), _TRUNCATE);
    s.logFile = ::_wfopen(s.activeLogPathWide, L"ab");
    if (s.logFile == nullptr) {
        return false;
    }
    std::error_code ec;
    s.currentLogBytes = static_cast<std::size_t>(fs::file_size(fs::path(wpath), ec));
#else
    s.logFile = std::fopen(s.activeLogPath.c_str(), "ab");
    if (s.logFile == nullptr) {
        return false;
    }
    std::error_code ec;
    s.currentLogBytes = static_cast<std::size_t>(fs::file_size(fs::path(s.activeLogPath), ec));
#endif
    if (ec) {
        s.currentLogBytes = 0;
    }
    return true;
}

fs::path toFsPath(const std::string& utf8Path) {
#ifdef _WIN32
    return fs::path(utf8ToWide(utf8Path));
#else
    return fs::path(utf8Path);
#endif
}

void rotateLogFilesLocked(DiagnosticsState& s) {
    if (s.logFile != nullptr) {
        std::fflush(s.logFile);
        std::fclose(s.logFile);
        s.logFile = nullptr;
    }

    const std::size_t backups = std::max<std::size_t>(1, s.config.maxLogBackups);
    std::error_code ec;

    // Delete oldest backup
    const fs::path oldest = toFsPath(s.activeLogPath + "." + std::to_string(backups));
    fs::remove(oldest, ec);
    ec.clear();

    // Shift .N-1 -> .N
    for (std::size_t i = backups - 1; i >= 1; --i) {
        const fs::path src = toFsPath(s.activeLogPath + "." + std::to_string(i));
        const fs::path dst = toFsPath(s.activeLogPath + "." + std::to_string(i + 1));
        if (fs::exists(src, ec)) {
            fs::rename(src, dst, ec);
            ec.clear();
        }
    }

    // Move active -> .1
    const fs::path activePath = toFsPath(s.activeLogPath);
    const fs::path firstBackup = toFsPath(s.activeLogPath + ".1");
    if (fs::exists(activePath, ec)) {
        fs::rename(activePath, firstBackup, ec);
        ec.clear();
    }

    openLogFileLocked(s);
}

#ifdef _WIN32
// ============================================================================
// 100% Crash-Safe Win32 Exception Diagnostics (Static BSS, POD-Only SEH)
// ============================================================================

struct CrashModuleEntry {
    uintptr_t base;
    DWORD size;
    char name[64];
    char path[MAX_PATH];
};

constexpr std::size_t kMaxCrashModules = 256;
constexpr int kMaxNativeStackFrames = 48;
constexpr int kMaxLuaStackFrames = 32;

volatile LONG g_crashFilterLock = 0;
char g_crashLineBuf[2048] = {};
CrashModuleEntry g_crashModules[kMaxCrashModules] = {};
std::size_t g_crashModuleCount = 0;
MODULEENTRY32W g_crashMe32 = {};
CONTEXT g_crashWalkContext = {};
alignas(SYMBOL_INFO) char g_crashSymBuf[sizeof(SYMBOL_INFO) + 256] = {};
wchar_t g_crashExeDirWide[MAX_PATH] = {};
wchar_t g_crashDumpPathWide[MAX_PATH] = {};
char g_crashDumpPathUtf8[MAX_PATH * 3] = {};

DWORD64 ptrToDword64NoSignExtend(const void* p) noexcept {
    return static_cast<DWORD64>(reinterpret_cast<uintptr_t>(p));
}

DWORD64 uptrToDword64NoSignExtend(uintptr_t v) noexcept {
    return static_cast<DWORD64>(v);
}

const char* exceptionCodeToName(DWORD code) noexcept {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
        case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
        case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
        case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
        case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
        case 0xE06D7363UL:                       return "CPP_EH_EXCEPTION";
        case 0xC0000374UL:                       return "STATUS_HEAP_CORRUPTION";
        case 0xC0000409UL:                       return "STATUS_STACK_BUFFER_OVERRUN";
        default:                                 return "UNKNOWN_WIN32_EXCEPTION";
    }
}

const char* accessViolationOpName(ULONG_PTR opCode) noexcept {
    switch (opCode) {
        case 0:  return "READ";
        case 1:  return "WRITE";
        case 8:  return "EXECUTE/DEP";
        default: return "UNKNOWN";
    }
}

const char* poisonPatternHint(uintptr_t addr) noexcept {
    if (addr == 0u) {
        return "NULL (nullptr dereference)";
    }
    if (addr < 0x10000u) {
        return "NULL+offset (near-null struct member dereference)";
    }
    const uint32_t low32 = static_cast<uint32_t>(addr);
    if (low32 == 0xDDDDDDDDu || (low32 & 0xFFFF0000u) == 0xDDDD0000u) {
        return "0xDDDDDDDD (CRT debug freed heap memory / use-after-free)";
    }
    if (low32 == 0xFEEEFEEEu || (low32 & 0xFFFF0000u) == 0xFEEE0000u) {
        return "0xFEEEFEEE (Win32 HeapFree freed block / use-after-free)";
    }
    if (low32 == 0xCDCDCDCDu || (low32 & 0xFFFF0000u) == 0xCDCD0000u) {
        return "0xCDCDCDCD (CRT debug uninitialized heap memory)";
    }
    if (low32 == 0xCCCCCCCCu || (low32 & 0xFFFF0000u) == 0xCCCC0000u) {
        return "0xCCCCCCCC (MSVC uninitialized stack memory)";
    }
    if (low32 == 0xFDFDFDFDu) {
        return "0xFDFDFDFD (CRT heap no-man's-land guard)";
    }
    if (low32 == 0xBAADF00Du) {
        return "0xBAADF00D (Win32 LocalAlloc uninitialized heap)";
    }
    return "none";
}

void crashWriteRaw(HANDLE hLog, const char* text, std::size_t len) noexcept {
    if (text == nullptr || len == 0) {
        return;
    }
    ::OutputDebugStringA(text);
    if (hLog != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        (void)::WriteFile(hLog, text, static_cast<DWORD>(len), &written, nullptr);
    }
}

#ifdef __GNUC__
__attribute__((format(printf, 2, 3)))
#endif
void crashWriteLine(HANDLE hLog, const char* fmt, ...) noexcept {
    char ts[40] = {};
    formatTimestamp(ts, sizeof(ts));
    const unsigned long tid = static_cast<unsigned long>(::GetCurrentThreadId());

    int prefixLen = std::snprintf(
        g_crashLineBuf,
        sizeof(g_crashLineBuf),
        "[%s] [FATAL] [T:%05lu] [Crash] ",
        ts,
        tid);
    if (prefixLen < 0) {
        prefixLen = 0;
    } else if (static_cast<std::size_t>(prefixLen) >= sizeof(g_crashLineBuf) - 2) {
        prefixLen = static_cast<int>(sizeof(g_crashLineBuf) - 2);
    }

    va_list args;
    va_start(args, fmt);
    const std::size_t rem = sizeof(g_crashLineBuf) - static_cast<std::size_t>(prefixLen) - 1;
    int bodyLen = std::vsnprintf(g_crashLineBuf + prefixLen, rem, fmt, args);
    va_end(args);

    std::size_t total = static_cast<std::size_t>(prefixLen);
    if (bodyLen > 0) {
        const std::size_t added = static_cast<std::size_t>(bodyLen);
        total += (added < rem) ? added : (rem - 1);
    }
    if (total + 1 < sizeof(g_crashLineBuf)) {
        g_crashLineBuf[total++] = '\n';
        g_crashLineBuf[total] = '\0';
    } else {
        g_crashLineBuf[sizeof(g_crashLineBuf) - 2] = '\n';
        g_crashLineBuf[sizeof(g_crashLineBuf) - 1] = '\0';
        total = sizeof(g_crashLineBuf) - 1;
    }

    crashWriteRaw(hLog, g_crashLineBuf, total);
}

void tryLockAndFlushStdioBuffer(DiagnosticsState* s) noexcept {
    if (s == nullptr) {
        return;
    }
    if (s->logMutex.try_lock()) {
        if (s->logFile != nullptr) {
            std::fflush(s->logFile);
        }
        s->logMutex.unlock();
    }
}

// POD-only SEH wrapper (zero C++ objects with destructors -> satisfies MSVC /EHsc C2712).
void sehTryFlushPendingLogBuffer(DiagnosticsState* s) {
    __try {
        tryLockAndFlushStdioBuffer(s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void snapshotLoadedModules() noexcept {
    g_crashModuleCount = 0;
    HANDLE hSnap = ::CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        ::GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    std::memset(&g_crashMe32, 0, sizeof(g_crashMe32));
    g_crashMe32.dwSize = sizeof(MODULEENTRY32W);

    if (::Module32FirstW(hSnap, &g_crashMe32)) {
        do {
            if (g_crashModuleCount >= kMaxCrashModules) {
                break;
            }
            CrashModuleEntry& dst = g_crashModules[g_crashModuleCount++];
            dst.base = reinterpret_cast<uintptr_t>(g_crashMe32.modBaseAddr);
            dst.size = g_crashMe32.modBaseSize;
            wideToUtf8Fixed(g_crashMe32.szModule, dst.name, sizeof(dst.name));
            wideToUtf8Fixed(g_crashMe32.szExePath, dst.path, sizeof(dst.path));
        } while (::Module32NextW(hSnap, &g_crashMe32));
    }

    ::CloseHandle(hSnap);
}

const CrashModuleEntry* findCrashModule(uintptr_t addr) noexcept {
    for (std::size_t i = 0; i < g_crashModuleCount; ++i) {
        const CrashModuleEntry& m = g_crashModules[i];
        if (addr >= m.base && (addr - m.base) < static_cast<uintptr_t>(m.size)) {
            return &m;
        }
    }
    return nullptr;
}

void populateSymbolSearchPath() noexcept {
    g_crashExeDirWide[0] = L'\0';
    const DWORD n = ::GetModuleFileNameW(nullptr, g_crashExeDirWide, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        g_crashExeDirWide[0] = L'\0';
        return;
    }
    for (DWORD i = n; i > 0; --i) {
        const wchar_t ch = g_crashExeDirWide[i - 1];
        if (ch == L'\\' || ch == L'/') {
            g_crashExeDirWide[i - 1] = L'\0';
            return;
        }
    }
    g_crashExeDirWide[0] = L'\0';
}

// POD-only SEH native x86 stack walker (zero C++ objects with destructors -> MSVC C2712 clean).
void sehWalkNativeStack(HANDLE hLog, const CONTEXT* origCtx) {
    if (origCtx == nullptr) {
        crashWriteLine(hLog, "  <ContextRecord is null; native stack walk unavailable>");
        return;
    }

    __try {
        g_crashWalkContext = *origCtx;

        HANDLE hProcess = ::GetCurrentProcess();
        HANDLE hThread = ::GetCurrentThread();

        ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
        populateSymbolSearchPath();
        const wchar_t* symPath = (g_crashExeDirWide[0] != L'\0') ? g_crashExeDirWide : nullptr;
        const BOOL symInitByUs = ::SymInitializeW(hProcess, symPath, TRUE);

        STACKFRAME64 frame{};
        DWORD machineType = IMAGE_FILE_MACHINE_I386;
#if defined(_M_IX86) || defined(__i386__)
        machineType = IMAGE_FILE_MACHINE_I386;
        frame.AddrPC.Offset    = uptrToDword64NoSignExtend(static_cast<uintptr_t>(g_crashWalkContext.Eip));
        frame.AddrPC.Mode      = AddrModeFlat;
        frame.AddrFrame.Offset = uptrToDword64NoSignExtend(static_cast<uintptr_t>(g_crashWalkContext.Ebp));
        frame.AddrFrame.Mode   = AddrModeFlat;
        frame.AddrStack.Offset = uptrToDword64NoSignExtend(static_cast<uintptr_t>(g_crashWalkContext.Esp));
        frame.AddrStack.Mode   = AddrModeFlat;
#elif defined(_M_X64) || defined(__x86_64__)
        machineType = IMAGE_FILE_MACHINE_AMD64;
        frame.AddrPC.Offset    = static_cast<DWORD64>(g_crashWalkContext.Rip);
        frame.AddrPC.Mode      = AddrModeFlat;
        frame.AddrFrame.Offset = static_cast<DWORD64>(g_crashWalkContext.Rbp);
        frame.AddrFrame.Mode   = AddrModeFlat;
        frame.AddrStack.Offset = static_cast<DWORD64>(g_crashWalkContext.Rsp);
        frame.AddrStack.Mode   = AddrModeFlat;
#endif

        for (int idx = 0; idx < kMaxNativeStackFrames; ++idx) {
            const BOOL walked = ::StackWalk64(
                machineType,
                hProcess,
                hThread,
                &frame,
                &g_crashWalkContext,
                nullptr,
                &::SymFunctionTableAccess64,
                &::SymGetModuleBase64,
                nullptr);
            if (!walked || frame.AddrPC.Offset == 0) {
                break;
            }

            const DWORD64 pc64 = frame.AddrPC.Offset;
            const uintptr_t pcPtr = static_cast<uintptr_t>(pc64);
            const CrashModuleEntry* mod = findCrashModule(pcPtr);
            const char* modName = mod ? mod->name : "<unknown>";
            const unsigned long long rva = mod
                ? static_cast<unsigned long long>(pcPtr - mod->base)
                : 0ULL;

            std::memset(g_crashSymBuf, 0, sizeof(g_crashSymBuf));
            auto* sym = reinterpret_cast<SYMBOL_INFO*>(g_crashSymBuf);
            sym->SizeOfStruct = sizeof(SYMBOL_INFO);
            sym->MaxNameLen = 255;
            DWORD64 symDisp = 0;
            const BOOL hasSym = ::SymFromAddr(hProcess, pc64, &symDisp, sym);

            IMAGEHLP_LINE64 lineInfo{};
            lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD lineDisp = 0;
            const BOOL hasLine = ::SymGetLineFromAddr64(hProcess, pc64, &lineDisp, &lineInfo);

            const char* symName = (hasSym && sym->Name[0] != '\0') ? sym->Name : "<nosym>";
            if (hasLine && lineInfo.FileName != nullptr) {
                crashWriteLine(
                    hLog,
                    "  #%02d 0x%08llX %s!%s+0x%llX [%s+0x%llX] (%s:%lu)",
                    idx,
                    static_cast<unsigned long long>(pc64),
                    modName,
                    symName,
                    static_cast<unsigned long long>(symDisp),
                    modName,
                    rva,
                    lineInfo.FileName,
                    static_cast<unsigned long>(lineInfo.LineNumber));
            } else {
                crashWriteLine(
                    hLog,
                    "  #%02d 0x%08llX %s!%s+0x%llX [%s+0x%llX]",
                    idx,
                    static_cast<unsigned long long>(pc64),
                    modName,
                    symName,
                    static_cast<unsigned long long>(symDisp),
                    modName,
                    rva);
            }
        }

        if (symInitByUs) {
            ::SymCleanup(hProcess);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        crashWriteLine(
            hLog,
            "  <SEH exception 0x%08lX during StackWalk64>",
            static_cast<unsigned long>(::GetExceptionCode()));
    }
}

// POD-only SEH Lua 5.1 / LuaJIT frame walker ("Sln" ONLY — never 't'!).
void sehDumpLuaCallFrames(HANDLE hLog, lua_State* L) {
    if (L == nullptr) {
        crashWriteLine(hLog, "  <lua_State is null / detached>");
        return;
    }

    __try {
        int dumped = 0;
        for (int level = 0; level < kMaxLuaStackFrames; ++level) {
            lua_Debug ar{};
            if (lua_getstack(L, level, &ar) == 0) {
                break;
            }
            // CRITICAL: Lua 5.1 / LuaJIT supports 'S', 'l', 'n', 'u', 'f', 'L' — NOT 't' (Lua 5.2+).
            if (lua_getinfo(L, "Sln", &ar) != 0) {
                const char* what = ar.what ? ar.what : "?";
                const char* name = (ar.name && ar.name[0] != '\0') ? ar.name : "<anon>";
                const char* namewhat = (ar.namewhat && ar.namewhat[0] != '\0') ? ar.namewhat : "";
                const char* src = ar.short_src[0] != '\0'
                    ? ar.short_src
                    : (ar.source ? ar.source : "<unknown>");
                crashWriteLine(
                    hLog,
                    "  #%02d [%s] %s%s%s at %s:%d (defined:%d)",
                    level,
                    what,
                    namewhat,
                    namewhat[0] != '\0' ? " " : "",
                    name,
                    src,
                    ar.currentline,
                    ar.linedefined);
            } else {
                crashWriteLine(hLog, "  #%02d <lua_getinfo(\"Sln\") returned 0>", level);
            }
            ++dumped;
        }
        if (dumped == 0) {
            crashWriteLine(hLog, "  <no active Lua call frames on bound lua_State>");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        crashWriteLine(
            hLog,
            "  <SEH exception 0x%08lX while walking Lua stack>",
            static_cast<unsigned long>(::GetExceptionCode()));
    }
}

bool writeMinidumpInternal(EXCEPTION_POINTERS* exPtrs, wchar_t* outPath, std::size_t outPathChars) {
    DiagnosticsState& s = state();
    bool expected = false;
    if (!s.dumpInProgress.compare_exchange_strong(expected, true)) {
        return false;
    }

    SYSTEMTIME st{};
    ::GetLocalTime(&st);

    wchar_t dumpPath[MAX_PATH] = {};
    ::_snwprintf_s(
        dumpPath,
        _countof(dumpPath),
        _TRUNCATE,
        L"%ls\\%ls_pid%lu_%04u%02u%02u_%02u%02u%02u.dmp",
        s.dumpDirWide,
        s.appNameWide,
        s.pid,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    HANDLE hFile = ::CreateFileW(
        dumpPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    bool ok = false;
    if (hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mei{};
        mei.ThreadId = ::GetCurrentThreadId();
        mei.ExceptionPointers = exPtrs;
        mei.ClientPointers = FALSE;

        DWORD dumpType = MiniDumpWithDataSegs |
                         MiniDumpWithHandleData |
                         MiniDumpWithThreadInfo |
                         MiniDumpWithUnloadedModules |
                         MiniDumpWithIndirectlyReferencedMemory;
        if (s.config.enableFullMemoryDump) {
            dumpType |= MiniDumpWithFullMemory;
        }

        ok = ::MiniDumpWriteDump(
            ::GetCurrentProcess(),
            static_cast<DWORD>(s.pid),
            hFile,
            static_cast<MINIDUMP_TYPE>(dumpType),
            exPtrs != nullptr ? &mei : nullptr,
            nullptr,
            nullptr) == TRUE;

        ::CloseHandle(hFile);
    }

    if (outPath != nullptr && outPathChars > 0) {
        ::wcsncpy_s(outPath, outPathChars, dumpPath, _TRUNCATE);
    }

    s.dumpInProgress.store(false);
    return ok;
}

LONG WINAPI unhandledExceptionFilter(EXCEPTION_POINTERS* exPtrs) {
    if (::InterlockedCompareExchange(&g_crashFilterLock, 1, 0) != 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DiagnosticsState& s = state();

    // 1. Non-blocking stdio flush attempt inside POD SEH helper (never blocks on logMutex).
    sehTryFlushPendingLogBuffer(&s);

    // 2. Open activeLogPathWide directly in append mode for crash-safe Win32 WriteFile output.
    HANDLE hLog = INVALID_HANDLE_VALUE;
    if (s.activeLogPathWide[0] != L'\0') {
        hLog = ::CreateFileW(
            s.activeLogPathWide,
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (hLog != INVALID_HANDLE_VALUE) {
            ::SetFilePointer(hLog, 0, nullptr, FILE_END);
        }
    }

    const EXCEPTION_RECORD* er = exPtrs ? exPtrs->ExceptionRecord : nullptr;
    const CONTEXT* ctx = exPtrs ? exPtrs->ContextRecord : nullptr;
    const DWORD code = er ? er->ExceptionCode : 0;
    const void* exAddrPtr = er ? er->ExceptionAddress : nullptr;
    const uintptr_t exAddr = reinterpret_cast<uintptr_t>(exAddrPtr);
    const DWORD crashTid = ::GetCurrentThreadId();
    const DWORD mainTid = s.mainThreadId;

    crashWriteLine(hLog, "================ UNHANDLED WIN32 EXCEPTION ================");
    crashWriteLine(
        hLog,
        "Exception: %s (0x%08lX) at 0x%08llX | CrashTID=%lu MainTID=%lu (%s)",
        exceptionCodeToName(code),
        static_cast<unsigned long>(code),
        static_cast<unsigned long long>(ptrToDword64NoSignExtend(exAddrPtr)),
        static_cast<unsigned long>(crashTid),
        static_cast<unsigned long>(mainTid),
        (crashTid == mainTid) ? "MAIN_THREAD" : "WORKER_THREAD");

    if (er != nullptr &&
        (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) &&
        er->NumberParameters >= 2) {
        const ULONG_PTR opCode = er->ExceptionInformation[0];
        const uintptr_t targetAddr = static_cast<uintptr_t>(er->ExceptionInformation[1]);
        crashWriteLine(
            hLog,
            "Access Fault: op=%s target=0x%08llX hint=%s",
            accessViolationOpName(opCode),
            static_cast<unsigned long long>(uptrToDword64NoSignExtend(targetAddr)),
            poisonPatternHint(targetAddr));
    }

    // 3. Snapshot loaded modules & log exact faulting ModuleName + 0xRVA.
    snapshotLoadedModules();
    const CrashModuleEntry* faultMod = findCrashModule(exAddr);
    if (faultMod != nullptr) {
        const unsigned long long faultRva = static_cast<unsigned long long>(exAddr - faultMod->base);
        crashWriteLine(
            hLog,
            "Faulting Module: %s + 0x%llX [base=0x%08llX, size=0x%08lX, path=%s]",
            faultMod->name,
            faultRva,
            static_cast<unsigned long long>(uptrToDword64NoSignExtend(faultMod->base)),
            static_cast<unsigned long>(faultMod->size),
            faultMod->path);
    } else {
        crashWriteLine(
            hLog,
            "Faulting Module: <unmapped/JIT/heap> at 0x%08llX (hint=%s)",
            static_cast<unsigned long long>(uptrToDword64NoSignExtend(exAddr)),
            poisonPatternHint(exAddr));
    }

    // 4. Log x86 CPU registers (resolving EIP and ECX/this module+RVA).
    if (ctx != nullptr) {
#if defined(_M_IX86) || defined(__i386__)
        crashWriteLine(
            hLog,
            "Registers x86: EAX=0x%08lX EBX=0x%08lX ECX=0x%08lX EDX=0x%08lX ESI=0x%08lX EDI=0x%08lX",
            static_cast<unsigned long>(ctx->Eax),
            static_cast<unsigned long>(ctx->Ebx),
            static_cast<unsigned long>(ctx->Ecx),
            static_cast<unsigned long>(ctx->Edx),
            static_cast<unsigned long>(ctx->Esi),
            static_cast<unsigned long>(ctx->Edi));
        crashWriteLine(
            hLog,
            "Registers x86: EBP=0x%08lX ESP=0x%08lX EIP=0x%08lX EFLAGS=0x%08lX",
            static_cast<unsigned long>(ctx->Ebp),
            static_cast<unsigned long>(ctx->Esp),
            static_cast<unsigned long>(ctx->Eip),
            static_cast<unsigned long>(ctx->EFlags));

        const uintptr_t eipVal = static_cast<uintptr_t>(ctx->Eip);
        if (const CrashModuleEntry* eipMod = findCrashModule(eipVal)) {
            crashWriteLine(
                hLog,
                "  EIP -> %s + 0x%llX",
                eipMod->name,
                static_cast<unsigned long long>(eipVal - eipMod->base));
        } else {
            crashWriteLine(
                hLog,
                "  EIP -> <unmapped 0x%08llX> (hint=%s)",
                static_cast<unsigned long long>(uptrToDword64NoSignExtend(eipVal)),
                poisonPatternHint(eipVal));
        }

        const uintptr_t ecxVal = static_cast<uintptr_t>(ctx->Ecx);
        if (const CrashModuleEntry* ecxMod = findCrashModule(ecxVal)) {
            crashWriteLine(
                hLog,
                "  ECX(this) -> %s + 0x%llX",
                ecxMod->name,
                static_cast<unsigned long long>(ecxVal - ecxMod->base));
        } else {
            crashWriteLine(
                hLog,
                "  ECX(this) -> 0x%08llX (hint=%s)",
                static_cast<unsigned long long>(uptrToDword64NoSignExtend(ecxVal)),
                poisonPatternHint(ecxVal));
        }
#elif defined(_M_X64) || defined(__x86_64__)
        crashWriteLine(
            hLog,
            "Registers x64: RAX=0x%016llX RBX=0x%016llX RCX=0x%016llX RDX=0x%016llX",
            static_cast<unsigned long long>(ctx->Rax),
            static_cast<unsigned long long>(ctx->Rbx),
            static_cast<unsigned long long>(ctx->Rcx),
            static_cast<unsigned long long>(ctx->Rdx));
        crashWriteLine(
            hLog,
            "Registers x64: RSI=0x%016llX RDI=0x%016llX RBP=0x%016llX RSP=0x%016llX RIP=0x%016llX EFLAGS=0x%08lX",
            static_cast<unsigned long long>(ctx->Rsi),
            static_cast<unsigned long long>(ctx->Rdi),
            static_cast<unsigned long long>(ctx->Rbp),
            static_cast<unsigned long long>(ctx->Rsp),
            static_cast<unsigned long long>(ctx->Rip),
            static_cast<unsigned long>(ctx->EFlags));
#endif
    }

    // 5. Walk up to 48 native stack frames on a COPY of CONTEXT.
    crashWriteLine(hLog, "Native Call Stack (max %d frames):", kMaxNativeStackFrames);
    sehWalkNativeStack(hLog, ctx);

    // 6. Walk up to 32 active Lua call frames inside POD SEH helper ("Sln").
    crashWriteLine(hLog, "Active Lua Call Stack (max %d frames):", kMaxLuaStackFrames);
    lua_State* L = s.luaState.load(std::memory_order_acquire);
    sehDumpLuaCallFrames(hLog, L);

    // 7. Compact loaded modules list (base..end size name).
    crashWriteLine(
        hLog,
        "Loaded Modules (%lu):",
        static_cast<unsigned long>(g_crashModuleCount));
    for (std::size_t i = 0; i < g_crashModuleCount; ++i) {
        const CrashModuleEntry& m = g_crashModules[i];
        const unsigned long long base64 = uptrToDword64NoSignExtend(m.base);
        const unsigned long long end64 = base64 + static_cast<unsigned long long>(m.size);
        crashWriteLine(
            hLog,
            "  [%02lu] 0x%08llX..0x%08llX size=0x%08lX %s",
            static_cast<unsigned long>(i),
            base64,
            end64,
            static_cast<unsigned long>(m.size),
            m.name);
    }

    // CRITICAL: Flush diagnostic crash log to disk BEFORE invoking MiniDumpWriteDump!
    if (hLog != INVALID_HANDLE_VALUE) {
        ::FlushFileBuffers(hLog);
    }

    // 8. Write .dmp minidump and append its path to the log.
    g_crashDumpPathWide[0] = L'\0';
    const bool dumped = writeMinidumpInternal(exPtrs, g_crashDumpPathWide, _countof(g_crashDumpPathWide));
    wideToUtf8Fixed(g_crashDumpPathWide, g_crashDumpPathUtf8, sizeof(g_crashDumpPathUtf8));

    crashWriteLine(
        hLog,
        "Minidump %s: %s",
        dumped ? "written" : "FAILED",
        g_crashDumpPathUtf8[0] != '\0' ? g_crashDumpPathUtf8 : "<none>");
    crashWriteLine(hLog, "===========================================================");

    if (hLog != INVALID_HANDLE_VALUE) {
        ::FlushFileBuffers(hLog);
        ::CloseHandle(hLog);
    }

    ::InterlockedExchange(&g_crashFilterLock, 0);

    if (s.prevExceptionFilter != nullptr) {
        return s.prevExceptionFilter(exPtrs);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

void onInvalidParameter(
    const wchar_t* /*expression*/,
    const wchar_t* /*function*/,
    const wchar_t* /*file*/,
    unsigned int /*line*/,
    uintptr_t /*pReserved*/)
{
    CrashAndTelemetry::log(
        LogLevel::Fatal,
        "Crash",
        "CRT invalid parameter handler triggered. Writing diagnostic minidump.");
    CrashAndTelemetry::writeMinidumpNow("crt_invalid_parameter");
    CrashAndTelemetry::flushLogs();
    std::abort();
}

void onPureCall() {
    CrashAndTelemetry::log(
        LogLevel::Fatal,
        "Crash",
        "CRT pure virtual function call detected. Writing diagnostic minidump.");
    CrashAndTelemetry::writeMinidumpNow("crt_purecall");
    CrashAndTelemetry::flushLogs();
    std::abort();
}
#endif

void onTerminate() {
    CrashAndTelemetry::log(
        LogLevel::Fatal,
        "Crash",
        "std::terminate invoked (unhandled C++ exception). Writing diagnostic minidump.");
    CrashAndTelemetry::writeMinidumpNow("std_terminate");
    CrashAndTelemetry::flushLogs();
    std::abort();
}

int luaPanicHandler(lua_State* L) {
    const char* msg = lua_tostring(L, -1);
    CrashAndTelemetry::log(
        LogLevel::Fatal,
        "LuaPanic",
        "Unprotected Lua error: %s",
        msg ? msg : "(non-string error)");
    CrashAndTelemetry::writeMinidumpNow("lua_panic");
    CrashAndTelemetry::flushLogs();
    return 0;
}

bool hasAppDelegateLuaPrintShim(lua_State* L) {
    if (L == nullptr) {
        return false;
    }
    lua_getglobal(L, "__GCLIENT_LOG_INFO__");
    const bool present = lua_isfunction(L, -1);
    lua_pop(L, 1);
    return present;
}

int luaPrintHandler(lua_State* L) {
    if (s_inLuaMirrorLog) {
        return 0;
    }
    ScopedLuaMirrorGuard mirrorGuard;

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
    CrashAndTelemetry::log(LogLevel::Info, "Lua", "%s", out.c_str());
    return 0;
}

int luaPrintForwardingClosure(lua_State* L) {
    // If AppDelegate's _G metatable shim (__GCLIENT_LOG_INFO__) is installed, it has already
    // logged [Lua] before forwarding to this original closure — skip duplicate logging!
    if (!s_inLuaMirrorLog && !hasAppDelegateLuaPrintShim(L)) {
        luaPrintHandler(L);
    }

    if (lua_isfunction(L, lua_upvalueindex(1))) {
        ScopedLuaMirrorGuard mirrorGuard;
        const int nargs = lua_gettop(L);
        lua_pushvalue(L, lua_upvalueindex(1));
        for (int i = 1; i <= nargs; ++i) {
            lua_pushvalue(L, i);
        }
        if (lua_pcall(L, nargs, 0, 0) != 0) {
            lua_pop(L, 1);
        }
    }
    return 0;
}

void installMirroredPrintGlobal(lua_State* L, const char* globalName) {
    lua_getglobal(L, globalName);
    if (lua_isfunction(L, -1) &&
        lua_tocfunction(L, -1) != &luaPrintHandler &&
        lua_tocfunction(L, -1) != &luaPrintForwardingClosure) {
        lua_pushcclosure(L, &luaPrintForwardingClosure, 1);
        lua_setglobal(L, globalName);
    } else {
        lua_pop(L, 1);
        const lua_CFunction printFn = &luaPrintHandler;
        lua_pushcfunction(L, printFn);
        lua_setglobal(L, globalName);
    }
}

unsigned long currentThreadIdNumeric() {
#ifdef _WIN32
    return static_cast<unsigned long>(::GetCurrentThreadId());
#else
    return static_cast<unsigned long>(
        std::hash<std::thread::id>{}(std::this_thread::get_id()) & 0xFFFFFul);
#endif
}

} // namespace

// ----------------------------------------------------------------------------
// Public CrashAndTelemetry API
// ----------------------------------------------------------------------------
bool CrashAndTelemetry::install(const DiagnosticsConfig& config) {
    DiagnosticsState& s = state();
    if (s.installed.exchange(true)) {
        return true;
    }

    s.config = config;
#ifdef _WIN32
    s.pid = static_cast<unsigned long>(::GetCurrentProcessId());
    s.mainThreadId = ::GetCurrentThreadId();
#else
    s.pid = static_cast<unsigned long>(::getpid());
#endif

    std::error_code ec;
    const fs::path logDir = toFsPath(config.logDirectory.empty() ? "." : config.logDirectory);
    const fs::path dumpDir = toFsPath(config.dumpDirectory.empty() ? "." : config.dumpDirectory);
    fs::create_directories(logDir, ec);
    ec.clear();
    fs::create_directories(dumpDir, ec);

    // PID-isolated log file: <logDir>/<appName>_pid<PID>.log
    const std::string logName =
        (config.appName.empty() ? "gclient" : config.appName) +
        "_pid" + std::to_string(s.pid) + ".log";

#ifdef _WIN32
    ::wcsncpy_s(s.dumpDirWide, _countof(s.dumpDirWide), dumpDir.c_str(), _TRUNCATE);
    const std::wstring appW = utf8ToWide(config.appName.empty() ? "gclient" : config.appName);
    ::wcsncpy_s(s.appNameWide, _countof(s.appNameWide), appW.c_str(), _TRUNCATE);
    s.activeLogPath = wideToUtf8((logDir / utf8ToWide(logName)).c_str());
#else
    s.activeLogPath = (logDir / logName).string();
#endif

    {
        std::lock_guard<std::mutex> lock(s.logMutex);
        openLogFileLocked(s);
    }

#ifdef _WIN32
    s.prevExceptionFilter = ::SetUnhandledExceptionFilter(&unhandledExceptionFilter);
    ::_set_invalid_parameter_handler(&onInvalidParameter);
    ::_set_purecall_handler(&onPureCall);
#endif
    s.prevTerminateHandler = std::set_terminate(&onTerminate);

    const std::string dumpDirStr =
#ifdef _WIN32
        wideToUtf8(s.dumpDirWide);
#else
        dumpDir.string();
#endif

    log(LogLevel::Info, "Diagnostics",
        "CrashAndTelemetry installed (log='%s', dumps='%s')",
        s.activeLogPath.c_str(),
        dumpDirStr.c_str());
    return true;
}

void CrashAndTelemetry::shutdown() {
    DiagnosticsState& s = state();
    if (!s.installed.exchange(false)) {
        return;
    }

    flushLogs();

#ifdef _WIN32
    if (s.prevExceptionFilter != nullptr) {
        ::SetUnhandledExceptionFilter(s.prevExceptionFilter);
        s.prevExceptionFilter = nullptr;
    }
#endif
    if (s.prevTerminateHandler != nullptr) {
        std::set_terminate(s.prevTerminateHandler);
        s.prevTerminateHandler = nullptr;
    }

    s.luaState.store(nullptr, std::memory_order_release);

    std::lock_guard<std::mutex> lock(s.logMutex);
    if (s.logFile != nullptr) {
        std::fclose(s.logFile);
        s.logFile = nullptr;
    }
}

void CrashAndTelemetry::clearLuaState() {
    state().luaState.store(nullptr, std::memory_order_release);
}

int CrashAndTelemetry::luaTracebackHandler(lua_State* L) {
    const char* errMsg = lua_tostring(L, 1);
    if (errMsg == nullptr) {
        errMsg = "(error object is not a string)";
    }

    std::string traceStr = errMsg;

    lua_getglobal(L, "debug");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "traceback");
        if (lua_isfunction(L, -1)) {
            lua_pushstring(L, errMsg);
            lua_pushinteger(L, 2);
            if (lua_pcall(L, 2, 1, 0) == 0 && lua_isstring(L, -1)) {
                traceStr = lua_tostring(L, -1);
            }
            lua_pop(L, 1); // pop traceback result or error
        } else {
            lua_pop(L, 1); // pop non-function
        }
    }
    lua_pop(L, 1); // pop debug table/nil

    log(LogLevel::Error, "LuaError", "\n%s", traceStr.c_str());
    flushLogs();

    lua_pushlstring(L, traceStr.data(), traceStr.size());
    return 1;
}

void CrashAndTelemetry::installLuaHooks(lua_State* L) {
    if (L == nullptr) {
        return;
    }

    state().luaState.store(L, std::memory_order_release);

    const lua_CFunction tbFn = &CrashAndTelemetry::luaTracebackHandler;
    lua_pushcfunction(L, tbFn);
    lua_setglobal(L, "__GCLIENT_NATIVE_TRACKBACK__");
    if (!hasAppDelegateLuaPrintShim(L)) {
        lua_pushcfunction(L, tbFn);
        lua_setglobal(L, "__G__TRACKBACK__");
    }

    const lua_CFunction printFn = &luaPrintHandler;
    lua_pushcfunction(L, printFn);
    lua_setglobal(L, "__GCLIENT_NATIVE_PRINT__");

    // Avoid double-wrapping print(), release_print(), and CCLuaLog() if AppDelegate's
    // Lua bootstrap shim (__GCLIENT_LOG_INFO__) is already active.
    if (!hasAppDelegateLuaPrintShim(L)) {
        installMirroredPrintGlobal(L, "print");
        installMirroredPrintGlobal(L, "release_print");
        installMirroredPrintGlobal(L, "CCLuaLog");
    }

    // Catch unprotected Lua errors before the process aborts silently.
    lua_atpanic(L, &luaPanicHandler);

    log(LogLevel::Info, "Diagnostics",
        "Lua debug.traceback() error hook (__G__TRACKBACK__), print/release_print/CCLuaLog mirrors, and lua_atpanic installed.");
}

void CrashAndTelemetry::log(LogLevel level, const char* category, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logV(level, category, fmt, args);
    va_end(args);
}

void CrashAndTelemetry::logV(LogLevel level, const char* category, const char* fmt, va_list args) {
    char timestamp[80] = {};
    formatTimestamp(timestamp, sizeof(timestamp));

    va_list argsCopy;
    va_copy(argsCopy, args);
    const int msgLen = std::vsnprintf(nullptr, 0, fmt, argsCopy);
    va_end(argsCopy);

    std::string body;
    if (msgLen > 0) {
        body.resize(static_cast<std::size_t>(msgLen));
        std::vsnprintf(body.data(), body.size() + 1, fmt, args);
    }

    char prefix[128] = {};
    const unsigned long tid = currentThreadIdNumeric();
    std::snprintf(
        prefix,
        sizeof(prefix),
        "[%s] [%s] [T:%05lu] [%s] ",
        timestamp,
        levelToTag(level),
        tid,
        category ? category : "App");

    std::string line;
    line.reserve(std::strlen(prefix) + body.size() + 2);
    line.append(prefix);
    line.append(body);
    line.push_back('\n');

#ifdef _WIN32
    ::OutputDebugStringA(line.c_str());
#endif

    DiagnosticsState& s = state();
    std::lock_guard<std::mutex> lock(s.logMutex);
    if (s.logFile != nullptr) {
        if (s.currentLogBytes + line.size() > s.config.maxLogFileBytes) {
            rotateLogFilesLocked(s);
        }
        if (s.logFile != nullptr) {
            const std::size_t written = std::fwrite(line.data(), 1, line.size(), s.logFile);
            s.currentLogBytes += written;
            std::fflush(s.logFile);
        }
    }
}

void CrashAndTelemetry::flushLogs() {
    DiagnosticsState& s = state();
    std::lock_guard<std::mutex> lock(s.logMutex);
    if (s.logFile != nullptr) {
        std::fflush(s.logFile);
    }
}

void CrashAndTelemetry::recordFrame(float dtSeconds) {
    DiagnosticsState& s = state();
    const double dtMs = static_cast<double>(dtSeconds) * 1000.0;

    bool shouldLog = false;
    FrameTelemetrySnapshot snapshot{};

    {
        std::lock_guard<std::mutex> lock(s.metricsMutex);
        s.frameTimesMs[s.frameCursor] = dtMs;
        s.frameCursor = (s.frameCursor + 1) % kFrameWindowSize;
        if (s.frameCountWindow < kFrameWindowSize) {
            ++s.frameCountWindow;
        }

        ++s.totalFrames;
        if (dtMs > kSlowFrameThresholdMs) {
            ++s.slowFrames;
        }
        s.elapsedSinceFlushSec += static_cast<double>(dtSeconds);

        if (s.elapsedSinceFlushSec >= s.config.metricsFlushIntervalSec && s.frameCountWindow > 0) {
            s.elapsedSinceFlushSec = 0.0;

            std::vector<double> sorted(
                s.frameTimesMs.begin(),
                s.frameTimesMs.begin() + static_cast<std::ptrdiff_t>(s.frameCountWindow));
            std::sort(sorted.begin(), sorted.end());

            double sumMs = 0.0;
            for (double v : sorted) {
                sumMs += v;
            }
            const double avgMs = sumMs / static_cast<double>(sorted.size());
            const std::size_t p95Idx = std::min(
                sorted.size() - 1,
                static_cast<std::size_t>(static_cast<double>(sorted.size()) * 0.95));

#ifdef _WIN32
            PROCESS_MEMORY_COUNTERS_EX pmc{};
            pmc.cb = sizeof(pmc);
            if (::GetProcessMemoryInfo(
                    ::GetCurrentProcess(),
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                    sizeof(pmc))) {
                snapshot.workingSetBytes = static_cast<uint64_t>(pmc.WorkingSetSize);
                snapshot.privateUsageBytes = static_cast<uint64_t>(pmc.PrivateUsage);
            }
#endif

            lua_State* L = s.luaState.load(std::memory_order_acquire);
            if (L != nullptr) {
                const int kb = lua_gc(L, LUA_GCCOUNT, 0);
                const int remBytes = lua_gc(L, LUA_GCCOUNTB, 0);
                snapshot.luaMemoryKB = static_cast<double>(kb) + (static_cast<double>(remBytes) / 1024.0);
            }

            snapshot.avgFrameMs = avgMs;
            snapshot.avgFps = (avgMs > 0.001) ? (1000.0 / avgMs) : 0.0;
            snapshot.maxFrameMs = sorted.back();
            snapshot.p95FrameMs = sorted[p95Idx];
            snapshot.totalFrames = s.totalFrames;
            snapshot.slowFrames = s.slowFrames;

            s.latestSnapshot = snapshot;
            shouldLog = true;
        }
    }

    if (shouldLog) {
        log(LogLevel::Info,
            "Telemetry",
            "fps=%.1f frame_ms(avg=%.2f p95=%.2f max=%.2f) ram_mb(ws=%.1f priv=%.1f) lua_gc_mb=%.2f frames=%llu slow=%llu",
            snapshot.avgFps,
            snapshot.avgFrameMs,
            snapshot.p95FrameMs,
            snapshot.maxFrameMs,
            static_cast<double>(snapshot.workingSetBytes) / (1024.0 * 1024.0),
            static_cast<double>(snapshot.privateUsageBytes) / (1024.0 * 1024.0),
            snapshot.luaMemoryKB / 1024.0,
            static_cast<unsigned long long>(snapshot.totalFrames),
            static_cast<unsigned long long>(snapshot.slowFrames));
    }
}

FrameTelemetrySnapshot CrashAndTelemetry::getLatestSnapshot() {
    std::lock_guard<std::mutex> lock(state().metricsMutex);
    return state().latestSnapshot;
}

std::string CrashAndTelemetry::writeMinidumpNow(const char* reason) {
#ifdef _WIN32
    wchar_t dumpPath[MAX_PATH] = {};
    const bool ok = writeMinidumpInternal(nullptr, dumpPath, _countof(dumpPath));
    const std::string utf8Path = wideToUtf8(dumpPath);
    log(LogLevel::Warn,
        "Diagnostics",
        "On-demand minidump (%s) %s: %s",
        reason ? reason : "manual",
        ok ? "written" : "FAILED",
        utf8Path.c_str());
    return ok ? utf8Path : std::string{};
#else
    log(LogLevel::Warn,
        "Diagnostics",
        "On-demand minidump requested (%s) [non-Win32 build]",
        reason ? reason : "manual");
    return {};
#endif
}

} // namespace gclient::diagnostics
