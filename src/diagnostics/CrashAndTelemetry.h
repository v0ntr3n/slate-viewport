#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <string>

struct lua_State;

namespace gclient::diagnostics {

enum class LogLevel : uint8_t {
    Trace = 0,
    Debug = 1,
    Info  = 2,
    Warn  = 3,
    Error = 4,
    Fatal = 5
};

struct DiagnosticsConfig {
    std::string logDirectory;
    std::string dumpDirectory;
    std::string appName = "gclient";

    std::size_t maxLogFileBytes = 10u * 1024u * 1024u; // 10 MiB per rotating file
    std::size_t maxLogBackups = 5u;

    double metricsFlushIntervalSec = 5.0; // Periodic telemetry log interval
    bool enableFullMemoryDump = false;
};

struct FrameTelemetrySnapshot {
    double avgFps = 0.0;
    double avgFrameMs = 0.0;
    double maxFrameMs = 0.0;
    double p95FrameMs = 0.0;
    uint64_t workingSetBytes = 0;
    uint64_t privateUsageBytes = 0;
    double luaMemoryKB = 0.0;
    uint64_t totalFrames = 0;
    uint64_t slowFrames = 0; // Frames exceeding 40.0 ms (30 FPS budget = 33.33 ms)
};

class CrashAndTelemetry final {
public:
    // Installs Win32 SetUnhandledExceptionFilter minidump writer, CRT/C++ fatal handlers,
    // and opens the PID-isolated rotating log file. Safe to call once at startup.
    static bool install(const DiagnosticsConfig& config);

    // Flushes pending telemetry/logs and restores previous exception handlers.
    static void shutdown();

    // Attaches global Lua debug.traceback() error hook (__G__TRACKBACK__), sets lua_atpanic,
    // and binds the Lua state for periodic Lua GC memory telemetry.
    static void installLuaHooks(lua_State* L);

    // Atomically detaches the bound Lua state pointer prior to VM destruction.
    static void clearLuaState();

    // Lua CFunction usable as an xpcall/pcall error handler that logs debug.traceback().
    static int luaTracebackHandler(lua_State* L);

    // Thread-safe formatted logging to PID-isolated rotating log + Win32 OutputDebugStringA.
    static void log(LogLevel level, const char* category, const char* fmt, ...);
    static void logV(LogLevel level, const char* category, const char* fmt, va_list args);
    static void flushLogs();

    // Lightweight per-frame collector called from the 30 FPS main loop.
    static void recordFrame(float dtSeconds);

    // Returns the most recently computed telemetry snapshot.
    static FrameTelemetrySnapshot getLatestSnapshot();

    // Triggers an on-demand minidump (e.g., on fatal Lua panic or watchdog trigger).
    static std::string writeMinidumpNow(const char* reason);
};

} // namespace gclient::diagnostics
