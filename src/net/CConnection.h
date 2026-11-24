#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// Must precede cocos2d.h / windows.h so winsock2.h is never conflicted by winsock.h.
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
#endif

#if defined(GCLIENT_USE_COCOS2DX)
#include "cocos2d.h"
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace gclient::net {

class CNetwork;

/// RAII reference-counted Winsock2 lifecycle guard (`WSAStartup(2.2)` / `WSACleanup`).
class WinsockSession {
public:
    WinsockSession();
    ~WinsockSession();

    WinsockSession(const WinsockSession&) = delete;
    WinsockSession& operator=(const WinsockSession&) = delete;

    bool isInitialized() const noexcept { return initialized_; }
    int lastError() const noexcept { return initError_; }

private:
    bool initialized_ = false;
    int initError_ = 0;

    static std::mutex s_mutex;
    static int s_refCount;
};

/// Redacted protocol trace entry — logs socket events, byte counts, and WSAGetLastError()
/// without ever storing raw payload contents or credentials.
struct ProtocolTraceEntry {
    uint64_t timestampMs = 0;
    const char* event = "";       // e.g. "CONNECT", "CONNECT_OK", "SEND", "RECV", "TIMEOUT", "CLOSE", "ERROR"
    int wsaError = 0;             // WSAGetLastError() on Win32 (or errno on POSIX)
    uint32_t byteCount = 0;       // Redacted length only — no raw payload bytes
    uint32_t detailCode = 0;      // Optional port, header size, or expected body length
};

/// Fixed-size thread-safe ring buffer of redacted protocol trace entries.
class ProtocolTraceRingBuffer {
public:
    static constexpr size_t kCapacity = 256;

    void record(const char* event, int wsaError = 0, uint32_t byteCount = 0, uint32_t detailCode = 0);
    std::vector<ProtocolTraceEntry> snapshot() const;
    std::string formatSummary(size_t maxEntries = 32) const;
    void clear();

private:
    mutable std::mutex mutex_;
    std::array<ProtocolTraceEntry, kCapacity> entries_{};
    size_t writeIndex_ = 0;
    size_t count_ = 0;
};

/// Non-blocking Winsock2 TCP connection matching Win32 Client `CConnection` API:
/// `connect`, `doRead`, `doPacketBody`, `send`, `close`, `setHeaderSize`,
/// `registerHeadFunc`, `registerBodyFunc`, `registerCloseFunc`.
/// Inherits from `cocos2d::CCObject` when `GCLIENT_USE_COCOS2DX` is defined so tolua++
/// `CCObject` casts (`conn:retain()`, `conn:release()`) operate safely.
class CConnection
#if defined(GCLIENT_USE_COCOS2DX)
    : public cocos2d::CCObject
#endif
{
public:
    enum class State {
        Disconnected,
        Connecting,
        Connected,
        Closing,
        Closed
    };

    // Native C++ callback signatures (used directly in C++ tests or alongside Lua script handlers).
    using HeadCallback = std::function<uint32_t(const char* headerData, size_t headerSize)>;
    using BodyCallback = std::function<void(const char* bodyData, size_t bodySize,
                                            const char* headerData, size_t headerSize)>;
    using CloseCallback = std::function<void()>;

    CConnection();
#if defined(GCLIENT_USE_COCOS2DX)
    ~CConnection() override;
#else
    virtual ~CConnection();
    void retain() noexcept {}
    void release() noexcept {}
#endif

    /// RAII retain/release guard keeping a CConnection alive across re-entrant Lua/C++ callbacks.
    class ScopedRetain {
    public:
        explicit ScopedRetain(CConnection* conn) noexcept : conn_(conn) {
            if (conn_ != nullptr) {
                conn_->retain();
            }
        }
        ~ScopedRetain() {
            if (conn_ != nullptr) {
                conn_->release();
            }
        }
        ScopedRetain(const ScopedRetain&) = delete;
        ScopedRetain& operator=(const ScopedRetain&) = delete;

    private:
        CConnection* conn_ = nullptr;
    };

    CConnection(const CConnection&) = delete;
    CConnection& operator=(const CConnection&) = delete;

    /// Initiates a non-blocking TCP connection to `host:port` and registers with `CNetwork::sharedNetwork()`.
    bool connect(const char* host, unsigned int port);

    /// Queues `data` for non-blocking transmission. If `wrapLCPacket` is true and `data` is not
    /// already a valid framed LCPacket, wraps it via `LCPacket::makeLCPacket(data)` first.
    bool send(const std::string& data, bool wrapLCPacket = false);
    bool send(const void* data, size_t length, bool wrapLCPacket = false);

    /// Closes the socket, clears pending buffers, and triggers `closeFunc` on the main thread.
    void close();

    /// Sets the fixed incoming packet header size in bytes.
    void setHeaderSize(int headerSize);
    int getHeaderSize() const noexcept { return headerSize_; }

    /// Cocos2d-x Lua script handler registration (tolua `LUA_FUNCTION` handler IDs).
    void registerHeadFunc(int luaHandler);
    void registerBodyFunc(int luaHandler);
    void registerCloseFunc(int luaHandler);

    /// Native C++ callback registration (optional alternative/override for C++ harnesses).
    void setHeadCallback(HeadCallback cb);
    void setBodyCallback(BodyCallback cb);
    void setCloseCallback(CloseCallback cb);

    /// Explicit connect and read timeout configuration (milliseconds; 0 disables read timeout).
    void setConnectTimeoutMs(uint32_t timeoutMs) noexcept { connectTimeoutMs_ = timeoutMs; }
    void setReadTimeoutMs(uint32_t timeoutMs) noexcept { readTimeoutMs_ = timeoutMs; }
    uint32_t getConnectTimeoutMs() const noexcept { return connectTimeoutMs_; }
    uint32_t getReadTimeoutMs() const noexcept { return readTimeoutMs_; }

    /// Parses framed packets from the internal receive buffer and dispatches `headFunc` / `bodyFunc`.
    void doRead();

    /// Dispatches a complete packet body + saved header to the registered body handler.
    void doPacketBody(const char* body, size_t bodyLength);

    State getState() const noexcept { return state_.load(std::memory_order_acquire); }
    bool isConnected() const noexcept { return getState() == State::Connected; }
    SOCKET nativeHandle() const noexcept { return socket_.load(std::memory_order_acquire); }

    /// Access to the redacted protocol trace ring buffer for diagnostics.
    const ProtocolTraceRingBuffer& traceBuffer() const noexcept { return trace_; }

    // --- Internal methods used by CNetwork poll loop and main-thread drain ---
    friend class CNetwork;

private:
    static int getLastSocketError() noexcept;
    static bool isWouldBlockError(int err) noexcept;

    void releaseAllScriptHandlers();
    static void removeLuaScriptHandler(int& handlerSlot);

    uint32_t getBodyLength(const char* headerPtr);
    void closeSocketHandle();

    // Called by CNetwork background poll thread:
    bool pollCompleteConnect();
    bool pollReadSocket(std::string& outChunk, bool& outPeerClosed, int& outError);
    bool pollFlushSendQueue(int& outError);
    bool hasPendingSendData() const;
    bool checkTimeouts(std::chrono::steady_clock::time_point now, const char*& outReason);

    // Called by CNetwork::update() on the Cocos2d-x main thread:
    void appendIncomingData(const char* data, size_t length);
    void notifyClosedOnMainThread(int wsaError, const char* reason);

    WinsockSession winsock_;
    std::atomic<SOCKET> socket_{INVALID_SOCKET};
    CNetwork* network_ = nullptr;
    std::atomic<State> state_{State::Disconnected};

    int headerSize_ = 8;
    uint32_t expectedBodyLength_ = 0;
    std::vector<char> currentHeader_;
    std::vector<char> recvBuffer_;
    size_t recvReadOffset_ = 0;

    // Thread-safe outgoing send queue (appended from main thread, drained by poll thread)
    mutable std::mutex sendMutex_;
    std::deque<std::string> sendQueue_;
    size_t frontSendOffset_ = 0;

    // Lua handler IDs (matching Cocos2d-x 2.2.6 CCLuaEngine)
    int headLuaHandler_ = 0;
    int bodyLuaHandler_ = 0;
    int closeLuaHandler_ = 0;
    bool closeNotified_ = false;

    // Optional native C++ callbacks
    HeadCallback headCallback_;
    BodyCallback bodyCallback_;
    CloseCallback closeCallback_;

    // Explicit timeouts (ms; readTimeoutMs_ = 0 disables idle read timeout for persistent lobby TCP)
    uint32_t connectTimeoutMs_ = 10000;
    uint32_t readTimeoutMs_ = 0;
    std::atomic<int64_t> connectStartMs_{0};
    std::atomic<int64_t> lastActivityMs_{0};

    ProtocolTraceRingBuffer trace_;
};

} // namespace gclient::net
