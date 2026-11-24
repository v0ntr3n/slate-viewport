#include "CConnection.h"
#include "CNetwork.h"
#include "LCPacket.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

#ifndef _WIN32
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(GCLIENT_USE_COCOS2DX)
#include "CCLuaEngine.h"
#include "cocos2d.h"
#endif

namespace gclient::net {

namespace {

constexpr uint32_t kMaxFrameBodyLength = 64u * 1024u * 1024u;
constexpr int kMaxFrameHeaderSize = 65536;

#ifdef _WIN32
constexpr int kSocketTimeoutError = WSAETIMEDOUT;
#else
constexpr int kSocketTimeoutError = ETIMEDOUT;
#endif

uint64_t nowEpochMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

int64_t steadyMs(std::chrono::steady_clock::time_point tp) {
    using namespace std::chrono;
    return duration_cast<milliseconds>(tp.time_since_epoch()).count();
}

int64_t nowSteadyMs() {
    return steadyMs(std::chrono::steady_clock::now());
}

void logMessage(const char* msg) {
#if defined(GCLIENT_USE_COCOS2DX)
    cocos2d::CCLog("%s", msg);
#else
    (void)msg;
#endif
}

} // namespace

// ============================================================================
// WinsockSession (RAII WSAStartup / WSACleanup)
// ============================================================================

std::mutex WinsockSession::s_mutex;
int WinsockSession::s_refCount = 0;

WinsockSession::WinsockSession() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_refCount == 0) {
        WSADATA wsaData{};
        initError_ = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (initError_ == 0) {
            initialized_ = true;
            ++s_refCount;
        }
    } else {
        initialized_ = true;
        ++s_refCount;
    }
#else
    initialized_ = true;
#endif
}

WinsockSession::~WinsockSession() {
#ifdef _WIN32
    if (!initialized_) {
        return;
    }
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_refCount > 0) {
        --s_refCount;
        if (s_refCount == 0) {
            ::WSACleanup();
        }
    }
#endif
}

// ============================================================================
// ProtocolTraceRingBuffer
// ============================================================================

void ProtocolTraceRingBuffer::record(const char* event, int wsaError,
                                     uint32_t byteCount, uint32_t detailCode) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_[writeIndex_] = ProtocolTraceEntry{
        nowEpochMs(),
        event != nullptr ? event : "",
        wsaError,
        byteCount,
        detailCode
    };
    writeIndex_ = (writeIndex_ + 1) % kCapacity;
    if (count_ < kCapacity) {
        ++count_;
    }
}

std::vector<ProtocolTraceEntry> ProtocolTraceRingBuffer::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProtocolTraceEntry> result;
    result.reserve(count_);
    const size_t start = (count_ == kCapacity) ? writeIndex_ : 0;
    for (size_t i = 0; i < count_; ++i) {
        result.push_back(entries_[(start + i) % kCapacity]);
    }
    return result;
}

std::string ProtocolTraceRingBuffer::formatSummary(size_t maxEntries) const {
    auto items = snapshot();
    const size_t beginIdx = items.size() > maxEntries ? (items.size() - maxEntries) : 0;
    std::ostringstream oss;
    for (size_t i = beginIdx; i < items.size(); ++i) {
        const auto& e = items[i];
        oss << "[" << e.timestampMs << "] " << e.event
            << " bytes=" << e.byteCount
            << " detail=" << e.detailCode
            << " wsaErr=" << e.wsaError << "\n";
    }
    return oss.str();
}

void ProtocolTraceRingBuffer::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    writeIndex_ = 0;
    count_ = 0;
}

// ============================================================================
// CConnection
// ============================================================================

CConnection::CConnection() {
    currentHeader_.resize(static_cast<size_t>(headerSize_), 0);
}

CConnection::~CConnection() {
    state_.store(State::Closed, std::memory_order_release);
    if (network_ != nullptr) {
        network_->onConnectionDestroyed(this);
        network_ = nullptr;
    }
    closeSocketHandle();
    releaseAllScriptHandlers();
}

void CConnection::removeLuaScriptHandler(int& handlerSlot) {
    if (handlerSlot <= 0) {
        handlerSlot = 0;
        return;
    }
#if defined(GCLIENT_USE_COCOS2DX)
    if (auto* mgr = cocos2d::CCScriptEngineManager::sharedManager()) {
        if (auto* engine = mgr->getScriptEngine()) {
            engine->removeScriptHandler(handlerSlot);
        }
    }
#endif
    handlerSlot = 0;
}

void CConnection::releaseAllScriptHandlers() {
    removeLuaScriptHandler(headLuaHandler_);
    removeLuaScriptHandler(bodyLuaHandler_);
    removeLuaScriptHandler(closeLuaHandler_);
}

int CConnection::getLastSocketError() noexcept {
#ifdef _WIN32
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

bool CConnection::isWouldBlockError(int err) noexcept {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY;
#else
    return err == EWOULDBLOCK || err == EAGAIN || err == EINPROGRESS || err == EALREADY;
#endif
}

bool CConnection::connect(const char* host, unsigned int port) {
    if (socket_.load(std::memory_order_acquire) != INVALID_SOCKET) {
        logMessage("socket already exists, you should use a new connection");
        trace_.record("CONNECT_REJECTED", 0, 0, port);
        return false;
    }

    if (!winsock_.isInitialized()) {
        trace_.record("WSA_INIT_FAILED", winsock_.lastError(), 0, port);
        return false;
    }

    if (host == nullptr || host[0] == '\0' || port == 0 || port > 65535u) {
        trace_.record("CONNECT_INVALID_ARGS", 0, 0, port);
        return false;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[16];
    std::snprintf(portStr, sizeof(portStr), "%u", port);

    addrinfo* addrList = nullptr;
    const int gaiErr = ::getaddrinfo(host, portStr, &hints, &addrList);
    if (gaiErr != 0 || addrList == nullptr) {
        trace_.record("DNS_FAILED", getLastSocketError(), 0, port);
        return false;
    }

    SOCKET sock = INVALID_SOCKET;
    int lastErr = 0;
    bool connectedImmediately = false;

    for (addrinfo* rp = addrList; rp != nullptr; rp = rp->ai_next) {
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET) {
            lastErr = getLastSocketError();
            continue;
        }

#ifdef _WIN32
        u_long nonBlocking = 1;
        if (::ioctlsocket(sock, FIONBIO, &nonBlocking) == SOCKET_ERROR) {
            lastErr = getLastSocketError();
            ::closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
#else
        const int flags = ::fcntl(sock, F_GETFL, 0);
        if (flags < 0 || ::fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            lastErr = getLastSocketError();
            ::close(sock);
            sock = INVALID_SOCKET;
            continue;
        }
#endif

        int nodelay = 1;
        ::setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

        const int rc = ::connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen));
        if (rc == 0) {
            connectedImmediately = true;
            break;
        }

        lastErr = getLastSocketError();
        if (isWouldBlockError(lastErr)) {
            connectedImmediately = false;
            break;
        }

#ifdef _WIN32
        ::closesocket(sock);
#else
        ::close(sock);
#endif
        sock = INVALID_SOCKET;
    }

    ::freeaddrinfo(addrList);

    if (sock == INVALID_SOCKET) {
        trace_.record("CONNECT_ERROR", lastErr, 0, port);
        return false;
    }

    socket_.store(sock, std::memory_order_release);
    closeNotified_ = false;
    expectedBodyLength_ = 0;
    currentHeader_.assign(static_cast<size_t>(headerSize_), 0);
    recvBuffer_.clear();
    recvReadOffset_ = 0;

    const int64_t nowMs = nowSteadyMs();
    connectStartMs_.store(nowMs, std::memory_order_release);
    lastActivityMs_.store(nowMs, std::memory_order_release);

    if (connectedImmediately) {
        state_.store(State::Connected, std::memory_order_release);
        trace_.record("CONNECT_OK", 0, 0, port);
    } else {
        state_.store(State::Connecting, std::memory_order_release);
        trace_.record("CONNECT_PENDING", lastErr, 0, port);
    }

    network_ = CNetwork::sharedNetwork();
    if (network_ != nullptr) {
        network_->addConnection(this);
    }

    return true;
}

bool CConnection::send(const std::string& data, bool wrapLCPacket) {
    return send(data.data(), data.size(), wrapLCPacket);
}

bool CConnection::send(const void* data, size_t length, bool wrapLCPacket) {
    const State st = getState();
    if (socket_.load(std::memory_order_acquire) == INVALID_SOCKET ||
        st == State::Closed || st == State::Closing || st == State::Disconnected) {
        trace_.record("SEND_DISCONNECTED", 0, static_cast<uint32_t>(length), wrapLCPacket ? 1u : 0u);
        return false;
    }

    std::string wireBytes;
    bool wrappedNow = false;
    if (wrapLCPacket) {
        // Idempotency guard: if Lua already called GameUtil:makeLCPacket(raw) before conn:send(pkt),
        // avoid double-compressing and double-framing an already valid LCPacket.
        if (LCPacket::isFramedLCPacket(data, length)) {
            wireBytes.assign(static_cast<const char*>(data), length);
        } else {
            wireBytes = LCPacket::makeLCPacket(data, length, true);
            if (wireBytes.empty()) {
                trace_.record("SEND_PACK_FAILED", 0, static_cast<uint32_t>(length), 1u);
                return false;
            }
            wrappedNow = true;
        }
    } else if (data != nullptr && length > 0) {
        wireBytes.assign(static_cast<const char*>(data), length);
    }

    if (wireBytes.empty()) {
        return true;
    }

    const uint32_t wireLen = static_cast<uint32_t>(wireBytes.size());
    {
        std::lock_guard<std::mutex> lock(sendMutex_);
        sendQueue_.push_back(std::move(wireBytes));
    }

    trace_.record("SEND_QUEUED", 0, wireLen, wrappedNow ? 1u : 0u);
    return true;
}

void CConnection::close() {
    ScopedRetain selfGuard(this);
    const State prev = state_.exchange(State::Closed, std::memory_order_acq_rel);
    if (prev == State::Closed && socket_.load(std::memory_order_acquire) == INVALID_SOCKET) {
        return;
    }

    trace_.record("CLOSE_REQUESTED", 0, 0, 0);

    {
        std::lock_guard<std::mutex> lock(sendMutex_);
        sendQueue_.clear();
        frontSendOffset_ = 0;
    }

    closeSocketHandle();

    if (network_ != nullptr) {
        network_->removeConnection(this);
    }

    notifyClosedOnMainThread(0, "LOCAL_CLOSE");
}

void CConnection::closeSocketHandle() {
    const SOCKET sock = socket_.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
    if (sock != INVALID_SOCKET) {
#ifdef _WIN32
        ::shutdown(sock, SD_BOTH);
        ::closesocket(sock);
#else
        ::shutdown(sock, SHUT_RDWR);
        ::close(sock);
#endif
    }
}

void CConnection::setHeaderSize(int headerSize) {
    if (headerSize <= 0 || headerSize > kMaxFrameHeaderSize) {
        return;
    }
    headerSize_ = headerSize;
    // Do NOT overwrite or resize currentHeader_ while a packet body is mid-frame!
    if (expectedBodyLength_ == 0) {
        currentHeader_.assign(static_cast<size_t>(headerSize_), 0);
    }
}

void CConnection::registerHeadFunc(int luaHandler) {
    if (headLuaHandler_ != luaHandler) {
        removeLuaScriptHandler(headLuaHandler_);
        headLuaHandler_ = luaHandler;
    }
}

void CConnection::registerBodyFunc(int luaHandler) {
    if (bodyLuaHandler_ != luaHandler) {
        removeLuaScriptHandler(bodyLuaHandler_);
        bodyLuaHandler_ = luaHandler;
    }
}

void CConnection::registerCloseFunc(int luaHandler) {
    if (closeLuaHandler_ != luaHandler) {
        removeLuaScriptHandler(closeLuaHandler_);
        closeLuaHandler_ = luaHandler;
    }
}

void CConnection::setHeadCallback(HeadCallback cb) {
    headCallback_ = std::move(cb);
}

void CConnection::setBodyCallback(BodyCallback cb) {
    bodyCallback_ = std::move(cb);
}

void CConnection::setCloseCallback(CloseCallback cb) {
    closeCallback_ = std::move(cb);
}

void CConnection::appendIncomingData(const char* data, size_t length) {
    if (data == nullptr || length == 0) {
        return;
    }
    recvBuffer_.insert(recvBuffer_.end(), data, data + length);
    lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
}

uint32_t CConnection::getBodyLength(const char* headerPtr) {
    if (headerPtr == nullptr || headerSize_ <= 0) {
        return 0u;
    }

    uint32_t bodyLen = 0u;
    bool resolved = false;

    if (headCallback_) {
        bodyLen = headCallback_(headerPtr, static_cast<size_t>(headerSize_));
        resolved = true;
    }
#if defined(GCLIENT_USE_COCOS2DX)
    else if (headLuaHandler_ > 0) {
        auto* engine = cocos2d::CCLuaEngine::defaultEngine();
        if (engine != nullptr) {
            auto* stack = engine->getLuaStack();
            stack->pushString(headerPtr, headerSize_);
            const int ret = stack->executeFunctionByHandler(headLuaHandler_, 1);
            bodyLen = ret > 0 ? static_cast<uint32_t>(ret) : 0u;
            resolved = true;
        }
    }
#endif

    if (!resolved && headerSize_ >= 4) {
        bodyLen = LCPacket::readBigEndianU32(reinterpret_cast<const uint8_t*>(headerPtr));
    }

    if (bodyLen == 0u || bodyLen > kMaxFrameBodyLength) {
        return 0u;
    }
    return bodyLen;
}

void CConnection::doRead() {
    ScopedRetain selfGuard(this);
    if (getState() == State::Closed) {
        recvBuffer_.clear();
        recvReadOffset_ = 0;
        return;
    }

    size_t cursor = recvReadOffset_;

    while (cursor <= recvBuffer_.size()) {
        const size_t available = recvBuffer_.size() - cursor;

        if (expectedBodyLength_ == 0) {
            if (headerSize_ <= 0) {
                break;
            }
            const size_t frameHeaderSize = static_cast<size_t>(headerSize_);
            if (available < frameHeaderSize) {
                break;
            }

            const uint32_t bodyLen = getBodyLength(recvBuffer_.data() + cursor);
            if (getState() == State::Closed) {
                recvBuffer_.clear();
                recvReadOffset_ = 0;
                return;
            }

            if (bodyLen == 0 || bodyLen > kMaxFrameBodyLength) {
                logMessage("lua error occured for HeadScript, close socket now");
                trace_.record("HEAD_SCRIPT_ERROR", 0, bodyLen, static_cast<uint32_t>(frameHeaderSize));
                close();
                return;
            }

            // Recompute header size and recvBuffer_.data() + cursor after getBodyLength(),
            // because headLuaHandler_ / headCallback_ may have closed or resized recvBuffer_.
            const size_t updatedHeaderSize = static_cast<size_t>(headerSize_);
            if (cursor + updatedHeaderSize > recvBuffer_.size()) {
                break;
            }
            const char* freshHeaderPtr = recvBuffer_.data() + cursor;
            currentHeader_.assign(freshHeaderPtr, freshHeaderPtr + updatedHeaderSize);
            cursor += updatedHeaderSize;
            expectedBodyLength_ = bodyLen;
        }

        if (cursor > recvBuffer_.size()) {
            break;
        }
        const size_t bodyAvailable = recvBuffer_.size() - cursor;
        if (bodyAvailable < static_cast<size_t>(expectedBodyLength_)) {
            break;
        }

        const char* bodyPtr = recvBuffer_.data() + cursor;
        const uint32_t bodyLen = expectedBodyLength_;
        cursor += static_cast<size_t>(bodyLen);
        expectedBodyLength_ = 0;

        trace_.record("PACKET_DISPATCH", 0, bodyLen, static_cast<uint32_t>(currentHeader_.size()));
        doPacketBody(bodyPtr, static_cast<size_t>(bodyLen));

        if (getState() == State::Closed) {
            recvBuffer_.clear();
            recvReadOffset_ = 0;
            return;
        }
    }

    if (cursor > 0) {
        if (cursor >= recvBuffer_.size()) {
            recvBuffer_.clear();
            recvReadOffset_ = 0;
        } else if (cursor >= 4096 || cursor * 2 >= recvBuffer_.size()) {
            recvBuffer_.erase(recvBuffer_.begin(),
                              recvBuffer_.begin() + static_cast<std::ptrdiff_t>(cursor));
            recvReadOffset_ = 0;
        } else {
            recvReadOffset_ = cursor;
        }
    }
}

void CConnection::doPacketBody(const char* body, size_t bodyLength) {
    ScopedRetain selfGuard(this);
    if (bodyCallback_) {
        bodyCallback_(body, bodyLength, currentHeader_.data(), currentHeader_.size());
        return;
    }

#if defined(GCLIENT_USE_COCOS2DX)
    if (bodyLuaHandler_ > 0) {
        auto* engine = cocos2d::CCLuaEngine::defaultEngine();
        if (engine != nullptr) {
            auto* stack = engine->getLuaStack();
            stack->pushString(body, static_cast<int>(bodyLength));
            stack->pushString(currentHeader_.data(), static_cast<int>(currentHeader_.size()));
            stack->executeFunctionByHandler(bodyLuaHandler_, 2);
        }
    }
#else
    (void)body;
    (void)bodyLength;
#endif
}

bool CConnection::pollCompleteConnect() {
    const SOCKET sock = socket_.load(std::memory_order_acquire);
    if (sock == INVALID_SOCKET || getState() != State::Connecting) {
        return false;
    }

    int soError = 0;
#ifdef _WIN32
    int optLen = sizeof(soError);
#else
    socklen_t optLen = sizeof(soError);
#endif
    if (::getsockopt(sock, SOL_SOCKET, SO_ERROR,
                     reinterpret_cast<char*>(&soError), &optLen) == SOCKET_ERROR) {
        soError = getLastSocketError();
    }

    if (soError != 0) {
        trace_.record("CONNECT_FAILED", soError, 0, 0);
        state_.store(State::Closing, std::memory_order_release);
        return false;
    }

    state_.store(State::Connected, std::memory_order_release);
    lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
    trace_.record("CONNECT_OK", 0, 0, 0);
    return true;
}

bool CConnection::pollReadSocket(std::string& outChunk, bool& outPeerClosed, int& outError) {
    outChunk.clear();
    outPeerClosed = false;
    outError = 0;

    const SOCKET sock = socket_.load(std::memory_order_acquire);
    if (sock == INVALID_SOCKET || getState() != State::Connected) {
        return false;
    }

    char buf[8192];
    for (;;) {
        const int n = static_cast<int>(::recv(sock, buf, sizeof(buf), 0));
        if (n > 0) {
            outChunk.append(buf, static_cast<size_t>(n));
            lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
            if (outChunk.size() >= 65536) {
                break;
            }
        } else if (n == 0) {
            outPeerClosed = true;
            trace_.record("RECV_EOF", 0, static_cast<uint32_t>(outChunk.size()), 0);
            break;
        } else {
            const int err = getLastSocketError();
            if (isWouldBlockError(err)) {
                break;
            }
            outError = err;
            trace_.record("RECV_ERROR", err, static_cast<uint32_t>(outChunk.size()), 0);
            break;
        }
    }

    if (!outChunk.empty()) {
        trace_.record("RECV_BYTES", 0, static_cast<uint32_t>(outChunk.size()), 0);
        return true;
    }
    return false;
}

bool CConnection::pollFlushSendQueue(int& outError) {
    outError = 0;
    const SOCKET sock = socket_.load(std::memory_order_acquire);
    if (sock == INVALID_SOCKET || getState() != State::Connected) {
        return true;
    }

#ifdef MSG_NOSIGNAL
    const int sendFlags = MSG_NOSIGNAL;
#else
    const int sendFlags = 0;
#endif

    std::lock_guard<std::mutex> lock(sendMutex_);
    uint32_t totalSent = 0;

    while (!sendQueue_.empty()) {
        const std::string& front = sendQueue_.front();
        const size_t remaining = front.size() - frontSendOffset_;
        if (remaining == 0) {
            sendQueue_.pop_front();
            frontSendOffset_ = 0;
            continue;
        }

        const int sent = static_cast<int>(
            ::send(sock, front.data() + frontSendOffset_, static_cast<int>(remaining), sendFlags));
        if (sent > 0) {
            frontSendOffset_ += static_cast<size_t>(sent);
            totalSent += static_cast<uint32_t>(sent);
            lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
            if (frontSendOffset_ >= front.size()) {
                sendQueue_.pop_front();
                frontSendOffset_ = 0;
            }
        } else if (sent == SOCKET_ERROR) {
            const int err = getLastSocketError();
            if (isWouldBlockError(err)) {
                break;
            }
            outError = err;
            trace_.record("SEND_ERROR", err, totalSent, 0);
            return false;
        } else {
            break;
        }
    }

    if (totalSent > 0) {
        trace_.record("SEND_BYTES", 0, totalSent, 0);
    }
    return true;
}

bool CConnection::hasPendingSendData() const {
    std::lock_guard<std::mutex> lock(sendMutex_);
    return !sendQueue_.empty();
}

bool CConnection::checkTimeouts(std::chrono::steady_clock::time_point now, const char*& outReason) {
    outReason = nullptr;
    const State st = getState();
    const int64_t nowMs = steadyMs(now);

    if (st == State::Connecting && connectTimeoutMs_ > 0) {
        const int64_t elapsed = nowMs - connectStartMs_.load(std::memory_order_acquire);
        if (elapsed >= static_cast<int64_t>(connectTimeoutMs_)) {
            outReason = "CONNECT_TIMEOUT";
            trace_.record("CONNECT_TIMEOUT", kSocketTimeoutError, 0, connectTimeoutMs_);
            return true;
        }
    } else if (st == State::Connected && readTimeoutMs_ > 0) {
        const int64_t idle = nowMs - lastActivityMs_.load(std::memory_order_acquire);
        if (idle >= static_cast<int64_t>(readTimeoutMs_)) {
            outReason = "READ_TIMEOUT";
            trace_.record("READ_TIMEOUT", kSocketTimeoutError, 0, readTimeoutMs_);
            return true;
        }
    }

    return false;
}

void CConnection::notifyClosedOnMainThread(int wsaError, const char* reason) {
    ScopedRetain selfGuard(this);
    if (closeNotified_) {
        return;
    }
    closeNotified_ = true;
    state_.store(State::Closed, std::memory_order_release);
    closeSocketHandle();
    expectedBodyLength_ = 0;
    recvReadOffset_ = 0;
    std::vector<char>().swap(recvBuffer_);
    trace_.record(reason != nullptr ? reason : "CLOSED", wsaError, 0, 0);

    if (closeCallback_) {
        closeCallback_();
        return;
    }

#if defined(GCLIENT_USE_COCOS2DX)
    if (closeLuaHandler_ > 0) {
        auto* engine = cocos2d::CCLuaEngine::defaultEngine();
        if (engine != nullptr) {
            auto* stack = engine->getLuaStack();
            stack->executeFunctionByHandler(closeLuaHandler_, 0);
        }
    }
#endif
}

} // namespace gclient::net
