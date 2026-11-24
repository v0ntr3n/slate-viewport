#include "CNetwork.h"

#include <algorithm>
#include <chrono>

#ifndef _WIN32
#include <cerrno>
#include <sys/select.h>
#endif

namespace gclient::net {

namespace {

#ifdef _WIN32
constexpr int kNetworkTimeoutError = WSAETIMEDOUT;
#else
constexpr int kNetworkTimeoutError = ETIMEDOUT;
#endif

} // namespace

std::mutex CNetwork::s_instanceMutex;
CNetwork* CNetwork::s_instance = nullptr;

CNetwork* CNetwork::sharedNetwork() {
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    if (s_instance == nullptr) {
        s_instance = new CNetwork();
    }
    return s_instance;
}

void CNetwork::destroySharedNetwork() {
    CNetwork* inst = nullptr;
    {
        std::lock_guard<std::mutex> lock(s_instanceMutex);
        inst = s_instance;
        s_instance = nullptr;
    }
    if (inst != nullptr) {
        inst->shutdown();
#if defined(GCLIENT_USE_COCOS2DX)
        inst->release();
#else
        delete inst;
#endif
    }
}

CNetwork::CNetwork() {
    startPollThread();
}

CNetwork::~CNetwork() {
    shutdown();
}

void CNetwork::startPollThread() {
    std::lock_guard<std::mutex> lock(threadLifecycleMutex_);
    bool expected = false;
    if (running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        if (pollThread_.joinable()) {
            pollThread_.join();
        }
        pollThread_ = std::thread(&CNetwork::pollLoop, this);
    }
}

void CNetwork::shutdown() {
    {
        std::lock_guard<std::mutex> lock(threadLifecycleMutex_);
        bool expected = true;
        if (running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
            if (pollThread_.joinable()) {
                pollThread_.join();
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventQueue_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        pendingAdd_.clear();
        pendingRemove_.clear();
    }
    polledConnections_.clear();

#if defined(GCLIENT_USE_COCOS2DX)
    std::vector<CConnection*> toRelease;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.clear();
        toRelease.swap(ownedConnections_);
    }

    for (CConnection* conn : toRelease) {
        if (conn != nullptr) {
            conn->network_ = nullptr;
            conn->closeSocketHandle();
            conn->release();
        }
    }
#else
    std::vector<std::unique_ptr<CConnection>> toDestroy;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.clear();
        toDestroy.swap(ownedConnections_);
    }

    for (auto& conn : toDestroy) {
        if (conn) {
            conn->network_ = nullptr;
            conn->closeSocketHandle();
        }
    }
#endif
}

void CNetwork::onConnectionDestroyed(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.erase(conn);
    }
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventQueue_.erase(
            std::remove_if(eventQueue_.begin(), eventQueue_.end(),
                           [conn](const PendingEvent& ev) { return ev.connection == conn; }),
            eventQueue_.end());
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        pendingAdd_.erase(std::remove(pendingAdd_.begin(), pendingAdd_.end(), conn), pendingAdd_.end());
        pendingRemove_.push_back(conn);
    }
}

CConnection* CNetwork::newConnection() {
    startPollThread();
#if defined(GCLIENT_USE_COCOS2DX)
    // `new CConnection()` starts with m_uReference == 1 (held by ownedConnections_).
    // Calling retain() + autorelease() matches Cocos2d-x factory conventions so Lua's
    // optional `conn:retain()` / `conn:release()` never drops the refcount below 1
    // while CNetwork's background pollThread_ is active.
    auto* raw = new CConnection();
    raw->network_ = this;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.insert(raw);
        ownedConnections_.push_back(raw);
    }
    raw->retain();
    raw->autorelease();
    return raw;
#else
    auto conn = std::make_unique<CConnection>();
    CConnection* raw = conn.get();
    raw->network_ = this;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.insert(raw);
        ownedConnections_.push_back(std::move(conn));
    }
    return raw;
#endif
}

void CNetwork::addConnection(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    startPollThread();
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.insert(conn);
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        pendingRemove_.erase(
            std::remove(pendingRemove_.begin(), pendingRemove_.end(), conn),
            pendingRemove_.end());
        pendingAdd_.push_back(conn);
    }
}

void CNetwork::removeConnection(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(pendingOpsMutex_);
    pendingAdd_.erase(std::remove(pendingAdd_.begin(), pendingAdd_.end(), conn), pendingAdd_.end());
    pendingRemove_.push_back(conn);
}

size_t CNetwork::activeConnectionCount() const {
    std::lock_guard<std::mutex> lock(ownedMutex_);
    return liveSet_.size();
}

void CNetwork::doAddConnection(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    if (std::find(polledConnections_.begin(), polledConnections_.end(), conn) ==
        polledConnections_.end()) {
        polledConnections_.push_back(conn);
    }
}

void CNetwork::doReleaseConnection(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    polledConnections_.erase(
        std::remove(polledConnections_.begin(), polledConnections_.end(), conn),
        polledConnections_.end());

    // Ensure underlying OS socket and queued send buffers are immediately cleaned up.
    conn->closeSocketHandle();
    {
        std::lock_guard<std::mutex> sendLock(conn->sendMutex_);
        conn->sendQueue_.clear();
        conn->frontSendOffset_ = 0;
    }

    CConnection::State st = conn->state_.load(std::memory_order_acquire);
    while (st == CConnection::State::Connecting || st == CConnection::State::Connected) {
        if (conn->state_.compare_exchange_weak(
                st, CConnection::State::Closing, std::memory_order_acq_rel)) {
            st = CConnection::State::Closing;
            break;
        }
    }

    // If connection was already closed locally on the main thread (State::Closed),
    // purge stale queued events and remove it from liveSet_ immediately.
    // Otherwise (State::Closing from remote EOF / timeout / error), keep it in liveSet_
    // until CNetwork::update() delivers queued Data + Closed events on the main thread.
    if (st == CConnection::State::Closed || st == CConnection::State::Disconnected) {
        {
            std::lock_guard<std::mutex> evLock(eventMutex_);
            eventQueue_.erase(
                std::remove_if(eventQueue_.begin(), eventQueue_.end(),
                               [conn](const PendingEvent& ev) { return ev.connection == conn; }),
                eventQueue_.end());
        }
        {
            std::lock_guard<std::mutex> ownLock(ownedMutex_);
            if (conn->getState() == CConnection::State::Closed ||
                conn->getState() == CConnection::State::Disconnected) {
                liveSet_.erase(conn);
            }
        }
    }
}

void CNetwork::enqueueEvent(PendingEvent&& ev) {
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventQueue_.push_back(std::move(ev));
}

void CNetwork::pollLoop() {
    while (running_.load(std::memory_order_acquire)) {
        {
            std::vector<CConnection*> adds;
            std::vector<CConnection*> removes;
            {
                std::lock_guard<std::mutex> lock(pendingOpsMutex_);
                adds.swap(pendingAdd_);
                removes.swap(pendingRemove_);
            }
            for (CConnection* c : adds) {
                doAddConnection(c);
            }
            for (CConnection* c : removes) {
                doReleaseConnection(c);
            }
        }

        if (polledConnections_.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        const auto now = std::chrono::steady_clock::now();

        fd_set readSet;
        fd_set writeSet;
        fd_set exceptSet;
        FD_ZERO(&readSet);
        FD_ZERO(&writeSet);
        FD_ZERO(&exceptSet);

        SOCKET maxFd = 0;
        size_t activeFdCount = 0;
        std::vector<CConnection*> timedOut;

        for (CConnection* conn : polledConnections_) {
            const CConnection::State st = conn->getState();
            const SOCKET sock = conn->nativeHandle();
            if (sock == INVALID_SOCKET || st == CConnection::State::Closed ||
                st == CConnection::State::Closing || st == CConnection::State::Disconnected) {
                timedOut.push_back(conn);
                continue;
            }

            const char* timeoutReason = nullptr;
            if (conn->checkTimeouts(now, timeoutReason)) {
                timedOut.push_back(conn);
                enqueueEvent(PendingEvent{
                    EventType::Closed,
                    conn,
                    {},
                    kNetworkTimeoutError,
                    timeoutReason
                });
                continue;
            }

            if (st == CConnection::State::Connecting) {
                FD_SET(sock, &writeSet);
                FD_SET(sock, &exceptSet);
            } else if (st == CConnection::State::Connected) {
                FD_SET(sock, &readSet);
                FD_SET(sock, &exceptSet);
                if (conn->hasPendingSendData()) {
                    FD_SET(sock, &writeSet);
                }
            }

            if (sock > maxFd) {
                maxFd = sock;
            }
            ++activeFdCount;
        }

        for (CConnection* dead : timedOut) {
            doReleaseConnection(dead);
        }

        if (activeFdCount == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 5000;

#ifdef _WIN32
        const int nfds = 0;
#else
        const int nfds = static_cast<int>(maxFd + 1);
#endif
        const int ready = ::select(nfds, &readSet, &writeSet, &exceptSet, &tv);

        if (ready <= 0) {
            continue;
        }

        std::vector<CConnection*> toRemove;
        for (CConnection* conn : polledConnections_) {
            const SOCKET sock = conn->nativeHandle();
            if (sock == INVALID_SOCKET) {
                toRemove.push_back(conn);
                continue;
            }

            const CConnection::State st = conn->getState();
            const bool isReadable = FD_ISSET(sock, &readSet) != 0;
            const bool isWritable = FD_ISSET(sock, &writeSet) != 0;
            const bool isExcept   = FD_ISSET(sock, &exceptSet) != 0;

            if (st == CConnection::State::Connecting) {
                if (isWritable || isExcept) {
                    if (!conn->pollCompleteConnect()) {
                        toRemove.push_back(conn);
                        enqueueEvent(PendingEvent{
                            EventType::Closed,
                            conn,
                            {},
                            CConnection::getLastSocketError(),
                            "CONNECT_FAILED"
                        });
                    }
                }
                continue;
            }

            if (st != CConnection::State::Connected) {
                continue;
            }

            if (isExcept) {
                toRemove.push_back(conn);
                enqueueEvent(PendingEvent{
                    EventType::Closed,
                    conn,
                    {},
                    CConnection::getLastSocketError(),
                    "SOCKET_EXCEPTION"
                });
                continue;
            }

            if (isWritable) {
                int sendErr = 0;
                if (!conn->pollFlushSendQueue(sendErr)) {
                    toRemove.push_back(conn);
                    enqueueEvent(PendingEvent{
                        EventType::Closed,
                        conn,
                        {},
                        sendErr,
                        "SEND_ERROR"
                    });
                    continue;
                }
            }

            if (isReadable) {
                std::string chunk;
                bool peerClosed = false;
                int recvErr = 0;
                if (conn->pollReadSocket(chunk, peerClosed, recvErr)) {
                    enqueueEvent(PendingEvent{
                        EventType::Data,
                        conn,
                        std::move(chunk),
                        0,
                        nullptr
                    });
                }
                if (peerClosed || recvErr != 0) {
                    toRemove.push_back(conn);
                    enqueueEvent(PendingEvent{
                        EventType::Closed,
                        conn,
                        {},
                        recvErr,
                        peerClosed ? "PEER_CLOSED" : "RECV_ERROR"
                    });
                }
            }
        }

        for (CConnection* dead : toRemove) {
            doReleaseConnection(dead);
        }
    }
}

void CNetwork::update(float /*dt*/) {
    std::deque<PendingEvent> drained;
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        if (eventQueue_.empty()) {
            return;
        }
        drained.swap(eventQueue_);
    }

    for (auto& ev : drained) {
        CConnection* conn = ev.connection;
        if (conn == nullptr) {
            continue;
        }

        bool isLive = false;
        {
            std::lock_guard<std::mutex> lock(ownedMutex_);
            isLive = (liveSet_.find(conn) != liveSet_.end());
            if (isLive) {
                conn->retain();
            }
        }
        if (!isLive) {
            continue;
        }

        struct ReleaseOnScopeExit {
            CConnection* c;
            ~ReleaseOnScopeExit() {
                if (c != nullptr) {
                    c->release();
                }
            }
        } releaseGuard{conn};

        if (ev.type == EventType::Data) {
            if (conn->getState() != CConnection::State::Closed) {
                conn->appendIncomingData(ev.data.data(), ev.data.size());
                conn->doRead();
            }
        } else if (ev.type == EventType::Closed) {
            conn->notifyClosedOnMainThread(ev.wsaError, ev.reason);
            if (conn->getState() == CConnection::State::Closed) {
                std::lock_guard<std::mutex> lock(ownedMutex_);
                liveSet_.erase(conn);
            }
        }
    }
}

} // namespace gclient::net
