#pragma once

#include "CConnection.h"

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace gclient::net {

/// Thread-safe network manager matching Win32 Client `CNetwork`:
/// - `CNetwork::sharedNetwork()`
/// - `CNetwork::newConnection()`
/// - `CNetwork::update(float dt)`
/// Inherits from `cocos2d::CCObject` when `GCLIENT_USE_COCOS2DX` is enabled.
class CNetwork
#if defined(GCLIENT_USE_COCOS2DX)
    : public cocos2d::CCObject
#endif
{
public:
    static CNetwork* sharedNetwork();
    static void destroySharedNetwork();

#if defined(GCLIENT_USE_COCOS2DX)
    ~CNetwork() override;
#else
    virtual ~CNetwork();
#endif

    /// Allocates and owns a new `CConnection` instance (matches `CNetwork::newConnection()`).
    CConnection* newConnection();

    /// Registers an active connection with the non-blocking poll loop.
    void addConnection(CConnection* conn);

    /// Unregisters a connection from the poll loop and schedules safe release.
    void removeConnection(CConnection* conn);

    /// Drains queued incoming packets and close events on the Cocos2d-x main thread.
    void update(float dt);

    /// Stops the background poll thread and closes all active connections.
    void shutdown();

    /// Number of currently owned connections (for diagnostics/tests).
    size_t activeConnectionCount() const;

    friend class CConnection;

private:
    enum class EventType {
        Data,
        Closed
    };

    struct PendingEvent {
        EventType type = EventType::Data;
        CConnection* connection = nullptr;
        std::string data;
        int wsaError = 0;
        const char* reason = nullptr;
    };

    CNetwork();

    CNetwork(const CNetwork&) = delete;
    CNetwork& operator=(const CNetwork&) = delete;

    void onConnectionDestroyed(CConnection* conn);
    void startPollThread();
    void pollLoop();
    void doAddConnection(CConnection* conn);
    void doReleaseConnection(CConnection* conn);
    void enqueueEvent(PendingEvent&& ev);

    WinsockSession winsock_;

    std::mutex threadLifecycleMutex_;
    std::atomic<bool> running_{false};
    std::thread pollThread_;

    mutable std::mutex ownedMutex_;
#if defined(GCLIENT_USE_COCOS2DX)
    std::vector<CConnection*> ownedConnections_;
#else
    std::vector<std::unique_ptr<CConnection>> ownedConnections_;
#endif
    std::unordered_set<CConnection*> liveSet_;

    std::mutex pendingOpsMutex_;
    std::vector<CConnection*> pendingAdd_;
    std::vector<CConnection*> pendingRemove_;

    std::vector<CConnection*> polledConnections_;

    std::mutex eventMutex_;
    std::deque<PendingEvent> eventQueue_;

    static std::mutex s_instanceMutex;
    static CNetwork* s_instance;
};

} // namespace gclient::net
