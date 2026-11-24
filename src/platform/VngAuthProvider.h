#pragma once

#include "platform/IAuthProvider.h"

#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bt {

/**
 * VNG / ZingID authentication provider for Win32.
 *
 * Supports native Win32 ZingID / Guest / PID+Token sign-in and persists valid
 * sessions across launches under %LOCALAPPDATA%/GCLIENT/vng_session.json (or an
 * explicit --profile-dir / multi-instance slot override via GCLIENT_SESSION_FILE).
 */
class VngAuthProvider final : public IAuthProvider {
public:
    struct Config {
        std::string gameId = "vnsg2";
        std::string authorizeUrl = "https://login-vnsg2.vnggames.net";
        std::string tokenUrl;
        std::string clientId = "vnsg2";
        std::string ghk = "d345c6c5c29669eae007b682625fbf42";
        std::string gtsdkGameId = "OMG";
        std::string userUrl = "https://pp.m.zing.vn";
        std::string gameVersion = "1.0.38";
        std::string sessionFilePath;
        int timeoutSeconds = 180;
    };

    VngAuthProvider();
    explicit VngAuthProvider(Config config);
    ~VngAuthProvider() override;

    std::string providerName() const override { return "VngAuthProvider"; }

    bool initialize(const std::map<std::string, std::string>& initParams) override;
    void login(AuthCallback onComplete) override;
    void logout(LogoutCallback onComplete) override;
    bool isAuthenticated() const override;
    AuthSession currentSession() const override;
    void poll() override;

    bool authenticateWithZingId(const std::string& username,
                                const std::string& password,
                                AuthSession& outSession,
                                std::string& outError);
    bool authenticateAsVngGuest(AuthSession& outSession,
                                std::string& outError);

    static bool isOfflineStubToken(const std::string& tok);
    static bool isEphemeralPidInstancePath(const std::string& path);
    static std::string defaultSessionFile();
    static std::string resolvePersistentDeviceId(const std::string& sessionFileHint = "");
    static bool purgePoisonedLocalAppDataSession();

    Config getConfig() const;
    std::string resolveSessionFilePath() const;
    bool tryLoadCachedSession(AuthSession& outSession) const;
    void saveCachedSession(const AuthSession& session) const;
    void clearCachedSession() const;

private:
    void cancelPendingLogin();
    void enqueueResult(AuthCallback cb, AuthResult res);

    mutable std::mutex mutex_;
    Config config_;
    AuthSession session_;
    bool initialized_ = false;

    std::atomic<bool> loginInProgress_{false};
    std::atomic<bool> cancelRequested_{false};
    std::thread workerThread_;

    std::mutex callbackMutex_;
    std::deque<std::pair<AuthCallback, AuthResult>> pendingCallbacks_;
};

} // namespace bt
