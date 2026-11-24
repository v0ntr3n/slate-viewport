#pragma once

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>

namespace bt {

/**
 * Represents an authenticated user session decoupled from any mobile SDK.
 */
struct AuthSession {
    std::string pid;             // Platform user ID (mapped to bt::Platform::_pid)
    std::string token;           // Session / access token
    std::string username;        // Display name or account identifier
    std::string extraJson;       // Optional provider-specific JSON payload
    bool authenticated = false;
    int64_t expiresAtEpoch = 0;  // Unix timestamp (seconds), 0 = non-expiring
};

/**
 * Result returned asynchronously or synchronously by IAuthProvider::login().
 */
struct AuthResult {
    bool success = false;
    bool fromCache = false;
    int errorCode = 0;
    std::string errorMessage;
    AuthSession session;
};

using AuthCallback = std::function<void(const AuthResult&)>;
using LogoutCallback = std::function<void(bool)>;

/**
 * Abstract authentication provider interface for the Win32 port of Win32 Client.
 * Decouples bt::Platform from volatile Android/iOS mobile SDKs (WeChat, QQ,
 * channel SDKs, etc.) by allowing offline stubs or external launcher/IPC
 * brokers to supply session credentials cleanly.
 */
class IAuthProvider {
public:
    virtual ~IAuthProvider() = default;

    virtual std::string providerName() const = 0;

    virtual bool initialize(const std::map<std::string, std::string>& initParams) = 0;

    virtual void login(AuthCallback onComplete) = 0;

    virtual void logout(LogoutCallback onComplete) = 0;

    virtual bool isAuthenticated() const = 0;

    virtual AuthSession currentSession() const = 0;

    /**
     * Optional main-thread pump called from bt::Platform::tickLoop() so
     * asynchronous IPC/broker implementations can dispatch results safely.
     */
    virtual void poll() {}
};

/**
 * Built-in offline / private-server authentication provider.
 * Resolves login deterministically without network or mobile SDK dependencies.
 */
class LocalStubAuthProvider final : public IAuthProvider {
public:
    struct Config {
        std::string defaultPid = "win32_local_0001";
        std::string defaultToken = "local_stub_session_token";
        std::string defaultUsername = "Win32Tester";
        std::string extraJson = "{}";
        bool failLogin = false;
        std::string failureMessage = "Simulated local login failure";
    };

    LocalStubAuthProvider() = default;
    explicit LocalStubAuthProvider(Config config) : config_(std::move(config)) {}

    std::string providerName() const override { return "LocalStubAuthProvider"; }

    bool initialize(const std::map<std::string, std::string>& initParams) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itPid = initParams.find("stub_pid");
        if (itPid != initParams.end() && !itPid->second.empty()) {
            config_.defaultPid = itPid->second;
        }
        auto itToken = initParams.find("stub_token");
        if (itToken != initParams.end() && !itToken->second.empty()) {
            config_.defaultToken = itToken->second;
        }
        auto itUser = initParams.find("stub_username");
        if (itUser != initParams.end() && !itUser->second.empty()) {
            config_.defaultUsername = itUser->second;
        }
        initialized_ = true;
        return true;
    }

    void login(AuthCallback onComplete) override {
        AuthResult result;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (config_.failLogin) {
                result.success = false;
                result.errorCode = -1;
                result.errorMessage = config_.failureMessage;
                session_ = AuthSession{};
            } else {
                session_.pid = config_.defaultPid;
                session_.token = config_.defaultToken;
                session_.username = config_.defaultUsername;
                session_.extraJson = config_.extraJson;
                session_.authenticated = true;
                session_.expiresAtEpoch = 0;

                result.success = true;
                result.errorCode = 0;
                result.session = session_;
            }
        }
        if (onComplete) {
            onComplete(result);
        }
    }

    void logout(LogoutCallback onComplete) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = AuthSession{};
        }
        if (onComplete) {
            onComplete(true);
        }
    }

    bool isAuthenticated() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_.authenticated;
    }

    AuthSession currentSession() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_;
    }

    void setConfig(Config config) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_ = std::move(config);
    }

private:
    mutable std::mutex mutex_;
    Config config_;
    AuthSession session_;
    bool initialized_ = false;
};

/**
 * External broker authentication provider hook.
 * Allows a Win32 desktop launcher, local IPC daemon, named pipe helper, or
 * config file to inject a pre-authenticated session token into the game engine
 * without embedding any third-party mobile SDK inside the game binary.
 *
 * Resolution priority during login():
 *   1. Custom IPC TokenFetcher functor (if installed by the host launcher).
 *   2. Directly injected session via injectSession().
 *   3. Local broker token file (key=value lines: pid=..., token=..., username=...).
 *   4. Process environment variables (GCLIENT_AUTH_PID, GCLIENT_AUTH_TOKEN, GCLIENT_AUTH_USER).
 */
class ExternalBrokerAuthProvider final : public IAuthProvider {
public:
    using TokenFetcher = std::function<bool(AuthSession& outSession, std::string& outError)>;

    ExternalBrokerAuthProvider() = default;

    explicit ExternalBrokerAuthProvider(std::string brokerTokenFilePath)
        : brokerTokenFilePath_(std::move(brokerTokenFilePath)) {}

    explicit ExternalBrokerAuthProvider(TokenFetcher fetcher)
        : customFetcher_(std::move(fetcher)) {}

    std::string providerName() const override { return "ExternalBrokerAuthProvider"; }

    void setTokenFetcher(TokenFetcher fetcher) {
        std::lock_guard<std::mutex> lock(mutex_);
        customFetcher_ = std::move(fetcher);
    }

    void setBrokerTokenFilePath(std::string path) {
        std::lock_guard<std::mutex> lock(mutex_);
        brokerTokenFilePath_ = std::move(path);
    }

    void injectSession(AuthSession session) {
        std::lock_guard<std::mutex> lock(mutex_);
        injectedSession_ = std::move(session);
        hasInjectedSession_ = !injectedSession_.pid.empty();
    }

    bool initialize(const std::map<std::string, std::string>& initParams) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itPath = initParams.find("broker_token_file");
        if (itPath != initParams.end() && !itPath->second.empty()) {
            brokerTokenFilePath_ = itPath->second;
        }
        initialized_ = true;
        return true;
    }

    void login(AuthCallback onComplete) override {
        AuthResult result;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            AuthSession resolved;
            std::string error;

            bool ok = false;
            if (customFetcher_) {
                ok = customFetcher_(resolved, error);
            } else if (hasInjectedSession_) {
                resolved = injectedSession_;
                ok = true;
            } else if (!brokerTokenFilePath_.empty() &&
                       loadFromBrokerFile(brokerTokenFilePath_, resolved, error)) {
                ok = true;
            } else if (loadFromEnvironment(resolved)) {
                ok = true;
            } else if (error.empty()) {
                error = "No broker session available (set TokenFetcher, injectSession, broker file, or GCLIENT_AUTH_PID/GCLIENT_AUTH_TOKEN)";
            }

            if (ok && !resolved.pid.empty()) {
                resolved.authenticated = true;
                session_ = resolved;
                result.success = true;
                result.errorCode = 0;
                result.session = session_;
            } else {
                session_ = AuthSession{};
                result.success = false;
                result.errorCode = -2;
                result.errorMessage = error.empty() ? "Broker returned empty pid" : error;
            }
        }

        if (onComplete) {
            onComplete(result);
        }
    }

    void logout(LogoutCallback onComplete) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = AuthSession{};
            hasInjectedSession_ = false;
            injectedSession_ = AuthSession{};
        }
        if (onComplete) {
            onComplete(true);
        }
    }

    bool isAuthenticated() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_.authenticated;
    }

    AuthSession currentSession() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_;
    }

private:
    static std::string trim(const std::string& s) {
        const size_t first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return {};
        const size_t last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    }

    static bool loadFromBrokerFile(const std::string& path,
                                   AuthSession& outSession,
                                   std::string& outError) {
        std::ifstream ifs(path);
        if (!ifs.is_open()) {
            outError = "Failed to open broker token file: " + path;
            return false;
        }
        std::string line;
        while (std::getline(ifs, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            const size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            const std::string key = trim(line.substr(0, eq));
            const std::string val = trim(line.substr(eq + 1));
            if (key == "pid") {
                outSession.pid = val;
            } else if (key == "token") {
                outSession.token = val;
            } else if (key == "username") {
                outSession.username = val;
            } else if (key == "extra_json") {
                outSession.extraJson = val;
            } else if (key == "expires_at") {
                try {
                    outSession.expiresAtEpoch = std::stoll(val);
                } catch (...) {
                    outSession.expiresAtEpoch = 0;
                }
            }
        }
        if (outSession.pid.empty()) {
            outError = "Broker token file missing required 'pid' field: " + path;
            return false;
        }
        return true;
    }

    static bool loadFromEnvironment(AuthSession& outSession) {
        const char* envPid = std::getenv("GCLIENT_AUTH_PID");
        if (!envPid || !*envPid) {
            return false;
        }
        outSession.pid = envPid;
        if (const char* envToken = std::getenv("GCLIENT_AUTH_TOKEN")) {
            outSession.token = envToken;
        }
        if (const char* envUser = std::getenv("GCLIENT_AUTH_USER")) {
            outSession.username = envUser;
        }
        if (const char* envExtra = std::getenv("GCLIENT_AUTH_EXTRA_JSON")) {
            outSession.extraJson = envExtra;
        }
        return true;
    }

    mutable std::mutex mutex_;
    TokenFetcher customFetcher_;
    std::string brokerTokenFilePath_;
    AuthSession injectedSession_;
    bool hasInjectedSession_ = false;
    AuthSession session_;
    bool initialized_ = false;
};

}  // namespace bt
