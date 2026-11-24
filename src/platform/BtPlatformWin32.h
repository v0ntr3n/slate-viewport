#pragma once

#include "IAuthProvider.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace bt {

/**
 * Platform callback event IDs matching tolua_Platform_open in
 * 01_libcocos2dlua_startup_and_bindings.c verbatim.
 */
enum PlatformEventId : int {
    kCreateNewRole        = 0,
    kEnterTheGameHall     = 1,
    kLevelUp              = 2,

    kInit                 = 1,
    kLogin                = 2,
    kGetServerlist        = 3,
    kGetHash              = 4,
    kGetVersion           = 5,
    kPay                  = 6,
    kQuit                 = 7,
    kLogout               = 8,
    kCrash                = 9,
    kDiffAccount          = 10,
    kShareBack            = 11,
    kPlayFinish           = 12,
    kLowMemory            = 13,
    kHandleOpenURL        = 14,
    kShowLogoFinish       = 15,
    kGetLoginedServerInfo = 16,
    kGetNotice            = 17,
    kQuestion             = 18,
    kGetAppleReview       = 19,
    kGetSuperNotice       = 20,
    kGetUserInformation   = 21,
    kGetBrowseActive      = 22,
    kIssueDJOrders        = 24,
    kGetForceFix          = 25,
    kHandleUrl            = 26,
    kNetworkCapture       = 31,
    kPermissionResult     = 32,
    kATTAuthorizedResult  = 35,
};

enum PlatformHttpStatus : int {
    kHttpSuccess = 0,
    kHttpFailed  = 1,
};

/**
 * Decoupled DES decryption interface for loadConfig() ("BTPRIKEY").
 * Implementations (e.g., OpenSSL DES, CryptoAPI, or custom DES_Decrypt2Buffer)
 * can be injected via Platform::setDesDecryptor().
 */
class IDesDecryptor {
public:
    virtual ~IDesDecryptor() = default;

    /**
     * Decrypts ciphertext using the given 8-byte key (e.g. "BTPRIKEY").
     * Returns true on success and populates outPlaintext.
     */
    virtual bool decrypt(const uint8_t* ciphertext,
                         size_t ciphertextLen,
                         const std::string& key,
                         std::string& outPlaintext) const = 0;
};

/**
 * Minimal flat/nested JSON value map used for platform/config.json and
 * platform/game_config.json without requiring an external JSON library.
 */
struct ConfigDocument {
    std::map<std::string, std::string> values;
    std::map<std::string, std::map<std::string, std::string>> objects;

    bool empty() const { return values.empty() && objects.empty(); }

    std::string getString(const std::string& key, const std::string& fallback = "") const {
        auto it = values.find(key);
        if (it != values.end() && !it->second.empty()) {
            return it->second;
        }
        return fallback;
    }

    bool hasKey(const std::string& key) const {
        auto it = values.find(key);
        return it != values.end() && !it->second.empty();
    }

    std::map<std::string, std::string> getObject(const std::string& key) const {
        auto it = objects.find(key);
        if (it != objects.end()) {
            return it->second;
        }
        return {};
    }
};

/**
 * Queued main-thread callback event drained by bt::Platform::tickLoop().
 */
struct PendingCallback {
    int eventId = 0;
    int statusCode = kHttpSuccess;
    std::string payload;
};

/**
 * Table-driven capability shim descriptor for dropped Android/iOS mobile SDK
 * calls (pay, shareWeixin, playVideo, openCustomWebView, push, tracking, etc.).
 */
struct CapabilityShimEntry {
    const char* methodName;
    const char* category;
    bool emitCallback;
    int callbackEventId;
    int defaultStatusCode;
    const char* defaultPayloadJson;
};

/**
 * Native Win32 port of bt::Platform (libnew_sdk.so, SDK version 0.10.41).
 *
 * Thread-safety model:
 *   - HTTP requests execute asynchronously on background threads via libcurl.
 *   - Completed HTTP responses, auth events, and capability-shim resolutions
 *     enqueue into receiveCallBack() under a mutex.
 *   - tickLoop() drains the queue on the Cocos2d-x main thread and invokes the
 *     registered callback(s) so Lua is never touched off-thread.
 */
class Platform {
public:
    using CallbackHandler = std::function<void(int eventId, int statusCode, const std::string& payload)>;
    using LogHandler = std::function<void(const std::string& level, const std::string& message)>;
    using WebViewBridgeHandler = std::function<void(const std::string& action,
                                                    int x,
                                                    int y,
                                                    int width,
                                                    int height,
                                                    const std::string& url)>;

    static constexpr const char* kSdkVersion = "0.10.41";
    static constexpr const char* kDefaultConfigDesKey = "BTPRIKEY";
    static constexpr const char* kDefaultSignKey = "9c98948d313ccdAE962e899a60692c_russia";

    static Platform* getInstance();

    // Dependency injection hooks (must be called before initSDK if overriding defaults)
    void setAuthProvider(std::shared_ptr<IAuthProvider> provider);
    std::shared_ptr<IAuthProvider> getAuthProvider() const;

    void setDesDecryptor(std::shared_ptr<IDesDecryptor> decryptor);
    void setLogHandler(LogHandler handler);
    void setCallbackHandler(CallbackHandler handler);
    void setSyncCallbackHandler(CallbackHandler handler);
    void setWebViewBridgeHandler(WebViewBridgeHandler handler);
    void dispatchWebViewBridge(const std::string& action,
                               int x,
                               int y,
                               int width,
                               int height,
                               const std::string& url);
    void setResourceRoot(const std::string& rootPath);

    // Core lifecycle & config (ported from 04_libnew_sdk_platform.c)
    void initSDK(const std::string& jsonParam = "", CallbackHandler callback = nullptr);
    ConfigDocument loadConfig(const std::string& relativePath) const;
    void tickLoop();

    // Authentication
    void login();
    void logout();
    bool isLogined() const;

    // URL, host, signing & config accessors
    std::string getHost() const;
    std::string getLogHost() const;
    std::string getStandAlone() const;
    std::string getKey() const;
    std::string getUrlParam() const;
    std::string signUrl(const std::string& url) const;
    std::string signUrl(const std::string& url, const std::string& customKey) const;
    std::string compleUrl(const std::string& url) const;

    // Web API calls (libcurl async HTTP -> receiveCallBack queue)
    void getServerList(const std::string& jsonParams = "{}");
    void getVersionInfo(const std::string& jsonParams = "{}");
    void getHash(const std::string& jsonParams = "{}");
    void getHashWithSimulation(const std::string& jsonParams = "{}");
    void getLoginedServerInfo(const std::string& jsonParams = "{}");
    void getNotice(const std::string& jsonParams = "{}");
    void getSuperNotice(const std::string& jsonParams = "{}");
    void getAppleReview(const std::string& jsonParams = "{}");
    void question(const std::string& jsonParams = "{}");
    void getUserInformation(const std::string& jsonParams = "{}");
    void getBrowseActive(const std::string& jsonParams = "{}");
    void getForceFix(const std::string& jsonParams = "{}");
    void callUniversalWebFunction(int eventId,
                                  const std::string& endpoint,
                                  const std::string& jsonParams = "{}");

    // Async main-thread callback queue
    void receiveCallBack(int eventId, int statusCode, const std::string& payload);
    void registeCallBackBySync(CallbackHandler handler);

    // Device / platform metadata
    bool isDebug() const;
    bool isAd() const;
    void setDebugEnv(bool debugEnv);
    std::string getUUID() const;
    std::string getPid() const;
    std::string getIdfa() const;
    std::string getPL() const;
    std::string getOS() const;
    std::string getGN() const;
    std::string getSDKVersion() const;
    std::string getUserCenterName() const;
    std::string getDeviceInfo() const;
    std::string getDeviceFeature() const;
    std::string getLocaleInfo() const;
    void setSimulationInfo(const std::string& jsonInfo);
    void setMainScreenBrightness(float brightness);
    float getMainScreenBrightness() const;
    bool checkMethod(const std::string& methodName) const;

    // Dropped Android/iOS mobile SDK calls routed through the table-driven capability shim
    void pay(const std::string& jsonParams = "{}");
    void showToolBar();
    void hideToolBar();
    void enterUserCenter();
    void accountSwitch();
    void sendInformationToPlatform(int infoType, const std::string& jsonParams = "{}");
    void pause();
    void onPressBack();
    void shareWeixin(const std::string& jsonParams = "{}");
    void playVideo(const std::string& videoPath = "");
    void openCustomWebView(const std::string& jsonParams = "{}");
    void closeCustomWebView();
    void doCustomWebViewAction(const std::string& jsonParams = "{}");
    void quit();
    void openUrl(const std::string& url);
    void sendTracking(const std::string& eventName, const std::string& jsonParams = "{}");
    void retention(const std::string& jsonParams = "{}");
    void sendLog(const std::string& jsonParams = "{}");
    void sendAdstat();
    void showMessage(const std::string& title, const std::string& message = "");
    void issueDJOrders();
    void searchHandleUrl();
    void getNetworkCapture(const std::string& jsonParams = "{}");
    void callUniversalFunction(const std::string& funcName, const std::string& jsonParams = "{}");
    void callUniversalFunctionWithBack(const std::string& funcName,
                                       const std::string& jsonParams = "{}");
    void callUniversalFunctionWithBack(const std::string& funcName,
                                       const std::string& jsonParams,
                                       std::function<void(const std::string&)> callback);

    // Table-driven capability shim lookup
    static const CapabilityShimEntry* findCapabilityShim(const std::string& methodName);
    bool invokeCapabilityShim(const std::string& methodName, const std::string& detail = "");

    // Utility helpers (exposed for testing & Lua bindings)
    static std::string urlEncode(const std::string& raw);
    static std::string sortUrlParams(const std::string& url);
    static std::string md5Hex(const std::string& data);
    static std::map<std::string, std::string> parseFlatJsonObject(const std::string& jsonStr);

private:
    Platform();
    ~Platform();
    Platform(const Platform&) = delete;
    Platform& operator=(const Platform&) = delete;

    void log(const std::string& level, const std::string& message) const;
    bool readBinaryFile(const std::string& path, std::vector<uint8_t>& outBytes) const;
    void sendHTTPRequest(int eventId, const std::string& url, bool shouldSign);
    std::string buildQueryFromJson(const std::string& jsonParams) const;
    void startLoginAttempt(bool allowInteractiveRetryOnExpiredCache);
    std::string resolveConfigPath(const std::string& relativePath) const;
    std::vector<std::string> buildConfigSearchRoots() const;

    mutable std::recursive_mutex stateMutex_;
    mutable std::mutex callbackQueueMutex_;
    std::deque<PendingCallback> callbackQueue_;

    std::shared_ptr<IAuthProvider> authProvider_;
    std::shared_ptr<IDesDecryptor> desDecryptor_;
    CallbackHandler callbackHandler_;
    CallbackHandler syncCallbackHandler_;
    LogHandler logHandler_;
    WebViewBridgeHandler webViewBridgeHandler_;

    ConfigDocument platformConfig_;
    ConfigDocument gameConfig_;
    std::map<std::string, std::string> payConfig_;
    std::map<std::string, std::string> localizedConfig_;

    std::string resourceRoot_;
    std::string platformDir_;
    std::string pid_;
    std::string sessionToken_;
    std::string uuid_;
    std::string simulationHashHost_;
    std::string pushUrl_;
    std::string gnOverride_;
    std::string combinedPl_;

    int64_t initTimestamp_ = 0;
    int debugLevel_ = 0;
    float screenBrightness_ = 1.0f;

    bool isDebugEnv_ = false;
    bool isInitialized_ = false;
    bool isLoggingIn_ = false;
    bool isLogined_ = false;
    bool isStandAlone_ = false;
    bool isSimulation_ = false;

    std::atomic<bool> shuttingDown_{false};
};

}  // namespace bt
