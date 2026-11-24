#pragma once

#include <string>

#include "cocos2d.h"

struct lua_State;

namespace gclient {

struct AppConfig {
    std::string resourcesDir;
    std::string baseAssetsDir;
    std::string profileDir;
    std::string writableDir;
    std::string hotfixDir;
    std::string logsDir;
    std::string dumpsDir;

    int windowWidth = 1136;
    int windowHeight = 640;

    bool muteAudio = false;
    bool validateAssetsOnly = false;
};

class AppDelegate final : private cocos2d::CCApplication {
public:
    explicit AppDelegate(const AppConfig& config = AppConfig{});
    ~AppDelegate() override;

    AppDelegate(const AppDelegate&) = delete;
    AppDelegate& operator=(const AppDelegate&) = delete;

    // CCApplication lifecycle overrides
    bool applicationDidFinishLaunching() override;
    void applicationDidEnterBackground() override;
    void applicationWillEnterForeground() override;

    bool assetValidationSucceeded() const noexcept { return m_assetValidationOk; }
    const AppConfig& config() const noexcept { return m_config; }

private:
    class FrameTicker;

    void configureFileUtils();
    void registerLuaBindings(lua_State* L);
    void scheduleNativeLoops();
    void unscheduleNativeLoops();
    bool runAssetValidation();

    AppConfig m_config;
    FrameTicker* m_ticker = nullptr;
    bool m_assetValidationOk = false;
};

} // namespace gclient
