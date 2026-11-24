#pragma once

#include "cocos2d.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

enum BTPlatformType {
    kBT_PLATFORM_IOS = 0,
    kBT_PLATFORM_ANDROID = 1
};

class BTUtil {
public:
    using PostUnscheduleAllHook = std::function<void()>;

    static void randomseed(unsigned int seed);
    static double random();

    static bool split(const std::string& str, const std::string& delim, std::vector<std::string>& out);
    static bool split(const std::string& str, char delim, std::vector<std::string>& out);
    static cocos2d::CCArray* cutString(cocos2d::CCString* str, cocos2d::CCString* delim);
    static cocos2d::CCArray* splitString(const std::string& utf8Str);

    static bool checkType(cocos2d::CCObject* obj, const std::string& typeName);
    static int64_t getSvrTimeInterval();
    static void syncTime(int64_t svrTime);

    static int getPlatform();          // Returns kBT_PLATFORM_ANDROID (1)
    static bool isAppStore();          // Returns false
    static bool isSimulator();
    static bool getDebugStatus();
    static int getBTOnlineType();

    static void setGuideState(bool state);
    static bool getGuideState();

    static void unscheduleAll();
    static void setPostUnscheduleAllHook(PostUnscheduleAllHook hook);

    static std::string getMd5SumByString(const std::string& input);
    static std::string getLuaOrigPackagePath();
    static std::string insertToSearchPathBegin(const std::string& path);
    static std::string sortUrlString(const std::string& url);

    static void exitNow();
    static void TimeStart();
    static uint64_t TimeEnd();
};

class ClassInfo {
public:
    static std::string description(cocos2d::CCArray* arr);
    static std::string description(cocos2d::CCDictionary* dict);
    static std::string description(cocos2d::CCString* str);
    static std::string description(cocos2d::CCInteger* val);
    static std::string description(const cocos2d::CCPoint& pt);
};
