#include "BTUtil.h"
#include "CCCrypto.h"

#if defined(__has_include)
#  if __has_include("cocos-ext.h")
#    include "cocos-ext.h"
#    define GCLIENT_BTUTIL_HAS_COCOS_EXT 1
#  endif
#  if __has_include("CocoStudio/GUI/UIWidgets/UIRichText.h")
#    include "CocoStudio/GUI/UIWidgets/UIRichText.h"
#    define GCLIENT_BTUTIL_HAS_UIRICHTEXT 1
#  endif
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <random>
#include <sstream>
#include <typeinfo>
#include <utility>

USING_NS_CC;

namespace {
// IMPORTANT on Win32 MSVC: RAND_MAX is 32767, whereas Android libc rand() is 0..2147483647.
// Using a 31-bit PRNG keeps BTUtil::random() in [0.0, 1.0) matching Android's / 2147483650.0.
std::mt19937 s_rng(static_cast<uint32_t>(std::time(nullptr)));
bool s_guideState = false;
int64_t s_svrTimeOffset = 0;
std::chrono::steady_clock::time_point s_timerStart = std::chrono::steady_clock::now();
BTUtil::PostUnscheduleAllHook s_postUnscheduleAllHook;
} // namespace

void BTUtil::randomseed(unsigned int seed) {
    s_rng.seed(seed);
}

double BTUtil::random() {
    const uint32_t v = s_rng() & 0x7FFFFFFFu;
    return static_cast<double>(v) / 2147483650.0;
}

bool BTUtil::split(const std::string& str, char delim, std::vector<std::string>& out) {
    if (str.empty()) return false;
    size_t start = 0;
    while (true) {
        const size_t pos = str.find(delim, start);
        if (pos == std::string::npos) break;
        out.emplace_back(str.substr(start, pos - start));
        start = pos + 1;
    }
    if (start < str.size()) {
        out.emplace_back(str.substr(start));
    }
    return true;
}

bool BTUtil::split(const std::string& str, const std::string& delim, std::vector<std::string>& out) {
    if (str.empty()) return false;
    if (delim.empty()) {
        out.push_back(str);
        return true;
    }
    size_t start = 0;
    while (true) {
        const size_t pos = str.find(delim, start);
        if (pos == std::string::npos) break;
        out.emplace_back(str.substr(start, pos - start));
        start = pos + delim.size();
    }
    if (start < str.size()) {
        out.emplace_back(str.substr(start));
    }
    return true;
}

CCArray* BTUtil::cutString(CCString* str, CCString* delim) {
    CCArray* arr = CCArray::create();
    if (!str || !delim) return arr;
    std::vector<std::string> parts;
    split(str->getCString(), delim->getCString(), parts);
    for (const auto& s : parts) {
        arr->addObject(CCString::create(s));
    }
    return arr;
}

// Matches 0x3418dc: splits UTF-8 string into individual codepoints.
CCArray* BTUtil::splitString(const std::string& utf8Str) {
    CCArray* arr = CCArray::create();
    size_t i = 0;
    const size_t n = utf8Str.size();
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(utf8Str[i]);
        size_t step = 1;
        if ((c & 0x80) == 0)       step = 1;
        else if ((c >> 4) == 0x0F) step = 4;
        else if ((c >> 5) == 0x07) step = 3;
        else if ((c >> 6) == 0x03) step = 2;
        if (i + step > n) step = n - i;
        arr->addObject(CCString::create(utf8Str.substr(i, step)));
        i += step;
    }
    return arr;
}

bool BTUtil::checkType(CCObject* obj, const std::string& typeName) {
    if (!obj || typeName.empty()) return false;

    if (typeName == "CCObject") return true;
    if (typeName == "CCNode" && dynamic_cast<CCNode*>(obj) != nullptr) return true;
    if (typeName == "CCScene" && dynamic_cast<CCScene*>(obj) != nullptr) return true;
    if (typeName == "CCSprite" && dynamic_cast<CCSprite*>(obj) != nullptr) return true;
    if (typeName == "CCLabelTTF" && dynamic_cast<CCLabelTTF*>(obj) != nullptr) return true;
    if (typeName == "CCArray" && dynamic_cast<CCArray*>(obj) != nullptr) return true;
    if (typeName == "CCDictionary" && dynamic_cast<CCDictionary*>(obj) != nullptr) return true;
    if (typeName == "CCString" && dynamic_cast<CCString*>(obj) != nullptr) return true;
    if (typeName == "CCInteger" && dynamic_cast<CCInteger*>(obj) != nullptr) return true;

#if defined(GCLIENT_BTUTIL_HAS_COCOS_EXT)
    if (typeName == "Layout" || typeName == "Panel" || typeName == "UIPanel" || typeName == "UILayout") {
        if (dynamic_cast<cocos2d::ui::Layout*>(obj) != nullptr) return true;
    }
    if (typeName == "Widget" || typeName == "UIWidget") {
        if (dynamic_cast<cocos2d::ui::Widget*>(obj) != nullptr) return true;
    }
    if (typeName == "ScrollView" || typeName == "UIScrollView") {
        if (dynamic_cast<cocos2d::ui::ScrollView*>(obj) != nullptr) return true;
    }
    if (typeName == "ListView" || typeName == "UIListView") {
        if (dynamic_cast<cocos2d::ui::ListView*>(obj) != nullptr) return true;
    }
    if (typeName == "PageView" || typeName == "UIPageView") {
        if (dynamic_cast<cocos2d::ui::PageView*>(obj) != nullptr) return true;
    }
    if (typeName == "Button" || typeName == "UIButton") {
        if (dynamic_cast<cocos2d::ui::Button*>(obj) != nullptr) return true;
    }
    if (typeName == "ImageView" || typeName == "UIImageView") {
        if (dynamic_cast<cocos2d::ui::ImageView*>(obj) != nullptr) return true;
    }
    if (typeName == "Label" || typeName == "UILabel") {
        if (dynamic_cast<cocos2d::ui::Label*>(obj) != nullptr) return true;
    }
    if (typeName == "LabelAtlas" || typeName == "UILabelAtlas") {
        if (dynamic_cast<cocos2d::ui::LabelAtlas*>(obj) != nullptr) return true;
    }
    if (typeName == "LoadingBar" || typeName == "UILoadingBar") {
        if (dynamic_cast<cocos2d::ui::LoadingBar*>(obj) != nullptr) return true;
    }
    if (typeName == "Slider" || typeName == "UISlider") {
        if (dynamic_cast<cocos2d::ui::Slider*>(obj) != nullptr) return true;
    }
    if (typeName == "CheckBox" || typeName == "UICheckBox") {
        if (dynamic_cast<cocos2d::ui::CheckBox*>(obj) != nullptr) return true;
    }
    if (typeName == "TextField" || typeName == "UITextField") {
        if (dynamic_cast<cocos2d::ui::TextField*>(obj) != nullptr) return true;
    }
    if (typeName == "SpineLuaAnimation" ||
        typeName == "SkeletonAnimation" ||
        typeName == "CCSkeletonAnimation" ||
        typeName == "CCSkeleton") {
        if (dynamic_cast<cocos2d::extension::CCSkeleton*>(obj) != nullptr) return true;
    }
    if (typeName == "CCScale9Sprite" || typeName == "Scale9Sprite") {
        if (dynamic_cast<cocos2d::extension::CCScale9Sprite*>(obj) != nullptr) return true;
    }
    if (typeName == "CCArmature" || typeName == "Armature") {
        if (dynamic_cast<cocos2d::extension::CCArmature*>(obj) != nullptr) return true;
    }
    if (auto* w = dynamic_cast<cocos2d::ui::Widget*>(obj)) {
        const std::string desc = w->getDescription();
        if (desc == typeName) return true;
        if ((desc == "Panel" && typeName == "Layout") ||
            (desc == "Layout" && typeName == "Panel")) {
            return true;
        }
    }
#endif

#if defined(GCLIENT_BTUTIL_HAS_UIRICHTEXT)
    if (typeName == "RichText" || typeName == "UIRichText") {
        if (dynamic_cast<cocos2d::ui::RichText*>(obj) != nullptr) return true;
    }
#endif

    const std::string rttiName(typeid(*obj).name());
    if (rttiName.find(typeName) != std::string::npos) {
        return true;
    }
    if (typeName == "Layout" || typeName == "Panel") {
        if (rttiName.find("Layout") != std::string::npos ||
            rttiName.find("Panel") != std::string::npos ||
            rttiName.find("ScrollView") != std::string::npos ||
            rttiName.find("ListView") != std::string::npos ||
            rttiName.find("PageView") != std::string::npos) {
            return true;
        }
    }
    if (typeName == "SpineLuaAnimation" || typeName == "SkeletonAnimation") {
        if (rttiName.find("GClientSkeletonAnimation") != std::string::npos ||
            rttiName.find("CCSkeletonAnimation") != std::string::npos ||
            rttiName.find("CCSkeleton") != std::string::npos ||
            rttiName.find("SpineLuaAnimation") != std::string::npos) {
            return true;
        }
    }
    if (typeName == "RichText") {
        if (rttiName.find("GClientRichText") != std::string::npos ||
            rttiName.find("RichText") != std::string::npos) {
            return true;
        }
    }

    return false;
}

int64_t BTUtil::getSvrTimeInterval() {
    return static_cast<int64_t>(std::time(nullptr)) + s_svrTimeOffset;
}

void BTUtil::syncTime(int64_t svrTime) {
    s_svrTimeOffset = svrTime - static_cast<int64_t>(std::time(nullptr));
}

int BTUtil::getPlatform() { return kBT_PLATFORM_ANDROID; }
bool BTUtil::isAppStore() { return false; }
bool BTUtil::isSimulator() { return false; }
bool BTUtil::getDebugStatus() { return false; }
int BTUtil::getBTOnlineType() { return 0; }

void BTUtil::setGuideState(bool state) { s_guideState = state; }
bool BTUtil::getGuideState() { return s_guideState; }

void BTUtil::setPostUnscheduleAllHook(PostUnscheduleAllHook hook) {
    s_postUnscheduleAllHook = std::move(hook);
}

void BTUtil::unscheduleAll() {
    // NEVER call CCScheduler::unscheduleAll(), which wipes CCDirector's CCActionManager
    // (freezing all CCActions permanently), CCTextureCache async image loading,
    // DeferredArmatureAsyncCallback, and WinHttpClient!
    // Instead, delegate to s_postUnscheduleAllHook (wired by AppDelegate), which cleanly
    // unschedules all tracked Lua CCScheduler script entries and re-verifies native loops.
    if (s_postUnscheduleAllHook) {
        PostUnscheduleAllHook hookCopy = s_postUnscheduleAllHook;
        hookCopy();
    }
}

std::string BTUtil::getMd5SumByString(const std::string& input) {
    return CCCrypto::md5(input.data(), input.size(), false);
}

std::string BTUtil::getLuaOrigPackagePath() {
    return "scripts/?.lua;?.lua";
}

std::string BTUtil::insertToSearchPathBegin(const std::string& path) {
    auto* fu = CCFileUtils::sharedFileUtils();
    std::vector<std::string> paths = fu->getSearchPaths();
    paths.insert(paths.begin(), path);
    fu->setSearchPaths(paths);
    return path;
}

// Matches 0x346928: splits on '?', splits query on '&', sorts params lexicographically,
// and concatenates them WITHOUT '&' separators for URL signing.
std::string BTUtil::sortUrlString(const std::string& url) {
    if (url.empty()) return "";
    std::vector<std::string> halves;
    split(url, "?", halves);
    if (halves.size() < 2 || halves[0].empty() || halves[1].empty()) {
        return url;
    }
    std::vector<std::string> params;
    split(halves[1], "&", params);
    std::sort(params.begin(), params.end());
    std::string out;
    for (const auto& p : params) out += p;
    return out;
}

void BTUtil::exitNow() {
    CCDirector::sharedDirector()->end();
    std::exit(0);
}

void BTUtil::TimeStart() {
    s_timerStart = std::chrono::steady_clock::now();
}

uint64_t BTUtil::TimeEnd() {
    const auto now = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - s_timerStart).count());
}

// ============================================================================
// ClassInfo
// ============================================================================

std::string ClassInfo::description(CCArray* arr) {
    if (!arr) return "CCArray(null)";
    std::ostringstream oss;
    oss << "CCArray(count=" << arr->count() << ")";
    return oss.str();
}

std::string ClassInfo::description(CCDictionary* dict) {
    if (!dict) return "CCDictionary(null)";
    std::ostringstream oss;
    oss << "CCDictionary(count=" << dict->count() << ")";
    return oss.str();
}

std::string ClassInfo::description(CCString* str) {
    if (!str) return "CCString(null)";
    return std::string("CCString(\"") + str->getCString() + "\")";
}

std::string ClassInfo::description(CCInteger* val) {
    if (!val) return "CCInteger(null)";
    std::ostringstream oss;
    oss << "CCInteger(" << val->getValue() << ")";
    return oss.str();
}

std::string ClassInfo::description(const CCPoint& pt) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "CCPoint(%.2f, %.2f)", pt.x, pt.y);
    return buf;
}
