#pragma once

#include "cocos2d.h"
#include "CCLuaEngine.h"

#include <ctime>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <vector>

// ============================================================================
// CLuaFuncs (matches 0x2ab93c / 0x2abe14)
// ============================================================================
class CLuaFuncs : public cocos2d::CCObject {
public:
    static CLuaFuncs* sharedLuaFuncs();

    virtual ~CLuaFuncs();

    void addHandler(const char* name, int luaFuncRef);
    void removeHandler(const char* name);
    int call(const char* name, const std::list<cocos2d::CCLuaValue>& args);

private:
    std::map<std::string, int> m_handlers;
};

// ============================================================================
// CTimer (matches 0x2b86f8) — Win32 scheduler-driven replacement for POSIX alarm
// ============================================================================
class CTimer : public cocos2d::CCObject {
public:
    static CTimer* sharedTimer();

    virtual ~CTimer();

    void addEvent(int delaySeconds, int luaFuncRef);
    void update(float dt) override;

private:
    struct Event {
        std::time_t fireAt;
        int luaFuncRef;
    };
    std::mutex m_mutex;
    std::vector<Event> m_events;
};

// ============================================================================
// CCStrokeLabel & SpriteBlur (boot-ready Cocos2d-x 2.2.6 Win32 implementations)
// ============================================================================
class CCStrokeLabel : public cocos2d::CCLabelTTF {
public:
    static CCStrokeLabel* create(const char* text, const char* fontName, int fontSize);
    void setStroke(unsigned int strokeSize, cocos2d::ccColor4B color);
    void setContrast(float contrast);
};

class SpriteBlur : public cocos2d::CCSprite {
public:
    static SpriteBlur* create(const char* filename);
    static SpriteBlur* createWithTexture(cocos2d::CCTexture2D* texture);
    bool initWithTexture(cocos2d::CCTexture2D* texture, const cocos2d::CCRect& rect) override;
    void initProgram();
    void setBlurSize(float size);
    void listenBack2Foreground(cocos2d::CCObject* obj);
    void draw() override;

private:
    float m_blurSize = 0.0f;
};

// Registers RichText, RichElement, RichElementText, RichElementImage, and RichElementCustomNode Lua bindings.
void RegisterRichTextBindings(lua_State* L);

// Wires PlistbLoader, PbGuiLoader, XmlbArmatureLoader, RichText, Spine, and CocoStudio UI hooks into Lua metatables.
void RegisterAssetLoaderHooks(lua_State* L);

// Unschedules all active Lua script timer entries registered via CCScheduler:scheduleScriptFunc
// without wiping engine system targets (CCActionManager, CCTextureCache, HTTP, async loaders).
void UnscheduleAllLuaScriptEntries();

// Ensures any pending DeferredArmatureAsyncCallback tasks remain scheduled on CCScheduler.
void RescheduleLuaHelpersCallbacks();
