#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

class CSGUIRoot;
class CSWidget;
class CSOptions;
class CSAnimation;
class CSSceneRoot;

namespace cocos2d {
class CCNode;
namespace ui {
class Widget;
}
}

namespace gclient {
namespace assets {

// ============================================================================
// PbGuiLoader - Protobuf CocoStudio GUI (.pb) & Scene (.pb) Loader (Win32 Port)
//
// Ported from libcocos2dlua.so (arm64-v8a):
//   - cocos2d::extension::GUIReader::widgetFromPbFile @ 0x531bc4
//   - cocos2d::extension::WidgetPropertiesReaderPb
//   - Wired to CSGUI.pb.h (CSGUIRoot / CSWidget / CSOptions / CSAnimation)
//     and CSScene.pb.h (CSSceneRoot / CSComponent / CSSceneData)
// ============================================================================

class PbGuiLoader {
public:
    // Port of GUIReader::widgetFromPbFile(const char* fileName).
    // Replaces extension with ".pb", loads & decrypts via BtDecryptHook,
    // parses CSGUIRoot, preloads texture sheets, builds the Widget tree,
    // and registers CocoStudio animations with Widget destruction guards.
    static cocos2d::ui::Widget* WidgetFromPbFile(const std::string& fileName);

    // Parses an in-memory decrypted CSGUIRoot protobuf buffer.
    static cocos2d::ui::Widget* WidgetFromPbBuffer(const uint8_t* data,
                                                   size_t size,
                                                   const std::string& baseDir,
                                                   const std::string& sourceFileName = "");

    // Builds a CocoStudio Widget tree from an already-parsed CSGUIRoot.
    static cocos2d::ui::Widget* CreateWidgetFromPbRoot(const CSGUIRoot& root,
                                                       const std::string& baseDir,
                                                       const std::string& sourceFileName = "");

    // Instantiates the concrete Cocos2d-x ui::Widget subclass for a CocoStudio
    // classname (including legacy aliases: Layout, TextArea, TextButton,
    // DragPanel, Text, TextBMFont, TextAtlas).
    static cocos2d::ui::Widget* CreateWidgetByClassName(const std::string& className);

    // Safely loads a sprite sheet (.plistb first, then verified non-empty XML
    // .plist) resolved across baseDir, collapsed ".." paths, and search roots.
    static bool LoadPlistSpriteFramesSafe(const std::string& plistPath,
                                          const std::string& baseDir = "");

    // Builds a single CSWidget node (and recursively its children).
    static cocos2d::ui::Widget* CreateWidgetFromPb(const CSWidget& pbWidget,
                                                   const std::string& baseDir);

    // Port of CocoStudio SceneReader protobuf loader wired to CSScene.pb.h.
    // Loads & decrypts a .pb scene file, parses CSSceneRoot, and constructs
    // the CCNode hierarchy with attached components.
    static cocos2d::CCNode* SceneFromPbFile(const std::string& fileName);

    // Builds a CCNode hierarchy from an already-parsed CSSceneRoot.
    static cocos2d::CCNode* CreateSceneFromPbRoot(const CSSceneRoot& root,
                                                  const std::string& baseDir);
};

} // namespace assets
} // namespace gclient
