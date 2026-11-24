#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>

class ArmatureRoot;

namespace gclient {
namespace assets {

// ============================================================================
// XmlbArmatureLoader - .xmlb / Protobuf Armature Loader (Win32 Port)
//
// Ported from libcocos2dlua.so (arm64-v8a):
//   - cocos2d::extension::CCDataReaderHelper::addDataFromBitCache @ 0x4e7ec8
//   - Wired to db.pb.h (ArmatureRoot / ArmatureData / ArmatureAnimationData /
//     ArmatureTextureData)
//
// Supports both:
//   1. Protobuf-encoded .xmlb assets deserialized via db.pb.h `ArmatureRoot`.
//   2. Raw packed binary BitCache buffers matching `addDataFromBitCache`.
// ============================================================================

struct XmlbBitCacheLayout {
    size_t skeletonStructSize         = 6;
    size_t armatureDataStructSize     = 66;
    size_t boneDataStructSize         = 68;
    size_t displayDataStructSize      = 65;
    size_t animationDataStructSize    = 66;
    size_t movementDataStructSize     = 74;
    size_t movementBoneDataStructSize = 66;
    size_t frameDataStructSize        = 168;
    size_t textureDataStructSize      = 68;
};

class XmlbArmatureLoader {
public:
    // Loads and decrypts an .xmlb file, auto-discovers sibling .plistb/.plist
    // sheets (including numbered <stem>0.plistb .. <stem>9.plistb), parses
    // ArmatureRoot protobuf (falling back to validated BitCache binary layout if
    // needed), and registers all armature, animation, and texture data into
    // CCArmatureDataManager.
    static bool AddDataFromXmlbFile(const std::string& filePath,
                                    const std::string& baseFilePath = "");

    // Preserves 3-argument (filePath, baseFilePath, asyncLock) callers without
    // allowing string literals (const char*) to implicitly convert to bool.
    template <typename Bool,
              typename = std::enable_if_t<std::is_same_v<Bool, bool>>>
    static bool AddDataFromXmlbFile(const std::string& filePath,
                                    const std::string& baseFilePath,
                                    Bool asyncLock) {
        return AddDataFromXmlbFileImpl(std::string(), std::string(), filePath, baseFilePath, asyncLock);
    }

    // Explicit 3-path overload matching CCArmatureDataManager::addArmatureFileInfo(
    // imagePath, plistPath, configFilePath) while also probing sibling sheets.
    static bool AddDataFromXmlbFile(const std::string& imagePath,
                                    const std::string& plistPath,
                                    const std::string& xmlbPath,
                                    bool asyncLock = false);

    // Null-safe C-string overload for (imagePath, plistPath, xmlbPath).
    static bool AddDataFromXmlbFile(const char* imagePath,
                                    const char* plistPath,
                                    const char* xmlbPath,
                                    bool asyncLock = false);

    // Parses an in-memory decrypted .xmlb buffer (trying ArmatureRoot protobuf
    // first, rejecting malformed Protobuf wire streams, and falling back only to
    // strictly validated packed binary BitCache) and preloads sibling sheets.
    static bool AddDataFromXmlbBuffer(const uint8_t* data,
                                      size_t size,
                                      const std::string& configFilePath,
                                      const std::string& baseFilePath = "",
                                      bool asyncLock = false,
                                      const std::string& plistPath = "",
                                      const std::string& imagePath = "");

    static bool AddDataFromXmlbBuffer(const uint8_t* data,
                                      size_t size,
                                      const char* imagePath,
                                      const char* plistPath,
                                      const char* configFilePath,
                                      bool asyncLock = false);

    // Parses an in-memory decrypted protobuf ArmatureRoot buffer and registers it.
    static bool AddDataFromProtobufBuffer(const uint8_t* data,
                                          size_t size,
                                          const std::string& configFilePath,
                                          const std::string& baseFilePath = "",
                                          bool asyncLock = false,
                                          const std::string& plistPath = "",
                                          const std::string& imagePath = "");

    // Registers an already-parsed db.pb.h ArmatureRoot into CCArmatureDataManager.
    static bool AddDataFromArmatureRoot(const ArmatureRoot& root,
                                        const std::string& configFilePath,
                                        const std::string& baseFilePath = "",
                                        bool asyncLock = false,
                                        const std::string& plistPath = "",
                                        const std::string& imagePath = "");

    // Strictly validates a packed binary BitCache buffer's magic, fixed C-strings,
    // display types, and record bounds before any CCArmatureData is registered.
    static bool ValidateBitCacheBuffer(const uint8_t* bitCacheData,
                                       size_t bitCacheSize,
                                       const XmlbBitCacheLayout& layout = XmlbBitCacheLayout());

    // Direct port of CCDataReaderHelper::addDataFromBitCache @ 0x4e7ec8 for
    // packed binary skeleton/armature/animation/texture bit-cache buffers.
    static bool AddDataFromBitCache(const uint8_t* bitCacheData,
                                    size_t bitCacheSize,
                                    const std::string& configFilePath,
                                    bool asyncLock = false,
                                    const XmlbBitCacheLayout& layout = XmlbBitCacheLayout(),
                                    const std::string& plistPath = "",
                                    const std::string& imagePath = "");

private:
    static bool AddDataFromXmlbFileImpl(const std::string& imagePath,
                                        const std::string& plistPath,
                                        const std::string& filePath,
                                        const std::string& baseFilePath,
                                        bool asyncLock);
};

} // namespace assets
} // namespace gclient
