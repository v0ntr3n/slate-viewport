#include "XmlbArmatureLoader.h"

#include "BtDecryptHook.h"
#include "PlistbLoader.h"
#include "db.pb.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_set>
#include <vector>

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "cocos2d.h"
#include "cocos-ext.h"
#endif

#if !defined(GCLIENT_STANDALONE_BUILD)
#include "diagnostics/CrashAndTelemetry.h"
#endif

namespace gclient {
namespace assets {

namespace {

uint16_t ReadLE16U(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) |
           (static_cast<uint16_t>(ptr[1]) << 8);
}

uint32_t ReadLE32U(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

void LogArmatureWarn(const char* msg) {
#if !defined(GCLIENT_STANDALONE_BUILD)
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Warn, "XmlbArmatureLoader", "%s", msg ? msg : "");
#endif
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    cocos2d::CCLog("[XmlbArmatureLoader][WARN] %s", msg ? msg : "");
#else
    std::fprintf(stderr, "[XmlbArmatureLoader][WARN] %s\n", msg ? msg : "");
#endif
}

bool ValidateFixedCStringField(const uint8_t* ptr, size_t maxLen, bool requireNonEmpty) {
    const void* nulPos = std::memchr(ptr, '\0', maxLen);
    if (nulPos == nullptr) {
        return false;
    }
    const size_t len = static_cast<size_t>(static_cast<const uint8_t*>(nulPos) - ptr);
    if (requireNonEmpty && len == 0) {
        return false;
    }
    for (size_t i = 0; i < len; ++i) {
        if (ptr[i] < 0x20u || ptr[i] == 0x7Fu) {
            return false;
        }
    }
    return true;
}

bool StartsWithAsciiCI(const uint8_t* ptr, size_t rem, const char* prefix) {
    const size_t pLen = std::strlen(prefix);
    if (rem < pLen) {
        return false;
    }
    for (size_t i = 0; i < pLen; ++i) {
        if (std::tolower(ptr[i]) != std::tolower(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

bool LooksLikePlaintextXml(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return false;
    }
    size_t off = 0;
    if (size >= 3 && data[0] == 0xEFu && data[1] == 0xBBu && data[2] == 0xBFu) {
        off = 3;
    }
    while (off < size && (data[off] == ' ' || data[off] == '\t' ||
                          data[off] == '\r' || data[off] == '\n')) {
        ++off;
    }
    const size_t rem = size - off;
    return StartsWithAsciiCI(data + off, rem, "<?xml") ||
           StartsWithAsciiCI(data + off, rem, "<plist") ||
           StartsWithAsciiCI(data + off, rem, "<skeleton") ||
           StartsWithAsciiCI(data + off, rem, "<armature") ||
           StartsWithAsciiCI(data + off, rem, "<!doctype") ||
           StartsWithAsciiCI(data + off, rem, "<!--");
}

bool ReadProtoVarint(const uint8_t* data, size_t size, size_t* ioOff, uint64_t* outVal) {
    uint64_t result = 0;
    int      shift  = 0;
    size_t   off    = *ioOff;
    while (off < size && shift < 64) {
        const uint8_t byte = data[off++];
        result |= static_cast<uint64_t>(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            *ioOff  = off;
            *outVal = result;
            return true;
        }
        shift += 7;
    }
    return false;
}

bool IsValidArmatureRootTopTag(uint64_t tag) {
    return tag == 0x0Du || tag == 0x12u || tag == 0x1Au || tag == 0x22u || tag == 0x2Au;
}

bool IsValidSubmessageFirstTag(uint64_t outerTag, uint64_t innerTag) {
    if (outerTag == 0x12u) {
        return innerTag == 0x0Du || innerTag == 0x12u || innerTag == 0x1Au;
    }
    if (outerTag == 0x1Au) {
        return innerTag == 0x0Au || innerTag == 0x12u;
    }
    if (outerTag == 0x22u) {
        return innerTag == 0x0Au || innerTag == 0x15u || innerTag == 0x1Du ||
               innerTag == 0x25u || innerTag == 0x2Du || innerTag == 0x32u || innerTag == 0x3Au;
    }
    return true;
}

bool LooksLikeArmatureProtobufWire(const uint8_t* data, size_t size) {
    if (!data || size < 2) {
        return false;
    }
    size_t   off      = 0;
    uint64_t firstTag = 0;
    if (!ReadProtoVarint(data, size, &off, &firstTag) || !IsValidArmatureRootTopTag(firstTag)) {
        return false;
    }

    if (firstTag == 0x0Du) {
        if (off + 4 > size) {
            return true;
        }
        float scaleVal = 0.0f;
        std::memcpy(&scaleVal, data + off, sizeof(float));
        off += 4;
        if (!std::isfinite(scaleVal) || scaleVal <= 0.0f || scaleVal > 64.0f) {
            return false;
        }
        if (off == size) {
            return true;
        }
        uint64_t secondTag = 0;
        if (!ReadProtoVarint(data, size, &off, &secondTag)) {
            return false;
        }
        return IsValidArmatureRootTopTag(secondTag);
    }

    uint64_t subLen = 0;
    if (!ReadProtoVarint(data, size, &off, &subLen)) {
        return false;
    }
    if (firstTag == 0x2Au) {
        return subLen > 0 && subLen <= 260 && off < size && data[off] >= 0x20u && data[off] < 0x7Fu;
    }
    if (subLen == 0) {
        return off == size || IsValidArmatureRootTopTag(data[off]);
    }
    if (off >= size) {
        return true;
    }
    uint64_t innerTag = 0;
    size_t   innerOff = off;
    if (!ReadProtoVarint(data, size, &innerOff, &innerTag)) {
        return false;
    }
    return IsValidSubmessageFirstTag(firstTag, innerTag);
}

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)

int16_t ReadLE16S(const uint8_t* ptr) {
    return static_cast<int16_t>(ReadLE16U(ptr));
}

int32_t ReadLE32S(const uint8_t* ptr) {
    return static_cast<int32_t>(ReadLE32U(ptr));
}

constexpr float kPi    = 3.14159265358979323846f;
constexpr float kTwoPi = 6.28318530717958647692f;

std::mutex g_armatureDataManagerMutex;

std::string ReadFixedCString(const uint8_t* ptr, size_t maxLen) {
    size_t len = 0;
    while (len < maxLen && ptr[len] != '\0') {
        ++len;
    }
    return std::string(reinterpret_cast<const char*>(ptr), len);
}

std::string StripAssetExtension(const std::string& normalizedPath) {
    const size_t slashPos = normalizedPath.find_last_of('/');
    const size_t dotPos   = normalizedPath.find_last_of('.');
    if (dotPos == std::string::npos ||
        (slashPos != std::string::npos && dotPos < slashPos)) {
        return normalizedPath;
    }
    return normalizedPath.substr(0, dotPos);
}

cocos2d::ccBlendFunc MapBitCacheBlendType(uint8_t rawBlend) {
    switch (rawBlend) {
        case 0:
            return { CC_BLEND_SRC, CC_BLEND_DST };
        case 1:
            return { GL_SRC_ALPHA, GL_ONE };
        case 2:
            return { GL_DST_COLOR, GL_ONE_MINUS_SRC_ALPHA };
        case 3:
            return { GL_ONE, GL_ONE_MINUS_SRC_COLOR };
        default:
            break;
    }

    switch (static_cast<cocos2d::extension::CCBlendType>(rawBlend)) {
        case cocos2d::extension::BLEND_ADD:
            return { GL_SRC_ALPHA, GL_ONE };
        case cocos2d::extension::BLEND_SCREEN:
            return { GL_ONE, GL_ONE_MINUS_SRC_COLOR };
        default:
            return { CC_BLEND_SRC, CC_BLEND_DST };
    }
}

bool IsValidNonEmptyXmlPlist(const std::string& candidatePath) {
    if (candidatePath.empty()) {
        return false;
    }
    if (candidatePath.size() >= 7 &&
        candidatePath.compare(candidatePath.size() - 7, 7, ".plistb") == 0) {
        return false;
    }
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) {
        return false;
    }
    const std::string full = fu->fullPathForFilename(candidatePath.c_str());
    if (full.empty() || !fu->isFileExist(full)) {
        return false;
    }
    unsigned long  sz  = 0;
    unsigned char* buf = LoadAndDecryptFileData(candidatePath, &sz, nullptr);
    if (!buf || sz == 0) {
        delete[] buf;
        return false;
    }
    const bool isXml = LooksLikePlaintextXml(buf, static_cast<size_t>(sz));
    delete[] buf;
    return isXml;
}

bool DoesAnyFileExist(const std::string& candidatePath) {
    if (candidatePath.empty()) {
        return false;
    }
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) {
        return false;
    }
    const std::string full = fu->fullPathForFilename(candidatePath.c_str());
    return !full.empty() && fu->isFileExist(full);
}

std::string ResolveParticlePlistPath(const std::string& rawPlist,
                                     const std::string& effectiveBase) {
    const std::string normRaw = NormalizeAssetPath(rawPlist);
    if (normRaw.empty()) {
        return std::string();
    }
    if (!effectiveBase.empty()) {
        const std::string relCand = ResolveRelativeAssetPath(normRaw, effectiveBase);
        if (DoesAnyFileExist(relCand)) {
            return relCand;
        }
        if (DoesAnyFileExist(normRaw)) {
            return normRaw;
        }
        return relCand;
    }
    return normRaw;
}

cocos2d::CCTexture2D* LoadExplicitTextureWithFallback(const std::string& imagePath,
                                                      const std::string& effectiveBase) {
    if (imagePath.empty()) {
        return nullptr;
    }
    auto* texCache = cocos2d::CCTextureCache::sharedTextureCache();
    if (!texCache) {
        return nullptr;
    }

    const std::string normImg = NormalizeAssetPath(imagePath);
    std::vector<std::string> basePaths;
    basePaths.push_back(normImg);
    if (!effectiveBase.empty()) {
        const std::string relImg = ResolveRelativeAssetPath(normImg, effectiveBase);
        if (relImg != normImg) {
            basePaths.push_back(relImg);
        }
    }

    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (fu) {
        for (const std::string& base : basePaths) {
            const std::vector<std::string> cands = PlistbLoader::BuildTextureCandidatePaths(base);
            for (const std::string& cand : cands) {
                const std::string full = fu->fullPathForFilename(cand.c_str());
                if (!full.empty() && fu->isFileExist(full)) {
                    if (cocos2d::CCTexture2D* tex = texCache->addImage(full.c_str())) {
                        return tex;
                    }
                }
            }
        }
    }

    for (const std::string& base : basePaths) {
        const std::vector<std::string> cands = PlistbLoader::BuildTextureCandidatePaths(base);
        for (const std::string& cand : cands) {
            if (cocos2d::CCTexture2D* tex = texCache->addImage(cand.c_str())) {
                return tex;
            }
        }
    }
    return nullptr;
}

bool TryLoadSpriteSheetCandidate(const std::string& sheetPath,
                                 cocos2d::CCTexture2D* explicitTex,
                                 std::unordered_set<std::string>& loadedSet) {
    const std::string normSheet = NormalizeAssetPath(sheetPath);
    if (normSheet.empty()) {
        return false;
    }
    if (loadedSet.find(normSheet) != loadedSet.end()) {
        return true;
    }

    if (PlistbLoader::AddSpriteFramesWithBinary(normSheet, explicitTex)) {
        loadedSet.insert(normSheet);
        loadedSet.insert(ReplaceFileExtension(normSheet, ".plistb"));
        loadedSet.insert(ReplaceFileExtension(normSheet, ".plist"));
        return true;
    }

    const std::string xmlPlistPath =
        (normSheet.size() >= 7 && normSheet.compare(normSheet.size() - 7, 7, ".plistb") == 0)
            ? normSheet.substr(0, normSheet.size() - 1)
            : normSheet;

    if (IsValidNonEmptyXmlPlist(xmlPlistPath)) {
        if (auto* sfc = cocos2d::CCSpriteFrameCache::sharedSpriteFrameCache()) {
            if (explicitTex) {
                sfc->addSpriteFramesWithFile(xmlPlistPath.c_str(), explicitTex);
            } else {
                sfc->addSpriteFramesWithFile(xmlPlistPath.c_str());
            }
            loadedSet.insert(normSheet);
            loadedSet.insert(xmlPlistPath);
            return true;
        }
    }

    return false;
}

bool LoadResolvedSpriteSheet(const std::string& rawSheetPath,
                             const std::string& effectiveBase,
                             cocos2d::CCTexture2D* explicitTex,
                             std::unordered_set<std::string>& loadedSet) {
    const std::string normSheet = NormalizeAssetPath(rawSheetPath);
    if (normSheet.empty()) {
        return false;
    }

    if (!effectiveBase.empty()) {
        const std::string relResolved = ResolveRelativeAssetPath(normSheet, effectiveBase);
        if (!relResolved.empty() && TryLoadSpriteSheetCandidate(relResolved, explicitTex, loadedSet)) {
            return true;
        }
    }

    return TryLoadSpriteSheetCandidate(normSheet, explicitTex, loadedSet);
}

void PreloadArmatureSpriteSheets(const std::string& normConfigPath,
                                 const std::string& effectiveBase,
                                 const std::string& plistPath,
                                 const std::string& imagePath,
                                 std::unordered_set<std::string>& loadedSet) {
    cocos2d::CCTexture2D* explicitTex = LoadExplicitTextureWithFallback(imagePath, effectiveBase);

    if (!plistPath.empty()) {
        LoadResolvedSpriteSheet(plistPath, effectiveBase, explicitTex, loadedSet);
    }

    const std::string dirAndStem = StripAssetExtension(normConfigPath);
    if (dirAndStem.empty()) {
        return;
    }

    cocos2d::CCTexture2D* stemTex = plistPath.empty() ? explicitTex : nullptr;
    if (!TryLoadSpriteSheetCandidate(dirAndStem + ".plistb", stemTex, loadedSet)) {
        TryLoadSpriteSheetCandidate(dirAndStem + ".plist", stemTex, loadedSet);
    }

    for (int idx = 0; idx <= 9; ++idx) {
        const std::string numberedStem = dirAndStem + std::to_string(idx);
        bool              loaded       =
            TryLoadSpriteSheetCandidate(numberedStem + ".plistb", nullptr, loadedSet);
        if (!loaded) {
            loaded = TryLoadSpriteSheetCandidate(numberedStem + ".plist", nullptr, loadedSet);
        }
        if (!loaded) {
            break;
        }
    }
}

void SanitizeArmatureBoneParents(cocos2d::extension::CCArmatureData* armData,
                                 const std::vector<cocos2d::extension::CCBoneData*>& bones,
                                 const std::string& configPath) {
    if (!armData) {
        return;
    }

    for (cocos2d::extension::CCBoneData* bone : bones) {
        if (!bone || bone->parentName.empty()) {
            continue;
        }

        if (bone->parentName == bone->name) {
            char msg[320];
            std::snprintf(msg,
                          sizeof(msg),
                          "Clearing self-parent on bone '%s' in armature '%s' (%s)",
                          bone->name.c_str(),
                          armData->name.c_str(),
                          configPath.c_str());
            LogArmatureWarn(msg);
            bone->parentName.clear();
            continue;
        }

        if (armData->boneDataDic.objectForKey(bone->parentName) == nullptr) {
            char msg[320];
            std::snprintf(msg,
                          sizeof(msg),
                          "Clearing missing parent '%s' on bone '%s' in armature '%s' (%s)",
                          bone->parentName.c_str(),
                          bone->name.c_str(),
                          armData->name.c_str(),
                          configPath.c_str());
            LogArmatureWarn(msg);
            bone->parentName.clear();
            continue;
        }

        std::unordered_set<std::string> visited;
        visited.insert(bone->name);
        std::string currParent = bone->parentName;
        while (!currParent.empty()) {
            if (visited.find(currParent) != visited.end()) {
                char msg[320];
                std::snprintf(msg,
                              sizeof(msg),
                              "Breaking parent cycle at bone '%s' (parent '%s') in armature '%s' (%s)",
                              bone->name.c_str(),
                              bone->parentName.c_str(),
                              armData->name.c_str(),
                              configPath.c_str());
                LogArmatureWarn(msg);
                bone->parentName.clear();
                break;
            }
            visited.insert(currParent);
            auto* ancestor = static_cast<cocos2d::extension::CCBoneData*>(
                armData->boneDataDic.objectForKey(currParent));
            if (!ancestor) {
                break;
            }
            currParent = ancestor->parentName;
        }
    }
}

void EnsureDummyAnimationDataForArmatures(cocos2d::extension::CCArmatureDataManager* manager,
                                          const std::vector<std::string>& armatureNames,
                                          const std::string& normConfigPath,
                                          bool asyncLock) {
    if (!manager) {
        return;
    }
    std::unordered_set<std::string> seen;
    for (const std::string& name : armatureNames) {
        if (name.empty() || !seen.insert(name).second) {
            continue;
        }
        if (asyncLock) {
            std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
            if (manager->getAnimationData(name.c_str()) == nullptr) {
                auto* dummyAnim = new cocos2d::extension::CCAnimationData();
                dummyAnim->name = name;
                manager->addAnimationData(name.c_str(), dummyAnim, normConfigPath.c_str());
                dummyAnim->release();
            }
        } else {
            if (manager->getAnimationData(name.c_str()) == nullptr) {
                auto* dummyAnim = new cocos2d::extension::CCAnimationData();
                dummyAnim->name = name;
                manager->addAnimationData(name.c_str(), dummyAnim, normConfigPath.c_str());
                dummyAnim->release();
            }
        }
    }
}

void NormalizeMovementBoneSkew(cocos2d::extension::CCMovementBoneData* movBoneData) {
    if (!movBoneData) {
        return;
    }
    const unsigned int count = movBoneData->frameList.count();
    if (count < 2) {
        return;
    }

    for (int i = static_cast<int>(count) - 1; i > 0; --i) {
        auto* curr = static_cast<cocos2d::extension::CCFrameData*>(
            movBoneData->frameList.objectAtIndex(static_cast<unsigned int>(i)));
        auto* prev = static_cast<cocos2d::extension::CCFrameData*>(
            movBoneData->frameList.objectAtIndex(static_cast<unsigned int>(i - 1)));
        if (!curr || !prev) {
            continue;
        }

        const float diffX = curr->skewX - prev->skewX;
        if (diffX < -kPi || diffX > kPi) {
            prev->skewX += (diffX < 0.0f) ? -kTwoPi : kTwoPi;
        }

        const float diffY = curr->skewY - prev->skewY;
        if (diffY < -kPi || diffY > kPi) {
            prev->skewY += (diffY < 0.0f) ? -kTwoPi : kTwoPi;
        }
    }
}

void AppendClosingFrame(cocos2d::extension::CCMovementBoneData* movBoneData) {
    if (!movBoneData || movBoneData->frameList.count() == 0) {
        return;
    }
    auto* lastFrame =
        static_cast<cocos2d::extension::CCFrameData*>(movBoneData->frameList.lastObject());
    if (!lastFrame) {
        return;
    }

    auto* closingFrame = new cocos2d::extension::CCFrameData();
    closingFrame->copy(lastFrame);
    closingFrame->frameID = movBoneData->duration;
    movBoneData->addFrameData(closingFrame);
    closingFrame->release();
}

void ApplyProtoColor(cocos2d::extension::CCBaseData* dst, const ArmatureColor& color) {
    dst->isUseColorInfo = true;
    dst->r              = static_cast<unsigned char>(color.has_r() ? color.r() : 255);
    dst->g              = static_cast<unsigned char>(color.has_g() ? color.g() : 255);
    dst->b              = static_cast<unsigned char>(color.has_b() ? color.b() : 255);
    dst->a              = static_cast<unsigned char>(color.has_a() ? color.a() : 255);
}

#endif // GCLIENT_ENABLE_COCOS2DX

} // namespace

bool XmlbArmatureLoader::ValidateBitCacheBuffer(const uint8_t* bitCacheData,
                                                size_t bitCacheSize,
                                                const XmlbBitCacheLayout& layout) {
    if (!bitCacheData || bitCacheSize < layout.skeletonStructSize) {
        return false;
    }
    if (bitCacheSize >= 4 && ReadLE32U(bitCacheData) == kBtDecryptMagic) {
        return false;
    }
    if (LooksLikePlaintextXml(bitCacheData, bitCacheSize)) {
        return false;
    }
    if (layout.armatureDataStructSize < 66 || layout.boneDataStructSize < 68 ||
        layout.displayDataStructSize < 65 || layout.animationDataStructSize < 66 ||
        layout.movementDataStructSize < 74 || layout.movementBoneDataStructSize < 66 ||
        layout.frameDataStructSize < 168 || layout.textureDataStructSize < 68) {
        return false;
    }

    const uint8_t* end    = bitCacheData + bitCacheSize;
    const uint8_t* cursor = bitCacheData;

    const uint16_t armatureCount  = ReadLE16U(cursor + 0);
    const uint16_t animationCount = ReadLE16U(cursor + 2);
    const uint16_t textureCount   = ReadLE16U(cursor + 4);
    cursor += layout.skeletonStructSize;

    if (armatureCount == 0 && animationCount == 0 && textureCount == 0) {
        return false;
    }

    for (uint16_t a = 0; a < armatureCount; ++a) {
        if (static_cast<size_t>(end - cursor) < layout.armatureDataStructSize) {
            return false;
        }
        const uint8_t* armHdr = cursor;
        if (!ValidateFixedCStringField(armHdr, 64, /*requireNonEmpty=*/true)) {
            return false;
        }
        const uint16_t boneCount = ReadLE16U(armHdr + 64);
        cursor += layout.armatureDataStructSize;

        for (uint16_t b = 0; b < boneCount; ++b) {
            if (static_cast<size_t>(end - cursor) < layout.boneDataStructSize) {
                return false;
            }
            const uint8_t* boneHdr = cursor;
            if (!ValidateFixedCStringField(boneHdr, 64, /*requireNonEmpty=*/true)) {
                return false;
            }
            const uint16_t displayCount = ReadLE16U(boneHdr + 66);
            cursor += layout.boneDataStructSize;

            for (uint16_t d = 0; d < displayCount; ++d) {
                if (static_cast<size_t>(end - cursor) < layout.displayDataStructSize) {
                    return false;
                }
                const uint8_t* dispHdr = cursor;
                if (dispHdr[0] > 2u) {
                    return false;
                }
                if (!ValidateFixedCStringField(dispHdr + 1, 64, /*requireNonEmpty=*/false)) {
                    return false;
                }
                cursor += layout.displayDataStructSize;
            }
        }
    }

    for (uint16_t a = 0; a < animationCount; ++a) {
        if (static_cast<size_t>(end - cursor) < layout.animationDataStructSize) {
            return false;
        }
        const uint8_t* animHdr = cursor;
        if (!ValidateFixedCStringField(animHdr, 64, /*requireNonEmpty=*/true)) {
            return false;
        }
        const uint16_t movCount = ReadLE16U(animHdr + 64);
        cursor += layout.animationDataStructSize;

        for (uint16_t m = 0; m < movCount; ++m) {
            if (static_cast<size_t>(end - cursor) < layout.movementDataStructSize) {
                return false;
            }
            const uint8_t* movHdr = cursor;
            if (!ValidateFixedCStringField(movHdr, 64, /*requireNonEmpty=*/true)) {
                return false;
            }
            const uint16_t movBoneCount = ReadLE16U(movHdr + 72);
            cursor += layout.movementDataStructSize;

            for (uint16_t mb = 0; mb < movBoneCount; ++mb) {
                if (static_cast<size_t>(end - cursor) < layout.movementBoneDataStructSize) {
                    return false;
                }
                const uint8_t* mbHdr = cursor;
                if (!ValidateFixedCStringField(mbHdr, 64, /*requireNonEmpty=*/true)) {
                    return false;
                }
                const uint16_t frameCount = ReadLE16U(mbHdr + 64);
                cursor += layout.movementBoneDataStructSize;

                for (uint16_t f = 0; f < frameCount; ++f) {
                    if (static_cast<size_t>(end - cursor) < layout.frameDataStructSize) {
                        return false;
                    }
                    const uint8_t* fr = cursor;
                    if (!ValidateFixedCStringField(fr + 40, 64, /*requireNonEmpty=*/false) ||
                        !ValidateFixedCStringField(fr + 104, 64, /*requireNonEmpty=*/false)) {
                        return false;
                    }
                    cursor += layout.frameDataStructSize;
                }
            }
        }
    }

    for (uint16_t t = 0; t < textureCount; ++t) {
        if (static_cast<size_t>(end - cursor) < layout.textureDataStructSize) {
            return false;
        }
        const uint8_t* texHdr = cursor;
        if (!ValidateFixedCStringField(texHdr, 64, /*requireNonEmpty=*/true)) {
            return false;
        }
        cursor += layout.textureDataStructSize;
    }

    const size_t rem = static_cast<size_t>(end - cursor);
    if (rem > 3) {
        return false;
    }
    for (size_t i = 0; i < rem; ++i) {
        if (cursor[i] != 0) {
            return false;
        }
    }
    return true;
}

bool XmlbArmatureLoader::AddDataFromXmlbFile(const std::string& filePath,
                                             const std::string& baseFilePath) {
    return AddDataFromXmlbFileImpl(std::string(), std::string(), filePath, baseFilePath, false);
}

bool XmlbArmatureLoader::AddDataFromXmlbFile(const std::string& imagePath,
                                             const std::string& plistPath,
                                             const std::string& xmlbPath,
                                             bool asyncLock) {
    return AddDataFromXmlbFileImpl(imagePath, plistPath, xmlbPath, std::string(), asyncLock);
}

bool XmlbArmatureLoader::AddDataFromXmlbFile(const char* imagePath,
                                             const char* plistPath,
                                             const char* xmlbPath,
                                             bool asyncLock) {
    if (!xmlbPath || xmlbPath[0] == '\0') {
        return false;
    }
    return AddDataFromXmlbFileImpl(imagePath ? std::string(imagePath) : std::string(),
                                   plistPath ? std::string(plistPath) : std::string(),
                                   std::string(xmlbPath),
                                   std::string(),
                                   asyncLock);
}

bool XmlbArmatureLoader::AddDataFromXmlbFileImpl(const std::string& imagePath,
                                                 const std::string& plistPath,
                                                 const std::string& filePath,
                                                 const std::string& baseFilePath,
                                                 bool asyncLock) {
    std::string normPath = NormalizeAssetPath(filePath);
    if (normPath.empty()) {
        return false;
    }

    unsigned long  fileSize = 0;
    DecryptResult  diag;
    unsigned char* rawData  = nullptr;

    const std::string xmlbPath = ReplaceFileExtension(normPath, ".xmlb");
    if (xmlbPath != normPath) {
        rawData = LoadAndDecryptFileData(xmlbPath, &fileSize, &diag);
        if (rawData && fileSize > 0) {
            normPath = xmlbPath;
        } else {
            delete[] rawData;
            rawData  = nullptr;
            fileSize = 0;
        }
    }
    if (!rawData || fileSize == 0) {
        delete[] rawData;
        rawData  = nullptr;
        fileSize = 0;
        rawData  = LoadAndDecryptFileData(normPath, &fileSize, &diag);
    }
    if ((!rawData || fileSize == 0) && !baseFilePath.empty()) {
        const std::string relXmlb = ResolveRelativeAssetPath(xmlbPath, baseFilePath);
        if (relXmlb != xmlbPath) {
            delete[] rawData;
            rawData  = nullptr;
            fileSize = 0;
            rawData  = LoadAndDecryptFileData(relXmlb, &fileSize, &diag);
            if (rawData && fileSize > 0) {
                normPath = relXmlb;
            }
        }
        if (!rawData || fileSize == 0) {
            const std::string relOrig = ResolveRelativeAssetPath(normPath, baseFilePath);
            if (relOrig != normPath) {
                delete[] rawData;
                rawData  = nullptr;
                fileSize = 0;
                rawData  = LoadAndDecryptFileData(relOrig, &fileSize, &diag);
                if (rawData && fileSize > 0) {
                    normPath = relOrig;
                }
            }
        }
    }

    if (!rawData || fileSize == 0) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
        cocos2d::CCLog("[XmlbArmatureLoader] Failed to load armature file: %s", normPath.c_str());
#endif
        delete[] rawData;
        return false;
    }

    const bool ok = AddDataFromXmlbBuffer(rawData,
                                          static_cast<size_t>(fileSize),
                                          normPath,
                                          baseFilePath,
                                          asyncLock,
                                          plistPath,
                                          imagePath);
    delete[] rawData;
    return ok;
}

bool XmlbArmatureLoader::AddDataFromXmlbBuffer(const uint8_t* data,
                                               size_t size,
                                               const std::string& configFilePath,
                                               const std::string& baseFilePath,
                                               bool asyncLock,
                                               const std::string& plistPath,
                                               const std::string& imagePath) {
    if (data == nullptr || size == 0) {
        return false;
    }
    if (size >= 4 && ReadLE32U(data) == kBtDecryptMagic) {
        LogArmatureWarn(("Rejected undecrypted 0xFEFEFEFE buffer for " + configFilePath).c_str());
        return false;
    }
    if (LooksLikePlaintextXml(data, size)) {
        LogArmatureWarn(("Rejected plaintext XML buffer in AddDataFromXmlbBuffer for " + configFilePath).c_str());
        return false;
    }

    ArmatureRoot root;
    if (root.ParseFromArray(data, static_cast<int>(size)) &&
        (root.armature_data_size() > 0 || root.animation_data_size() > 0 ||
         root.texture_data_size() > 0 || root.config_file_path_size() > 0 ||
         root.has_content_scale())) {
        return AddDataFromArmatureRoot(
            root, configFilePath, baseFilePath, asyncLock, plistPath, imagePath);
    }

    const XmlbBitCacheLayout defaultLayout;
    if (!ValidateBitCacheBuffer(data, size, defaultLayout)) {
        if (LooksLikeArmatureProtobufWire(data, size)) {
            LogArmatureWarn(("Malformed Protobuf ArmatureRoot stream rejected (skipping BitCache): " +
                             configFilePath)
                                .c_str());
        }
        return false;
    }

    return AddDataFromBitCache(data,
                               size,
                               configFilePath,
                               asyncLock,
                               defaultLayout,
                               plistPath,
                               imagePath);
}

bool XmlbArmatureLoader::AddDataFromXmlbBuffer(const uint8_t* data,
                                               size_t size,
                                               const char* imagePath,
                                               const char* plistPath,
                                               const char* configFilePath,
                                               bool asyncLock) {
    if (!configFilePath || configFilePath[0] == '\0') {
        return false;
    }
    return AddDataFromXmlbBuffer(data,
                                 size,
                                 std::string(configFilePath),
                                 std::string(),
                                 asyncLock,
                                 plistPath ? std::string(plistPath) : std::string(),
                                 imagePath ? std::string(imagePath) : std::string());
}

bool XmlbArmatureLoader::AddDataFromProtobufBuffer(const uint8_t* data,
                                                   size_t size,
                                                   const std::string& configFilePath,
                                                   const std::string& baseFilePath,
                                                   bool asyncLock,
                                                   const std::string& plistPath,
                                                   const std::string& imagePath) {
    if (data == nullptr || size == 0) {
        return false;
    }
    if (size >= 4 && ReadLE32U(data) == kBtDecryptMagic) {
        return false;
    }

    ArmatureRoot root;
    if (!root.ParseFromArray(data, static_cast<int>(size))) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
        cocos2d::CCLog("[XmlbArmatureLoader] ArmatureRoot::ParseFromArray failed for %s",
                       configFilePath.c_str());
#endif
        return false;
    }

    return AddDataFromArmatureRoot(
        root, configFilePath, baseFilePath, asyncLock, plistPath, imagePath);
}

bool XmlbArmatureLoader::AddDataFromArmatureRoot(const ArmatureRoot& root,
                                                 const std::string& configFilePath,
                                                 const std::string& baseFilePath,
                                                 bool asyncLock,
                                                 const std::string& plistPath,
                                                 const std::string& imagePath) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normConfigPath = NormalizeAssetPath(configFilePath);
    const std::string effectiveBase  =
        baseFilePath.empty() ? normConfigPath : NormalizeAssetPath(baseFilePath);

    const float rawContentScale = root.has_content_scale() ? root.content_scale() : 1.0f;
    const float contentScale =
        (std::isfinite(rawContentScale) && rawContentScale > 0.0f) ? rawContentScale : 1.0f;
    auto* manager = cocos2d::extension::CCArmatureDataManager::sharedArmatureDataManager();
    if (!manager) {
        return false;
    }

    std::unordered_set<std::string> loadedSheets;
    PreloadArmatureSpriteSheets(normConfigPath, effectiveBase, plistPath, imagePath, loadedSheets);

    for (int i = 0; i < root.config_file_path_size(); ++i) {
        LoadResolvedSpriteSheet(root.config_file_path(i), effectiveBase, nullptr, loadedSheets);
    }

    std::vector<std::string> armatureNamesForAnimGuard;

    for (int i = 0; i < root.armature_data_size(); ++i) {
        const ArmatureData& pbArm = root.armature_data(i);
        if (pbArm.name().empty()) {
            continue;
        }

        auto* armData = new cocos2d::extension::CCArmatureData();
        armData->init();
        armData->name        = pbArm.name();
        armData->dataVersion = pbArm.version();
        armatureNamesForAnimGuard.push_back(armData->name);

        std::vector<cocos2d::extension::CCBoneData*> addedBones;
        addedBones.reserve(static_cast<size_t>(pbArm.bone_data_size()));

        for (int b = 0; b < pbArm.bone_data_size(); ++b) {
            const ArmatureBoneData& pbBone = pbArm.bone_data(b);
            if (pbBone.name().empty()) {
                continue;
            }

            auto* boneData = new cocos2d::extension::CCBoneData();
            boneData->init();
            boneData->name       = pbBone.name();
            boneData->parentName = pbBone.parent();
            boneData->x          = pbBone.x() * contentScale;
            boneData->y          = pbBone.y() * contentScale;
            boneData->zOrder     = static_cast<int>(pbBone.z());
            boneData->scaleX     = pbBone.has_cx() ? pbBone.cx() : 1.0f;
            boneData->scaleY     = pbBone.has_cy() ? pbBone.cy() : 1.0f;
            boneData->skewX      = pbBone.kx();
            boneData->skewY      = pbBone.ky();

            if (pbBone.has_color()) {
                ApplyProtoColor(boneData, pbBone.color());
            }

            for (int d = 0; d < pbBone.display_data_size(); ++d) {
                const ArmatureDisplayData& pbDisp = pbBone.display_data(d);
                const int32_t dtype = pbDisp.has_displaytype()
                                          ? pbDisp.displaytype()
                                          : static_cast<int32_t>(cocos2d::extension::CS_DISPLAY_SPRITE);

                cocos2d::extension::CCDisplayData* dispData = nullptr;
                if (dtype == cocos2d::extension::CS_DISPLAY_SPRITE) {
                    auto* spriteDisp        = new cocos2d::extension::CCSpriteDisplayData();
                    spriteDisp->displayType = cocos2d::extension::CS_DISPLAY_SPRITE;
                    if (pbDisp.has_name()) {
                        spriteDisp->displayName = pbDisp.name();
                    }
                    if (pbDisp.skin_data_size() > 0) {
                        const ArmatureSkinData& skin = pbDisp.skin_data(0);
                        spriteDisp->skinData.x       = skin.x() * contentScale;
                        spriteDisp->skinData.y       = skin.y() * contentScale;
                        spriteDisp->skinData.scaleX  = skin.has_cx() ? skin.cx() : 1.0f;
                        spriteDisp->skinData.scaleY  = skin.has_cy() ? skin.cy() : 1.0f;
                        spriteDisp->skinData.skewX   = skin.kx();
                        spriteDisp->skinData.skewY   = skin.ky();
                    }
                    dispData = spriteDisp;
                } else if (dtype == cocos2d::extension::CS_DISPLAY_ARMATURE) {
                    auto* armDisp        = new cocos2d::extension::CCArmatureDisplayData();
                    armDisp->displayType = cocos2d::extension::CS_DISPLAY_ARMATURE;
                    if (pbDisp.has_name()) {
                        armDisp->displayName = pbDisp.name();
                        if (!armDisp->displayName.empty()) {
                            armatureNamesForAnimGuard.push_back(armDisp->displayName);
                        }
                    }
                    dispData = armDisp;
                } else if (dtype == cocos2d::extension::CS_DISPLAY_PARTICLE) {
                    auto* partDisp        = new cocos2d::extension::CCParticleDisplayData();
                    partDisp->displayType = cocos2d::extension::CS_DISPLAY_PARTICLE;
                    if (pbDisp.has_plist() && !pbDisp.plist().empty()) {
                        partDisp->displayName =
                            ResolveParticlePlistPath(pbDisp.plist(), effectiveBase);
                    } else if (pbDisp.has_name() && !pbDisp.name().empty()) {
                        partDisp->displayName =
                            ResolveParticlePlistPath(pbDisp.name(), effectiveBase);
                    }
                    dispData = partDisp;
                }

                if (dispData) {
                    boneData->addDisplayData(dispData);
                    dispData->release();
                }
            }

            armData->addBoneData(boneData);
            addedBones.push_back(boneData);
            boneData->release();
        }

        SanitizeArmatureBoneParents(armData, addedBones, normConfigPath);

        if (asyncLock) {
            std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
            manager->addArmatureData(armData->name.c_str(), armData, normConfigPath.c_str());
        } else {
            manager->addArmatureData(armData->name.c_str(), armData, normConfigPath.c_str());
        }
        armData->release();
    }

    for (int i = 0; i < root.animation_data_size(); ++i) {
        const ArmatureAnimationData& pbAnim = root.animation_data(i);
        if (pbAnim.name().empty()) {
            continue;
        }

        auto* animData = new cocos2d::extension::CCAnimationData();
        animData->name = pbAnim.name();

        for (int m = 0; m < pbAnim.mov_data_size(); ++m) {
            const ArmatureMovData& pbMov = pbAnim.mov_data(m);
            if (pbMov.name().empty()) {
                continue;
            }

            auto* movData          = new cocos2d::extension::CCMovementData();
            movData->name          = pbMov.name();
            movData->duration      = pbMov.dr();
            movData->loop          = pbMov.lp();
            movData->durationTo    = std::max(0, pbMov.to());
            movData->durationTween = std::max(0, pbMov.drtw());
            movData->tweenEasing   = static_cast<cocos2d::extension::CCTweenType>(pbMov.twe());
            const float rawScale   = pbMov.has_sc() ? pbMov.sc() : 1.0f;
            movData->scale         = (std::isfinite(rawScale) && rawScale > 0.0f) ? rawScale : 1.0f;

            int maxBoneDuration = 0;

            for (int mb = 0; mb < pbMov.mov_bone_data_size(); ++mb) {
                const ArmatureMovBoneData& pbMovBone = pbMov.mov_bone_data(mb);
                if (pbMovBone.name().empty() || pbMovBone.frame_data_size() == 0) {
                    continue;
                }

                auto* movBoneData  = new cocos2d::extension::CCMovementBoneData();
                movBoneData->init();
                movBoneData->name  = pbMovBone.name();
                movBoneData->delay = pbMovBone.dl();

                int cumulativeDuration    = 0;
                int nextSequentialFrameId = 0;

                for (int f = 0; f < pbMovBone.frame_data_size(); ++f) {
                    const ArmatureFrameData& pbFrame = pbMovBone.frame_data(f);

                    auto* frameData         = new cocos2d::extension::CCFrameData();
                    frameData->displayIndex = pbFrame.di();
                    frameData->x            = pbFrame.x() * contentScale;
                    frameData->y            = pbFrame.y() * contentScale;
                    frameData->zOrder       = pbFrame.z();
                    frameData->scaleX       = pbFrame.has_cx() ? pbFrame.cx() : 1.0f;
                    frameData->scaleY       = pbFrame.has_cy() ? pbFrame.cy() : 1.0f;
                    frameData->skewX        = pbFrame.kx();
                    frameData->skewY        = pbFrame.ky();
                    frameData->tweenEasing  =
                        static_cast<cocos2d::extension::CCTweenType>(pbFrame.twe());
                    frameData->isTween =
                        pbFrame.has_tweenframe() ? pbFrame.tweenframe() : true;

                    if (pbFrame.has_dr()) {
                        frameData->duration = (pbFrame.dr() >= 0) ? pbFrame.dr() : 1;
                    } else {
                        frameData->duration = 1;
                    }

                    if (pbFrame.has_fi() && pbFrame.fi() >= 0) {
                        frameData->frameID = pbFrame.fi();
                    } else {
                        frameData->frameID = nextSequentialFrameId;
                    }
                    nextSequentialFrameId =
                        frameData->frameID + ((frameData->duration > 0) ? frameData->duration : 1);

                    if (pbFrame.has_bd()) {
                        switch (static_cast<cocos2d::extension::CCBlendType>(pbFrame.bd())) {
                            case cocos2d::extension::BLEND_LAYER:
                            case cocos2d::extension::BLEND_ADD:
                                frameData->blendFunc = { GL_SRC_ALPHA, GL_ONE };
                                break;
                            case cocos2d::extension::BLEND_MULTIPLY:
                                frameData->blendFunc = { GL_DST_COLOR, GL_ONE_MINUS_SRC_ALPHA };
                                break;
                            case cocos2d::extension::BLEND_SCREEN:
                                frameData->blendFunc = { GL_ONE, GL_ONE_MINUS_SRC_COLOR };
                                break;
                            default:
                                frameData->blendFunc = { CC_BLEND_SRC, CC_BLEND_DST };
                                break;
                        }
                    }
                    if (pbFrame.has_evt()) {
                        frameData->strEvent = pbFrame.evt();
                    }
                    if (pbFrame.has_color()) {
                        ApplyProtoColor(frameData, pbFrame.color());
                    }

                    cumulativeDuration += frameData->duration;
                    movBoneData->duration =
                        std::max(cumulativeDuration, frameData->frameID + frameData->duration);
                    movBoneData->addFrameData(frameData);
                    frameData->release();
                }

                if (movBoneData->frameList.count() == 0) {
                    movBoneData->release();
                    continue;
                }

                maxBoneDuration = std::max(maxBoneDuration, movBoneData->duration);
                NormalizeMovementBoneSkew(movBoneData);
                movData->addMovementBoneData(movBoneData);
                movBoneData->release();
            }

            if (movData->duration < 1) {
                movData->duration = std::max(1, maxBoneDuration);
            }

            animData->addMovement(movData);
            movData->release();
        }

        if (asyncLock) {
            std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
            manager->addAnimationData(animData->name.c_str(), animData, normConfigPath.c_str());
        } else {
            manager->addAnimationData(animData->name.c_str(), animData, normConfigPath.c_str());
        }
        animData->release();
    }

    EnsureDummyAnimationDataForArmatures(
        manager, armatureNamesForAnimGuard, normConfigPath, asyncLock);

    for (int i = 0; i < root.texture_data_size(); ++i) {
        const ArmatureTextureData& pbTex = root.texture_data(i);
        if (pbTex.name().empty()) {
            continue;
        }

        if (pbTex.has_plistfile() && !pbTex.plistfile().empty()) {
            LoadResolvedSpriteSheet(pbTex.plistfile(), effectiveBase, nullptr, loadedSheets);
        }

        if (manager->getTextureData(pbTex.name().c_str()) != nullptr) {
            continue;
        }

        auto* texData   = new cocos2d::extension::CCTextureData();
        texData->init();
        texData->name   = pbTex.name();
        texData->width  = pbTex.width();
        texData->height = pbTex.height();
        texData->pivotX = pbTex.px();
        texData->pivotY = pbTex.py();

        for (int c = 0; c < pbTex.contour_data_size(); ++c) {
            const ArmatureContourData& pbContour = pbTex.contour_data(c);
            if (pbContour.vertex_size() < 3) {
                continue;
            }
            auto* contour = new cocos2d::extension::CCContourData();
            contour->init();

            for (int v = 0; v < pbContour.vertex_size(); ++v) {
                const ArmatureVertex& pbV = pbContour.vertex(v);
                auto*                 vtx = new cocos2d::extension::CCContourVertex2(
                    pbV.x() * contentScale, pbV.y() * contentScale);
                contour->vertexList.addObject(vtx);
                vtx->release();
            }

            texData->addContourData(contour);
            contour->release();
        }

        if (asyncLock) {
            std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
            manager->addTextureData(texData->name.c_str(), texData, normConfigPath.c_str());
        } else {
            manager->addTextureData(texData->name.c_str(), texData, normConfigPath.c_str());
        }
        texData->release();
    }

    return true;
#else
    (void)root;
    (void)configFilePath;
    (void)baseFilePath;
    (void)asyncLock;
    (void)plistPath;
    (void)imagePath;
    return false;
#endif
}

bool XmlbArmatureLoader::AddDataFromBitCache(const uint8_t* bitCacheData,
                                             size_t bitCacheSize,
                                             const std::string& configFilePath,
                                             bool asyncLock,
                                             const XmlbBitCacheLayout& layout,
                                             const std::string& plistPath,
                                             const std::string& imagePath) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    if (!ValidateBitCacheBuffer(bitCacheData, bitCacheSize, layout)) {
        return false;
    }

    auto* manager = cocos2d::extension::CCArmatureDataManager::sharedArmatureDataManager();
    if (!manager) {
        return false;
    }

    const std::string normConfigPath = NormalizeAssetPath(configFilePath);
    if (!normConfigPath.empty() || !plistPath.empty() || !imagePath.empty()) {
        std::unordered_set<std::string> loadedSheets;
        PreloadArmatureSpriteSheets(
            normConfigPath, normConfigPath, plistPath, imagePath, loadedSheets);
    }

    const uint8_t* end    = bitCacheData + bitCacheSize;
    const uint8_t* cursor = bitCacheData;

    const uint16_t armatureCount  = ReadLE16U(cursor + 0);
    const uint16_t animationCount = ReadLE16U(cursor + 2);
    const uint16_t textureCount   = ReadLE16U(cursor + 4);
    cursor += layout.skeletonStructSize;

    std::vector<std::string> armatureNamesForAnimGuard;

    for (uint16_t a = 0; a < armatureCount; ++a) {
        if (cursor + layout.armatureDataStructSize > end) {
            return false;
        }
        const uint8_t* armHdr    = cursor;
        const uint16_t boneCount = ReadLE16U(armHdr + 64);
        cursor += layout.armatureDataStructSize;

        auto* armData = new cocos2d::extension::CCArmatureData();
        armData->init();
        armData->name = ReadFixedCString(armHdr, 64);
        armatureNamesForAnimGuard.push_back(armData->name);

        std::vector<cocos2d::extension::CCBoneData*> addedBones;
        addedBones.reserve(boneCount);

        for (uint16_t b = 0; b < boneCount; ++b) {
            if (cursor + layout.boneDataStructSize > end) {
                armData->release();
                return false;
            }
            const uint8_t* boneHdr      = cursor;
            const uint16_t displayCount = ReadLE16U(boneHdr + 66);
            cursor += layout.boneDataStructSize;

            auto* boneData   = new cocos2d::extension::CCBoneData();
            boneData->init();
            boneData->name   = ReadFixedCString(boneHdr, 64);
            boneData->zOrder = static_cast<int>(static_cast<int8_t>(boneHdr[64]));

            for (uint16_t d = 0; d < displayCount; ++d) {
                if (cursor + layout.displayDataStructSize > end) {
                    boneData->release();
                    armData->release();
                    return false;
                }
                const uint8_t* dispHdr = cursor;
                cursor += layout.displayDataStructSize;

                const uint8_t     rawDispType = dispHdr[0];
                const std::string rawDispName = ReadFixedCString(dispHdr + 1, 64);

                cocos2d::extension::CCDisplayData* dispData = nullptr;
                if (rawDispType == 0) {
                    auto* sprDisp        = new cocos2d::extension::CCSpriteDisplayData();
                    sprDisp->displayType = cocos2d::extension::CS_DISPLAY_SPRITE;
                    sprDisp->displayName = rawDispName;
                    dispData             = sprDisp;
                } else if (rawDispType == 1) {
                    auto* armDisp        = new cocos2d::extension::CCArmatureDisplayData();
                    armDisp->displayType = cocos2d::extension::CS_DISPLAY_ARMATURE;
                    armDisp->displayName = rawDispName;
                    if (!armDisp->displayName.empty()) {
                        armatureNamesForAnimGuard.push_back(armDisp->displayName);
                    }
                    dispData = armDisp;
                } else if (rawDispType == 2) {
                    auto* partDisp        = new cocos2d::extension::CCParticleDisplayData();
                    partDisp->displayType = cocos2d::extension::CS_DISPLAY_PARTICLE;
                    partDisp->displayName =
                        ResolveParticlePlistPath(rawDispName, normConfigPath);
                    dispData = partDisp;
                }

                if (dispData) {
                    boneData->addDisplayData(dispData);
                    dispData->release();
                }
            }

            armData->addBoneData(boneData);
            addedBones.push_back(boneData);
            boneData->release();
        }

        SanitizeArmatureBoneParents(armData, addedBones, normConfigPath);

        if (asyncLock) {
            std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
            manager->addArmatureData(armData->name.c_str(), armData, normConfigPath.c_str());
        } else {
            manager->addArmatureData(armData->name.c_str(), armData, normConfigPath.c_str());
        }
        armData->release();
    }

    for (uint16_t a = 0; a < animationCount; ++a) {
        if (cursor + layout.animationDataStructSize > end) {
            return false;
        }
        const uint8_t* animHdr  = cursor;
        const uint16_t movCount = ReadLE16U(animHdr + 64);
        cursor += layout.animationDataStructSize;

        auto* animData = new cocos2d::extension::CCAnimationData();
        animData->name = ReadFixedCString(animHdr, 64);

        for (uint16_t m = 0; m < movCount; ++m) {
            if (cursor + layout.movementDataStructSize > end) {
                animData->release();
                return false;
            }
            const uint8_t* movHdr       = cursor;
            const uint16_t movBoneCount = ReadLE16U(movHdr + 72);
            cursor += layout.movementDataStructSize;

            auto* movData       = new cocos2d::extension::CCMovementData();
            movData->name       = ReadFixedCString(movHdr, 64);
            movData->duration   = ReadLE32S(movHdr + 64);
            movData->durationTo = std::max(0, static_cast<int>(ReadLE16S(movHdr + 68)));
            movData->loop       = (movHdr[70] != 0);
            if (!std::isfinite(movData->scale) || movData->scale <= 0.0f) {
                movData->scale = 1.0f;
            }

            int maxBoneDuration = 0;

            for (uint16_t mb = 0; mb < movBoneCount; ++mb) {
                if (cursor + layout.movementBoneDataStructSize > end) {
                    movData->release();
                    animData->release();
                    return false;
                }
                const uint8_t* mbHdr      = cursor;
                const uint16_t frameCount = ReadLE16U(mbHdr + 64);
                cursor += layout.movementBoneDataStructSize;

                auto* movBoneData = new cocos2d::extension::CCMovementBoneData();
                movBoneData->init();
                movBoneData->name = ReadFixedCString(mbHdr, 64);

                int cumulativeFrameId = 0;
                for (uint16_t f = 0; f < frameCount; ++f) {
                    if (cursor + layout.frameDataStructSize > end) {
                        movBoneData->release();
                        movData->release();
                        animData->release();
                        return false;
                    }
                    const uint8_t* fr = cursor;
                    cursor += layout.frameDataStructSize;

                    auto* frameData = new cocos2d::extension::CCFrameData();
                    frameData->x = static_cast<float>(
                        static_cast<double>(ReadLE16S(fr + 0)) +
                        static_cast<double>(ReadLE16S(fr + 4)) * 0.001);
                    frameData->y = static_cast<float>(
                        static_cast<double>(ReadLE16S(fr + 2)) +
                        static_cast<double>(ReadLE16S(fr + 6)) * 0.001);
                    frameData->scaleX = static_cast<float>(
                        static_cast<double>(ReadLE16S(fr + 8)) +
                        static_cast<double>(ReadLE16S(fr + 12)) * 0.001);
                    frameData->scaleY = static_cast<float>(
                        static_cast<double>(ReadLE16S(fr + 10)) +
                        static_cast<double>(ReadLE16S(fr + 14)) * 0.001);

                    frameData->skewX          = static_cast<float>(ReadLE16S(fr + 16)) * 0.001f;
                    frameData->skewY          = static_cast<float>(ReadLE16S(fr + 18)) * 0.001f;
                    frameData->tweenEasing    =
                        static_cast<cocos2d::extension::CCTweenType>(ReadLE16S(fr + 20));
                    frameData->duration       = std::max(0, static_cast<int>(ReadLE16S(fr + 24)));
                    frameData->a              = static_cast<unsigned char>(ReadLE16S(fr + 26));
                    frameData->r              = static_cast<unsigned char>(ReadLE16S(fr + 28));
                    frameData->g              = static_cast<unsigned char>(ReadLE16S(fr + 30));
                    frameData->b              = static_cast<unsigned char>(ReadLE16S(fr + 32));
                    frameData->zOrder         = static_cast<int>(static_cast<int8_t>(fr[34]));
                    frameData->isTween        = (fr[35] != 0);
                    frameData->displayIndex   = static_cast<int>(static_cast<int8_t>(fr[36]));
                    frameData->isUseColorInfo = (fr[37] != 0);
                    frameData->blendFunc      = MapBitCacheBlendType(fr[38]);

                    frameData->strEvent    = ReadFixedCString(fr + 40, 64);
                    frameData->strMovement = ReadFixedCString(fr + 104, 64);

                    frameData->frameID = cumulativeFrameId;
                    cumulativeFrameId += frameData->duration;
                    movBoneData->duration = cumulativeFrameId;

                    movBoneData->addFrameData(frameData);
                    frameData->release();
                }

                if (movBoneData->frameList.count() == 0) {
                    movBoneData->release();
                    continue;
                }

                NormalizeMovementBoneSkew(movBoneData);
                AppendClosingFrame(movBoneData);
                maxBoneDuration = std::max(maxBoneDuration, movBoneData->duration);

                movData->addMovementBoneData(movBoneData);
                movBoneData->release();
            }

            if (movData->duration < 1) {
                movData->duration = std::max(1, maxBoneDuration);
            }

            animData->addMovement(movData);
            movData->release();
        }

        if (asyncLock) {
            std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
            manager->addAnimationData(animData->name.c_str(), animData, normConfigPath.c_str());
        } else {
            manager->addAnimationData(animData->name.c_str(), animData, normConfigPath.c_str());
        }
        animData->release();
    }

    EnsureDummyAnimationDataForArmatures(
        manager, armatureNamesForAnimGuard, normConfigPath, asyncLock);

    for (uint16_t t = 0; t < textureCount; ++t) {
        if (cursor + layout.textureDataStructSize > end) {
            return false;
        }
        const uint8_t* texHdr = cursor;
        cursor += layout.textureDataStructSize;

        const std::string texName = ReadFixedCString(texHdr, 64);
        if (manager->getTextureData(texName.c_str()) != nullptr) {
            cocos2d::CCLog("[XmlbArmatureLoader] Duplicate texture data skipped: %s",
                           texName.c_str());
            continue;
        }

        auto* texData   = new cocos2d::extension::CCTextureData();
        texData->init();
        texData->name   = texName;
        texData->pivotX = static_cast<float>(ReadLE16S(texHdr + 64)) * 0.001f;
        texData->pivotY = static_cast<float>(ReadLE16S(texHdr + 66)) * 0.001f;

        if (asyncLock) {
            std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
            manager->addTextureData(texData->name.c_str(), texData, normConfigPath.c_str());
        } else {
            manager->addTextureData(texData->name.c_str(), texData, normConfigPath.c_str());
        }
        texData->release();
    }

    return true;
#else
    (void)bitCacheData;
    (void)bitCacheSize;
    (void)configFilePath;
    (void)asyncLock;
    (void)layout;
    (void)plistPath;
    (void)imagePath;
    return false;
#endif
}

} // namespace assets
} // namespace gclient
