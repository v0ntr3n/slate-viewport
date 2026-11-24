#include "PbGuiLoader.h"

#include "BtDecryptHook.h"
#include "PlistbLoader.h"
#include "XmlbArmatureLoader.h"
#include "CSGUI.pb.h"
#include "CSScene.pb.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "cocos2d.h"
#include "cocos-ext.h"
#include "CocoStudio/Action/CCActionFrame.h"
#include "CocoStudio/Action/CCActionNode.h"
#endif

#if !defined(GCLIENT_STANDALONE_BUILD)
#include "diagnostics/CrashAndTelemetry.h"
#endif

namespace gclient {
namespace assets {

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
namespace {

void LogGuiWarn(const char* msg) {
#if !defined(GCLIENT_STANDALONE_BUILD)
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Warn, "PbGuiLoader", "%s", msg ? msg : "");
#endif
    cocos2d::CCLog("[PbGuiLoader][WARN] %s", msg ? msg : "");
}

std::string ExtractDirectoryPrefix(const std::string& normalizedPath) {
    const size_t slashPos = normalizedPath.find_last_of('/');
    if (slashPos == std::string::npos) {
        return std::string();
    }
    return normalizedPath.substr(0, slashPos + 1);
}

bool EndsWithCaseInsensitive(const std::string& str, const char* suffix) {
    const size_t sufLen = std::strlen(suffix);
    if (str.size() < sufLen) {
        return false;
    }
    const size_t offset = str.size() - sufLen;
    for (size_t i = 0; i < sufLen; ++i) {
        if (std::tolower(static_cast<unsigned char>(str[offset + i])) !=
            std::tolower(static_cast<unsigned char>(suffix[i]))) {
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

std::string JoinBaseAndRelativePath(const std::string& baseDir, const std::string& relPath) {
    const std::string normRel = NormalizeAssetPath(relPath);
    if (normRel.empty()) {
        return std::string();
    }
    if (normRel[0] == '/' || (normRel.size() >= 2 && normRel[1] == ':')) {
        return normRel;
    }
    const std::string normBase = NormalizeAssetPath(baseDir);
    if (normBase.empty() || normBase == ".") {
        return normRel;
    }
    if (normBase.back() == '/') {
        return NormalizeAssetPath(normBase + normRel);
    }
    return NormalizeAssetPath(normBase + "/" + normRel);
}

std::string StripLeadingDotDotSegments(const std::string& normalizedPath) {
    size_t pos = 0;
    while (pos + 3 <= normalizedPath.size() &&
           normalizedPath.compare(pos, 3, "../") == 0) {
        pos += 3;
    }
    if (normalizedPath.compare(pos, std::string::npos, "..") == 0) {
        return std::string();
    }
    return normalizedPath.substr(pos);
}

void AppendUniquePath(std::vector<std::string>& out, const std::string& candidate) {
    if (candidate.empty()) {
        return;
    }
    for (const std::string& existing : out) {
        if (existing == candidate) {
            return;
        }
    }
    out.push_back(candidate);
}

std::vector<std::string> BuildRelativeCandidatePaths(const std::string& rawRelPath,
                                                     const std::string& baseDir) {
    std::vector<std::string> out;
    const std::string normRel = NormalizeAssetPath(rawRelPath);
    if (normRel.empty()) {
        return out;
    }
    AppendUniquePath(out, JoinBaseAndRelativePath(baseDir, normRel));
    AppendUniquePath(out, normRel);
    const std::string strippedRel = StripLeadingDotDotSegments(normRel);
    if (!strippedRel.empty()) {
        AppendUniquePath(out, strippedRel);
    }
    return out;
}

bool DoesExactAssetFileExist(const std::string& candidatePath, std::string* outFullPath = nullptr) {
    if (candidatePath.empty()) {
        return false;
    }
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) {
        return false;
    }
    const std::string full = fu->fullPathForFilename(candidatePath.c_str());
    if (!full.empty() && fu->isFileExist(full)) {
        if (outFullPath) {
            *outFullPath = full;
        }
        return true;
    }
    return false;
}

bool DoesAssetOrTextureVariantExist(const std::string& candidatePath) {
    if (DoesExactAssetFileExist(candidatePath)) {
        return true;
    }
    if (EndsWithCaseInsensitive(candidatePath, ".plist")) {
        if (DoesExactAssetFileExist(candidatePath + "b")) {
            return true;
        }
        return false;
    }
    if (EndsWithCaseInsensitive(candidatePath, ".fnt") ||
        EndsWithCaseInsensitive(candidatePath, ".pb") ||
        EndsWithCaseInsensitive(candidatePath, ".xmlb") ||
        EndsWithCaseInsensitive(candidatePath, ".tmx")) {
        return false;
    }
    for (const std::string& texCand : PlistbLoader::BuildTextureCandidatePaths(candidatePath)) {
        if (DoesExactAssetFileExist(texCand)) {
            return true;
        }
    }
    return false;
}

std::string ResolveLocalAssetPath(const std::string& rawRelPath, const std::string& baseDir) {
    const std::vector<std::string> candidates = BuildRelativeCandidatePaths(rawRelPath, baseDir);
    if (candidates.empty()) {
        return std::string();
    }
    for (const std::string& cand : candidates) {
        if (DoesAssetOrTextureVariantExist(cand)) {
            return cand;
        }
    }
    return candidates.front();
}

// Stock Cocos2d-x 2.2.6 declares Layout::doLayout() as `protected: virtual void doLayout()`.
struct LayoutDoLayoutAccessor : public cocos2d::ui::Layout {
    static void Invoke(cocos2d::ui::Layout* layout) {
        if (!layout) {
            return;
        }
        void (cocos2d::ui::Layout::*doLayoutFn)() = &LayoutDoLayoutAccessor::doLayout;
        (layout->*doLayoutFn)();
    }
};

void TriggerLayoutPass(cocos2d::ui::Layout* layout) {
    if (!layout) {
        return;
    }
    layout->requestDoLayout();
    LayoutDoLayoutAccessor::Invoke(layout);
}

// Standard C++ [class.protected] accessor for CCTextureCache::m_pTextures so split-root
// BMFont / Atlas textures (e.g. .fnt in Resources/ and .pkm/.png in assets/) can be
// pre-aliased under the exact key CCLabelBMFont / CCTextureAtlas queries.
struct TextureCacheAccessor : public cocos2d::CCTextureCache {
    static cocos2d::CCDictionary* GetTexturesDict(cocos2d::CCTextureCache* cache) {
        if (!cache) {
            return nullptr;
        }
        cocos2d::CCDictionary* cocos2d::CCTextureCache::*memberPtr =
            &TextureCacheAccessor::m_pTextures;
        return cache->*memberPtr;
    }
};

cocos2d::CCTexture2D* ProbeAndLoadTextureAcrossRoots(const std::string& rawTexPath,
                                                     const std::string& baseDir,
                                                     std::string* outResolvedCand = nullptr) {
    auto* texCache = cocos2d::CCTextureCache::sharedTextureCache();
    auto* fu       = cocos2d::CCFileUtils::sharedFileUtils();
    if (!texCache) {
        return nullptr;
    }

    const std::vector<std::string> baseCandidates = BuildRelativeCandidatePaths(rawTexPath, baseDir);
    std::vector<std::string>       allCandidates;
    for (const std::string& b : baseCandidates) {
        for (const std::string& tc : PlistbLoader::BuildTextureCandidatePaths(b)) {
            AppendUniquePath(allCandidates, tc);
        }
    }

    if (fu) {
        for (const std::string& cand : allCandidates) {
            const std::string full = fu->fullPathForFilename(cand.c_str());
            if (!full.empty() && fu->isFileExist(full)) {
                if (cocos2d::CCTexture2D* tex = texCache->addImage(full.c_str())) {
                    if (outResolvedCand) *outResolvedCand = cand;
                    return tex;
                }
            }
        }
    }

    for (const std::string& cand : allCandidates) {
        if (cocos2d::CCTexture2D* tex = texCache->addImage(cand.c_str())) {
            if (outResolvedCand) *outResolvedCand = cand;
            return tex;
        }
    }
    return nullptr;
}

bool BufferLooksLikeXmlPlistDict(const uint8_t* data, size_t size) {
    if (!data || size < 16) {
        return false;
    }
    if (IsBtEncryptedBuffer(data, size)) {
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
    if (!StartsWithAsciiCI(data + off, rem, "<?xml") &&
        !StartsWithAsciiCI(data + off, rem, "<plist") &&
        !StartsWithAsciiCI(data + off, rem, "<!doctype") &&
        !StartsWithAsciiCI(data + off, rem, "<!--")) {
        return false;
    }
    const std::string view(reinterpret_cast<const char*>(data + off), rem);
    return view.find("<plist") != std::string::npos &&
           view.find("<dict") != std::string::npos;
}

std::string ExtractXmlKeyStringValue(const std::string& xml, const char* keyName) {
    const std::string needle = std::string("<key>") + keyName + "</key>";
    const size_t      kPos   = xml.find(needle);
    if (kPos == std::string::npos) {
        return std::string();
    }
    const size_t sOpen = xml.find("<string>", kPos + needle.size());
    if (sOpen == std::string::npos) {
        return std::string();
    }
    const size_t valStart = sOpen + 8;
    const size_t sClose   = xml.find("</string>", valStart);
    if (sClose == std::string::npos) {
        return std::string();
    }
    return xml.substr(valStart, sClose - valStart);
}

bool VerifyValidXmlPlistOnDisk(const std::string& xmlCandidate, std::string* outXmlContent = nullptr) {
    if (xmlCandidate.empty() || EndsWithCaseInsensitive(xmlCandidate, ".plistb")) {
        return false;
    }
    std::string fullPath;
    if (!DoesExactAssetFileExist(xmlCandidate, &fullPath)) {
        return false;
    }
    unsigned long  sz  = 0;
    unsigned char* buf = LoadAndDecryptFileData(xmlCandidate, &sz, nullptr);
    if (!buf || sz == 0) {
        delete[] buf;
        return false;
    }
    const bool ok = BufferLooksLikeXmlPlistDict(buf, static_cast<size_t>(sz));
    if (ok && outXmlContent) {
        outXmlContent->assign(reinterpret_cast<const char*>(buf), static_cast<size_t>(sz));
    }
    delete[] buf;
    return ok;
}

// Parses all bitmap page texture filenames referenced in an AngelCode BMFont .fnt
// file (supports text `page id=0 file="..."`, XML `<page ... file="..."/>`, and
// binary `"BMF\x03"` block-3 page tables).
std::vector<std::string> ExtractFntPageFiles(const uint8_t* data, size_t size) {
    std::vector<std::string> pages;
    if (!data || size < 4) {
        return pages;
    }

    // Binary AngelCode BMFont v3 ("BMF\x03")
    if (data[0] == 'B' && data[1] == 'M' && data[2] == 'F' && data[3] == 3) {
        size_t off = 4;
        while (off + 5 <= size) {
            const uint8_t  blockType = data[off];
            const uint32_t blockSize = static_cast<uint32_t>(data[off + 1]) |
                                       (static_cast<uint32_t>(data[off + 2]) << 8) |
                                       (static_cast<uint32_t>(data[off + 3]) << 16) |
                                       (static_cast<uint32_t>(data[off + 4]) << 24);
            off += 5;
            if (off + blockSize > size) {
                break;
            }
            if (blockType == 3 && blockSize > 0) {
                size_t pOff = 0;
                while (pOff < blockSize) {
                    const uint8_t* start  = data + off + pOff;
                    const void*    nulPtr = std::memchr(start, '\0', blockSize - pOff);
                    const size_t   sLen   = nulPtr
                                                ? static_cast<size_t>(static_cast<const uint8_t*>(nulPtr) - start)
                                                : (blockSize - pOff);
                    if (sLen > 0) {
                        AppendUniquePath(pages, std::string(reinterpret_cast<const char*>(start), sLen));
                    }
                    pOff += sLen + 1;
                }
            }
            off += blockSize;
        }
        return pages;
    }

    // Text or XML BMFont
    const std::string content(reinterpret_cast<const char*>(data), size);
    size_t            lineStart = 0;
    while (lineStart < content.size()) {
        size_t lineEnd = content.find('\n', lineStart);
        if (lineEnd == std::string::npos) {
            lineEnd = content.size();
        }
        const std::string line = content.substr(lineStart, lineEnd - lineStart);
        lineStart              = lineEnd + 1;

        const size_t pagePos = line.find("page");
        if (pagePos == std::string::npos) {
            continue;
        }
        // Avoid matching `<pages>` container tag without `file=`.
        const size_t fileKeyPos = line.find("file=", pagePos);
        if (fileKeyPos == std::string::npos) {
            continue;
        }
        size_t valPos = fileKeyPos + 5;
        while (valPos < line.size() && (line[valPos] == ' ' || line[valPos] == '\t')) {
            ++valPos;
        }
        if (valPos >= line.size()) {
            continue;
        }
        if (line[valPos] == '"' || line[valPos] == '\'') {
            const char   quote  = line[valPos++];
            const size_t endPos = line.find(quote, valPos);
            if (endPos != std::string::npos && endPos > valPos) {
                AppendUniquePath(pages, line.substr(valPos, endPos - valPos));
            }
        } else {
            size_t endPos = valPos;
            while (endPos < line.size() && line[endPos] != ' ' && line[endPos] != '\t' &&
                   line[endPos] != '\r' && line[endPos] != '\n' && line[endPos] != '>') {
                ++endPos;
            }
            if (endPos > valPos) {
                AppendUniquePath(pages, line.substr(valPos, endPos - valPos));
            }
        }
    }
    return pages;
}

// Resolves a CSData resource reference:
//   resourceType == 0 (UI_TEX_TYPE_LOCAL) => resolved across baseDir + rel, collapsed "..", and search roots
//   resourceType == 1 (UI_TEX_TYPE_PLIST) => sprite frame name in CCSpriteFrameCache
std::string ResolveCsDataPath(const CSData& data,
                              const std::string& baseDir,
                              cocos2d::ui::TextureResType* outType) {
    const auto texType = static_cast<cocos2d::ui::TextureResType>(data.resourcetype());
    if (outType) {
        *outType = texType;
    }
    if (!data.has_path() || data.path().empty()) {
        return std::string();
    }
    if (texType == cocos2d::ui::UI_TEX_TYPE_PLIST) {
        return NormalizeAssetPath(data.path());
    }
    return ResolveLocalAssetPath(data.path(), baseDir);
}

bool CanLoadWidgetTexture(const std::string& path, cocos2d::ui::TextureResType rt) {
    if (path.empty()) {
        return false;
    }
    if (rt == cocos2d::ui::UI_TEX_TYPE_PLIST) {
        auto* sfc = cocos2d::CCSpriteFrameCache::sharedSpriteFrameCache();
        return sfc && sfc->spriteFrameByName(path.c_str()) != nullptr;
    }
    return DoesAssetOrTextureVariantExist(path) ||
           ProbeAndLoadTextureAcrossRoots(path, std::string()) != nullptr;
}

void ApplyBaseWidgetOptions(cocos2d::ui::Widget* widget,
                            const CSOptions& opt) {
    if (!widget) {
        return;
    }

    if (opt.has_ignoresize()) {
        widget->ignoreContentAdaptWithSize(opt.ignoresize());
    }

    if (opt.has_sizetype()) {
        widget->setSizeType(static_cast<cocos2d::ui::SizeType>(opt.sizetype()));
    }
    if (opt.has_positiontype()) {
        widget->setPositionType(static_cast<cocos2d::ui::PositionType>(opt.positiontype()));
    }

    if (opt.has_width() || opt.has_height()) {
        const float w = opt.has_width() ? opt.width() : widget->getSize().width;
        const float h = opt.has_height() ? opt.height() : widget->getSize().height;
        widget->setSize(cocos2d::CCSize(w, h));
    }
    if (opt.has_sizepercentx() || opt.has_sizepercenty()) {
        const float sx = opt.has_sizepercentx() ? opt.sizepercentx() : 0.0f;
        const float sy = opt.has_sizepercenty() ? opt.sizepercenty() : 0.0f;
        widget->setSizePercent(cocos2d::CCPoint(sx, sy));
    }

    if (opt.has_tag()) {
        widget->setTag(opt.tag());
    }
    if (opt.has_actiontag()) {
        widget->setActionTag(opt.actiontag());
    }
    if (opt.has_touchable()) {
        widget->setTouchEnabled(opt.touchable());
    }
    if (opt.has_name()) {
        widget->setName(opt.name().c_str());
    }

    const float posX = opt.has_x() ? static_cast<float>(opt.x()) : 0.0f;
    const float posY = opt.has_y() ? static_cast<float>(opt.y()) : 0.0f;
    widget->setPosition(cocos2d::CCPoint(posX, posY));

    if (opt.has_positionpercentx() || opt.has_positionpercenty()) {
        const float px = opt.has_positionpercentx() ? opt.positionpercentx() : 0.0f;
        const float py = opt.has_positionpercenty() ? opt.positionpercenty() : 0.0f;
        widget->setPositionPercent(cocos2d::CCPoint(px, py));
    }

    if (opt.has_scalex()) {
        widget->setScaleX(opt.scalex());
    }
    if (opt.has_scaley()) {
        widget->setScaleY(opt.scaley());
    }
    if (opt.has_rotation()) {
        widget->setRotation(opt.rotation());
    }
    if (opt.has_visible()) {
        widget->setVisible(opt.visible());
    }
    if (opt.has_zorder()) {
        widget->setZOrder(opt.zorder());
    }
    if (opt.has_flipx()) {
        widget->setFlipX(opt.flipx());
    }
    if (opt.has_flipy()) {
        widget->setFlipY(opt.flipy());
    }

    if (opt.has_anchorpointx() || opt.has_anchorpointy()) {
        const float ax = opt.has_anchorpointx() ? opt.anchorpointx() : 0.5f;
        const float ay = opt.has_anchorpointy() ? opt.anchorpointy() : 0.5f;
        widget->setAnchorPoint(cocos2d::CCPoint(ax, ay));
    }

    if (opt.has_opacity()) {
        widget->setOpacity(static_cast<GLubyte>(opt.opacity()));
    }
    if (opt.has_colorr() || opt.has_colorg() || opt.has_colorb()) {
        const GLubyte r = static_cast<GLubyte>(opt.has_colorr() ? opt.colorr() : 255);
        const GLubyte g = static_cast<GLubyte>(opt.has_colorg() ? opt.colorg() : 255);
        const GLubyte b = static_cast<GLubyte>(opt.has_colorb() ? opt.colorb() : 255);
        widget->setColor(cocos2d::ccc3(r, g, b));
    }

    if (opt.has_layoutparameter()) {
        const CSLayoutParameter& lp = opt.layoutparameter();
        const int32_t            t  = lp.type();
        if (t == 1) {
            auto* linear = cocos2d::ui::LinearLayoutParameter::create();
            if (lp.has_gravity()) {
                linear->setGravity(static_cast<cocos2d::ui::LinearGravity>(lp.gravity()));
            }
            linear->setMargin(cocos2d::ui::Margin(
                lp.has_marginleft() ? lp.marginleft() : 0.0f,
                lp.has_margintop() ? lp.margintop() : 0.0f,
                lp.has_marginright() ? lp.marginright() : 0.0f,
                lp.has_margindown() ? lp.margindown() : 0.0f));
            widget->setLayoutParameter(linear);
        } else if (t == 2) {
            auto* rel = cocos2d::ui::RelativeLayoutParameter::create();
            if (lp.has_relativename()) {
                rel->setRelativeName(lp.relativename().c_str());
            }
            if (lp.has_relativetoname()) {
                rel->setRelativeToWidgetName(lp.relativetoname().c_str());
            }
            if (lp.has_align()) {
                rel->setAlign(static_cast<cocos2d::ui::RelativeAlign>(lp.align()));
            }
            rel->setMargin(cocos2d::ui::Margin(
                lp.has_marginleft() ? lp.marginleft() : 0.0f,
                lp.has_margintop() ? lp.margintop() : 0.0f,
                lp.has_marginright() ? lp.marginright() : 0.0f,
                lp.has_margindown() ? lp.margindown() : 0.0f));
            widget->setLayoutParameter(rel);
        }
    }
}

void ApplyLayoutOptions(cocos2d::ui::Layout* layout,
                        const CSOptions& opt,
                        const std::string& baseDir) {
    if (!layout) {
        return;
    }

    if (opt.has_clipable()) {
        layout->setClippingEnabled(opt.clipable());
    }

    if (opt.has_colortype()) {
        layout->setBackGroundColorType(
            static_cast<cocos2d::ui::LayoutBackGroundColorType>(opt.colortype()));
    }

    if (opt.has_bgcolorr() || opt.has_bgcolorg() || opt.has_bgcolorb()) {
        layout->setBackGroundColor(cocos2d::ccc3(
            static_cast<GLubyte>(opt.has_bgcolorr() ? opt.bgcolorr() : 255),
            static_cast<GLubyte>(opt.has_bgcolorg() ? opt.bgcolorg() : 255),
            static_cast<GLubyte>(opt.has_bgcolorb() ? opt.bgcolorb() : 255)));
    }

    if (opt.has_bgstartcolorr() || opt.has_bgendcolorr()) {
        const cocos2d::ccColor3B startC = cocos2d::ccc3(
            static_cast<GLubyte>(opt.has_bgstartcolorr() ? opt.bgstartcolorr() : 255),
            static_cast<GLubyte>(opt.has_bgstartcolorg() ? opt.bgstartcolorg() : 255),
            static_cast<GLubyte>(opt.has_bgstartcolorb() ? opt.bgstartcolorb() : 255));
        const cocos2d::ccColor3B endC = cocos2d::ccc3(
            static_cast<GLubyte>(opt.has_bgendcolorr() ? opt.bgendcolorr() : 255),
            static_cast<GLubyte>(opt.has_bgendcolorg() ? opt.bgendcolorg() : 255),
            static_cast<GLubyte>(opt.has_bgendcolorb() ? opt.bgendcolorb() : 255));
        layout->setBackGroundColor(startC, endC);
    }

    if (opt.has_vectorx() || opt.has_vectory()) {
        layout->setBackGroundColorVector(cocos2d::CCPoint(
            opt.has_vectorx() ? opt.vectorx() : 0.0f,
            opt.has_vectory() ? opt.vectory() : -1.0f));
    }

    if (opt.has_bgcoloropacity()) {
        layout->setBackGroundColorOpacity(static_cast<GLubyte>(opt.bgcoloropacity()));
    }

    if (opt.has_backgroundscale9enable()) {
        layout->setBackGroundImageScale9Enabled(opt.backgroundscale9enable());
    }

    if (opt.has_backgroundimagedata()) {
        cocos2d::ui::TextureResType resType = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           bgPath  =
            ResolveCsDataPath(opt.backgroundimagedata(), baseDir, &resType);
        if (!bgPath.empty()) {
            layout->setBackGroundImage(bgPath.c_str(), resType);
        }
    }

    if (opt.has_backgroundscale9enable() && opt.backgroundscale9enable()) {
        layout->setBackGroundImageCapInsets(cocos2d::CCRect(
            opt.has_capinsetsx() ? opt.capinsetsx() : 0.0f,
            opt.has_capinsetsy() ? opt.capinsetsy() : 0.0f,
            opt.has_capinsetswidth() ? opt.capinsetswidth() : 0.0f,
            opt.has_capinsetsheight() ? opt.capinsetsheight() : 0.0f));
    }

    if (opt.has_layouttype()) {
        layout->setLayoutType(static_cast<cocos2d::ui::LayoutType>(opt.layouttype()));
    }

    if (opt.has_adaptscreen() && opt.adaptscreen()) {
        const cocos2d::CCSize winSize = cocos2d::CCDirector::sharedDirector()->getWinSize();
        layout->setSize(winSize);
    }
}

void ApplyButtonOptions(cocos2d::ui::Button* button,
                        const CSOptions& opt,
                        const std::string& baseDir) {
    if (!button) {
        return;
    }

    if (opt.has_scale9enable()) {
        button->setScale9Enabled(opt.scale9enable());
    }

    if (opt.has_normaldata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.normaldata(), baseDir, &rt);
        if (!p.empty()) {
            button->loadTextureNormal(p.c_str(), rt);
        }
    }
    if (opt.has_presseddata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.presseddata(), baseDir, &rt);
        if (!p.empty()) {
            button->loadTexturePressed(p.c_str(), rt);
        }
    }
    if (opt.has_disbleddata()) {
        // Note: CSGUI.proto field 31 is spelled `disbledData`.
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.disbleddata(), baseDir, &rt);
        if (!p.empty()) {
            button->loadTextureDisabled(p.c_str(), rt);
        }
    }

    if (opt.has_scale9enable() && opt.scale9enable()) {
        button->setCapInsets(cocos2d::CCRect(
            opt.has_capinsetsx() ? opt.capinsetsx() : 0.0f,
            opt.has_capinsetsy() ? opt.capinsetsy() : 0.0f,
            opt.has_capinsetswidth() ? opt.capinsetswidth() : 0.0f,
            opt.has_capinsetsheight() ? opt.capinsetsheight() : 0.0f));
        if (opt.has_scale9width() && opt.has_scale9height()) {
            button->setSize(cocos2d::CCSize(opt.scale9width(), opt.scale9height()));
        }
    }

    if (opt.has_text()) {
        button->setTitleText(opt.text());
    }
    if (opt.has_fontname()) {
        button->setTitleFontName(opt.fontname().c_str());
    }
    if (opt.has_fontsize()) {
        button->setTitleFontSize(static_cast<float>(opt.fontsize()));
    }
    if (opt.has_textcolorr() || opt.has_textcolorg() || opt.has_textcolorb()) {
        button->setTitleColor(cocos2d::ccc3(
            static_cast<GLubyte>(opt.has_textcolorr() ? opt.textcolorr() : 255),
            static_cast<GLubyte>(opt.has_textcolorg() ? opt.textcolorg() : 255),
            static_cast<GLubyte>(opt.has_textcolorb() ? opt.textcolorb() : 255)));
    }
}

void ApplyCheckBoxOptions(cocos2d::ui::CheckBox* cb,
                          const CSOptions& opt,
                          const std::string& baseDir) {
    if (!cb) {
        return;
    }

    if (opt.has_backgroundboxdata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.backgroundboxdata(), baseDir, &rt);
        if (!p.empty()) cb->loadTextureBackGround(p.c_str(), rt);
    }
    if (opt.has_backgroundboxselecteddata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  =
            ResolveCsDataPath(opt.backgroundboxselecteddata(), baseDir, &rt);
        if (!p.empty()) cb->loadTextureBackGroundSelected(p.c_str(), rt);
    }
    if (opt.has_frontcrossdata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.frontcrossdata(), baseDir, &rt);
        if (!p.empty()) cb->loadTextureFrontCross(p.c_str(), rt);
    }
    if (opt.has_backgroundboxdisableddata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  =
            ResolveCsDataPath(opt.backgroundboxdisableddata(), baseDir, &rt);
        if (!p.empty()) cb->loadTextureBackGroundDisabled(p.c_str(), rt);
    }
    if (opt.has_frontcrossdisableddata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  =
            ResolveCsDataPath(opt.frontcrossdisableddata(), baseDir, &rt);
        if (!p.empty()) cb->loadTextureFrontCrossDisabled(p.c_str(), rt);
    }
}

void ApplyImageViewOptions(cocos2d::ui::ImageView* img,
                           const CSOptions& opt,
                           const std::string& baseDir) {
    if (!img) {
        return;
    }

    if (opt.has_filenamedata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.filenamedata(), baseDir, &rt);
        if (!p.empty()) {
            img->loadTexture(p.c_str(), rt);
        }
    }

    if (opt.has_scale9enable()) {
        img->setScale9Enabled(opt.scale9enable());
        if (opt.scale9enable()) {
            img->setCapInsets(cocos2d::CCRect(
                opt.has_capinsetsx() ? opt.capinsetsx() : 0.0f,
                opt.has_capinsetsy() ? opt.capinsetsy() : 0.0f,
                opt.has_capinsetswidth() ? opt.capinsetswidth() : 0.0f,
                opt.has_capinsetsheight() ? opt.capinsetsheight() : 0.0f));
            if (opt.has_scale9width() && opt.has_scale9height()) {
                img->setSize(cocos2d::CCSize(opt.scale9width(), opt.scale9height()));
            }
        }
    }
}

void ApplyLabelOptions(cocos2d::ui::Label* label, const CSOptions& opt) {
    if (!label) {
        return;
    }

    if (opt.has_touchscaleenable()) {
        label->setTouchScaleChangeEnabled(opt.touchscaleenable());
    }

    const int fontSize = (opt.has_fontsize() && opt.fontsize() > 0) ? opt.fontsize() : 20;
    if (opt.has_fontsize()) {
        label->setFontSize(opt.fontsize());
    }
    if (opt.has_fontname()) {
        label->setFontName(opt.fontname());
    }
    if (opt.has_halignment()) {
        label->setTextHorizontalAlignment(
            static_cast<cocos2d::CCTextAlignment>(opt.halignment()));
    }
    if (opt.has_valignment()) {
        label->setTextVerticalAlignment(
            static_cast<cocos2d::CCVerticalTextAlignment>(opt.valignment()));
    }
    if (opt.has_text()) {
        label->setText(opt.text());
    }

    const bool  optIgnoreSize = opt.has_ignoresize() ? opt.ignoresize() : true;
    float       areaW         = opt.has_areawidth() ? opt.areawidth() : 0.0f;
    float       areaH         = opt.has_areaheight() ? opt.areaheight() : 0.0f;
    const float optW          = opt.has_width() ? opt.width() : 0.0f;
    const float optH          = opt.has_height() ? opt.height() : 0.0f;

    if (!optIgnoreSize && areaW <= 0.0f && optW > 0.0f) {
        areaW = optW;
    }
    if (!optIgnoreSize && areaH <= 0.0f && optH > 0.0f) {
        areaH = optH;
    }

    const float refHeight           = (areaH > 0.0f) ? areaH : optH;
    const float singleLineThreshold = static_cast<float>(fontSize) * 1.6f;

    if (areaW > 0.0f && areaH > 0.0f && refHeight > singleLineThreshold) {
        label->ignoreContentAdaptWithSize(false);
        label->setTextAreaSize(cocos2d::CCSize(areaW, 0.0f));

        if (auto* ttf = dynamic_cast<cocos2d::CCLabelTTF*>(label->getVirtualRenderer())) {
            ttf->setDimensions(cocos2d::CCSize(areaW, 0.0f));
            const cocos2d::CCSize naturalSize = ttf->getContentSize();
            const float           targetH     = std::max(areaH, naturalSize.height);
            label->setSize(cocos2d::CCSize(areaW, targetH));
            label->setTextAreaSize(cocos2d::CCSize(areaW, 0.0f));
            ttf->setDimensions(cocos2d::CCSize(areaW, 0.0f));
            ttf->setScaleX(1.0f);
            ttf->setScaleY(1.0f);
        }
    } else {
        label->ignoreContentAdaptWithSize(true);
        label->setTextAreaSize(cocos2d::CCSizeZero);
        if (auto* ttf = dynamic_cast<cocos2d::CCLabelTTF*>(label->getVirtualRenderer())) {
            ttf->setDimensions(cocos2d::CCSizeZero);
            ttf->setScaleX(1.0f);
            ttf->setScaleY(1.0f);
        }
    }
}

void ApplyLabelAtlasOptions(cocos2d::ui::LabelAtlas* atlas,
                            const CSOptions& opt,
                            const std::string& baseDir) {
    if (!atlas) {
        return;
    }

    const int itemW = opt.has_itemwidth() ? opt.itemwidth() : 0;
    const int itemH = opt.has_itemheight() ? opt.itemheight() : 0;
    if (itemW <= 0 || itemH <= 0) {
        // Prevents integer divide-by-zero (0xC0000094) in CCAtlasNode::calculateMaxItems().
        if (opt.has_charmapfiledata() || opt.has_charmapfile()) {
            LogGuiWarn("Skipping LabelAtlas::setProperty because itemWidth/itemHeight <= 0");
        }
        return;
    }

    std::string rawCharMap;
    if (opt.has_charmapfiledata() && opt.charmapfiledata().has_path()) {
        rawCharMap = opt.charmapfiledata().path();
    } else if (opt.has_charmapfile()) {
        rawCharMap = opt.charmapfile();
    }
    if (rawCharMap.empty()) {
        return;
    }

    std::string           resolvedTexPath;
    cocos2d::CCTexture2D* tex =
        ProbeAndLoadTextureAcrossRoots(rawCharMap, baseDir, &resolvedTexPath);
    if (!tex) {
        char msg[320];
        std::snprintf(msg,
                      sizeof(msg),
                      "Skipping LabelAtlas::setProperty: missing charMap texture '%s' (base '%s')",
                      rawCharMap.c_str(),
                      baseDir.c_str());
        LogGuiWarn(msg);
        return;
    }

    if (resolvedTexPath.empty()) {
        resolvedTexPath = ResolveLocalAssetPath(rawCharMap, baseDir);
    }

    // Alias under fullPathForFilename(resolvedTexPath) in CCTextureCache::m_pTextures so
    // CCTextureAtlas::initWithFile never misses if extension fallback (.pkm/.pvr.ccz) occurred.
    auto* fu       = cocos2d::CCFileUtils::sharedFileUtils();
    auto* texCache = cocos2d::CCTextureCache::sharedTextureCache();
    if (fu && texCache) {
        if (cocos2d::CCDictionary* texDict = TextureCacheAccessor::GetTexturesDict(texCache)) {
            const std::string expectedKey = fu->fullPathForFilename(resolvedTexPath.c_str());
            if (!expectedKey.empty() && texDict->objectForKey(expectedKey) == nullptr) {
                texDict->setObject(tex, expectedKey);
            }
        }
    }

    const std::string startChar =
        (opt.has_startcharmap() && !opt.startcharmap().empty()) ? opt.startcharmap() : "0";
    atlas->setProperty(opt.has_stringvalue() ? opt.stringvalue() : "",
                       resolvedTexPath,
                       itemW,
                       itemH,
                       startChar);
}

void ApplyLabelBMFontOptions(cocos2d::ui::LabelBMFont* bmfont,
                             const CSOptions& opt,
                             const std::string& baseDir) {
    if (!bmfont) {
        return;
    }

    bool fntReady = false;
    if (opt.has_filenamedata() && opt.filenamedata().has_path() &&
        !opt.filenamedata().path().empty()) {
        const std::string              rawFnt     = opt.filenamedata().path();
        const std::vector<std::string> candidates = BuildRelativeCandidatePaths(rawFnt, baseDir);

        std::string    chosenFnt;
        unsigned long  fntSize = 0;
        unsigned char* fntData = nullptr;
        for (const std::string& cand : candidates) {
            if (!DoesExactAssetFileExist(cand)) {
                continue;
            }
            fntData = LoadAndDecryptFileData(cand, &fntSize, nullptr);
            if (fntData && fntSize > 0) {
                chosenFnt = cand;
                break;
            }
            delete[] fntData;
            fntData = nullptr;
            fntSize = 0;
        }

        if (!fntData || fntSize == 0) {
            delete[] fntData;
            char msg[320];
            std::snprintf(msg,
                          sizeof(msg),
                          "Skipping LabelBMFont::setFntFile: missing or empty .fnt '%s' (base '%s')",
                          rawFnt.c_str(),
                          baseDir.c_str());
            LogGuiWarn(msg);
            return;
        }

        const std::vector<std::string> pageFiles =
            ExtractFntPageFiles(fntData, static_cast<size_t>(fntSize));
        delete[] fntData;

        if (pageFiles.empty()) {
            char msg[320];
            std::snprintf(msg,
                          sizeof(msg),
                          "Skipping LabelBMFont::setFntFile: no bitmap page entries in '%s'",
                          chosenFnt.c_str());
            LogGuiWarn(msg);
            return;
        }

        const std::string fntDir   = ExtractDirectoryPrefix(chosenFnt);
        auto*             fu       = cocos2d::CCFileUtils::sharedFileUtils();
        auto*             texCache = cocos2d::CCTextureCache::sharedTextureCache();
        bool              allPagesLoaded = true;

        for (const std::string& pageFile : pageFiles) {
            cocos2d::CCTexture2D* pageTex = ProbeAndLoadTextureAcrossRoots(pageFile, fntDir);
            if (!pageTex) {
                char msg[320];
                std::snprintf(msg,
                              sizeof(msg),
                              "Skipping LabelBMFont::setFntFile: missing page texture '%s' for '%s'",
                              pageFile.c_str(),
                              chosenFnt.c_str());
                LogGuiWarn(msg);
                allPagesLoaded = false;
                break;
            }

            // Pre-alias the loaded texture under fu->fullPathFromRelativeFile(pageFile, chosenFnt)
            // so when .fnt is in Resources/ and page texture is in assets/, CCLabelBMFont's
            // internal CCTextureCache::addImage lookup hits immediately instead of NULL->retain()!
            if (fu && texCache) {
                if (cocos2d::CCDictionary* texDict =
                        TextureCacheAccessor::GetTexturesDict(texCache)) {
                    const std::string expectedAtlasKey =
                        fu->fullPathFromRelativeFile(pageFile.c_str(), chosenFnt.c_str());
                    if (!expectedAtlasKey.empty() &&
                        texDict->objectForKey(expectedAtlasKey) == nullptr) {
                        texDict->setObject(pageTex, expectedAtlasKey);
                    }
                }
            }
        }

        if (!allPagesLoaded) {
            return;
        }

        bmfont->setFntFile(chosenFnt.c_str());
        fntReady = true;
    }

    if (fntReady && opt.has_text()) {
        bmfont->setText(opt.text().c_str());
    }
}

void ApplyLoadingBarOptions(cocos2d::ui::LoadingBar* bar,
                            const CSOptions& opt,
                            const std::string& baseDir) {
    if (!bar) {
        return;
    }

    const cocos2d::CCSize preLoadSize  = bar->getSize();
    const bool            scale9Enable = opt.has_scale9enable() && opt.scale9enable();

    float targetW = preLoadSize.width;
    float targetH = preLoadSize.height;
    if (scale9Enable) {
        if (opt.has_scale9width() && opt.scale9width() > 0.0f) {
            targetW = opt.scale9width();
        } else if (opt.has_width() && opt.width() > 0.0f) {
            targetW = opt.width();
        } else if (opt.has_length() && opt.length() > 0.0f) {
            targetW = opt.length();
        }

        if (opt.has_scale9height() && opt.scale9height() > 0.0f) {
            targetH = opt.scale9height();
        } else if (opt.has_height() && opt.height() > 0.0f) {
            targetH = opt.height();
        }
    } else {
        if (opt.has_width() && opt.width() > 0.0f) {
            targetW = opt.width();
        } else if (opt.has_length() && opt.length() > 0.0f) {
            targetW = opt.length();
        }
        if (opt.has_height() && opt.height() > 0.0f) {
            targetH = opt.height();
        }
    }

    if (opt.has_scale9enable()) {
        bar->setScale9Enabled(scale9Enable);
    }

    if (opt.has_texturedata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.texturedata(), baseDir, &rt);
        if (!p.empty() && CanLoadWidgetTexture(p, rt)) {
            bar->loadTexture(p.c_str(), rt);
        }
    }

    if (scale9Enable) {
        bar->setScale9Enabled(true);
        bar->setCapInsets(cocos2d::CCRect(
            opt.has_capinsetsx() ? opt.capinsetsx() : 0.0f,
            opt.has_capinsetsy() ? opt.capinsetsy() : 0.0f,
            opt.has_capinsetswidth() ? opt.capinsetswidth() : 0.0f,
            opt.has_capinsetsheight() ? opt.capinsetsheight() : 0.0f));
        if (targetW <= 0.0f && bar->getSize().width > 0.0f) {
            targetW = bar->getSize().width;
        }
        if (targetH <= 0.0f && bar->getSize().height > 0.0f) {
            targetH = bar->getSize().height;
        }
        bar->setSize(cocos2d::CCSize(targetW, targetH));
    } else {
        const bool ignoreSize = opt.has_ignoresize() ? opt.ignoresize() : true;
        if (!ignoreSize && (targetW > 0.0f || targetH > 0.0f)) {
            const float resolvedW = (targetW > 0.0f) ? targetW : bar->getSize().width;
            const float resolvedH = (targetH > 0.0f) ? targetH : bar->getSize().height;
            bar->ignoreContentAdaptWithSize(false);
            bar->setSize(cocos2d::CCSize(resolvedW, resolvedH));
        }
    }

    if (opt.has_direction()) {
        bar->setDirection(static_cast<cocos2d::ui::LoadingBarType>(
            static_cast<int>(opt.direction())));
    }
    if (opt.has_percent()) {
        bar->setPercent(opt.percent());
    }
}

void ApplySliderOptions(cocos2d::ui::Slider* slider,
                        const CSOptions& opt,
                        const std::string& baseDir) {
    if (!slider) {
        return;
    }

    if (opt.has_bartexturescale9enable()) {
        slider->setScale9Enabled(opt.bartexturescale9enable());
    }

    if (opt.has_barfilenamedata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.barfilenamedata(), baseDir, &rt);
        if (!p.empty()) slider->loadBarTexture(p.c_str(), rt);
    } else if (opt.has_barfilename() && !opt.barfilename().empty()) {
        slider->loadBarTexture(ResolveLocalAssetPath(opt.barfilename(), baseDir).c_str());
    }

    if (opt.has_ballnormaldata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.ballnormaldata(), baseDir, &rt);
        if (!p.empty()) slider->loadSlidBallTextureNormal(p.c_str(), rt);
    }
    if (opt.has_ballpresseddata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.ballpresseddata(), baseDir, &rt);
        if (!p.empty()) slider->loadSlidBallTexturePressed(p.c_str(), rt);
    }
    if (opt.has_balldisableddata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.balldisableddata(), baseDir, &rt);
        if (!p.empty()) slider->loadSlidBallTextureDisabled(p.c_str(), rt);
    }
    if (opt.has_progressbardata()) {
        cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
        const std::string           p  = ResolveCsDataPath(opt.progressbardata(), baseDir, &rt);
        if (!p.empty()) slider->loadProgressBarTexture(p.c_str(), rt);
    }

    if (opt.has_bartexturescale9enable() && opt.bartexturescale9enable() && opt.has_length()) {
        slider->setSize(cocos2d::CCSize(opt.length(), slider->getSize().height));
    }
    if (opt.has_percent()) {
        slider->setPercent(opt.percent());
    }
}

void ApplyTextFieldOptions(cocos2d::ui::TextField* tf, const CSOptions& opt) {
    if (!tf) {
        return;
    }

    if (opt.has_touchsizewidth() && opt.has_touchsizeheight()) {
        tf->setTouchSize(cocos2d::CCSize(opt.touchsizewidth(), opt.touchsizeheight()));
    }
    if (opt.has_placeholder()) {
        tf->setPlaceHolder(opt.placeholder());
    }
    if (opt.has_text()) {
        tf->setText(opt.text());
    }
    if (opt.has_fontsize()) {
        tf->setFontSize(opt.fontsize());
    }
    if (opt.has_fontname()) {
        tf->setFontName(opt.fontname());
    }
    if (opt.has_maxlengthenable()) {
        tf->setMaxLengthEnabled(opt.maxlengthenable());
        if (opt.maxlengthenable() && opt.has_maxlength()) {
            tf->setMaxLength(opt.maxlength());
        }
    }
    if (opt.has_passwordenable()) {
        tf->setPasswordEnabled(opt.passwordenable());
        if (opt.passwordenable() && opt.has_passwordstyletext()) {
            tf->setPasswordStyleText(opt.passwordstyletext().c_str());
        }
    }
}

void ApplyScrollViewOptions(cocos2d::ui::ScrollView* sv,
                            const CSOptions& opt,
                            const std::string& baseDir) {
    if (!sv) {
        return;
    }

    ApplyLayoutOptions(sv, opt, baseDir);

    if (opt.has_innerwidth() && opt.has_innerheight()) {
        sv->setInnerContainerSize(cocos2d::CCSize(opt.innerwidth(), opt.innerheight()));
    }
    if (opt.has_direction()) {
        sv->setDirection(static_cast<cocos2d::ui::SCROLLVIEW_DIR>(
            static_cast<int>(opt.direction())));
    }
    if (opt.has_bounceenable()) {
        sv->setBounceEnabled(opt.bounceenable());
    }
}

void ApplyListViewOptions(cocos2d::ui::ListView* lv,
                          const CSOptions& opt,
                          const std::string& baseDir) {
    if (!lv) {
        return;
    }

    ApplyScrollViewOptions(lv, opt, baseDir);

    if (opt.has_gravity()) {
        lv->setGravity(static_cast<cocos2d::ui::ListViewGravity>(
            static_cast<int>(opt.gravity())));
    }
    if (opt.has_itemmargin()) {
        lv->setItemsMargin(opt.itemmargin());
    }
}

struct ActionManagerAccessor : public cocos2d::extension::ActionManager {
    static cocos2d::CCDictionary* GetActionDic(cocos2d::extension::ActionManager* mgr) {
        if (!mgr) {
            return nullptr;
        }
        cocos2d::CCDictionary* cocos2d::extension::ActionManager::*memberPtr =
            &ActionManagerAccessor::m_pActionDic;
        return mgr->*memberPtr;
    }
};

// ============================================================================
// WidgetActionGroup & WidgetActionGuardComponent
//
// Stock Cocos2d-x 2.2.6 ActionNode stores its target `CCObject* m_pObject` as a
// RAW unretained pointer while ActionManager::m_pActionDic retains ActionObject
// globally. When panels (e.g. CopyEndGetFragmentPanel) close and destroy their
// Widgets without stopping/releasing every alias key in ActionManager, ticking
// ActionNodes dereference freed Widget memory (UAF).
//
// Attaching a CCComponent guard to both `rootWidget` and each `targetWidget`:
//   - Stops playing ActionObjects on `onExit()` so off-stage panels never tick.
//   - On `~Widget()` (`~CCNode()` -> `~CCComponentContainer()`), immediately
//     stops ActionObjects, nulls `ActionNode::setObject(nullptr)` before Widget
//     memory is freed, and evicts stale `actionArray` entries from `m_pActionDic`.
// ============================================================================
struct TrackedActionNodeEntry {
    cocos2d::extension::ActionObject* actionObj    = nullptr;
    cocos2d::extension::ActionNode*   actionNode   = nullptr;
    cocos2d::ui::Widget*              targetWidget = nullptr;
};

struct WidgetActionGroup {
    cocos2d::CCArray*                   actionArray = nullptr;
    std::vector<std::string>            registeredKeys;
    std::vector<TrackedActionNodeEntry> entries;

    ~WidgetActionGroup() {
        for (auto& e : entries) {
            if (e.actionObj) {
                if (e.actionObj->isPlaying()) {
                    e.actionObj->stop();
                }
                e.actionObj->release();
                e.actionObj = nullptr;
            }
            if (e.actionNode) {
                e.actionNode->setObject(nullptr);
                e.actionNode->release();
                e.actionNode = nullptr;
            }
        }
        if (actionArray) {
            actionArray->release();
            actionArray = nullptr;
        }
    }

    void stopPlayingForWidget(cocos2d::ui::Widget* widget, bool allIfRoot) {
        for (auto& e : entries) {
            if ((allIfRoot || e.targetWidget == widget) && e.actionObj && e.actionObj->isPlaying()) {
                e.actionObj->stop();
            }
        }
    }

    void detachDestroyedWidget(cocos2d::ui::Widget* widget) {
        if (!widget) {
            return;
        }
        for (auto& e : entries) {
            if (e.targetWidget == widget) {
                if (e.actionObj && e.actionObj->isPlaying()) {
                    e.actionObj->stop();
                }
                if (e.actionNode && e.actionNode->getObject() == widget) {
                    e.actionNode->setObject(nullptr);
                }
                e.targetWidget = nullptr;
            }
        }
    }

    void detachAllAndEvictFromActionManager() {
        for (auto& e : entries) {
            if (e.actionObj && e.actionObj->isPlaying()) {
                e.actionObj->stop();
            }
            if (e.actionNode) {
                e.actionNode->setObject(nullptr);
            }
            e.targetWidget = nullptr;
        }
        if (!actionArray || registeredKeys.empty()) {
            return;
        }
        auto* mgr       = cocos2d::extension::ActionManager::shareManager();
        auto* actionDic = ActionManagerAccessor::GetActionDic(mgr);
        if (!actionDic) {
            return;
        }
        for (const std::string& key : registeredKeys) {
            if (actionDic->objectForKey(key) == actionArray) {
                actionDic->removeObjectForKey(key);
            }
        }
        registeredKeys.clear();
    }
};

std::mutex                                                                g_actionGroupsMutex;
std::unordered_map<cocos2d::CCArray*, std::weak_ptr<WidgetActionGroup>>   g_activeActionGroups;

void DetachOverwrittenActionArray(cocos2d::CCArray* prevArray) {
    if (!prevArray) {
        return;
    }
    std::shared_ptr<WidgetActionGroup> group;
    {
        std::lock_guard<std::mutex> lock(g_actionGroupsMutex);
        auto it = g_activeActionGroups.find(prevArray);
        if (it != g_activeActionGroups.end()) {
            group = it->second.lock();
        }
    }
    if (group) {
        for (auto& e : group->entries) {
            if (e.actionObj && e.actionObj->isPlaying()) {
                e.actionObj->stop();
            }
            if (e.actionNode) {
                e.actionNode->setObject(nullptr);
            }
            e.targetWidget = nullptr;
        }
    } else {
        for (unsigned int i = 0; i < prevArray->count(); ++i) {
            auto* prevObj = dynamic_cast<cocos2d::extension::ActionObject*>(
                prevArray->objectAtIndex(i));
            if (prevObj && prevObj->isPlaying()) {
                prevObj->stop();
            }
        }
    }
}

class WidgetActionGuardComponent final : public cocos2d::CCComponent {
public:
    WidgetActionGuardComponent(cocos2d::ui::Widget* ownerWidget,
                               bool isRootGuard,
                               const char* compName)
        : m_ownerWidget(ownerWidget),
          m_isRootGuard(isRootGuard) {
        init();
        setName(compName);
    }

    ~WidgetActionGuardComponent() override {
        for (const auto& group : m_groups) {
            if (!group) {
                continue;
            }
            if (m_isRootGuard) {
                group->detachAllAndEvictFromActionManager();
                if (group->actionArray) {
                    std::lock_guard<std::mutex> lock(g_actionGroupsMutex);
                    g_activeActionGroups.erase(group->actionArray);
                }
            } else {
                group->detachDestroyedWidget(m_ownerWidget);
            }
        }
    }

    void onExit() override {
        cocos2d::CCComponent::onExit();
        for (const auto& group : m_groups) {
            if (group) {
                group->stopPlayingForWidget(m_ownerWidget, m_isRootGuard);
            }
        }
    }

    void addGroup(const std::shared_ptr<WidgetActionGroup>& group) {
        if (!group) {
            return;
        }
        for (const auto& existing : m_groups) {
            if (existing == group) {
                return;
            }
        }
        m_groups.push_back(group);
    }

private:
    cocos2d::ui::Widget*                            m_ownerWidget = nullptr;
    bool                                            m_isRootGuard = false;
    std::vector<std::shared_ptr<WidgetActionGroup>> m_groups;
};

void AttachActionGuardToWidget(cocos2d::ui::Widget* widget,
                               bool isRootGuard,
                               const std::shared_ptr<WidgetActionGroup>& group) {
    if (!widget || !group) {
        return;
    }
    const char* compName =
        isRootGuard ? "__gclient_action_root_guard__" : "__gclient_action_target_guard__";
    if (auto* existing =
            dynamic_cast<WidgetActionGuardComponent*>(widget->getComponent(compName))) {
        existing->addGroup(group);
        return;
    }
    auto* guard = new WidgetActionGuardComponent(widget, isRootGuard, compName);
    guard->addGroup(group);
    if (widget->addComponent(guard)) {
        guard->release();
    } else {
        delete guard;
    }
}

cocos2d::ui::Widget* SeekActionWidgetByActionTag(cocos2d::ui::Widget* root, int actionTag) {
    if (!root) {
        return nullptr;
    }
    if (root->getActionTag() == actionTag) {
        return root;
    }
    cocos2d::CCArray* children = root->getChildren();
    if (!children) {
        return nullptr;
    }
    const unsigned int count = children->count();
    for (unsigned int i = 0; i < count; ++i) {
        auto* childWidget = dynamic_cast<cocos2d::ui::Widget*>(children->objectAtIndex(i));
        if (!childWidget) {
            continue;
        }
        if (cocos2d::ui::Widget* found = SeekActionWidgetByActionTag(childWidget, actionTag)) {
            return found;
        }
    }
    return nullptr;
}

void AddUniqueAnimationKey(std::vector<std::string>& keys, const std::string& candidate) {
    if (candidate.empty()) {
        return;
    }
    for (const std::string& existing : keys) {
        if (existing == candidate) {
            return;
        }
    }
    keys.push_back(candidate);
}

std::vector<std::string> BuildActionDictionaryKeys(const std::string& sourceFileName) {
    std::vector<std::string> keys;
    const std::string normPath = NormalizeAssetPath(sourceFileName);
    if (normPath.empty()) {
        return keys;
    }

    const size_t      slashPos = normPath.find_last_of('/');
    const std::string baseName =
        (slashPos == std::string::npos) ? normPath : normPath.substr(slashPos + 1);

    if (!baseName.empty()) {
        AddUniqueAnimationKey(keys, baseName);
        AddUniqueAnimationKey(keys, ReplaceFileExtension(baseName, ".json"));
        AddUniqueAnimationKey(keys, ReplaceFileExtension(baseName, ".pb"));
    }

    AddUniqueAnimationKey(keys, normPath);
    AddUniqueAnimationKey(keys, ReplaceFileExtension(normPath, ".json"));
    AddUniqueAnimationKey(keys, ReplaceFileExtension(normPath, ".pb"));
    return keys;
}

void RegisterGuiAnimations(const CSAnimation& anim,
                           const std::string& sourceFileName,
                           cocos2d::ui::Widget* rootWidget) {
    if (!rootWidget || anim.actionlist_size() == 0) {
        return;
    }

    auto* actionMgr = cocos2d::extension::ActionManager::shareManager();
    if (!actionMgr) {
        return;
    }

    cocos2d::CCDictionary* actionDic = ActionManagerAccessor::GetActionDic(actionMgr);
    if (!actionDic) {
        return;
    }

    auto* actionArray = cocos2d::CCArray::create();
    if (!actionArray) {
        return;
    }

    auto group         = std::make_shared<WidgetActionGroup>();
    group->actionArray = actionArray;
    actionArray->retain();

    std::vector<cocos2d::ui::Widget*> boundTargets;

    for (int i = 0; i < anim.actionlist_size(); ++i) {
        const CSAction& pbAction   = anim.actionlist(i);
        const float     unitTime   = (pbAction.has_unittime() && pbAction.unittime() > 0.0f)
                                         ? pbAction.unittime()
                                         : (1.0f / 60.0f);
        auto*           actionObj  = new cocos2d::extension::ActionObject();
        actionObj->setName(pbAction.name().c_str());
        actionObj->setLoop(pbAction.loop());
        actionObj->setUnitTime(unitTime);

        for (int n = 0; n < pbAction.actionnodelist_size(); ++n) {
            const CSActionNode& pbNode     = pbAction.actionnodelist(n);
            auto*               actionNode = new cocos2d::extension::ActionNode();
            actionNode->setActionTag(pbNode.actiontag());
            actionNode->setUnitTime(unitTime);

            cocos2d::ui::Widget* targetWidget =
                SeekActionWidgetByActionTag(rootWidget, pbNode.actiontag());
            if (targetWidget) {
                actionNode->setObject(targetWidget);
                boundTargets.push_back(targetWidget);
            }

            TrackedActionNodeEntry tracked;
            tracked.actionObj    = actionObj;
            tracked.actionNode   = actionNode;
            tracked.targetWidget = targetWidget;
            actionObj->retain();
            actionNode->retain();
            group->entries.push_back(tracked);

            int moveSlot  = 0;
            int scaleSlot = 0;
            int rotSlot   = 0;
            int fadeSlot  = 0;
            int tintSlot  = 0;

            for (int f = 0; f < pbNode.actionframelist_size(); ++f) {
                const CSActionFrame& pbFrame = pbNode.actionframelist(f);
                const int            frameId = pbFrame.frameid();

                if (pbFrame.has_positionx() || pbFrame.has_positiony()) {
                    auto* moveFrame = new cocos2d::extension::ActionMoveFrame();
                    moveFrame->setFrameIndex(frameId);
                    moveFrame->setPosition(cocos2d::CCPoint(
                        pbFrame.has_positionx() ? pbFrame.positionx() : 0.0f,
                        pbFrame.has_positiony() ? pbFrame.positiony() : 0.0f));
                    actionNode->insertFrame(moveSlot++, moveFrame);
                    moveFrame->release();
                }

                if (pbFrame.has_scalex() || pbFrame.has_scaley()) {
                    auto* scaleFrame = new cocos2d::extension::ActionScaleFrame();
                    scaleFrame->setFrameIndex(frameId);
                    scaleFrame->setScaleX(pbFrame.has_scalex() ? pbFrame.scalex() : 1.0f);
                    scaleFrame->setScaleY(pbFrame.has_scaley() ? pbFrame.scaley() : 1.0f);
                    actionNode->insertFrame(scaleSlot++, scaleFrame);
                    scaleFrame->release();
                }

                if (pbFrame.has_rotation()) {
                    auto* rotFrame = new cocos2d::extension::ActionRotationFrame();
                    rotFrame->setFrameIndex(frameId);
                    rotFrame->setRotation(pbFrame.rotation());
                    actionNode->insertFrame(rotSlot++, rotFrame);
                    rotFrame->release();
                }

                if (pbFrame.has_opacity()) {
                    auto* fadeFrame = new cocos2d::extension::ActionFadeFrame();
                    fadeFrame->setFrameIndex(frameId);
                    fadeFrame->setOpacity(pbFrame.opacity());
                    actionNode->insertFrame(fadeSlot++, fadeFrame);
                    fadeFrame->release();
                }

                if (pbFrame.has_colorr() || pbFrame.has_colorg() || pbFrame.has_colorb()) {
                    auto* tintFrame = new cocos2d::extension::ActionTintFrame();
                    tintFrame->setFrameIndex(frameId);
                    tintFrame->setColor(cocos2d::ccc3(
                        static_cast<GLubyte>(pbFrame.has_colorr() ? pbFrame.colorr() : 255),
                        static_cast<GLubyte>(pbFrame.has_colorg() ? pbFrame.colorg() : 255),
                        static_cast<GLubyte>(pbFrame.has_colorb() ? pbFrame.colorb() : 255)));
                    actionNode->insertFrame(tintSlot++, tintFrame);
                    tintFrame->release();
                }
            }

            actionObj->addActionNode(actionNode);
            actionNode->release();
        }

        actionArray->addObject(actionObj);
        actionObj->release();
    }

    const std::vector<std::string> keys = BuildActionDictionaryKeys(sourceFileName);
    group->registeredKeys               = keys;

    {
        std::lock_guard<std::mutex> lock(g_actionGroupsMutex);
        g_activeActionGroups[actionArray] = group;
    }

    AttachActionGuardToWidget(rootWidget, /*isRootGuard=*/true, group);
    for (cocos2d::ui::Widget* targetWidget : boundTargets) {
        AttachActionGuardToWidget(targetWidget, /*isRootGuard=*/false, group);
    }

    for (const std::string& key : keys) {
        if (auto* prevArray = dynamic_cast<cocos2d::CCArray*>(actionDic->objectForKey(key))) {
            if (prevArray != actionArray) {
                DetachOverwrittenActionArray(prevArray);
            }
        }
        actionDic->setObject(actionArray, key);
    }
}

bool ValidateSceneParticlePlist(const std::string& rawPlistPath,
                                const std::string& baseDir,
                                std::string* outResolvedPlist) {
    const std::vector<std::string> candidates = BuildRelativeCandidatePaths(rawPlistPath, baseDir);
    for (const std::string& cand : candidates) {
        std::string xmlContent;
        if (!VerifyValidXmlPlistOnDisk(cand, &xmlContent)) {
            continue;
        }
        // Particle plists either embed base64 `textureImageData` or reference `textureFileName`.
        const std::string embeddedData = ExtractXmlKeyStringValue(xmlContent, "textureImageData");
        const std::string texFile      = ExtractXmlKeyStringValue(xmlContent, "textureFileName");
        if (embeddedData.empty() && !texFile.empty()) {
            const std::string plistDir = ExtractDirectoryPrefix(cand);
            if (!ProbeAndLoadTextureAcrossRoots(texFile, plistDir) &&
                !DoesAssetOrTextureVariantExist(JoinBaseAndRelativePath(plistDir, texFile)) &&
                !DoesAssetOrTextureVariantExist(NormalizeAssetPath(texFile))) {
                char msg[320];
                std::snprintf(msg,
                              sizeof(msg),
                              "Skipping CCParticleSystemQuad '%s': missing particle texture '%s'",
                              cand.c_str(),
                              texFile.c_str());
                LogGuiWarn(msg);
                return false;
            }
        }
        if (outResolvedPlist) {
            *outResolvedPlist = cand;
        }
        return true;
    }
    return false;
}

void AttachSceneComponent(cocos2d::CCNode* node,
                          const CSComponent& comp,
                          const std::string& baseDir) {
    if (!node) {
        return;
    }

    const std::string& cls      = comp.classname();
    const std::string& compName = comp.name();

    std::string rawPath;
    std::string rawPlist;
    int32_t     resType = 0;
    if (comp.has_filedata()) {
        resType = comp.filedata().resourcetype();
        if (comp.filedata().has_path() && !comp.filedata().path().empty()) {
            rawPath = comp.filedata().path();
        }
        if (comp.filedata().has_plist() && !comp.filedata().plist().empty()) {
            rawPlist = comp.filedata().plist();
        }
    }

    const std::string resPath =
        (resType == 1) ? NormalizeAssetPath(rawPath) : ResolveLocalAssetPath(rawPath, baseDir);
    const std::string plistPath = ResolveLocalAssetPath(rawPlist, baseDir);

    if (cls == "CCSprite") {
        cocos2d::CCSprite* sprite = nullptr;
        if (resType == 1) {
            if (!rawPlist.empty()) {
                PbGuiLoader::LoadPlistSpriteFramesSafe(rawPlist, baseDir);
            }
            if (!resPath.empty()) {
                auto* sfc = cocos2d::CCSpriteFrameCache::sharedSpriteFrameCache();
                if (sfc && sfc->spriteFrameByName(resPath.c_str()) != nullptr) {
                    sprite = cocos2d::CCSprite::createWithSpriteFrameName(resPath.c_str());
                }
            }
        } else if (!resPath.empty() && CanLoadWidgetTexture(resPath, cocos2d::ui::UI_TEX_TYPE_LOCAL)) {
            sprite = cocos2d::CCSprite::create(resPath.c_str());
        }

        if (sprite) {
            auto* renderComp = cocos2d::extension::CCComRender::create(sprite, compName.c_str());
            node->addComponent(renderComp);
        }
    } else if (cls == "CCTMXTiledMap") {
        if (!resPath.empty() && DoesExactAssetFileExist(resPath)) {
            if (auto* tmx = cocos2d::CCTMXTiledMap::create(resPath.c_str())) {
                auto* renderComp = cocos2d::extension::CCComRender::create(tmx, compName.c_str());
                node->addComponent(renderComp);
            }
        }
    } else if (cls == "CCParticleSystemQuad") {
        if (!rawPath.empty()) {
            std::string verifiedPlist;
            if (ValidateSceneParticlePlist(rawPath, baseDir, &verifiedPlist)) {
                if (auto* ps = cocos2d::CCParticleSystemQuad::create(verifiedPlist.c_str())) {
                    ps->setPosition(cocos2d::CCPointZero);
                    auto* renderComp =
                        cocos2d::extension::CCComRender::create(ps, compName.c_str());
                    node->addComponent(renderComp);
                }
            } else {
                char msg[320];
                std::snprintf(msg,
                              sizeof(msg),
                              "Skipping CCParticleSystemQuad::create: missing or invalid plist '%s' (base '%s')",
                              rawPath.c_str(),
                              baseDir.c_str());
                LogGuiWarn(msg);
            }
        }
    } else if (cls == "CCArmature") {
        if (!resPath.empty()) {
            if (!plistPath.empty()) {
                XmlbArmatureLoader::AddDataFromXmlbFile(std::string(), plistPath, resPath);
            } else {
                XmlbArmatureLoader::AddDataFromXmlbFile(resPath, baseDir);
            }
            const size_t slashPos = resPath.find_last_of('/');
            const size_t dotPos   = resPath.find_last_of('.');
            const size_t start    = (slashPos == std::string::npos) ? 0 : slashPos + 1;
            const size_t len =
                (dotPos == std::string::npos || dotPos < start) ? std::string::npos : (dotPos - start);
            const std::string armName = resPath.substr(start, len);

            auto* armMgr = cocos2d::extension::CCArmatureDataManager::sharedArmatureDataManager();
            if (armMgr && !armName.empty() &&
                armMgr->getArmatureData(armName.c_str()) != nullptr) {
                if (auto* arm = cocos2d::extension::CCArmature::create(armName.c_str())) {
                    if (comp.has_selectedactionname() && !comp.selectedactionname().empty()) {
                        const std::string& actionName = comp.selectedactionname();
                        auto*              anim       = arm->getAnimation();
                        auto*              animData   = anim ? anim->getAnimationData() : nullptr;
                        if (anim && animData &&
                            animData->getMovement(actionName.c_str()) != nullptr) {
                            anim->play(actionName.c_str());
                        } else {
                            char msg[320];
                            std::snprintf(
                                msg,
                                sizeof(msg),
                                "Skipping missing armature movement '%s' on '%s'",
                                actionName.c_str(),
                                armName.c_str());
                            LogGuiWarn(msg);
                        }
                    }
                    auto* renderComp =
                        cocos2d::extension::CCComRender::create(arm, compName.c_str());
                    node->addComponent(renderComp);
                }
            } else {
                char msg[320];
                std::snprintf(msg,
                              sizeof(msg),
                              "Skipping CCArmature::create: armature '%s' not registered from '%s'",
                              armName.c_str(),
                              resPath.c_str());
                LogGuiWarn(msg);
            }
        }
    } else if (cls == "GUIComponent") {
        if (!resPath.empty()) {
            if (auto* uiWidget = PbGuiLoader::WidgetFromPbFile(resPath)) {
                auto* uiLayer = cocos2d::ui::TouchGroup::create();
                uiLayer->addWidget(uiWidget);
                auto* renderComp =
                    cocos2d::extension::CCComRender::create(uiLayer, compName.c_str());
                node->addComponent(renderComp);
            }
        }
    } else if (cls == "CCComAudio") {
        auto* audioComp = cocos2d::extension::CCComAudio::create();
        audioComp->setName(compName.c_str());
        if (!resPath.empty()) {
            audioComp->setFile(resPath.c_str());
        }
        node->addComponent(audioComp);
    } else if (cls == "CCComAttribute") {
        auto* attrComp = cocos2d::extension::CCComAttribute::create();
        attrComp->setName(compName.c_str());
        if (!resPath.empty() && DoesExactAssetFileExist(resPath)) {
            attrComp->parse(resPath.c_str());
        }
        node->addComponent(attrComp);
    }
}

} // namespace
#endif // GCLIENT_ENABLE_COCOS2DX

cocos2d::ui::Widget* PbGuiLoader::CreateWidgetByClassName(const std::string& className) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    if (className == "Button" || className == "TextButton") {
        return cocos2d::ui::Button::create();
    }
    if (className == "CheckBox") {
        return cocos2d::ui::CheckBox::create();
    }
    if (className == "ImageView") {
        return cocos2d::ui::ImageView::create();
    }
    if (className == "Label" || className == "TextArea" || className == "Text") {
        return cocos2d::ui::Label::create();
    }
    if (className == "LabelAtlas" || className == "TextAtlas") {
        return cocos2d::ui::LabelAtlas::create();
    }
    if (className == "LabelBMFont" || className == "TextBMFont") {
        return cocos2d::ui::LabelBMFont::create();
    }
    if (className == "LoadingBar") {
        return cocos2d::ui::LoadingBar::create();
    }
    if (className == "Slider") {
        return cocos2d::ui::Slider::create();
    }
    if (className == "TextField") {
        return cocos2d::ui::TextField::create();
    }
    if (className == "Panel" || className == "Layout") {
        return cocos2d::ui::Layout::create();
    }
    if (className == "ScrollView" || className == "DragPanel") {
        return cocos2d::ui::ScrollView::create();
    }
    if (className == "ListView") {
        return cocos2d::ui::ListView::create();
    }
    if (className == "PageView") {
        return cocos2d::ui::PageView::create();
    }
    return cocos2d::ui::Widget::create();
#else
    (void)className;
    return nullptr;
#endif
}

bool PbGuiLoader::LoadPlistSpriteFramesSafe(const std::string& plistPath,
                                            const std::string& baseDir) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    if (plistPath.empty()) {
        return false;
    }

    CSData csData;
    csData.set_resourcetype(0);
    csData.set_path(plistPath);
    const std::string primaryResolved = ResolveCsDataPath(csData, baseDir, nullptr);

    std::vector<std::string> candidates;
    AppendUniquePath(candidates, primaryResolved);
    for (const std::string& c : BuildRelativeCandidatePaths(plistPath, baseDir)) {
        AppendUniquePath(candidates, c);
    }

    // Pass 1: try binary .plistb across all candidate paths.
    for (const std::string& cand : candidates) {
        if (PlistbLoader::AddSpriteFramesWithBinary(cand)) {
            return true;
        }
    }

    // Pass 2: fallback to CCSpriteFrameCache::addSpriteFramesWithFile ONLY after
    // verifying the .plist exists on disk, is non-empty XML (NOT .plistb or 0xFEFEFEFE),
    // and probing its atlas texture across split Resources/ and assets/ roots.
    auto* sfc = cocos2d::CCSpriteFrameCache::sharedSpriteFrameCache();
    if (!sfc) {
        return false;
    }

    for (const std::string& cand : candidates) {
        const std::string xmlCand =
            EndsWithCaseInsensitive(cand, ".plistb") ? cand.substr(0, cand.size() - 1) : cand;
        if (!EndsWithCaseInsensitive(xmlCand, ".plist")) {
            continue;
        }
        std::string xmlContent;
        if (!VerifyValidXmlPlistOnDisk(xmlCand, &xmlContent)) {
            continue;
        }

        std::string texName = ExtractXmlKeyStringValue(xmlContent, "realTextureFileName");
        if (texName.empty()) {
            texName = ExtractXmlKeyStringValue(xmlContent, "textureFileName");
        }

        cocos2d::CCTexture2D* explicitTex = nullptr;
        if (!texName.empty()) {
            explicitTex =
                ProbeAndLoadTextureAcrossRoots(texName, ExtractDirectoryPrefix(xmlCand));
            if (!explicitTex) {
                char msg[320];
                std::snprintf(msg,
                              sizeof(msg),
                              "Skipping XML sprite sheet '%s': missing atlas texture '%s'",
                              xmlCand.c_str(),
                              texName.c_str());
                LogGuiWarn(msg);
                continue;
            }
        }

        if (explicitTex) {
            sfc->addSpriteFramesWithFile(xmlCand.c_str(), explicitTex);
        } else {
            sfc->addSpriteFramesWithFile(xmlCand.c_str());
        }
        return true;
    }

    return false;
#else
    (void)plistPath;
    (void)baseDir;
    return false;
#endif
}

cocos2d::ui::Widget* PbGuiLoader::WidgetFromPbFile(const std::string& fileName) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normInput = NormalizeAssetPath(fileName);
    const std::string baseDir   = ExtractDirectoryPrefix(normInput);
    const std::string pbPath    = ReplaceFileExtension(normInput, ".pb");

    unsigned long  fileSize = 0;
    DecryptResult  diag;
    unsigned char* rawData = LoadAndDecryptFileData(pbPath, &fileSize, &diag);
    if (!rawData || fileSize == 0) {
        cocos2d::CCLog("PbGuiLoader::WidgetFromPbFile: file[%s] not exist!", pbPath.c_str());
        delete[] rawData;
        return nullptr;
    }

    cocos2d::ui::Widget* widget =
        WidgetFromPbBuffer(rawData, static_cast<size_t>(fileSize), baseDir, normInput);
    delete[] rawData;

    cocos2d::CCLog("widgetFromPbFile load %s end", pbPath.c_str());
    return widget;
#else
    (void)fileName;
    return nullptr;
#endif
}

cocos2d::ui::Widget* PbGuiLoader::WidgetFromPbBuffer(const uint8_t* data,
                                                     size_t size,
                                                     const std::string& baseDir,
                                                     const std::string& sourceFileName) {
    if (!data || size == 0 || IsBtEncryptedBuffer(data, size)) {
        return nullptr;
    }

    CSGUIRoot root;
    if (!root.ParseFromArray(data, static_cast<int>(size))) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
        cocos2d::CCLog("parse gui file:%s failed", sourceFileName.c_str());
#endif
        return nullptr;
    }

    return CreateWidgetFromPbRoot(root, baseDir, sourceFileName);
}

cocos2d::ui::Widget* PbGuiLoader::CreateWidgetFromPbRoot(const CSGUIRoot& root,
                                                         const std::string& baseDir,
                                                         const std::string& sourceFileName) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normBaseDir = NormalizeAssetPath(baseDir);

    // 1. Preload all texture sprite sheets listed in CSGUIRoot.textures safely.
    for (int i = 0; i < root.textures_size(); ++i) {
        LoadPlistSpriteFramesSafe(root.textures(i), normBaseDir);
    }

    if (!root.has_widgettree()) {
        return nullptr;
    }

    // 2. Recursively construct the CocoStudio widget tree.
    cocos2d::ui::Widget* rootWidget = CreateWidgetFromPb(root.widgettree(), normBaseDir);

    // 3. Parse and register CSAnimation action timelines if present.
    if (root.has_animation()) {
        RegisterGuiAnimations(root.animation(), sourceFileName, rootWidget);
    }

    return rootWidget;
#else
    (void)root;
    (void)baseDir;
    (void)sourceFileName;
    return nullptr;
#endif
}

cocos2d::ui::Widget* PbGuiLoader::CreateWidgetFromPb(const CSWidget& pbWidget,
                                                     const std::string& baseDir) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string cls = pbWidget.has_classname() ? pbWidget.classname() : "Widget";
    const CSOptions&  opt = pbWidget.options();

    cocos2d::ui::Widget* widget = CreateWidgetByClassName(cls);
    if (!widget) {
        return nullptr;
    }

    ApplyBaseWidgetOptions(widget, opt);

    if (cls == "Button" || cls == "TextButton") {
        ApplyButtonOptions(static_cast<cocos2d::ui::Button*>(widget), opt, baseDir);
    } else if (cls == "CheckBox") {
        ApplyCheckBoxOptions(static_cast<cocos2d::ui::CheckBox*>(widget), opt, baseDir);
    } else if (cls == "ImageView") {
        ApplyImageViewOptions(static_cast<cocos2d::ui::ImageView*>(widget), opt, baseDir);
    } else if (cls == "Label" || cls == "TextArea" || cls == "Text") {
        ApplyLabelOptions(static_cast<cocos2d::ui::Label*>(widget), opt);
    } else if (cls == "LabelAtlas" || cls == "TextAtlas") {
        ApplyLabelAtlasOptions(static_cast<cocos2d::ui::LabelAtlas*>(widget), opt, baseDir);
    } else if (cls == "LabelBMFont" || cls == "TextBMFont") {
        ApplyLabelBMFontOptions(static_cast<cocos2d::ui::LabelBMFont*>(widget), opt, baseDir);
    } else if (cls == "LoadingBar") {
        ApplyLoadingBarOptions(static_cast<cocos2d::ui::LoadingBar*>(widget), opt, baseDir);
    } else if (cls == "Slider") {
        ApplySliderOptions(static_cast<cocos2d::ui::Slider*>(widget), opt, baseDir);
    } else if (cls == "TextField") {
        ApplyTextFieldOptions(static_cast<cocos2d::ui::TextField*>(widget), opt);
    } else if (cls == "Panel" || cls == "Layout") {
        ApplyLayoutOptions(static_cast<cocos2d::ui::Layout*>(widget), opt, baseDir);
    } else if (cls == "ScrollView" || cls == "DragPanel") {
        ApplyScrollViewOptions(static_cast<cocos2d::ui::ScrollView*>(widget), opt, baseDir);
    } else if (cls == "ListView") {
        ApplyListViewOptions(static_cast<cocos2d::ui::ListView*>(widget), opt, baseDir);
    } else if (cls == "PageView") {
        ApplyLayoutOptions(static_cast<cocos2d::ui::PageView*>(widget), opt, baseDir);
    }

    for (int i = 0; i < pbWidget.children_size(); ++i) {
        const CSWidget&      childPb = pbWidget.children(i);
        cocos2d::ui::Widget* child   = CreateWidgetFromPb(childPb, baseDir);
        if (child) {
            if (cls == "PageView") {
                if (auto* pageLayout = dynamic_cast<cocos2d::ui::Layout*>(child)) {
                    static_cast<cocos2d::ui::PageView*>(widget)->addPage(pageLayout);
                } else {
                    widget->addChild(child);
                }
            } else if (cls == "ListView") {
                static_cast<cocos2d::ui::ListView*>(widget)->pushBackCustomItem(child);
            } else {
                widget->addChild(child);
            }

            // Re-sync percent size & percent position now that child->getParent() != nullptr.
            const CSOptions& childOpt = childPb.options();
            if (childOpt.has_sizetype() && childOpt.sizetype() == 1) {
                const float sx = childOpt.has_sizepercentx() ? childOpt.sizepercentx() : 0.0f;
                const float sy = childOpt.has_sizepercenty() ? childOpt.sizepercenty() : 0.0f;
                child->setSizePercent(cocos2d::CCPoint(sx, sy));
                if (auto* childLayout = dynamic_cast<cocos2d::ui::Layout*>(child)) {
                    TriggerLayoutPass(childLayout);
                }
            }
            if (childOpt.has_positiontype() && childOpt.positiontype() == 1) {
                const float px =
                    childOpt.has_positionpercentx() ? childOpt.positionpercentx() : 0.0f;
                const float py =
                    childOpt.has_positionpercenty() ? childOpt.positionpercenty() : 0.0f;
                child->setPositionPercent(cocos2d::CCPoint(px, py));
            }
        }
    }

    if (auto* layoutWidget = dynamic_cast<cocos2d::ui::Layout*>(widget)) {
        TriggerLayoutPass(layoutWidget);
    }

    return widget;
#else
    (void)pbWidget;
    (void)baseDir;
    return nullptr;
#endif
}

cocos2d::CCNode* PbGuiLoader::SceneFromPbFile(const std::string& fileName) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normInput = NormalizeAssetPath(fileName);
    const std::string baseDir   = ExtractDirectoryPrefix(normInput);
    const std::string pbPath    = ReplaceFileExtension(normInput, ".pb");

    unsigned long  fileSize = 0;
    DecryptResult  diag;
    unsigned char* rawData = LoadAndDecryptFileData(pbPath, &fileSize, &diag);
    if (!rawData || fileSize == 0) {
        cocos2d::CCLog("PbGuiLoader::SceneFromPbFile: file[%s] not exist!", pbPath.c_str());
        delete[] rawData;
        return nullptr;
    }

    CSSceneRoot root;
    const bool  parsed = root.ParseFromArray(rawData, static_cast<int>(fileSize));
    delete[] rawData;

    if (!parsed) {
        cocos2d::CCLog("PbGuiLoader::SceneFromPbFile: parse scene file:%s failed", pbPath.c_str());
        return nullptr;
    }

    return CreateSceneFromPbRoot(root, baseDir);
#else
    (void)fileName;
    return nullptr;
#endif
}

cocos2d::CCNode* PbGuiLoader::CreateSceneFromPbRoot(const CSSceneRoot& root,
                                                    const std::string& baseDir) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    auto* node = cocos2d::CCNode::create();
    if (!node) {
        return nullptr;
    }

    node->setPosition(cocos2d::CCPoint(static_cast<float>(root.x()),
                                       static_cast<float>(root.y())));
    node->setVisible(root.has_visible() ? root.visible() : true);
    if (root.has_objecttag()) {
        node->setTag(root.objecttag());
    }
    node->setZOrder(root.zorder());
    node->setScaleX(root.has_scalex() ? root.scalex() : 1.0f);
    node->setScaleY(root.has_scaley() ? root.scaley() : 1.0f);
    node->setRotation(static_cast<float>(root.rotation()));

    for (int i = 0; i < root.components_size(); ++i) {
        AttachSceneComponent(node, root.components(i), baseDir);
    }

    for (int i = 0; i < root.gameobjects_size(); ++i) {
        if (auto* child = CreateSceneFromPbRoot(root.gameobjects(i), baseDir)) {
            node->addChild(child);
        }
    }

    return node;
#else
    (void)root;
    (void)baseDir;
    return nullptr;
#endif
}

} // namespace assets
} // namespace gclient
