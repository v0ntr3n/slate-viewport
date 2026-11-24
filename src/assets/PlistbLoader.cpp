#include "PlistbLoader.h"

#include "BtDecryptHook.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_set>

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "cocos2d.h"
#endif

namespace gclient {
namespace assets {

namespace {

std::mutex                      g_loadedPlistbMutex;
std::unordered_set<std::string> g_loadedPlistbFiles;

uint16_t ReadLE16U(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) |
           (static_cast<uint16_t>(ptr[1]) << 8);
}

int16_t ReadLE16S(const uint8_t* ptr) {
    return static_cast<int16_t>(ReadLE16U(ptr));
}

uint32_t ReadLE32U(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

bool ReadValidatedFixedCString(const uint8_t* ptr,
                               size_t maxLen,
                               bool requireNonEmpty,
                               std::string* outStr) {
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
    if (outStr) {
        outStr->assign(reinterpret_cast<const char*>(ptr), len);
    }
    return true;
}

bool StartsWithAsciiCI(const uint8_t* ptr, size_t rem, const char* prefix) {
    const size_t pLen = std::strlen(prefix);
    if (rem < pLen) {
        return false;
    }
    for (size_t i = 0; i < pLen; ++i) {
        const unsigned char a = ptr[i];
        const unsigned char b = static_cast<unsigned char>(prefix[i]);
        if (std::tolower(a) != std::tolower(b)) {
            return false;
        }
    }
    return true;
}

bool LooksLikePlaintextXmlPlist(const uint8_t* data, size_t size) {
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
           StartsWithAsciiCI(data + off, rem, "<!doctype") ||
           StartsWithAsciiCI(data + off, rem, "<!--");
}

bool EndsWithCaseInsensitive(const std::string& str, const char* suffix) {
    const size_t sufLen = std::strlen(suffix);
    if (str.size() < sufLen) {
        return false;
    }
    const size_t offset = str.size() - sufLen;
    for (size_t i = 0; i < sufLen; ++i) {
        const unsigned char a = static_cast<unsigned char>(str[offset + i]);
        const unsigned char b = static_cast<unsigned char>(suffix[i]);
        if (std::tolower(a) != std::tolower(b)) {
            return false;
        }
    }
    return true;
}

std::string StripTextureExtension(const std::string& normalizedPath) {
    if (EndsWithCaseInsensitive(normalizedPath, ".pvr.ccz")) {
        return normalizedPath.substr(0, normalizedPath.size() - 8);
    }
    if (EndsWithCaseInsensitive(normalizedPath, ".pvr.gz")) {
        return normalizedPath.substr(0, normalizedPath.size() - 7);
    }
    const size_t slashPos = normalizedPath.find_last_of('/');
    const size_t dotPos   = normalizedPath.find_last_of('.');
    if (dotPos == std::string::npos ||
        (slashPos != std::string::npos && dotPos < slashPos)) {
        return normalizedPath;
    }
    return normalizedPath.substr(0, dotPos);
}

void AppendUniqueCandidate(std::vector<std::string>& out, const std::string& candidate) {
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

std::string BuildPlistbPath(const std::string& plistPath) {
    const std::string norm = NormalizeAssetPath(plistPath);
    if (norm.empty()) {
        return norm;
    }
    if (EndsWithCaseInsensitive(norm, ".plistb")) {
        return norm;
    }
    if (EndsWithCaseInsensitive(norm, ".plist")) {
        return norm + "b";
    }
    return ReplaceFileExtension(norm, ".plistb");
}

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)

std::string BuildXmlPlistPath(const std::string& plistPath) {
    const std::string norm = NormalizeAssetPath(plistPath);
    if (norm.empty()) {
        return norm;
    }
    if (EndsWithCaseInsensitive(norm, ".plistb")) {
        return norm.substr(0, norm.size() - 1);
    }
    if (EndsWithCaseInsensitive(norm, ".plist")) {
        return norm;
    }
    return ReplaceFileExtension(norm, ".plist");
}

void SetDictString(cocos2d::CCDictionary* dict, const std::string& key, const std::string& val) {
    auto* strObj = new cocos2d::CCString(val);
    dict->setObject(strObj, key);
    strObj->release();
}

std::string UnescapeXmlText(const char* s, size_t len) {
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        if (s[i] == '&') {
            if (i + 4 < len && std::memcmp(s + i, "&amp;", 5) == 0) {
                out.push_back('&');
                i += 4;
                continue;
            }
            if (i + 3 < len && std::memcmp(s + i, "&lt;", 4) == 0) {
                out.push_back('<');
                i += 3;
                continue;
            }
            if (i + 3 < len && std::memcmp(s + i, "&gt;", 4) == 0) {
                out.push_back('>');
                i += 3;
                continue;
            }
            if (i + 5 < len && std::memcmp(s + i, "&quot;", 6) == 0) {
                out.push_back('"');
                i += 5;
                continue;
            }
            if (i + 5 < len && std::memcmp(s + i, "&apos;", 6) == 0) {
                out.push_back('\'');
                i += 5;
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

struct XmlCursor {
    const char* p   = nullptr;
    const char* end = nullptr;

    void skipWsAndComments() {
        while (p < end) {
            if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
                ++p;
                continue;
            }
            if (end - p >= 4 && std::memcmp(p, "<!--", 4) == 0) {
                p += 4;
                while (end - p >= 3 && std::memcmp(p, "-->", 3) != 0) {
                    ++p;
                }
                if (end - p >= 3) {
                    p += 3;
                } else {
                    p = end;
                }
                continue;
            }
            if (end - p >= 2 && (std::memcmp(p, "<?", 2) == 0 || std::memcmp(p, "<!", 2) == 0)) {
                while (p < end && *p != '>') {
                    ++p;
                }
                if (p < end) {
                    ++p;
                }
                continue;
            }
            break;
        }
    }

    bool readNextTag(std::string* outName, bool* outIsClosing, bool* outSelfClosing) {
        skipWsAndComments();
        if (p >= end || *p != '<') {
            return false;
        }
        ++p;
        *outIsClosing   = false;
        *outSelfClosing = false;
        if (p < end && *p == '/') {
            *outIsClosing = true;
            ++p;
        }
        const char* nameStart = p;
        while (p < end && *p != '>' && *p != '/' &&
               *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
            ++p;
        }
        outName->assign(nameStart, static_cast<size_t>(p - nameStart));
        while (p < end && *p != '>') {
            if (*p == '/' && (p + 1 < end && p[1] == '>')) {
                *outSelfClosing = true;
            }
            ++p;
        }
        if (p >= end || *p != '>') {
            return false;
        }
        ++p;
        return !outName->empty();
    }

    bool readElementTextUntilClose(const std::string& tagName, std::string* outText) {
        const char* textStart = p;
        const std::string closeSeq = "</" + tagName + ">";
        while (p < end) {
            if (*p == '<' && static_cast<size_t>(end - p) >= closeSeq.size() &&
                std::memcmp(p, closeSeq.data(), closeSeq.size()) == 0) {
                *outText = UnescapeXmlText(textStart, static_cast<size_t>(p - textStart));
                p += closeSeq.size();
                return true;
            }
            ++p;
        }
        return false;
    }
};

cocos2d::CCObject* ParseXmlPlistValue(XmlCursor& cur,
                                      const std::string& openTag,
                                      bool selfClosing,
                                      int depth);

cocos2d::CCDictionary* ParseXmlDictBody(XmlCursor& cur, int depth) {
    if (depth > 32) {
        return nullptr;
    }
    auto* dict = new cocos2d::CCDictionary();
    while (true) {
        std::string tag;
        bool        isClosing   = false;
        bool        selfClosing = false;
        if (!cur.readNextTag(&tag, &isClosing, &selfClosing)) {
            dict->release();
            return nullptr;
        }
        if (isClosing) {
            if (tag == "dict") {
                return dict;
            }
            dict->release();
            return nullptr;
        }
        if (tag != "key") {
            dict->release();
            return nullptr;
        }
        std::string keyName;
        if (!selfClosing && !cur.readElementTextUntilClose("key", &keyName)) {
            dict->release();
            return nullptr;
        }

        std::string valTag;
        bool        valClosing     = false;
        bool        valSelfClosing = false;
        if (!cur.readNextTag(&valTag, &valClosing, &valSelfClosing) || valClosing) {
            dict->release();
            return nullptr;
        }
        cocos2d::CCObject* valObj = ParseXmlPlistValue(cur, valTag, valSelfClosing, depth + 1);
        if (!valObj) {
            dict->release();
            return nullptr;
        }
        dict->setObject(valObj, keyName);
        valObj->release();
    }
}

cocos2d::CCArray* ParseXmlArrayBody(XmlCursor& cur, int depth) {
    if (depth > 32) {
        return nullptr;
    }
    auto* arr = new cocos2d::CCArray();
    while (true) {
        std::string tag;
        bool        isClosing   = false;
        bool        selfClosing = false;
        if (!cur.readNextTag(&tag, &isClosing, &selfClosing)) {
            arr->release();
            return nullptr;
        }
        if (isClosing) {
            if (tag == "array") {
                return arr;
            }
            arr->release();
            return nullptr;
        }
        cocos2d::CCObject* item = ParseXmlPlistValue(cur, tag, selfClosing, depth + 1);
        if (!item) {
            arr->release();
            return nullptr;
        }
        arr->addObject(item);
        item->release();
    }
}

cocos2d::CCObject* ParseXmlPlistValue(XmlCursor& cur,
                                      const std::string& openTag,
                                      bool selfClosing,
                                      int depth) {
    if (openTag == "dict") {
        if (selfClosing) {
            return new cocos2d::CCDictionary();
        }
        return ParseXmlDictBody(cur, depth);
    }
    if (openTag == "array") {
        if (selfClosing) {
            return new cocos2d::CCArray();
        }
        return ParseXmlArrayBody(cur, depth);
    }
    if (openTag == "true") {
        if (!selfClosing) {
            std::string dummy;
            (void)cur.readElementTextUntilClose("true", &dummy);
        }
        return new cocos2d::CCString("1");
    }
    if (openTag == "false") {
        if (!selfClosing) {
            std::string dummy;
            (void)cur.readElementTextUntilClose("false", &dummy);
        }
        return new cocos2d::CCString("0");
    }
    if (openTag == "string" || openTag == "integer" || openTag == "real" || openTag == "data") {
        if (selfClosing) {
            return new cocos2d::CCString("");
        }
        std::string text;
        if (!cur.readElementTextUntilClose(openTag, &text)) {
            return nullptr;
        }
        return new cocos2d::CCString(text);
    }
    return nullptr;
}

cocos2d::CCDictionary* ParseXmlPlistToDictionary(const uint8_t* data, size_t size) {
    size_t off = 0;
    if (size >= 3 && data[0] == 0xEFu && data[1] == 0xBBu && data[2] == 0xBFu) {
        off = 3;
    }
    XmlCursor cur;
    cur.p   = reinterpret_cast<const char*>(data + off);
    cur.end = reinterpret_cast<const char*>(data + size);

    std::string tag;
    bool        isClosing   = false;
    bool        selfClosing = false;
    if (!cur.readNextTag(&tag, &isClosing, &selfClosing) || isClosing) {
        return nullptr;
    }
    if (tag == "plist") {
        if (selfClosing) {
            return nullptr;
        }
        if (!cur.readNextTag(&tag, &isClosing, &selfClosing) || isClosing) {
            return nullptr;
        }
    }
    if (tag != "dict") {
        return nullptr;
    }
    cocos2d::CCDictionary* dict = selfClosing ? new cocos2d::CCDictionary()
                                              : ParseXmlDictBody(cur, 0);
    if (!dict) {
        return nullptr;
    }
    dict->autorelease();
    return dict;
}

cocos2d::CCDictionary* BuildSpriteSheetDictionary(const PlistbFileData& parsed) {
    auto* root = cocos2d::CCDictionary::create();
    if (!root) {
        return nullptr;
    }

    auto* metadata = new cocos2d::CCDictionary();
    SetDictString(metadata, "format", "2");
    SetDictString(metadata, "textureFileName", parsed.textureFileName);
    SetDictString(metadata, "realTextureFileName", parsed.textureFileName);
    root->setObject(metadata, "metadata");
    metadata->release();

    auto* frames = new cocos2d::CCDictionary();
    char  buf[128];
    for (const auto& rec : parsed.frames) {
        if (rec.frameName.empty()) {
            continue;
        }
        auto* entry = new cocos2d::CCDictionary();
        std::snprintf(buf,
                      sizeof(buf),
                      "{{%d,%d},{%d,%d}}",
                      static_cast<int>(rec.rectX),
                      static_cast<int>(rec.rectY),
                      static_cast<int>(rec.rectWidth),
                      static_cast<int>(rec.rectHeight));
        SetDictString(entry, "frame", buf);

        std::snprintf(buf,
                      sizeof(buf),
                      "{%d,%d}",
                      static_cast<int>(rec.offsetX),
                      static_cast<int>(rec.offsetY));
        SetDictString(entry, "offset", buf);

        SetDictString(entry, "rotated", rec.rotated ? "true" : "false");

        std::snprintf(buf,
                      sizeof(buf),
                      "{%d,%d}",
                      static_cast<int>(rec.originalWidth),
                      static_cast<int>(rec.originalHeight));
        SetDictString(entry, "sourceSize", buf);

        frames->setObject(entry, rec.frameName);
        entry->release();
    }
    root->setObject(frames, "frames");
    frames->release();
    return root;
}

#endif // GCLIENT_ENABLE_COCOS2DX

} // namespace

bool PlistbLoader::ParseBuffer(const uint8_t* data,
                               size_t size,
                               PlistbFileData* outData,
                               std::string* outError) {
    if (data == nullptr || outData == nullptr) {
        if (outError) *outError = "Null buffer or output pointer";
        return false;
    }

    if (size >= 4 && ReadLE32U(data) == kBtDecryptMagic) {
        if (outError) *outError = "Undecrypted 0xFEFEFEFE buffer passed to PlistbLoader::ParseBuffer";
        return false;
    }

    if (LooksLikePlaintextXmlPlist(data, size)) {
        if (outError) *outError = "Plaintext XML plist passed to binary PlistbLoader::ParseBuffer";
        return false;
    }

    if (size < kPlistbHeaderSize) {
        if (outError) *outError = "Buffer smaller than 66-byte .plistb header";
        return false;
    }

    std::string texName;
    if (!ReadValidatedFixedCString(data, kPlistbNameMaxLen, /*requireNonEmpty=*/true, &texName)) {
        if (outError) {
            *outError = "Invalid or non-NUL-terminated textureFileName in .plistb header";
        }
        return false;
    }

    const int16_t frameCount = ReadLE16S(data + 64);
    if (frameCount < 0) {
        if (outError) *outError = "Negative frame count in .plistb header";
        return false;
    }

    const size_t requiredBytes =
        kPlistbHeaderSize + static_cast<size_t>(frameCount) * kPlistbRecordSize;
    if (size < requiredBytes) {
        if (outError) {
            char msg[160];
            std::snprintf(msg,
                          sizeof(msg),
                          "Truncated .plistb buffer: need %zu bytes for %d frames, got %zu",
                          requiredBytes,
                          static_cast<int>(frameCount),
                          size);
            *outError = msg;
        }
        return false;
    }

    std::vector<PlistbFrameRecord> parsedFrames;
    parsedFrames.reserve(static_cast<size_t>(frameCount));

    const uint8_t* cursor = data + kPlistbHeaderSize;
    for (int16_t i = 0; i < frameCount; ++i, cursor += kPlistbRecordSize) {
        PlistbFrameRecord rec;
        if (!ReadValidatedFixedCString(cursor, kPlistbNameMaxLen, /*requireNonEmpty=*/false, &rec.frameName)) {
            if (outError) {
                *outError = "Invalid or non-NUL-terminated frameName in .plistb record";
            }
            return false;
        }
        rec.rectX          = static_cast<float>(ReadLE16U(cursor + 64));
        rec.rectY          = static_cast<float>(ReadLE16U(cursor + 66));
        rec.rectWidth      = static_cast<float>(ReadLE16U(cursor + 68));
        rec.rectHeight     = static_cast<float>(ReadLE16U(cursor + 70));
        rec.rotated        = (cursor[72] != 0);
        rec.offsetX        = static_cast<float>(ReadLE16S(cursor + 74));
        rec.offsetY        = static_cast<float>(ReadLE16S(cursor + 76));
        rec.originalWidth  = static_cast<float>(ReadLE16U(cursor + 78));
        rec.originalHeight = static_cast<float>(ReadLE16U(cursor + 80));
        parsedFrames.push_back(std::move(rec));
    }

    outData->textureFileName = std::move(texName);
    outData->frames          = std::move(parsedFrames);
    return true;
}

std::vector<std::string> PlistbLoader::BuildTextureCandidatePaths(const std::string& texturePath) {
    std::vector<std::string> candidates;
    const std::string norm = NormalizeAssetPath(texturePath);
    if (norm.empty()) {
        return candidates;
    }

    const std::string stem = StripTextureExtension(norm);
    AppendUniqueCandidate(candidates, norm);
    AppendUniqueCandidate(candidates, stem + ".pvr.ccz");
    AppendUniqueCandidate(candidates, stem + ".pkm");
    AppendUniqueCandidate(candidates, stem + ".png");
    AppendUniqueCandidate(candidates, stem + ".webp");
    AppendUniqueCandidate(candidates, stem + ".jpg");
    return candidates;
}

bool PlistbLoader::AddSpriteFramesFromPlistbFile(const std::string& plistPath,
                                                 cocos2d::CCTexture2D* texture,
                                                 cocos2d::CCSpriteFrameCache* cache) {
    return AddSpriteFramesWithBinary(plistPath, texture, cache);
}

bool PlistbLoader::AddSpriteFramesWithBinary(const std::string& plistPath,
                                             cocos2d::CCTexture2D* texture,
                                             cocos2d::CCSpriteFrameCache* cache) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normBasePath = NormalizeAssetPath(plistPath);
    const std::string plistbPath   = BuildPlistbPath(normBasePath);
    if (plistbPath.empty()) {
        return false;
    }

    unsigned long  fileSize = 0;
    DecryptResult  diag;
    unsigned char* rawData = LoadAndDecryptFileData(plistbPath, &fileSize, &diag);
    if (!rawData || fileSize == 0) {
        cocos2d::CCLog("[PlistbLoader] Failed to load binary plist: %s", plistbPath.c_str());
        delete[] rawData;
        return false;
    }

    PlistbFileData parsed;
    std::string    parseErr;
    const bool     ok = ParseBuffer(rawData, static_cast<size_t>(fileSize), &parsed, &parseErr);
    delete[] rawData;

    if (!ok) {
        cocos2d::CCLog("[PlistbLoader] Parse failed for %s: %s",
                       plistbPath.c_str(),
                       parseErr.c_str());
        return false;
    }

    cocos2d::CCTexture2D* targetTexture = texture;
    if (!targetTexture) {
        auto* texCache = cocos2d::CCTextureCache::sharedTextureCache();
        if (!texCache) {
            return false;
        }

        const std::string texRelPath  = NormalizeAssetPath(parsed.textureFileName);
        const std::string relBaseTex  = ResolveRelativeAssetPath(texRelPath, plistbPath);
        auto*             fu          = cocos2d::CCFileUtils::sharedFileUtils();

        std::vector<std::string> candidateList = BuildTextureCandidatePaths(relBaseTex);
        if (fu) {
            const std::string fromFu = NormalizeAssetPath(
                fu->fullPathFromRelativeFile(texRelPath.c_str(), plistbPath.c_str()));
            if (!fromFu.empty() && fromFu != relBaseTex) {
                for (const std::string& c : BuildTextureCandidatePaths(fromFu)) {
                    AppendUniqueCandidate(candidateList, c);
                }
            }
        }

        if (fu) {
            for (const std::string& cand : candidateList) {
                const std::string full = fu->fullPathForFilename(cand.c_str());
                if (!full.empty() && fu->isFileExist(full)) {
                    targetTexture = texCache->addImage(full.c_str());
                    if (targetTexture) {
                        break;
                    }
                }
            }
        }

        if (!targetTexture) {
            for (const std::string& cand : candidateList) {
                targetTexture = texCache->addImage(cand.c_str());
                if (targetTexture) {
                    break;
                }
            }
        }

        if (!targetTexture) {
            cocos2d::CCLog("cocos2d: CCSpriteFrameCache: Couldn't load texture: %s (from %s)",
                           relBaseTex.c_str(),
                           plistbPath.c_str());
            return false;
        }
    }

    cocos2d::CCSpriteFrameCache* targetCache =
        cache ? cache : cocos2d::CCSpriteFrameCache::sharedSpriteFrameCache();
    if (!targetCache) {
        return false;
    }

    for (const auto& rec : parsed.frames) {
        if (rec.frameName.empty()) {
            continue;
        }

        if (targetCache->spriteFrameByName(rec.frameName.c_str()) != nullptr) {
            cocos2d::CCLog("addSpriteFramesWithBinary : Duplicate frame skipped (%s)",
                           rec.frameName.c_str());
            continue;
        }

        const cocos2d::CCRect  rect(rec.rectX, rec.rectY, rec.rectWidth, rec.rectHeight);
        const cocos2d::CCPoint offset(rec.offsetX, rec.offsetY);
        const cocos2d::CCSize  originalSize(rec.originalWidth, rec.originalHeight);

        auto* frame = new cocos2d::CCSpriteFrame();
        frame->initWithTexture(targetTexture, rect, rec.rotated, offset, originalSize);
        targetCache->addSpriteFrame(frame, rec.frameName.c_str());
        frame->release();
    }

    {
        std::lock_guard<std::mutex> lock(g_loadedPlistbMutex);
        g_loadedPlistbFiles.insert(normBasePath);
        g_loadedPlistbFiles.insert(plistbPath);
    }
    return true;
#else
    (void)plistPath;
    (void)texture;
    (void)cache;
    return false;
#endif
}

cocos2d::CCDictionary* PlistbLoader::LoadDictionaryFromBinaryBuffer(const uint8_t* data,
                                                                    size_t size,
                                                                    std::string* outError) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    if (!data || size == 0) {
        if (outError) *outError = "Null or empty plist buffer";
        return nullptr;
    }
    if (size >= 4 && ReadLE32U(data) == kBtDecryptMagic) {
        if (outError) *outError = "Undecrypted 0xFEFEFEFE buffer in LoadDictionaryFromBinaryBuffer";
        return nullptr;
    }

    if (LooksLikePlaintextXmlPlist(data, size)) {
        cocos2d::CCDictionary* xmlDict = ParseXmlPlistToDictionary(data, size);
        if (!xmlDict && outError) {
            *outError = "Failed to parse XML plist dictionary";
        }
        return xmlDict;
    }

    PlistbFileData parsed;
    if (ParseBuffer(data, size, &parsed, outError)) {
        return BuildSpriteSheetDictionary(parsed);
    }
    return nullptr;
#else
    (void)data;
    (void)size;
    if (outError) *outError = "Cocos2d-x disabled in standalone build";
    return nullptr;
#endif
}

cocos2d::CCDictionary* PlistbLoader::LoadDictionaryFromBinaryFile(const std::string& plistPath,
                                                                  std::string* outError) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string norm = NormalizeAssetPath(plistPath);
    if (norm.empty()) {
        if (outError) *outError = "Empty plist path";
        return nullptr;
    }

    std::vector<std::string> candidates;
    AppendUniqueCandidate(candidates, BuildPlistbPath(norm));
    AppendUniqueCandidate(candidates, BuildXmlPlistPath(norm));
    AppendUniqueCandidate(candidates, norm);

    for (const std::string& cand : candidates) {
        unsigned long  fileSize = 0;
        DecryptResult  diag;
        unsigned char* rawData = LoadAndDecryptFileData(cand, &fileSize, &diag);
        if (!rawData || fileSize == 0) {
            delete[] rawData;
            continue;
        }
        cocos2d::CCDictionary* dict =
            LoadDictionaryFromBinaryBuffer(rawData, static_cast<size_t>(fileSize), outError);
        delete[] rawData;
        if (dict) {
            return dict;
        }
    }

    if (outError && outError->empty()) {
        *outError = "Unable to load plist/plistb dictionary: " + norm;
    }
    return nullptr;
#else
    (void)plistPath;
    if (outError) *outError = "Cocos2d-x disabled in standalone build";
    return nullptr;
#endif
}

bool PlistbLoader::IsPlistbLoaded(const std::string& plistPath) {
    const std::string norm   = NormalizeAssetPath(plistPath);
    const std::string plistb = BuildPlistbPath(norm);
    std::lock_guard<std::mutex> lock(g_loadedPlistbMutex);
    return g_loadedPlistbFiles.find(norm) != g_loadedPlistbFiles.end() ||
           g_loadedPlistbFiles.find(plistb) != g_loadedPlistbFiles.end();
}

void PlistbLoader::ClearLoadedTracking() {
    std::lock_guard<std::mutex> lock(g_loadedPlistbMutex);
    g_loadedPlistbFiles.clear();
}

} // namespace assets
} // namespace gclient
