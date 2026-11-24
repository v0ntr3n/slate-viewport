#include "BtDecryptHook.h"

#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "cocos2d.h"
#endif

#if !defined(GCLIENT_STANDALONE_BUILD)
#include "diagnostics/CrashAndTelemetry.h"
#endif

namespace gclient {
namespace assets {

namespace {

// ============================================================================
// Pluggable Key Table Slot (#include "07_bt_decrypt_keys.inc")
// ============================================================================
#if defined(__has_include)
#if __has_include("07_bt_decrypt_keys.inc")
#include "07_bt_decrypt_keys.inc"
#endif
#elif defined(GCLIENT_USE_BT_DECRYPT_KEYS_INC)
#include "07_bt_decrypt_keys.inc"
#endif

#if !defined(GCLIENT_BT_DECRYPT_KEYS_DEFINED)
#define GCLIENT_BT_DECRYPT_KEYS_DEFINED 0
static const BtKeyEntry kBtDefaultKeyTables[kBtKeyTableCount] = {};
#endif

std::mutex        g_runtimeKeyTablesMutex;
BtKeyEntry        g_runtimeKeyTables[kBtKeyTableCount] = {};
std::atomic<bool> g_warnedMissingKeys{false};

#if !defined(GCLIENT_STANDALONE_BUILD)
gclient::diagnostics::LogLevel ParseLogLevel(const char* level) {
    if (!level) {
        return gclient::diagnostics::LogLevel::Info;
    }
    if (std::strcmp(level, "ERROR") == 0) {
        return gclient::diagnostics::LogLevel::Error;
    }
    if (std::strcmp(level, "WARN") == 0) {
        return gclient::diagnostics::LogLevel::Warn;
    }
    if (std::strcmp(level, "DEBUG") == 0) {
        return gclient::diagnostics::LogLevel::Debug;
    }
    if (std::strcmp(level, "TRACE") == 0) {
        return gclient::diagnostics::LogLevel::Trace;
    }
    if (std::strcmp(level, "FATAL") == 0) {
        return gclient::diagnostics::LogLevel::Fatal;
    }
    return gclient::diagnostics::LogLevel::Info;
}
#endif

void LogMessage(const char* level, const char* text) {
    const char* safeLevel = level ? level : "INFO";
    const char* safeText  = text ? text : "";
#if !defined(GCLIENT_STANDALONE_BUILD)
    const gclient::diagnostics::LogLevel diagLevel = ParseLogLevel(safeLevel);
    gclient::diagnostics::CrashAndTelemetry::log(diagLevel, "BtDecryptHook", "%s", safeText);
    cocos2d::CCLog("[BtDecryptHook][%s] %s", safeLevel, safeText);
#elif defined(GCLIENT_ENABLE_COCOS2DX)
    cocos2d::CCLog("[BtDecryptHook][%s] %s", safeLevel, safeText);
#if defined(_WIN32)
    std::string dbg = std::string("[BtDecryptHook][") + safeLevel + "] " + safeText + "\n";
    OutputDebugStringA(dbg.c_str());
#endif
#else
    std::fprintf(stderr, "[BtDecryptHook][%s] %s\n", safeLevel, safeText);
#if defined(_WIN32)
    std::string dbg = std::string("[BtDecryptHook][") + safeLevel + "] " + safeText + "\n";
    OutputDebugStringA(dbg.c_str());
#endif
#endif
}

void WarnIfKeysMissingOnce() {
    if (g_warnedMissingKeys.load(std::memory_order_relaxed)) {
        return;
    }
    if (!HasDecryptKeys()) {
        bool expected = false;
        if (g_warnedMissingKeys.compare_exchange_strong(expected, true)) {
            LogMessage(
                "WARN",
                "07_bt_decrypt_keys.inc is not present and no runtime key tables are registered. "
                "Encrypted assets with 0xFEFEFEFE headers will fail decryption until key tables are supplied.");
        }
    }
}

BtKeyEntry ResolveKeyTable(uint8_t keyIndex) {
    if (keyIndex > kBtMaxKeyIndex) {
        return {};
    }
    {
        std::lock_guard<std::mutex> lock(g_runtimeKeyTablesMutex);
        if (g_runtimeKeyTables[keyIndex].data != nullptr &&
            g_runtimeKeyTables[keyIndex].length > 0) {
            return g_runtimeKeyTables[keyIndex];
        }
    }
    return kBtDefaultKeyTables[keyIndex];
}

const char* StatusToString(DecryptStatus status) {
    switch (status) {
        case DecryptStatus::Ok:                    return "OK";
        case DecryptStatus::NotEncrypted:          return "NOT_ENCRYPTED";
        case DecryptStatus::InvalidBuffer:         return "INVALID_BUFFER";
        case DecryptStatus::TruncatedHeader:       return "TRUNCATED_HEADER";
        case DecryptStatus::PayloadLengthMismatch: return "PAYLOAD_LENGTH_MISMATCH";
        case DecryptStatus::UnsupportedAlgoIndex:  return "UNSUPPORTED_ALGO_INDEX";
        case DecryptStatus::InvalidKeyIndex:       return "INVALID_KEY_INDEX";
        case DecryptStatus::MissingKeyTable:       return "MISSING_KEY_TABLE";
        default:                                   return "UNKNOWN";
    }
}

uint32_t ReadLE32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

} // namespace

bool HasDecryptKeys() {
    std::lock_guard<std::mutex> lock(g_runtimeKeyTablesMutex);
    for (size_t i = 0; i < kBtKeyTableCount; ++i) {
        if ((g_runtimeKeyTables[i].data != nullptr && g_runtimeKeyTables[i].length > 0) ||
            (kBtDefaultKeyTables[i].data != nullptr && kBtDefaultKeyTables[i].length > 0)) {
            return true;
        }
    }
    return false;
}

bool RegisterKeyTable(uint8_t keyIndex, const uint8_t* keyData, uint32_t keyLength) {
    if (keyIndex > kBtMaxKeyIndex || keyData == nullptr || keyLength == 0 ||
        keyLength > kBtMaxKeyLength) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_runtimeKeyTablesMutex);
        g_runtimeKeyTables[keyIndex].data   = keyData;
        g_runtimeKeyTables[keyIndex].length = keyLength;
    }
    return true;
}

bool IsBtEncryptedBuffer(const uint8_t* data, size_t size) {
    if (data == nullptr || size < kBtDecryptHeaderSize) {
        return false;
    }
    return ReadLE32(data) == kBtDecryptMagic;
}

void LogDecryptFailure(const DecryptResult& diag, const char* contextPath) {
    char buf[512];
    std::snprintf(
        buf,
        sizeof(buf),
        "status=%s path=\"%s\" magic=0x%08X algo=%u keyIndex=%u headerPayload=%u actualPayload=%zu detail=\"%s\"",
        StatusToString(diag.status),
        contextPath ? contextPath : "<memory>",
        diag.magic,
        static_cast<unsigned>(diag.algoIndex),
        static_cast<unsigned>(diag.keyIndex),
        diag.headerPayloadSize,
        diag.actualPayloadSize,
        diag.message.c_str());
    LogMessage("ERROR", buf);
}

uint32_t DecryptBasic(uint8_t* data, uint32_t totalSize, DecryptResult* outDiag) {
    DecryptResult diag;
    if (data == nullptr) {
        diag.status  = DecryptStatus::InvalidBuffer;
        diag.message = "Null buffer passed to DecryptBasic";
        if (outDiag) *outDiag = diag;
        return 3u;
    }

    if (totalSize < kBtDecryptHeaderSize) {
        diag.status            = DecryptStatus::TruncatedHeader;
        diag.actualPayloadSize = 0;
        diag.message           = "Buffer smaller than 32-byte Win32 Client header";
        if (outDiag) *outDiag = diag;
        return 3u;
    }

    diag.magic             = ReadLE32(data);
    diag.headerPayloadSize = ReadLE32(data + 4);
    diag.algoIndex         = data[8];
    diag.keyIndex          = data[9];

    const uint32_t payloadLen = totalSize - static_cast<uint32_t>(kBtDecryptHeaderSize);
    diag.actualPayloadSize    = payloadLen;

    if (payloadLen != diag.headerPayloadSize) {
        diag.status  = DecryptStatus::PayloadLengthMismatch;
        diag.message = "Header payload size does not match (totalSize - 32)";
        if (outDiag) *outDiag = diag;
        return 3u;
    }

    if (diag.keyIndex > kBtMaxKeyIndex) {
        diag.status  = DecryptStatus::InvalidKeyIndex;
        diag.message = "Key index out of range (expected 0..15)";
        if (outDiag) *outDiag = diag;
        return 3u;
    }

    const BtKeyEntry key = ResolveKeyTable(diag.keyIndex);
    if (key.data == nullptr || key.length == 0) {
        WarnIfKeysMissingOnce();
        diag.status  = DecryptStatus::MissingKeyTable;
        diag.message = "Key table slot is empty (drop 07_bt_decrypt_keys.inc or register key)";
        if (outDiag) *outDiag = diag;
        return 3u;
    }

    // Matches decrypt_basic @ 0x340e4c:
    // XORs every even byte (i = 0, 2, 4, ...) of payload with
    // HASH_BITS[(i + (payloadLen % keyLen)) % keyLen].
    if (payloadLen > 0) {
        uint8_t*       payload = data + kBtDecryptHeaderSize;
        const uint32_t keyLen  = key.length;
        const uint32_t offset  = payloadLen % keyLen;
        for (uint32_t i = 0; i < payloadLen; i += 2) {
            const uint32_t idx = (i + offset) % keyLen;
            payload[i] ^= key.data[idx];
        }
    }

    diag.status  = DecryptStatus::Ok;
    diag.message = "Decrypted successfully";
    if (outDiag) *outDiag = diag;
    return 0u;
}

bool DecryptBuffer(uint8_t* data,
                   size_t* size,
                   const char* contextPath,
                   DecryptResult* outDiag) {
    DecryptResult diag;
    if (data == nullptr || size == nullptr) {
        diag.status  = DecryptStatus::InvalidBuffer;
        diag.message = "Null data or size pointer";
        LogDecryptFailure(diag, contextPath);
        if (outDiag) *outDiag = diag;
        return false;
    }

    if (*size < kBtDecryptHeaderSize) {
        diag.status            = DecryptStatus::NotEncrypted;
        diag.actualPayloadSize = *size;
        diag.message           = "Buffer shorter than 32-byte header; treating as plaintext";
        if (outDiag) *outDiag = diag;
        return false;
    }

    diag.magic             = ReadLE32(data);
    diag.headerPayloadSize = ReadLE32(data + 4);
    diag.algoIndex         = data[8];
    diag.keyIndex          = data[9];
    diag.actualPayloadSize = *size - kBtDecryptHeaderSize;

    // Plaintext pass-through: magic != 0xFEFEFEFE is normal for unencrypted assets.
    if (diag.magic != kBtDecryptMagic) {
        diag.status  = DecryptStatus::NotEncrypted;
        diag.message = "No 0xFEFEFEFE header; plaintext asset";
        if (outDiag) *outDiag = diag;
        return false;
    }

    // Dispatch on algoIndex (off_CC01A0[a1[8] + 16]):
    // algoIndex == 0 or 1 => decrypt_basic (07_bt_decrypt_keys.inc documents header[8] == 1).
    if (diag.algoIndex != 0 && diag.algoIndex != 1) {
        diag.status  = DecryptStatus::UnsupportedAlgoIndex;
        diag.message = "Unsupported encryption algorithm index in header[8]";
        LogDecryptFailure(diag, contextPath);
        if (outDiag) *outDiag = diag;
        return false;
    }

    const uint32_t rc = DecryptBasic(data, static_cast<uint32_t>(*size), &diag);
    if (rc != 0u) {
        LogDecryptFailure(diag, contextPath);
        if (outDiag) *outDiag = diag;
        return false;
    }

    // Strip the 32-byte header safely using memmove (overlapping regions) and
    // always NUL-terminate (plus clear the remaining reclaimed header tail) so
    // 0-byte encrypted payloads and text assets (.plist, .fnt, .json) never
    // expose trailing ciphertext or 0xFEFEFEFE to C-string parsers.
    const size_t payloadLen = *size - kBtDecryptHeaderSize;
    if (payloadLen > 0) {
        std::memmove(data, data + kBtDecryptHeaderSize, payloadLen);
    }
    data[payloadLen] = '\0';
    if (kBtDecryptHeaderSize > 1) {
        std::memset(data + payloadLen + 1, 0, kBtDecryptHeaderSize - 1);
    }
    *size = payloadLen;

    if (outDiag) *outDiag = diag;
    return true;
}

std::string NormalizeAssetPath(const std::string& rawPath) {
    if (rawPath.empty()) {
        return std::string();
    }

    std::string unified;
    unified.reserve(rawPath.size());
    for (char c : rawPath) {
        unified.push_back(c == '\\' ? '/' : c);
    }

    std::string prefix;
    size_t      pos                  = 0;
    bool        isAbsolute           = false;
    size_t      minProtectedSegments = 0;

    if (unified.size() >= 2 && unified[0] == '/' && unified[1] == '/' &&
        (unified.size() == 2 || unified[2] != '/')) {
        // Windows UNC prefix "//server/share/..."
        prefix               = "//";
        pos                  = 2;
        isAbsolute           = true;
        minProtectedSegments = 2;
    } else if (unified[0] == '/') {
        // POSIX leading slash
        prefix     = "/";
        isAbsolute = true;
        while (pos < unified.size() && unified[pos] == '/') {
            ++pos;
        }
    } else if (unified.size() >= 2 &&
               std::isalpha(static_cast<unsigned char>(unified[0])) &&
               unified[1] == ':') {
        if (unified.size() >= 3 && unified[2] == '/') {
            // Windows drive-absolute prefix "C:/"
            prefix     = unified.substr(0, 3);
            pos        = 3;
            isAbsolute = true;
            while (pos < unified.size() && unified[pos] == '/') {
                ++pos;
            }
        } else {
            // Windows drive-relative prefix "C:"
            prefix     = unified.substr(0, 2);
            pos        = 2;
            isAbsolute = false;
        }
    }

    const bool hadTrailingSlash = (pos < unified.size() && unified.back() == '/');

    std::vector<std::string> segments;
    while (pos < unified.size()) {
        while (pos < unified.size() && unified[pos] == '/') {
            ++pos;
        }
        if (pos >= unified.size()) {
            break;
        }
        const size_t nextSlash = unified.find('/', pos);
        const size_t segEnd    = (nextSlash == std::string::npos) ? unified.size() : nextSlash;
        std::string  seg       = unified.substr(pos, segEnd - pos);
        pos                    = segEnd;

        if (seg.empty() || seg == ".") {
            continue;
        }
        if (seg == "..") {
            if (segments.size() > minProtectedSegments && segments.back() != "..") {
                segments.pop_back();
            } else if (!isAbsolute) {
                segments.push_back(std::move(seg));
            }
        } else {
            segments.push_back(std::move(seg));
        }
    }

    if (segments.empty()) {
        if (!prefix.empty()) {
            return prefix;
        }
        if (unified == ".") {
            return ".";
        }
        return std::string();
    }

    std::string out = prefix;
    for (size_t i = 0; i < segments.size(); ++i) {
        if (i > 0) {
            out.push_back('/');
        }
        out.append(segments[i]);
    }

    if (hadTrailingSlash && !out.empty() && out.back() != '/') {
        out.push_back('/');
    }

    return out;
}

std::string ResolveRelativeAssetPath(const std::string& relativePath,
                                     const std::string& baseFilePath) {
    const std::string normRel  = NormalizeAssetPath(relativePath);
    const std::string normBase = NormalizeAssetPath(baseFilePath);

    if (normRel.empty()) {
        return normBase;
    }

    // Already absolute (POSIX root, UNC, or Windows drive letter like C:/...).
    if (normRel[0] == '/' || (normRel.size() >= 2 && normRel[1] == ':')) {
        return normRel;
    }

    const size_t slashPos = normBase.find_last_of('/');
    if (slashPos == std::string::npos) {
        return normRel;
    }

    return NormalizeAssetPath(normBase.substr(0, slashPos + 1) + normRel);
}

std::string ReplaceFileExtension(const std::string& path, const std::string& newExt) {
    const std::string norm     = NormalizeAssetPath(path);
    const size_t      slashPos = norm.find_last_of('/');
    const size_t      dotPos   = norm.find_last_of('.');

    if (dotPos == std::string::npos ||
        (slashPos != std::string::npos && dotPos < slashPos)) {
        return norm + newExt;
    }
    return norm.substr(0, dotPos) + newExt;
}

unsigned char* LoadAndDecryptFileData(const std::string& filePath,
                                      unsigned long* outSize,
                                      DecryptResult* outDiag) {
    if (outSize) {
        *outSize = 0;
    }
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normPath = NormalizeAssetPath(filePath);
    if (normPath.empty()) {
        return nullptr;
    }
    auto* fu = cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) {
        return nullptr;
    }

    const std::string fullPath = fu->fullPathForFilename(normPath.c_str());
    unsigned long     rawSize  = 0;
    unsigned char*    buffer   = fu->getFileData(fullPath.c_str(), "rb", &rawSize);
    if (!buffer || rawSize == 0) {
        delete[] buffer;
        return nullptr;
    }

    // Guard truncated 0xFEFEFEFE files (< 32 bytes) so raw magic bytes never leak.
    if (rawSize >= 4 && rawSize < kBtDecryptHeaderSize && ReadLE32(buffer) == kBtDecryptMagic) {
        DecryptResult diag;
        diag.status            = DecryptStatus::TruncatedHeader;
        diag.magic             = kBtDecryptMagic;
        diag.actualPayloadSize = 0;
        diag.message           = "Truncated 0xFEFEFEFE header (< 32 bytes)";
        LogDecryptFailure(diag, fullPath.c_str());
        if (outDiag) *outDiag = diag;
        delete[] buffer;
        return nullptr;
    }

    // If CCFileUtils::getFileData did not strip the 0xFEFEFEFE header (or if its
    // callback failed), run DecryptBuffer explicitly and reject any failure or
    // 0-byte payload rather than returning raw ciphertext to callers.
    if (IsBtEncryptedBuffer(buffer, static_cast<size_t>(rawSize))) {
        size_t sz = static_cast<size_t>(rawSize);
        if (!DecryptBuffer(buffer, &sz, fullPath.c_str(), outDiag) || sz == 0) {
            delete[] buffer;
            return nullptr;
        }
        rawSize = static_cast<unsigned long>(sz);
    } else if (outDiag) {
        outDiag->status            = DecryptStatus::NotEncrypted;
        outDiag->actualPayloadSize = static_cast<size_t>(rawSize);
        outDiag->message           = "Plaintext or already decrypted by CCFileUtils";
    }

    if (outSize) {
        *outSize = rawSize;
    }
    return buffer;
#else
    (void)filePath;
    (void)outDiag;
    return nullptr;
#endif
}

void InstallBtDecryptHook(cocos2d::CCFileUtils* fileUtils) {
    WarnIfKeysMissingOnce();

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    cocos2d::CCFileUtils* fu = fileUtils ? fileUtils : cocos2d::CCFileUtils::sharedFileUtils();
    if (!fu) {
        LogMessage("ERROR", "InstallBtDecryptHook called before CCFileUtils::sharedFileUtils() is ready");
        return;
    }
#if defined(GCLIENT_CCFILEUTILS_HAS_SET_DECRYPT)
    fu->setDecrypt(bt_decrypt);
    fu->setDecryptor(bt_decrypt);
    LogMessage("INFO", "Registered bt_decrypt callback on CCFileUtils");
#else
    (void)fu;
    LogMessage("INFO", "BtDecryptHook initialized (using explicit LoadAndDecryptFileData path)");
#endif
#else
    (void)fileUtils;
#endif
}

} // namespace assets
} // namespace gclient

bool bt_decrypt(unsigned char* data, unsigned long* size) {
    if (data == nullptr || size == nullptr) {
        return false;
    }
    size_t sz = static_cast<size_t>(*size);
    const bool ok = gclient::assets::DecryptBuffer(data, &sz, nullptr, nullptr);
    if (ok) {
        *size = static_cast<unsigned long>(sz);
    }
    return ok;
}

bool bt_decrypt_u64(uint8_t* data, uint64_t* size) {
    if (data == nullptr || size == nullptr) {
        return false;
    }
    size_t sz = static_cast<size_t>(*size);
    const bool ok = gclient::assets::DecryptBuffer(data, &sz, nullptr, nullptr);
    if (ok) {
        *size = static_cast<uint64_t>(sz);
    }
    return ok;
}

uint32_t decrypt_basic(uint8_t* data, int totalSize) {
    if (totalSize < 0) {
        return 3u;
    }
    return gclient::assets::DecryptBasic(data, static_cast<uint32_t>(totalSize), nullptr);
}
