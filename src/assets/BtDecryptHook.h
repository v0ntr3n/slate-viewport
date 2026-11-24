#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace cocos2d {
class CCFileUtils;
}

namespace gclient {
namespace assets {

// ============================================================================
// BtDecryptHook - Win32 Client Asset Decryption & Path Normalization (Win32 Port)
//
// Ported from libcocos2dlua.so (arm64-v8a):
//   - bt_decrypt             @ 0x340ef4
//   - decrypt_basic          @ 0x340e4c
//   - CCFileUtils::setDecrypt @ 0x655ba8
//
// Binary Header Layout (32 bytes, little-endian):
//   [0..3]   uint32_t magic        == 0xFEFEFEFE (-16843010)
//   [4..7]   uint32_t payloadSize  == totalSize - 32
//   [8]      uint8_t  algoIndex    (0 => decrypt_basic)
//   [9]      uint8_t  keyIndex     (0..15 => key table slot)
//   [10..31] uint8_t  reserved[22]
// ============================================================================

constexpr uint32_t kBtDecryptMagic      = 0xFEFEFEFEu;
constexpr size_t   kBtDecryptHeaderSize = 32;
constexpr uint8_t  kBtMaxKeyIndex       = 15;
constexpr size_t   kBtKeyTableCount     = 16;
constexpr size_t   kBtMaxKeyLength      = 508;

enum class DecryptStatus : uint32_t {
    Ok                    = 0,
    NotEncrypted          = 1,
    InvalidBuffer         = 2,
    TruncatedHeader       = 3,
    PayloadLengthMismatch = 4,
    UnsupportedAlgoIndex  = 5,
    InvalidKeyIndex       = 6,
    MissingKeyTable       = 7,
};

struct DecryptResult {
    DecryptStatus status            = DecryptStatus::Ok;
    uint32_t      magic             = 0;
    uint8_t       algoIndex         = 0;
    uint8_t       keyIndex          = 0;
    uint32_t      headerPayloadSize = 0;
    size_t        actualPayloadSize = 0;
    std::string   message;

    bool ok() const { return status == DecryptStatus::Ok; }
};

struct BtKeyEntry {
    const uint8_t* data   = nullptr;
    uint32_t       length = 0;
};

// Returns true if 07_bt_decrypt_keys.inc was compiled in or runtime keys were registered.
bool HasDecryptKeys();

// Optional runtime override/registration for a key slot (0..15). Thread-safe.
bool RegisterKeyTable(uint8_t keyIndex, const uint8_t* keyData, uint32_t keyLength);

// Checks whether a buffer begins with the 0xFEFEFEFE 32-byte header.
bool IsBtEncryptedBuffer(const uint8_t* data, size_t size);

// Core decrypt_basic port (operates in-place on data + 32, does NOT strip header).
// Returns 0 on success, 3 on failure (matching original ARM64 return contract).
uint32_t DecryptBasic(uint8_t* data, uint32_t totalSize, DecryptResult* outDiag = nullptr);

// Full in-place decrypt + 32-byte header strip + NUL termination with structured diagnostics.
// Safe on overlapping memory (uses memmove instead of memcpy) and always writes
// data[payloadLen] = '\0' within the reclaimed 32-byte header space.
bool DecryptBuffer(uint8_t* data,
                   size_t* size,
                   const char* contextPath = nullptr,
                   DecryptResult* outDiag = nullptr);

// Canonical POSIX '/' path normalization for Win32 Cocos2d-x asset lookups:
//   - Replaces all '\' with '/'
//   - Collapses redundant consecutive '/' (preserving UNC "//", leading "/", and drive prefixes)
//   - Collapses "." and ".." segments cleanly (preserving leading ".." on relative paths)
std::string NormalizeAssetPath(const std::string& rawPath);

// Resolves a relative asset path against a base file path using POSIX '/' separators.
std::string ResolveRelativeAssetPath(const std::string& relativePath,
                                     const std::string& baseFilePath);

// Replaces or appends a file extension on a normalized POSIX path.
std::string ReplaceFileExtension(const std::string& path, const std::string& newExt);

// Convenience helper: reads a file via CCFileUtils::sharedFileUtils()->getFileData()
// and ensures bt_decrypt has been applied even on stock Cocos2d-x 2.2.6 Win32 builds
// that do not have CCFileUtils::setDecrypt patched in.
// Never returns raw undecrypted 0xFEFEFEFE bytes or 0-byte encrypted payloads.
// Caller owns the returned buffer and must release it with `delete[]`.
unsigned char* LoadAndDecryptFileData(const std::string& filePath,
                                      unsigned long* outSize,
                                      DecryptResult* outDiag = nullptr);

// Registers bt_decrypt with CCFileUtils (if patched with setDecrypt/setDecryptor)
// and logs key-table readiness.
void InstallBtDecryptHook(cocos2d::CCFileUtils* fileUtils = nullptr);

// Structured error logger for decryption failures.
void LogDecryptFailure(const DecryptResult& diag, const char* contextPath = nullptr);

} // namespace assets
} // namespace gclient

// ============================================================================
// C-ABI / Cocos2d-x 2.2.6 Callback Entry Points
// ============================================================================

// Matches Cocos2d-x 2.2.6 Win32 CCFileUtils decryptor callback (unsigned long*).
bool bt_decrypt(unsigned char* data, unsigned long* size);

// Matches 64-bit ARM64/x64 callback signature (uint64_t*).
bool bt_decrypt_u64(uint8_t* data, uint64_t* size);

// Direct port of decrypt_basic @ 0x340e4c.
uint32_t decrypt_basic(uint8_t* data, int totalSize);
