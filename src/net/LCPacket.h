#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace gclient::net {

/// Win32 Client / BabelTime LC packet framing, zlib compression, and MD5 integrity helpers.
/// Ported from `GameUtil::makeLCPacket`, `zipData`, `unzipData`, `getU32`, `writeU32`
/// in `libcocos2dlua.so` (`03_libcocos2dlua_network_and_packets.c`).
class LCPacket {
public:
    static constexpr size_t kHeaderLengthSize = 4;   // Big-endian uint32 payload length
    static constexpr size_t kHeaderFlagsSize  = 4;   // Protocol flag bytes (default: {1, 1, 1, 1})
    static constexpr size_t kHeaderMd5Size    = 16;  // Raw 16-byte MD5 digest
    static constexpr size_t kTotalHeaderSize  = kHeaderLengthSize + kHeaderFlagsSize + kHeaderMd5Size; // 24 bytes

    struct DecodedPacket {
        uint32_t bodyLength = 0;
        std::array<uint8_t, kHeaderFlagsSize> flags{0, 0, 0, 0};
        std::array<uint8_t, kHeaderMd5Size> md5{};
        std::string payload;       // Decompressed (if requested) or raw body bytes
        bool md5Valid = false;
    };

    /// Builds a BabelTime LC packet matching `GameUtil::makeLCPacket`:
    ///   1. Optionally compresses `rawPayload` with zlib (`compress2`).
    ///   2. Computes 16-byte raw MD5 over `"BabelTime"` + adjacent-byte XOR stream
    ///      (last byte XORed with payload length low 8 bits).
    ///   3. Prepends 24-byte header:
    ///        [0..3]  Big-endian uint32 length of body
    ///        [4..7]  Flags (`{1, 1, 1, 1}` when compressed, `{0, 1, 1, 1}` when uncompressed)
    ///        [8..23] 16-byte raw MD5 digest
    ///      followed by the body bytes.
    static std::string makeLCPacket(const std::string& rawPayload, bool compressPayload = true);
    static std::string makeLCPacket(const void* data, size_t size, bool compressPayload = true);

    /// Returns true if `data` already carries a valid 24-byte BabelTime LCPacket header
    /// (matching body length, protocol flags `{0|1, 1, 1, 1}`, and 16-byte BabelTime MD5).
    static bool isFramedLCPacket(const void* data, size_t size);

    /// Parses and verifies a framed LC packet (24-byte header + body).
    /// Returns true if framing is valid (and decompression succeeds when `decompress` is true).
    static bool parseLCPacket(const void* packetData, size_t packetSize,
                              DecodedPacket& outPacket, bool decompress = true);

    /// Computes the BabelTime integrity MD5 digest for a packet body buffer.
    static std::array<uint8_t, kHeaderMd5Size> computeBabelTimeMd5(const uint8_t* body, size_t bodySize);

    /// Standard zlib compression (`compress2`, matches `ZipUtils::compress` / `zipDataVn`).
    static bool zlibCompress(const uint8_t* input, size_t inputSize, std::string& output);

    /// Standard zlib decompression (`uncompress` / `inflate`, matches `unzipData`).
    static bool zlibDecompress(const uint8_t* input, size_t inputSize, std::string& output,
                               size_t maxOutputSize = 64 * 1024 * 1024);

    /// Big-endian 32-bit unsigned integer helpers (matching `GameUtil::getU32` / `writeU32`).
    static uint32_t readBigEndianU32(const uint8_t* data);
    static void writeBigEndianU32(uint8_t* out, uint32_t value);
};

} // namespace gclient::net
