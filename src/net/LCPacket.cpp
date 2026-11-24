#include "LCPacket.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>

namespace gclient::net {

namespace {

// Self-contained RFC 1321 MD5 implementation (zero external OpenSSL dependency on Win32).
struct Md5Context {
    uint32_t state[4];
    uint64_t bitCount;
    uint8_t buffer[64];
};

constexpr uint32_t kMd5Shift[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

constexpr uint32_t kMd5Table[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

inline uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32u - n));
}

inline uint32_t readLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void writeLe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFFu);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
}

void md5Init(Md5Context& ctx) {
    ctx.state[0] = 0x67452301u;
    ctx.state[1] = 0xefcdab89u;
    ctx.state[2] = 0x98badcfeu;
    ctx.state[3] = 0x10325476u;
    ctx.bitCount = 0;
}

void md5Transform(Md5Context& ctx, const uint8_t block[64]) {
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = readLe32(block + i * 4);
    }

    uint32_t a = ctx.state[0];
    uint32_t b = ctx.state[1];
    uint32_t c = ctx.state[2];
    uint32_t d = ctx.state[3];

    for (uint32_t i = 0; i < 64; ++i) {
        uint32_t f = 0;
        uint32_t g = 0;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5u * i + 1u) & 15u;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3u * i + 5u) & 15u;
        } else {
            f = c ^ (b | (~d));
            g = (7u * i) & 15u;
        }
        const uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + kMd5Table[i] + m[g], kMd5Shift[i]);
        a = tmp;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
}

void md5Update(Md5Context& ctx, const uint8_t* data, size_t len) {
    size_t idx = static_cast<size_t>((ctx.bitCount >> 3) & 63u);
    ctx.bitCount += static_cast<uint64_t>(len) * 8u;

    size_t i = 0;
    if (idx > 0) {
        const size_t partLen = 64u - idx;
        if (len >= partLen) {
            std::memcpy(ctx.buffer + idx, data, partLen);
            md5Transform(ctx, ctx.buffer);
            i = partLen;
            idx = 0;
        } else {
            std::memcpy(ctx.buffer + idx, data, len);
            return;
        }
    }

    while (i + 64u <= len) {
        md5Transform(ctx, data + i);
        i += 64u;
    }

    if (i < len) {
        std::memcpy(ctx.buffer, data + i, len - i);
    }
}

std::array<uint8_t, 16> md5Final(Md5Context& ctx) {
    uint8_t bits[8];
    writeLe32(bits, static_cast<uint32_t>(ctx.bitCount & 0xFFFFFFFFu));
    writeLe32(bits + 4, static_cast<uint32_t>((ctx.bitCount >> 32) & 0xFFFFFFFFu));

    const size_t idx = static_cast<size_t>((ctx.bitCount >> 3) & 63u);
    const size_t padLen = (idx < 56u) ? (56u - idx) : (120u - idx);

    uint8_t padding[64]{};
    padding[0] = 0x80u;
    md5Update(ctx, padding, padLen);
    md5Update(ctx, bits, 8u);

    std::array<uint8_t, 16> digest{};
    for (int i = 0; i < 4; ++i) {
        writeLe32(digest.data() + i * 4, ctx.state[i]);
    }
    return digest;
}

} // namespace

uint32_t LCPacket::readBigEndianU32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

void LCPacket::writeBigEndianU32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>((value >> 24) & 0xFFu);
    out[1] = static_cast<uint8_t>((value >> 16) & 0xFFu);
    out[2] = static_cast<uint8_t>((value >> 8) & 0xFFu);
    out[3] = static_cast<uint8_t>(value & 0xFFu);
}

bool LCPacket::zlibCompress(const uint8_t* input, size_t inputSize, std::string& output) {
    if (input == nullptr && inputSize > 0) {
        return false;
    }

    static const uint8_t kEmptyByte = 0;
    const Bytef* srcPtr = (input != nullptr) ? reinterpret_cast<const Bytef*>(input) : &kEmptyByte;
    uLongf destLen = compressBound(static_cast<uLong>(inputSize));
    output.resize(static_cast<size_t>(destLen));

    const int rc = compress2(
        reinterpret_cast<Bytef*>(output.data()),
        &destLen,
        srcPtr,
        static_cast<uLong>(inputSize),
        Z_DEFAULT_COMPRESSION);

    if (rc != Z_OK) {
        output.clear();
        return false;
    }

    output.resize(static_cast<size_t>(destLen));
    return true;
}

bool LCPacket::zlibDecompress(const uint8_t* input, size_t inputSize, std::string& output,
                              size_t maxOutputSize) {
    if (input == nullptr || inputSize == 0) {
        output.clear();
        return inputSize == 0;
    }

    z_stream strm{};
    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input));
    strm.avail_in = static_cast<uInt>(inputSize);

    // 15 + 32 enables automatic zlib/gzip header detection.
    int rc = inflateInit2(&strm, 15 + 32);
    if (rc != Z_OK) {
        return false;
    }

    output.clear();
    uint8_t chunk[16384];
    do {
        strm.next_out = chunk;
        strm.avail_out = sizeof(chunk);
        rc = inflate(&strm, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&strm);
            output.clear();
            return false;
        }
        const size_t produced = sizeof(chunk) - strm.avail_out;
        if (output.size() + produced > maxOutputSize) {
            inflateEnd(&strm);
            output.clear();
            return false;
        }
        output.append(reinterpret_cast<const char*>(chunk), produced);
    } while (rc != Z_STREAM_END);

    inflateEnd(&strm);
    return true;
}

std::array<uint8_t, LCPacket::kHeaderMd5Size> LCPacket::computeBabelTimeMd5(
    const uint8_t* body, size_t bodySize) {
    // Matches `GameUtil::makeLCPacket` @ 0x2b4b04:
    //   buf[0..8]   = "BabelTime"
    //   buf[9 + i]  = body[i + 1] ^ body[i]       for 0 <= i < bodySize - 1
    //   buf[9 + N-1]= body[N - 1] ^ (N & 0xFF)    for i == bodySize - 1
    static constexpr char kSalt[9] = {'B', 'a', 'b', 'e', 'l', 'T', 'i', 'm', 'e'};

    std::vector<uint8_t> hashInput(9 + bodySize);
    std::memcpy(hashInput.data(), kSalt, 9);

    if (body != nullptr && bodySize > 0) {
        for (size_t i = 0; i + 1 < bodySize; ++i) {
            hashInput[9 + i] = static_cast<uint8_t>(body[i + 1] ^ body[i]);
        }
        hashInput[9 + bodySize - 1] =
            static_cast<uint8_t>(body[bodySize - 1] ^ static_cast<uint8_t>(bodySize & 0xFFu));
    }

    Md5Context ctx{};
    md5Init(ctx);
    md5Update(ctx, hashInput.data(), hashInput.size());
    return md5Final(ctx);
}

std::string LCPacket::makeLCPacket(const std::string& rawPayload, bool compressPayload) {
    return makeLCPacket(rawPayload.data(), rawPayload.size(), compressPayload);
}

std::string LCPacket::makeLCPacket(const void* data, size_t size, bool compressPayload) {
    const auto* rawBytes = static_cast<const uint8_t*>(data);

    std::string body;
    if (compressPayload) {
        if (!zlibCompress(rawBytes, size, body)) {
            return {};
        }
    } else if (rawBytes != nullptr && size > 0) {
        body.assign(reinterpret_cast<const char*>(rawBytes), size);
    }

    const uint32_t bodyLen = static_cast<uint32_t>(body.size());
    const auto md5Digest = computeBabelTimeMd5(
        reinterpret_cast<const uint8_t*>(body.data()), body.size());

    std::string packet(kTotalHeaderSize + body.size(), '\0');
    auto* out = reinterpret_cast<uint8_t*>(packet.data());

    // [0..3] Big-endian body length
    writeBigEndianU32(out, bodyLen);

    // [4..7] Protocol flags: {1, 1, 1, 1} matches libcocos2dlua.so GameUtil::makeLCPacket
    out[4] = compressPayload ? 1u : 0u;
    out[5] = 1u;
    out[6] = 1u;
    out[7] = 1u;

    // [8..23] Raw 16-byte BabelTime MD5 digest
    std::memcpy(out + 8, md5Digest.data(), kHeaderMd5Size);

    // [24..] Payload bytes
    if (!body.empty()) {
        std::memcpy(out + kTotalHeaderSize, body.data(), body.size());
    }

    return packet;
}

bool LCPacket::isFramedLCPacket(const void* data, size_t size) {
    if (data == nullptr || size < kTotalHeaderSize) {
        return false;
    }

    const auto* bytes = static_cast<const uint8_t*>(data);
    const size_t actualBodySize = size - kTotalHeaderSize;
    const uint32_t declaredBodyLen = readBigEndianU32(bytes);
    if (static_cast<size_t>(declaredBodyLen) != actualBodySize) {
        return false;
    }

    if ((bytes[4] != 0u && bytes[4] != 1u) ||
        bytes[5] != 1u || bytes[6] != 1u || bytes[7] != 1u) {
        return false;
    }

    const auto expectedMd5 = computeBabelTimeMd5(bytes + kTotalHeaderSize, actualBodySize);
    return std::memcmp(bytes + 8, expectedMd5.data(), kHeaderMd5Size) == 0;
}

bool LCPacket::parseLCPacket(const void* packetData, size_t packetSize,
                             DecodedPacket& outPacket, bool decompress) {
    if (packetData == nullptr || packetSize < kTotalHeaderSize) {
        return false;
    }

    const auto* bytes = static_cast<const uint8_t*>(packetData);
    const uint32_t bodyLen = readBigEndianU32(bytes);
    if (static_cast<size_t>(bodyLen) > packetSize - kTotalHeaderSize) {
        return false;
    }

    outPacket.bodyLength = bodyLen;
    std::memcpy(outPacket.flags.data(), bytes + 4, kHeaderFlagsSize);
    std::memcpy(outPacket.md5.data(), bytes + 8, kHeaderMd5Size);

    const uint8_t* bodyPtr = bytes + kTotalHeaderSize;
    const auto expectedMd5 = computeBabelTimeMd5(bodyPtr, bodyLen);
    outPacket.md5Valid = (expectedMd5 == outPacket.md5);

    const bool isCompressed = (outPacket.flags[0] != 0);
    if (decompress && isCompressed) {
        if (!zlibDecompress(bodyPtr, bodyLen, outPacket.payload)) {
            return false;
        }
    } else {
        outPacket.payload.assign(reinterpret_cast<const char*>(bodyPtr), bodyLen);
    }

    return true;
}

} // namespace gclient::net
