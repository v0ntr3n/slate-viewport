#pragma once

#include <cstddef>
#include <string>

class CCCrypto {
public:
    enum DigestType {
        EDigestMD5 = 1,
        EDigestSha1 = 2
    };

    static std::string md5(const void* data, size_t len, bool raw = false);
    static std::string sha1(const void* data, size_t len, bool raw = false);
    static std::string bin2hex(const void* data, size_t len);
    static std::string hex2bin(const std::string& hex);
    static std::string encodeBase64(const void* data, size_t len);
    static std::string decodeBase64(const std::string& b64);
};
