#include "GameUtil.h"
#include "CCCrypto.h"
#if defined(__has_include)
#  if __has_include("net/LCPacket.h")
#    include "net/LCPacket.h"
#  elif __has_include("../net/LCPacket.h")
#    include "../net/LCPacket.h"
#  else
#    include "net/LCPacket.h"
#  endif
#else
#  include "net/LCPacket.h"
#endif

#include "support/zip_support/unzip.h"
#include <zlib.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#  include <direct.h>
#  include <io.h>
#else
#  include <unistd.h>
#endif

USING_NS_CC;
namespace fs = std::filesystem;

namespace {

unsigned char fromHex(unsigned char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
    return 0;
}

#ifdef _WIN32
std::wstring utf8ToWide(const char* utf8) {
    if (!utf8 || !*utf8) return {};
    const int req = ::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (req <= 0) return {};
    std::wstring w(static_cast<size_t>(req), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w.data(), req);
    if (!w.empty() && w.back() == L'\0') {
        w.pop_back();
    }
    return w;
}

std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int req = ::WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (req <= 0) return {};
    std::string out(static_cast<size_t>(req), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), req, nullptr, nullptr);
    return out;
}
#endif

fs::path utf8ToPath(const char* utf8) {
    if (!utf8 || !*utf8) return {};
#ifdef _WIN32
    std::wstring w = utf8ToWide(utf8);
    if (w.empty()) return {};
    return fs::path(w);
#else
    return fs::path(utf8);
#endif
}

std::string pathToUtf8(const fs::path& p) {
#ifdef _WIN32
    return wideToUtf8(p.wstring());
#else
    return p.string();
#endif
}

FILE* openFileRb(const fs::path& p) {
    if (p.empty()) return nullptr;
#ifdef _WIN32
    return ::_wfopen(p.c_str(), L"rb");
#else
    return std::fopen(p.c_str(), "rb");
#endif
}

FILE* openFileWb(const fs::path& p) {
    if (p.empty()) return nullptr;
#ifdef _WIN32
    return ::_wfopen(p.c_str(), L"wb");
#else
    return std::fopen(p.c_str(), "wb");
#endif
}

bool normalizeZipEntryRelativePath(const char* rawEntryName, fs::path& outRel, bool& outIsDir) {
    outRel.clear();
    outIsDir = false;
    if (!rawEntryName || !*rawEntryName) {
        return false;
    }

    std::string normalized(rawEntryName);
    for (char& ch : normalized) {
        if (ch == '\\') ch = '/';
    }
    if (!normalized.empty() && normalized.back() == '/') {
        outIsDir = true;
    }
    while (!normalized.empty() && normalized.front() == '/') {
        normalized.erase(normalized.begin());
    }
    while (!normalized.empty() && normalized.back() == '/') {
        normalized.pop_back();
    }
    if (normalized.empty()) {
        return outIsDir;
    }

    const fs::path candidate = utf8ToPath(normalized.c_str());
    if (candidate.empty() || candidate.is_absolute() || candidate.has_root_name()) {
        return false;
    }
    for (const fs::path& part : candidate) {
        if (part == "..") {
            return false;
        }
    }
    outRel = candidate;
    return true;
}

inline uint16_t readZipLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t readZipLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// Unicode-safe Central Directory ZIP extractor used when unzOpen cannot open UTF-8 paths on Win32
// (or when minizip is unavailable in standalone harnesses).
int extractZipViaFileStream(FILE* zfp, const fs::path& baseDir) {
    if (std::fseek(zfp, 0, SEEK_END) != 0) {
        return GameUtil::EUnzipBadFile;
    }
    const long fileLenLong = std::ftell(zfp);
    if (fileLenLong < 22) {
        return GameUtil::EUnzipBadFile;
    }
    const size_t fileLen = static_cast<size_t>(fileLenLong);
    const size_t tailLen = std::min<size_t>(fileLen, 65557u);
    std::vector<uint8_t> tail(tailLen);
    if (std::fseek(zfp, static_cast<long>(fileLen - tailLen), SEEK_SET) != 0 ||
        std::fread(tail.data(), 1, tailLen, zfp) != tailLen) {
        return GameUtil::EUnzipBadFile;
    }

    size_t eocdPos = tailLen;
    for (size_t i = tailLen - 22; ; --i) {
        if (readZipLe32(tail.data() + i) == 0x06054b50u) {
            eocdPos = i;
            break;
        }
        if (i == 0) break;
    }
    if (eocdPos == tailLen) {
        return GameUtil::EUnzipBadFile;
    }

    const uint8_t* eocd = tail.data() + eocdPos;
    const uint16_t totalEntries = readZipLe16(eocd + 10);
    const uint32_t cdSize = readZipLe32(eocd + 12);
    const uint32_t cdOffset = readZipLe32(eocd + 16);
    if (static_cast<size_t>(cdOffset) + static_cast<size_t>(cdSize) > fileLen) {
        return GameUtil::EUnzipBadFile;
    }

    std::vector<uint8_t> cd(cdSize);
    if (cdSize > 0) {
        if (std::fseek(zfp, static_cast<long>(cdOffset), SEEK_SET) != 0 ||
            std::fread(cd.data(), 1, cdSize, zfp) != cdSize) {
            return GameUtil::EUnzipBadFile;
        }
    }

    size_t cdCursor = 0;
    uint8_t inBuf[16384];
    uint8_t outBuf[16384];

    for (uint16_t idx = 0; idx < totalEntries; ++idx) {
        if (cdCursor + 46 > cd.size()) {
            return GameUtil::EUnzipBadFile;
        }
        const uint8_t* entry = cd.data() + cdCursor;
        if (readZipLe32(entry) != 0x02014b50u) {
            return GameUtil::EUnzipBadFile;
        }

        const uint16_t method = readZipLe16(entry + 10);
        const uint32_t compSize = readZipLe32(entry + 20);
        const uint16_t nameLen = readZipLe16(entry + 28);
        const uint16_t extraLen = readZipLe16(entry + 30);
        const uint16_t commentLen = readZipLe16(entry + 32);
        const uint32_t localHeaderOff = readZipLe32(entry + 42);

        if (cdCursor + 46 + nameLen + extraLen + commentLen > cd.size()) {
            return GameUtil::EUnzipBadFile;
        }
        std::string entryName(reinterpret_cast<const char*>(entry + 46), nameLen);
        cdCursor += 46 + nameLen + extraLen + commentLen;

        fs::path relPath;
        bool isDir = false;
        if (!normalizeZipEntryRelativePath(entryName.c_str(), relPath, isDir)) {
            return GameUtil::EUnzipBadFile;
        }
        const fs::path targetPath = baseDir.empty() ? relPath : (baseDir / relPath);
        if (targetPath.empty()) {
            continue;
        }

        if (isDir) {
            std::error_code ec;
            if (!fs::is_directory(targetPath, ec) && !fs::create_directories(targetPath, ec)) {
                return GameUtil::EUnzipOutOfStorage;
            }
            continue;
        }

        if (static_cast<size_t>(localHeaderOff) + 30 > fileLen) {
            return GameUtil::EUnzipBadFile;
        }
        uint8_t localHdr[30];
        if (std::fseek(zfp, static_cast<long>(localHeaderOff), SEEK_SET) != 0 ||
            std::fread(localHdr, 1, sizeof(localHdr), zfp) != sizeof(localHdr) ||
            readZipLe32(localHdr) != 0x04034b50u) {
            return GameUtil::EUnzipBadFile;
        }
        const uint16_t localNameLen = readZipLe16(localHdr + 26);
        const uint16_t localExtraLen = readZipLe16(localHdr + 28);
        const size_t dataOffset = static_cast<size_t>(localHeaderOff) + 30u + localNameLen + localExtraLen;
        if (dataOffset + compSize > fileLen ||
            std::fseek(zfp, static_cast<long>(dataOffset), SEEK_SET) != 0) {
            return GameUtil::EUnzipBadFile;
        }

        std::error_code ec;
        const fs::path parent = targetPath.parent_path();
        if (!parent.empty()) {
            fs::create_directories(parent, ec);
        }
        FILE* fp = openFileWb(targetPath);
        if (!fp) {
            return GameUtil::EUnzipBadFile;
        }

        if (method == 0) {
            size_t rem = compSize;
            while (rem > 0) {
                const size_t chunk = std::min<size_t>(rem, sizeof(inBuf));
                if (std::fread(inBuf, 1, chunk, zfp) != chunk) {
                    std::fclose(fp);
                    return GameUtil::EUnzipBadFile;
                }
                if (std::fwrite(inBuf, 1, chunk, fp) != chunk) {
                    std::fclose(fp);
                    return GameUtil::EUnzipOutOfStorage;
                }
                rem -= chunk;
            }
        } else if (method == 8) {
            z_stream strm{};
            if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
                std::fclose(fp);
                return GameUtil::EUnzipBadFile;
            }
            size_t rem = compSize;
            int zrc = Z_OK;
            while (rem > 0 && zrc != Z_STREAM_END) {
                const size_t chunk = std::min<size_t>(rem, sizeof(inBuf));
                if (std::fread(inBuf, 1, chunk, zfp) != chunk) {
                    inflateEnd(&strm);
                    std::fclose(fp);
                    return GameUtil::EUnzipBadFile;
                }
                rem -= chunk;
                strm.next_in = inBuf;
                strm.avail_in = static_cast<uInt>(chunk);
                do {
                    strm.next_out = outBuf;
                    strm.avail_out = sizeof(outBuf);
                    zrc = inflate(&strm, Z_NO_FLUSH);
                    if (zrc != Z_OK && zrc != Z_STREAM_END) {
                        inflateEnd(&strm);
                        std::fclose(fp);
                        return GameUtil::EUnzipBadFile;
                    }
                    const size_t produced = sizeof(outBuf) - strm.avail_out;
                    if (produced > 0 && std::fwrite(outBuf, 1, produced, fp) != produced) {
                        inflateEnd(&strm);
                        std::fclose(fp);
                        return GameUtil::EUnzipOutOfStorage;
                    }
                } while (strm.avail_out == 0);
            }
            inflateEnd(&strm);
            if (zrc != Z_STREAM_END && compSize > 0) {
                std::fclose(fp);
                return GameUtil::EUnzipBadFile;
            }
        } else {
            std::fclose(fp);
            return GameUtil::EUnzipBadFile;
        }

        std::fclose(fp);
    }

    return GameUtil::EUnzipOk;
}

} // namespace

int GameUtil::rename(const char* oldPath, const char* newPath) {
    if (!oldPath || !newPath) return -1;
#ifdef _WIN32
    const std::wstring oldW = utf8ToWide(oldPath);
    const std::wstring newW = utf8ToWide(newPath);
    if (oldW.empty() || newW.empty()) return -1;
    std::error_code ec;
    const fs::path parent = fs::path(newW).parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
    }
    return ::MoveFileExW(oldW.c_str(), newW.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) ? 0 : -1;
#else
    std::error_code ec;
    const fs::path parent = fs::path(newPath).parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
    }
    return std::rename(oldPath, newPath);
#endif
}

int GameUtil::mkdir(const char* path) {
    if (!path || !*path) return -1;
    const fs::path p = utf8ToPath(path);
    if (p.empty()) return -1;
    std::error_code ec;
    if (fs::is_directory(p, ec)) return 0;
    ec.clear();
    return (fs::create_directories(p, ec) || fs::is_directory(p, ec)) ? 0 : -1;
}

int GameUtil::rmdir(const char* path) {
    if (!path || !*path) return -1;
    const fs::path p = utf8ToPath(path);
    if (p.empty()) return -1;
    std::error_code ec;
    return fs::remove(p, ec) ? 0 : -1;
}

int GameUtil::unlink(const char* path) {
    if (!path || !*path) return -1;
#ifdef _WIN32
    const std::wstring w = utf8ToWide(path);
    if (w.empty()) return -1;
    return ::_wunlink(w.c_str());
#else
    return ::unlink(path);
#endif
}

int GameUtil::access(const char* path, int mode) {
    if (!path || !*path) return -1;
#ifdef _WIN32
    const std::wstring w = utf8ToWide(path);
    if (w.empty()) return -1;
    // MSVC _waccess only supports 00 (existence), 02 (write), 04 (read), and 06 (read/write);
    // masking bit 1 avoids MSVC invalid-parameter assertions if EXOk (1) is passed.
    const int winMode = mode & 0x06;
    return ::_waccess(w.c_str(), winMode);
#else
    return ::access(path, mode);
#endif
}

bool GameUtil::isDir(const char* path) {
    if (!path || !*path) return false;
    const fs::path p = utf8ToPath(path);
    if (p.empty()) return false;
    std::error_code ec;
    return fs::is_directory(p, ec);
}

CCArray* GameUtil::readdir(const char* path) {
    CCArray* arr = CCArray::create();
    if (!path || path[0] == '\0') return arr;
    const fs::path p = utf8ToPath(path);
    if (p.empty()) return arr;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(p, ec)) {
        arr->addObject(CCString::create(pathToUtf8(entry.path().filename())));
    }
    return arr;
}

int GameUtil::getDPI() {
    // Fixed 160 baseline DPI (Android mdpi = 1.0x) so Windows 125%/150% desktop scaling
    // never distorts Util:px2dp / px2pt UI layouts.
    return 160;
}

std::string GameUtil::getExternalStorageLocation() {
    return CCFileUtils::sharedFileUtils()->getWritablePath();
}

// Matches 0x2b4520: returns 0 (EUnzipOk), 1 (EUnzipFileNotExist), 2 (EUnzipBadFile), 3 (EUnzipOutOfStorage).
int GameUtil::unzip(const char* zipPath, const char* dstDir) {
    if (!zipPath || zipPath[0] == '\0') return EUnzipFileNotExist;

    const fs::path zipFsPath = utf8ToPath(zipPath);
    if (zipFsPath.empty()) return EUnzipFileNotExist;
    std::error_code existEc;
    if (!fs::exists(zipFsPath, existEc) || fs::is_directory(zipFsPath, existEc)) {
        return EUnzipFileNotExist;
    }

    const fs::path baseDir = utf8ToPath(dstDir ? dstDir : "");

    unzFile zf = nullptr;
#ifdef _WIN32
    // Only pass narrow path to unzOpen if zipPath is pure ASCII; non-ASCII UTF-8 paths
    // (such as Vietnamese user profile directories) go directly through _wfopen below.
    bool isPureAscii = true;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(zipPath); *p != '\0'; ++p) {
        if (*p >= 0x80u) {
            isPureAscii = false;
            break;
        }
    }
    if (isPureAscii) {
        zf = unzOpen(zipPath);
    }
#else
    zf = unzOpen(zipPath);
#endif

    if (!zf) {
        FILE* zfp = openFileRb(zipFsPath);
        if (!zfp) {
            return EUnzipFileNotExist;
        }
        const int streamRes = extractZipViaFileStream(zfp, baseDir);
        std::fclose(zfp);
        return streamRes;
    }

    unz_global_info gi;
    if (unzGetGlobalInfo(zf, &gi) != UNZ_OK) {
        unzClose(zf);
        return EUnzipBadFile;
    }

    char nameBuf[1024];
    char readBuf[4096];
    for (uLong i = 0; i < gi.number_entry; ++i) {
        unz_file_info fi;
        if (unzGetCurrentFileInfo(zf, &fi, nameBuf, sizeof(nameBuf), nullptr, 0, nullptr, 0) != UNZ_OK) {
            unzClose(zf);
            return EUnzipBadFile;
        }

        fs::path relPath;
        bool isDirEntry = false;
        if (!normalizeZipEntryRelativePath(nameBuf, relPath, isDirEntry)) {
            unzClose(zf);
            return EUnzipBadFile;
        }
        const fs::path targetPath = baseDir.empty() ? relPath : (baseDir / relPath);

        if (isDirEntry) {
            if (!targetPath.empty()) {
                std::error_code ec;
                if (!fs::is_directory(targetPath, ec) && !fs::create_directories(targetPath, ec)) {
                    unzClose(zf);
                    return EUnzipOutOfStorage;
                }
            }
        } else if (!targetPath.empty()) {
            if (unzOpenCurrentFile(zf) != UNZ_OK) {
                unzClose(zf);
                return EUnzipBadFile;
            }
            std::error_code ec;
            const fs::path parent = targetPath.parent_path();
            if (!parent.empty()) {
                fs::create_directories(parent, ec);
            }
            FILE* fp = openFileWb(targetPath);
            if (!fp) {
                unzCloseCurrentFile(zf);
                unzClose(zf);
                return EUnzipBadFile;
            }
            int n = 0;
            bool writeFailed = false;
            while ((n = unzReadCurrentFile(zf, readBuf, sizeof(readBuf))) > 0) {
                if (std::fwrite(readBuf, 1, static_cast<size_t>(n), fp) != static_cast<size_t>(n)) {
                    writeFailed = true;
                    break;
                }
            }
            std::fclose(fp);
            unzCloseCurrentFile(zf);
            if (writeFailed) {
                unzClose(zf);
                return EUnzipOutOfStorage;
            }
            if (n < 0) {
                unzClose(zf);
                return EUnzipBadFile;
            }
        }
        if (i + 1 < gi.number_entry && unzGoToNextFile(zf) != UNZ_OK) {
            unzClose(zf);
            return EUnzipBadFile;
        }
    }
    unzClose(zf);
    return EUnzipOk;
}

std::string GameUtil::convertEncoding(const char* str, const char* /*encoding*/) {
    return str ? std::string(str) : "";
}

CCArray* GameUtil::getAssetFiles(const char* subDir) {
    std::string base = CCFileUtils::sharedFileUtils()->fullPathForFilename(subDir ? subDir : "");
    return readdir(base.c_str());
}

bool GameUtil::checkRecordPermission() { return false; }
void GameUtil::installApk(const char* /*path*/) {}
void GameUtil::setTimeZone(int /*tz*/) {}

uint64_t GameUtil::getMicroSeconds() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

// Matches GameUtil::makeLCPacket @ 0x2b4b04:
// Delegates directly to gclient::net::LCPacket::makeLCPacket(data, true).
std::string GameUtil::makeLCPacket(const std::string& data) {
    return gclient::net::LCPacket::makeLCPacket(data, true);
}

// Big-endian 32-bit helpers (matches 0x2B3680 and 0x2B2A48)
uint32_t GameUtil::getU32(const std::string& data) {
    if (data.size() < 4) return 0;
    const auto* b = reinterpret_cast<const unsigned char*>(data.data());
    return (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | uint32_t(b[3]);
}

std::string GameUtil::writeU32(uint32_t val, char* optionalBuf) {
    std::string out(4, '\0');
    char* dst = optionalBuf ? optionalBuf : &out[0];
    dst[0] = static_cast<char>((val >> 24) & 0xFF);
    dst[1] = static_cast<char>((val >> 16) & 0xFF);
    dst[2] = static_cast<char>((val >> 8) & 0xFF);
    dst[3] = static_cast<char>(val & 0xFF);
    if (optionalBuf) {
        std::memcpy(&out[0], optionalBuf, 4);
    }
    return out;
}

std::string GameUtil::zipData(const std::string& data) {
    if (data.empty()) return "";
    uLongf destLen = compressBound(static_cast<uLong>(data.size()));
    std::string res(destLen, '\0');
    if (compress2(reinterpret_cast<Bytef*>(&res[0]), &destLen,
                  reinterpret_cast<const Bytef*>(data.data()),
                  static_cast<uLong>(data.size()), Z_DEFAULT_COMPRESSION) != Z_OK) {
        return "";
    }
    res.resize(destLen);
    return res;
}

std::string GameUtil::unzipData(const std::string& data) {
    if (data.empty()) return "";
    std::string out;
    if (!gclient::net::LCPacket::zlibDecompress(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size(),
            out)) {
        return "";
    }
    return out;
}

// Matches 0x2B3874
std::string GameUtil::urlEncode(const std::string& str) {
    static const char HEX[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(str.size());
    for (unsigned char c : str) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(HEX[c >> 4]);
            out.push_back(HEX[c & 0x0F]);
        }
    }
    return out;
}

// Matches 0x2B3D3C
std::string GameUtil::urlDecode(const std::string& str) {
    std::string out;
    out.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            const unsigned char hi = fromHex(static_cast<unsigned char>(str[i + 1]));
            const unsigned char lo = fromHex(static_cast<unsigned char>(str[i + 2]));
            out.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
        } else if (str[i] == '+') {
            out.push_back(' ');
        } else {
            out.push_back(str[i]);
        }
    }
    return out;
}
