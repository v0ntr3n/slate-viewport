#pragma once

#include "cocos2d.h"

#include <cstdint>
#include <string>

class GameUtil {
public:
    enum AccessMode {
        EFOk = 0,
        EXOk = 1,
        EWOk = 2,
        EROk = 4
    };

    enum UnzipResult {
        EUnzipOk = 0,
        EUnzipFileNotExist = 1,
        EUnzipBadFile = 2,
        EUnzipOutOfStorage = 3
    };

    static int rename(const char* oldPath, const char* newPath);
    static int mkdir(const char* path);
    static int rmdir(const char* path);
    static int unlink(const char* path);
    static cocos2d::CCArray* readdir(const char* path);
    static int access(const char* path, int mode);
    static bool isDir(const char* path);

    static int getDPI();
    static std::string getExternalStorageLocation();
    static int unzip(const char* zipPath, const char* dstDir);
    static std::string convertEncoding(const char* str, const char* encoding);
    static cocos2d::CCArray* getAssetFiles(const char* subDir);

    static bool checkRecordPermission();
    static void installApk(const char* path);
    static void setTimeZone(int tz);
    static uint64_t getMicroSeconds();

    static std::string makeLCPacket(const std::string& data);
    static uint32_t getU32(const std::string& data);
    static std::string writeU32(uint32_t val, char* optionalBuf = nullptr);
    static std::string zipData(const std::string& data);
    static std::string unzipData(const std::string& data);
    static std::string urlEncode(const std::string& str);
    static std::string urlDecode(const std::string& str);
};
