#include "tolua_GameTemplate.h"
#include "CConfigManager.h"
#include "GameUtil.h"
#include "LuaHelpers.h"
#include "LuaHttpAndCrypto.h"

#if defined(__has_include)
#  if __has_include("net/CNetwork.h")
#    include "net/CNetwork.h"
#    define GCLIENT_HAS_CNETWORK 1
#  elif __has_include("../net/CNetwork.h")
#    include "../net/CNetwork.h"
#    define GCLIENT_HAS_CNETWORK 1
#  endif
#endif

#ifdef GCLIENT_HAS_CNETWORK
using gclient::net::CConnection;
using gclient::net::CNetwork;
#endif

#include "CCLuaEngine.h"
#include "cocos2d.h"
#include "tolua_fix.h"

#include <cstdint>
#include <string>
#include <type_traits>

USING_NS_CC;

#if !defined(GCLIENT_HAS_CNETWORK)
// Forward interface declarations matching CNetwork/CConnection in src/network/CNetwork.h
// so tolua_GameTemplate.cpp compiles even before src/network is added to the include path.
class CConnection : public cocos2d::CCObject {
public:
    void send(const std::string& data, bool useLCPacket = true);
    bool connect(const char* host, unsigned int port);
    void registerBodyFunc(int luaFuncRef);
    void registerHeadFunc(int luaFuncRef);
    void registerCloseFunc(int luaFuncRef);
    void setHeaderSize(int size);
    void close();
};

class CNetwork : public cocos2d::CCObject {
public:
    static CNetwork* sharedNetwork();
    CConnection* newConnection();
};
#endif

namespace {

GameTemplateForwardingHooks s_hooks;

template <typename T>
inline void pushCCObject(lua_State* tolua_S, T* obj, const char* typeName) {
    static_assert(std::is_base_of<CCObject, T>::value, "T must inherit CCObject");
    if (!obj) {
        lua_pushnil(tolua_S);
        return;
    }
    CCObject* baseObj = static_cast<CCObject*>(obj);
    const int nID = static_cast<int>(baseObj->m_uID);
    int* pLuaID = &baseObj->m_nLuaID;
    toluafix_pushusertype_ccobject(
        tolua_S, nID, pLuaID, static_cast<void*>(baseObj), typeName ? typeName : "CCObject");
}

CCObject* extractToluaCCObject(lua_State* L, int idx, const char* expectedType) {
    if (!L) return nullptr;
    const int absIdx = (idx < 0 && idx > LUA_REGISTRYINDEX) ? (lua_gettop(L) + idx + 1) : idx;
    if (absIdx <= 0 || absIdx > lua_gettop(L)) return nullptr;

    tolua_Error err{};
    const char* checkType = (expectedType && *expectedType) ? expectedType : "CCObject";
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, checkType, 0, &err) ||
            tolua_isusertype(L, absIdx, "CCObject", 0, &err)) {
            return static_cast<CCObject*>(tolua_tousertype(L, absIdx, nullptr));
        }
        return nullptr;
    }
    if (lua_type(L, absIdx) == LUA_TTABLE) {
        lua_pushvalue(L, absIdx);
        for (int depth = 0; depth < 4; ++depth) {
            if (!lua_istable(L, -1)) break;
            lua_pushlstring(L, ".c_instance", 11);
            lua_rawget(L, -2);
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                lua_getfield(L, -1, ".c_instance");
            }
            lua_remove(L, -2);
            if (lua_type(L, -1) == LUA_TUSERDATA) {
                CCObject* obj = nullptr;
                if (tolua_isusertype(L, -1, checkType, 0, &err) ||
                    tolua_isusertype(L, -1, "CCObject", 0, &err)) {
                    obj = static_cast<CCObject*>(tolua_tousertype(L, -1, nullptr));
                }
                lua_pop(L, 1);
                return obj;
            }
        }
        lua_pop(L, 1);
    }
    return nullptr;
}

template <typename T>
T* getSafeToluaCCObject(lua_State* L, int idx, const char* expectedType) {
    static_assert(std::is_base_of<CCObject, T>::value, "T must inherit CCObject");
    CCObject* obj = extractToluaCCObject(L, idx, expectedType);
    return obj ? dynamic_cast<T*>(obj) : nullptr;
}

template <typename T>
T* getSafeRawUsertype(lua_State* L, int idx, const char* expectedType) {
    if (!L || !expectedType) return nullptr;
    const int absIdx = (idx < 0 && idx > LUA_REGISTRYINDEX) ? (lua_gettop(L) + idx + 1) : idx;
    if (absIdx <= 0 || absIdx > lua_gettop(L)) return nullptr;
    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA &&
        tolua_isusertype(L, absIdx, expectedType, 0, &err)) {
        return static_cast<T*>(tolua_tousertype(L, absIdx, nullptr));
    }
    return nullptr;
}

void tolua_reg_types_GameTemplate(lua_State* tolua_S) {
    tolua_usertype(tolua_S, "CCHttpClient");
    tolua_usertype(tolua_S, "LuaHttpRequest");
    tolua_usertype(tolua_S, "CNetwork");
    tolua_usertype(tolua_S, "CCCrypto");
    tolua_usertype(tolua_S, "CTimer");
    tolua_usertype(tolua_S, "LuaHttpResponse");
    tolua_usertype(tolua_S, "CConnection");
    tolua_usertype(tolua_S, "CCHttpResponse");
    tolua_usertype(tolua_S, "CCHttpRequest");
    tolua_usertype(tolua_S, "CCObject");
    tolua_usertype(tolua_S, "SpriteBlur");
    tolua_usertype(tolua_S, "GameUtil");
    tolua_usertype(tolua_S, "CLuaFuncs");
    tolua_usertype(tolua_S, "CCArray");
    tolua_usertype(tolua_S, "CCStrokeLabel");
    tolua_usertype(tolua_S, "CTable");
    tolua_usertype(tolua_S, "CConfigurationManager");
}

// ============================================================================
// CLuaFuncs (3 methods)
// ============================================================================

int tolua_GameTemplate_CLuaFuncs_sharedLuaFuncs00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "CLuaFuncs", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'sharedLuaFuncs'.", &tolua_err);
        return 0;
    }
    pushCCObject(tolua_S, CLuaFuncs::sharedLuaFuncs(), "CLuaFuncs");
    return 1;
}

int tolua_GameTemplate_CLuaFuncs_addHandler00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CLuaFuncs", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !toluafix_isfunction(tolua_S, 3, "LUA_FUNCTION", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'addHandler'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CLuaFuncs>(tolua_S, 1, "CLuaFuncs");
    const char* name = tolua_tostring(tolua_S, 2, "");
    const int handler = toluafix_ref_function(tolua_S, 3, 0);
    if (self) self->addHandler(name, handler);
    return 0;
}

int tolua_GameTemplate_CLuaFuncs_removeHandler00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CLuaFuncs", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'removeHandler'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CLuaFuncs>(tolua_S, 1, "CLuaFuncs");
    const char* name = tolua_tostring(tolua_S, 2, "");
    if (self) self->removeHandler(name);
    return 0;
}

// ============================================================================
// GameUtil (all 23 methods)
// ============================================================================

int tolua_GameTemplate_GameUtil_installApk00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'installApk'.", &tolua_err);
        return 0;
    }
    GameUtil::installApk(tolua_tostring(tolua_S, 2, ""));
    return 0;
}

int tolua_GameTemplate_GameUtil_rename00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 3, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'rename'.", &tolua_err);
        return 0;
    }
    const int ret = GameUtil::rename(tolua_tostring(tolua_S, 2, ""), tolua_tostring(tolua_S, 3, ""));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(ret));
    return 1;
}

int tolua_GameTemplate_GameUtil_mkdir00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'mkdir'.", &tolua_err);
        return 0;
    }
    const int ret = GameUtil::mkdir(tolua_tostring(tolua_S, 2, ""));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(ret));
    return 1;
}

int tolua_GameTemplate_GameUtil_rmdir00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'rmdir'.", &tolua_err);
        return 0;
    }
    const int ret = GameUtil::rmdir(tolua_tostring(tolua_S, 2, ""));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(ret));
    return 1;
}

int tolua_GameTemplate_GameUtil_unlink00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'unlink'.", &tolua_err);
        return 0;
    }
    const int ret = GameUtil::unlink(tolua_tostring(tolua_S, 2, ""));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(ret));
    return 1;
}

int tolua_GameTemplate_GameUtil_readdir00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'readdir'.", &tolua_err);
        return 0;
    }
    pushCCObject(tolua_S, GameUtil::readdir(tolua_tostring(tolua_S, 2, "")), "CCArray");
    return 1;
}

int tolua_GameTemplate_GameUtil_access00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 3, 1, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'access'.", &tolua_err);
        return 0;
    }
    const char* path = tolua_tostring(tolua_S, 2, "");
    const int mode = static_cast<int>(tolua_tonumber(tolua_S, 3, GameUtil::EFOk));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(GameUtil::access(path, mode)));
    return 1;
}

int tolua_GameTemplate_GameUtil_isDir00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'isDir'.", &tolua_err);
        return 0;
    }
    tolua_pushboolean(tolua_S, GameUtil::isDir(tolua_tostring(tolua_S, 2, "")) ? 1 : 0);
    return 1;
}

int tolua_GameTemplate_GameUtil_getDPI00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getDPI'.", &tolua_err);
        return 0;
    }
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(GameUtil::getDPI()));
    return 1;
}

int tolua_GameTemplate_GameUtil_getExternalStorageLocation00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getExternalStorageLocation'.", &tolua_err);
        return 0;
    }
    tolua_pushcppstring(tolua_S, GameUtil::getExternalStorageLocation());
    return 1;
}

int tolua_GameTemplate_GameUtil_unzip00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 3, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'unzip'.", &tolua_err);
        return 0;
    }
    const int ret = GameUtil::unzip(tolua_tostring(tolua_S, 2, ""), tolua_tostring(tolua_S, 3, ""));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(ret));
    return 1;
}

int tolua_GameTemplate_GameUtil_convertEncoding00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 3, 1, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'convertEncoding'.", &tolua_err);
        return 0;
    }
    const std::string ret = GameUtil::convertEncoding(
        tolua_tostring(tolua_S, 2, ""), tolua_tostring(tolua_S, 3, "UTF-8"));
    tolua_pushcppstring(tolua_S, ret);
    return 1;
}

int tolua_GameTemplate_GameUtil_getAssetFiles00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getAssetFiles'.", &tolua_err);
        return 0;
    }
    pushCCObject(tolua_S, GameUtil::getAssetFiles(tolua_tostring(tolua_S, 2, "")), "CCArray");
    return 1;
}

int tolua_GameTemplate_GameUtil_checkRecordPermission00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'checkRecordPermission'.", &tolua_err);
        return 0;
    }
    tolua_pushboolean(tolua_S, GameUtil::checkRecordPermission() ? 1 : 0);
    return 1;
}

int tolua_GameTemplate_GameUtil_setTimeZone00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !(lua_isnumber(tolua_S, 2) || lua_isstring(tolua_S, 2)) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'setTimeZone'.", &tolua_err);
        return 0;
    }
    if (lua_isnumber(tolua_S, 2)) {
        GameUtil::setTimeZone(static_cast<int>(tolua_tonumber(tolua_S, 2, 0)));
    }
    return 0;
}

int tolua_GameTemplate_GameUtil_urlEncode00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'urlEncode'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    const std::string out = GameUtil::urlEncode(std::string(ptr ? ptr : "", len));
    lua_pushlstring(tolua_S, out.data(), out.size());
    return 1;
}

int tolua_GameTemplate_GameUtil_urlDecode00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'urlDecode'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    const std::string out = GameUtil::urlDecode(std::string(ptr ? ptr : "", len));
    lua_pushlstring(tolua_S, out.data(), out.size());
    return 1;
}

int tolua_GameTemplate_GameUtil_getMicroSeconds00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getMicroSeconds'.", &tolua_err);
        return 0;
    }
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(GameUtil::getMicroSeconds()));
    return 1;
}

int tolua_GameTemplate_GameUtil_makeLCPacket00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'makeLCPacket'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    const std::string out = GameUtil::makeLCPacket(std::string(ptr ? ptr : "", len));
    lua_pushlstring(tolua_S, out.data(), out.size());
    return 1;
}

int tolua_GameTemplate_GameUtil_getU3200(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getU32'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    const uint32_t val = GameUtil::getU32(std::string(ptr ? ptr : "", len));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(val));
    return 1;
}

int tolua_GameTemplate_GameUtil_writeU3200(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'writeU32'.", &tolua_err);
        return 0;
    }
    const uint32_t val = static_cast<uint32_t>(tolua_tonumber(tolua_S, 2, 0));
    const std::string out = GameUtil::writeU32(val);
    lua_pushlstring(tolua_S, out.data(), out.size());
    return 1;
}

int tolua_GameTemplate_GameUtil_zipData00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'zipData'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    const std::string out = GameUtil::zipData(std::string(ptr ? ptr : "", len));
    lua_pushlstring(tolua_S, out.data(), out.size());
    return 1;
}

int tolua_GameTemplate_GameUtil_unzipData00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'unzipData'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    const std::string out = GameUtil::unzipData(std::string(ptr ? ptr : "", len));
    lua_pushlstring(tolua_S, out.data(), out.size());
    return 1;
}

// ============================================================================
// CTimer (2 methods)
// ============================================================================

int tolua_GameTemplate_CTimer_sharedTimer00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "CTimer", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'sharedTimer'.", &tolua_err);
        return 0;
    }
    pushCCObject(tolua_S, CTimer::sharedTimer(), "CTimer");
    return 1;
}

int tolua_GameTemplate_CTimer_addEvent00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CTimer", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err) ||
        !toluafix_isfunction(tolua_S, 3, "LUA_FUNCTION", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'addEvent'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CTimer>(tolua_S, 1, "CTimer");
    const int delaySeconds = static_cast<int>(tolua_tonumber(tolua_S, 2, 0));
    const int handler = toluafix_ref_function(tolua_S, 3, 0);
    if (self) self->addEvent(delaySeconds, handler);
    return 0;
}

// ============================================================================
// CConnection (all 7 methods)
// ============================================================================

int tolua_GameTemplate_CConnection_send00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isboolean(tolua_S, 3, 1, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'send'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CConnection>(tolua_S, 1, "CConnection");
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    const bool useLCPacket = tolua_toboolean(tolua_S, 3, 1) != 0;
    if (self) self->send(std::string(ptr ? ptr : "", len), useLCPacket);
    return 0;
}

int tolua_GameTemplate_CConnection_connect00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &tolua_err) ||
        !tolua_isstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 3, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'connect'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CConnection>(tolua_S, 1, "CConnection");
    const char* host = tolua_tostring(tolua_S, 2, "");
    const unsigned int port = static_cast<unsigned int>(tolua_tonumber(tolua_S, 3, 0));
    const bool ok = self ? self->connect(host, port) : false;
    tolua_pushboolean(tolua_S, ok ? 1 : 0);
    return 1;
}

int tolua_GameTemplate_CConnection_registerBodyFunc00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &tolua_err) ||
        !toluafix_isfunction(tolua_S, 2, "LUA_FUNCTION", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'registerBodyFunc'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CConnection>(tolua_S, 1, "CConnection");
    const int handler = toluafix_ref_function(tolua_S, 2, 0);
    if (self) self->registerBodyFunc(handler);
    return 0;
}

int tolua_GameTemplate_CConnection_registerHeadFunc00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &tolua_err) ||
        !toluafix_isfunction(tolua_S, 2, "LUA_FUNCTION", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'registerHeadFunc'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CConnection>(tolua_S, 1, "CConnection");
    const int handler = toluafix_ref_function(tolua_S, 2, 0);
    if (self) self->registerHeadFunc(handler);
    return 0;
}

int tolua_GameTemplate_CConnection_registerCloseFunc00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &tolua_err) ||
        !toluafix_isfunction(tolua_S, 2, "LUA_FUNCTION", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'registerCloseFunc'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CConnection>(tolua_S, 1, "CConnection");
    const int handler = toluafix_ref_function(tolua_S, 2, 0);
    if (self) self->registerCloseFunc(handler);
    return 0;
}

int tolua_GameTemplate_CConnection_setHeaderSize00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'setHeaderSize'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CConnection>(tolua_S, 1, "CConnection");
    const int size = static_cast<int>(tolua_tonumber(tolua_S, 2, 0));
    if (self) self->setHeaderSize(size);
    return 0;
}

int tolua_GameTemplate_CConnection_close00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'close'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CConnection>(tolua_S, 1, "CConnection");
    if (self) self->close();
    return 0;
}

// ============================================================================
// CNetwork (2 methods)
// ============================================================================

int tolua_GameTemplate_CNetwork_sharedNetwork00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "CNetwork", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'sharedNetwork'.", &tolua_err);
        return 0;
    }
#if defined(GCLIENT_USE_COCOS2DX) || !defined(GCLIENT_HAS_CNETWORK)
    pushCCObject(tolua_S, CNetwork::sharedNetwork(), "CNetwork");
#else
    tolua_pushusertype(tolua_S, static_cast<void*>(CNetwork::sharedNetwork()), "CNetwork");
#endif
    return 1;
}

int tolua_GameTemplate_CNetwork_newConnection00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CNetwork", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'newConnection'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CNetwork>(tolua_S, 1, "CNetwork");
#if defined(GCLIENT_USE_COCOS2DX) || !defined(GCLIENT_HAS_CNETWORK)
    pushCCObject(tolua_S, self ? self->newConnection() : nullptr, "CConnection");
#else
    tolua_pushusertype(tolua_S, static_cast<void*>(self ? self->newConnection() : nullptr), "CConnection");
#endif
    return 1;
}

// ============================================================================
// CCStrokeLabel (3 methods)
// ============================================================================

int tolua_GameTemplate_CCStrokeLabel_create00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "CCStrokeLabel", 0, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'create'.", &tolua_err);
        return 0;
    }
    const char* text = lua_isstring(tolua_S, 2) ? tolua_tostring(tolua_S, 2, "") : "";
    const char* fontName = lua_isstring(tolua_S, 3) ? tolua_tostring(tolua_S, 3, "") : "";
    const int fontSize = lua_isnumber(tolua_S, 4)
        ? static_cast<int>(tolua_tonumber(tolua_S, 4, 16))
        : 16;
    pushCCObject(tolua_S, CCStrokeLabel::create(text, fontName, fontSize), "CCStrokeLabel");
    return 1;
}

int tolua_GameTemplate_CCStrokeLabel_setStroke00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CCStrokeLabel", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'setStroke'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CCStrokeLabel>(tolua_S, 1, "CCStrokeLabel");
    const unsigned int strokeSize = static_cast<unsigned int>(tolua_tonumber(tolua_S, 2, 1));
    ccColor4B color = ccc4(0, 0, 0, 255);
    if (lua_type(tolua_S, 3) == LUA_TUSERDATA) {
        if (tolua_isusertype(tolua_S, 3, "ccColor4B", 0, &tolua_err)) {
            if (auto* c = static_cast<ccColor4B*>(tolua_tousertype(tolua_S, 3, nullptr))) {
                color = *c;
            }
        } else if (tolua_isusertype(tolua_S, 3, "ccColor3B", 0, &tolua_err)) {
            if (auto* c = static_cast<ccColor3B*>(tolua_tousertype(tolua_S, 3, nullptr))) {
                color = ccc4(c->r, c->g, c->b, 255);
            }
        }
    }
    if (self) self->setStroke(strokeSize, color);
    return 0;
}

int tolua_GameTemplate_CCStrokeLabel_setContrast00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CCStrokeLabel", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'setContrast'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<CCStrokeLabel>(tolua_S, 1, "CCStrokeLabel");
    const float contrast = static_cast<float>(tolua_tonumber(tolua_S, 2, 1.0));
    if (self) self->setContrast(contrast);
    return 0;
}

// ============================================================================
// CTable (getRowById, getColumnName, getColName, getIdsByConditionStr, release)
// ============================================================================

int tolua_GameTemplate_CTable_getRowById00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CTable", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getRowById'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeRawUsertype<CTable>(tolua_S, 1, "CTable");
    const std::string id(tolua_tocppstring(tolua_S, 2, ""));
    pushCCObject(tolua_S, self ? self->getRowById(id) : nullptr, "CCArray");
    return 1;
}

int tolua_GameTemplate_CTable_getColumnName00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CTable", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getColumnName'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeRawUsertype<CTable>(tolua_S, 1, "CTable");
    pushCCObject(tolua_S, self ? self->getColumnName() : nullptr, "CCArray");
    return 1;
}

int tolua_GameTemplate_CTable_getColName00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CTable", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getColName'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeRawUsertype<CTable>(tolua_S, 1, "CTable");
    pushCCObject(tolua_S, self ? self->getColName() : nullptr, "CCArray");
    return 1;
}

int tolua_GameTemplate_CTable_getIdsByConditionStr00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CTable", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getIdsByConditionStr'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeRawUsertype<CTable>(tolua_S, 1, "CTable");
    const std::string cond(tolua_tocppstring(tolua_S, 2, ""));
    pushCCObject(tolua_S, self ? self->getIdsByConditionStr(cond) : nullptr, "CCArray");
    return 1;
}

int tolua_GameTemplate_CTable_release00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CTable", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'release'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeRawUsertype<CTable>(tolua_S, 1, "CTable");
    if (self) self->release();
    return 0;
}

// ============================================================================
// CConfigurationManager (2 methods)
// ============================================================================

int tolua_GameTemplate_CConfigurationManager_sharedConfigurationManager00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "CConfigurationManager", 0, &tolua_err) ||
        !tolua_isboolean(tolua_S, 2, 1, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'sharedConfigurationManager'.", &tolua_err);
        return 0;
    }
    const bool reload = tolua_toboolean(tolua_S, 2, 0) != 0;
    CConfigurationManager* ret = CConfigurationManager::sharedConfigurationManager(reload);
    tolua_pushusertype(tolua_S, static_cast<void*>(ret), "CConfigurationManager");
    return 1;
}

int tolua_GameTemplate_CConfigurationManager_getTable00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "CConfigurationManager", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 3, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getTable'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeRawUsertype<CConfigurationManager>(tolua_S, 1, "CConfigurationManager");
    const std::string dbFile(tolua_tocppstring(tolua_S, 2, ""));
    const std::string tableName(tolua_tocppstring(tolua_S, 3, ""));
    CTable* ret = self ? self->getTable(dbFile, tableName) : nullptr;
    tolua_pushusertype(tolua_S, static_cast<void*>(ret), "CTable");
    return 1;
}

// ============================================================================
// SpriteBlur (all 7 methods)
// ============================================================================

int tolua_GameTemplate_SpriteBlur_draw00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'draw'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<SpriteBlur>(tolua_S, 1, "SpriteBlur");
    if (self) self->draw();
    return 0;
}

int tolua_GameTemplate_SpriteBlur_initProgram00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'initProgram'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<SpriteBlur>(tolua_S, 1, "SpriteBlur");
    if (self) self->initProgram();
    return 0;
}

int tolua_GameTemplate_SpriteBlur_setBlurSize00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'setBlurSize'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<SpriteBlur>(tolua_S, 1, "SpriteBlur");
    const float size = static_cast<float>(tolua_tonumber(tolua_S, 2, 0.0));
    if (self) self->setBlurSize(size);
    return 0;
}

int tolua_GameTemplate_SpriteBlur_listenBack2Foreground00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCObject", 1, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'listenBack2Foreground'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<SpriteBlur>(tolua_S, 1, "SpriteBlur");
    auto* obj = extractToluaCCObject(tolua_S, 2, "CCObject");
    if (self) self->listenBack2Foreground(obj);
    return 0;
}

int tolua_GameTemplate_SpriteBlur_initWithTexture00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCTexture2D", 1, &tolua_err) ||
        !tolua_isusertype(tolua_S, 3, "CCRect", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'initWithTexture'.", &tolua_err);
        return 0;
    }
    auto* self = getSafeToluaCCObject<SpriteBlur>(tolua_S, 1, "SpriteBlur");
    auto* tex = getSafeToluaCCObject<CCTexture2D>(tolua_S, 2, "CCTexture2D");
    auto* rect = getSafeRawUsertype<CCRect>(tolua_S, 3, "CCRect");
    const bool ok = (self && rect) ? self->initWithTexture(tex, *rect) : false;
    tolua_pushboolean(tolua_S, ok ? 1 : 0);
    return 1;
}

int tolua_GameTemplate_SpriteBlur_create00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "SpriteBlur", 0, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'create'.", &tolua_err);
        return 0;
    }
    const char* filename = lua_isstring(tolua_S, 2) ? tolua_tostring(tolua_S, 2, "") : "";
    pushCCObject(tolua_S, SpriteBlur::create(filename), "SpriteBlur");
    return 1;
}

int tolua_GameTemplate_SpriteBlur_createWithTexture00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "SpriteBlur", 0, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'createWithTexture'.", &tolua_err);
        return 0;
    }
    auto* tex = getSafeToluaCCObject<CCTexture2D>(tolua_S, 2, "CCTexture2D");
    pushCCObject(tolua_S, SpriteBlur::createWithTexture(tex), "SpriteBlur");
    return 1;
}

// ============================================================================
// Default logged stubs for external HTTP / Crypto forwarding hooks
// ============================================================================

int tolua_unwired_stub(lua_State* tolua_S) {
    lua_Debug ar;
    const char* fnName = (lua_getstack(tolua_S, 0, &ar) && lua_getinfo(tolua_S, "n", &ar) && ar.name)
        ? ar.name
        : "<unknown>";
    CCLog("tolua_GameTemplate: unwired forwarding hook called for '%s'", fnName);
    lua_pushnil(tolua_S);
    return 1;
}

void registerDefaultCCHttpRequest(lua_State* tolua_S) {
    tolua_cclass(tolua_S, "CCHttpRequest", "CCHttpRequest", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CCHttpRequest");
    tolua_constant(tolua_S, "kHttpGet", 0.0);
    tolua_constant(tolua_S, "kHttpPost", 1.0);
    tolua_constant(tolua_S, "kHttpPut", 2.0);
    tolua_constant(tolua_S, "kHttpDelete", 3.0);
    tolua_constant(tolua_S, "kHttpUnkown", 4.0);
    tolua_function(tolua_S, "setRequestType", tolua_unwired_stub);
    tolua_function(tolua_S, "getRequestType", tolua_unwired_stub);
    tolua_function(tolua_S, "setUrl", tolua_unwired_stub);
    tolua_function(tolua_S, "getUrl", tolua_unwired_stub);
    tolua_function(tolua_S, "setRequestData", tolua_unwired_stub);
    tolua_function(tolua_S, "getRequestData", tolua_unwired_stub);
    tolua_function(tolua_S, "getRequestDataSize", tolua_unwired_stub);
    tolua_function(tolua_S, "setTag", tolua_unwired_stub);
    tolua_function(tolua_S, "getTag", tolua_unwired_stub);
    tolua_function(tolua_S, "getTarget", tolua_unwired_stub);
    tolua_function(tolua_S, "setTimeoutForConnect", tolua_unwired_stub);
    tolua_function(tolua_S, "getTimeoutForConnect", tolua_unwired_stub);
    tolua_function(tolua_S, "setTimeoutForRead", tolua_unwired_stub);
    tolua_function(tolua_S, "getTimeoutForRead", tolua_unwired_stub);
    tolua_function(tolua_S, "setTimeoutForLowSpeed", tolua_unwired_stub);
    tolua_function(tolua_S, "getTimeoutForLowSpeed", tolua_unwired_stub);
    tolua_function(tolua_S, "setLowSpeed", tolua_unwired_stub);
    tolua_function(tolua_S, "getLowSpeed", tolua_unwired_stub);
    tolua_endmodule(tolua_S);
}

void registerDefaultCCHttpResponse(lua_State* tolua_S) {
    tolua_cclass(tolua_S, "CCHttpResponse", "CCHttpResponse", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CCHttpResponse");
    tolua_function(tolua_S, "isSucceed", tolua_unwired_stub);
    tolua_function(tolua_S, "getResponseCode", tolua_unwired_stub);
    tolua_function(tolua_S, "getErrorBuffer", tolua_unwired_stub);
    tolua_endmodule(tolua_S);
}

void registerDefaultCCHttpClient(lua_State* tolua_S) {
    tolua_cclass(tolua_S, "CCHttpClient", "CCHttpClient", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CCHttpClient");
    tolua_function(tolua_S, "getInstance", tolua_unwired_stub);
    tolua_function(tolua_S, "destroyInstance", tolua_unwired_stub);
    tolua_function(tolua_S, "send", tolua_unwired_stub);
    tolua_function(tolua_S, "enableCookies", tolua_unwired_stub);
    tolua_endmodule(tolua_S);
}

void registerDefaultLuaHttpRequest(lua_State* tolua_S) {
    tolua_cclass(tolua_S, "LuaHttpRequest", "LuaHttpRequest", "CCHttpRequest", nullptr);
    tolua_beginmodule(tolua_S, "LuaHttpRequest");
    tolua_function(tolua_S, "newRequest", tolua_unwired_stub);
    tolua_function(tolua_S, "setHeaders", tolua_unwired_stub);
    tolua_function(tolua_S, "addHeader", tolua_unwired_stub);
    tolua_function(tolua_S, "getHeaders", tolua_unwired_stub);
    tolua_function(tolua_S, "setResponseScriptFunc", tolua_unwired_stub);
    tolua_function(tolua_S, "setBodyDataScriptFunc", tolua_unwired_stub);
    tolua_function(tolua_S, "setHeaderDataScriptFunc", tolua_unwired_stub);
    tolua_endmodule(tolua_S);
}

void registerDefaultLuaHttpResponse(lua_State* tolua_S) {
    tolua_cclass(tolua_S, "LuaHttpResponse", "LuaHttpResponse", "CCHttpResponse", nullptr);
    tolua_beginmodule(tolua_S, "LuaHttpResponse");
    tolua_function(tolua_S, "getHeaders", tolua_unwired_stub);
    tolua_function(tolua_S, "getHeadersSize", tolua_unwired_stub);
    tolua_function(tolua_S, "getResponseData", tolua_unwired_stub);
    tolua_function(tolua_S, "getResponseDataSize", tolua_unwired_stub);
    tolua_function(tolua_S, "getRequest", tolua_unwired_stub);
    tolua_endmodule(tolua_S);
}

void registerDefaultCCCrypto(lua_State* tolua_S) {
    tolua_cclass(tolua_S, "CCCrypto", "CCCrypto", "", nullptr);
    tolua_beginmodule(tolua_S, "CCCrypto");
    tolua_constant(tolua_S, "EDigestMD5", 1.0);
    tolua_constant(tolua_S, "EDigestSha1", 2.0);
    tolua_function(tolua_S, "encodeBase64", tolua_unwired_stub);
    tolua_function(tolua_S, "decodeBase64", tolua_unwired_stub);
    tolua_function(tolua_S, "md5", tolua_unwired_stub);
    tolua_function(tolua_S, "sha1", tolua_unwired_stub);
    tolua_function(tolua_S, "bin2hex", tolua_unwired_stub);
    tolua_function(tolua_S, "createDigest", tolua_unwired_stub);
    tolua_function(tolua_S, "addBytes", tolua_unwired_stub);
    tolua_function(tolua_S, "getDigest", tolua_unwired_stub);
    tolua_function(tolua_S, "hex2bin", tolua_unwired_stub);
    tolua_endmodule(tolua_S);
}

// ============================================================================
// Global Lua helpers registered at end of tolua_GameTemplate_open (lines 429-434)
// ============================================================================

int lua_andBit(lua_State* L) {
    const uint32_t a = static_cast<uint32_t>(luaL_checknumber(L, 1));
    const uint32_t b = static_cast<uint32_t>(luaL_checknumber(L, 2));
    lua_pushnumber(L, static_cast<lua_Number>(a & b));
    return 1;
}

int lua_xorBit(lua_State* L) {
    const uint32_t a = static_cast<uint32_t>(luaL_checknumber(L, 1));
    const uint32_t b = static_cast<uint32_t>(luaL_checknumber(L, 2));
    lua_pushnumber(L, static_cast<lua_Number>(a ^ b));
    return 1;
}

int lua_dumpMemory(lua_State* L) {
    const int kb = lua_gc(L, LUA_GCCOUNT, 0);
    CCLog("Lua memory usage: %d KB", kb);
    lua_pushnumber(L, static_cast<lua_Number>(kb));
    return 1;
}

} // namespace

TOLUA_API void tolua_GameTemplate_set_hooks(const GameTemplateForwardingHooks& hooks) {
    s_hooks = hooks;
}

TOLUA_API int tolua_GameTemplate_open(lua_State* tolua_S) {
    tolua_open(tolua_S);
    tolua_reg_types_GameTemplate(tolua_S);
    tolua_module(tolua_S, nullptr, 0);
    tolua_beginmodule(tolua_S, nullptr);

    // CLuaFuncs
    tolua_cclass(tolua_S, "CLuaFuncs", "CLuaFuncs", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CLuaFuncs");
    tolua_function(tolua_S, "sharedLuaFuncs", tolua_GameTemplate_CLuaFuncs_sharedLuaFuncs00);
    tolua_function(tolua_S, "addHandler", tolua_GameTemplate_CLuaFuncs_addHandler00);
    tolua_function(tolua_S, "removeHandler", tolua_GameTemplate_CLuaFuncs_removeHandler00);
    tolua_endmodule(tolua_S);

    // GameUtil (8 constants + all 23 methods)
    tolua_cclass(tolua_S, "GameUtil", "GameUtil", "", nullptr);
    tolua_beginmodule(tolua_S, "GameUtil");
    tolua_constant(tolua_S, "EFOk", static_cast<lua_Number>(GameUtil::EFOk));
    tolua_constant(tolua_S, "EROk", static_cast<lua_Number>(GameUtil::EROk));
    tolua_constant(tolua_S, "EWOk", static_cast<lua_Number>(GameUtil::EWOk));
    tolua_constant(tolua_S, "EXOk", static_cast<lua_Number>(GameUtil::EXOk));
    tolua_constant(tolua_S, "EUnzipOk", static_cast<lua_Number>(GameUtil::EUnzipOk));
    tolua_constant(tolua_S, "EUnzipFileNotExist", static_cast<lua_Number>(GameUtil::EUnzipFileNotExist));
    tolua_constant(tolua_S, "EUnzipBadFile", static_cast<lua_Number>(GameUtil::EUnzipBadFile));
    tolua_constant(tolua_S, "EUnzipOutOfStorage", static_cast<lua_Number>(GameUtil::EUnzipOutOfStorage));
    tolua_function(tolua_S, "installApk", tolua_GameTemplate_GameUtil_installApk00);
    tolua_function(tolua_S, "rename", tolua_GameTemplate_GameUtil_rename00);
    tolua_function(tolua_S, "mkdir", tolua_GameTemplate_GameUtil_mkdir00);
    tolua_function(tolua_S, "rmdir", tolua_GameTemplate_GameUtil_rmdir00);
    tolua_function(tolua_S, "unlink", tolua_GameTemplate_GameUtil_unlink00);
    tolua_function(tolua_S, "readdir", tolua_GameTemplate_GameUtil_readdir00);
    tolua_function(tolua_S, "access", tolua_GameTemplate_GameUtil_access00);
    tolua_function(tolua_S, "isDir", tolua_GameTemplate_GameUtil_isDir00);
    tolua_function(tolua_S, "getDPI", tolua_GameTemplate_GameUtil_getDPI00);
    tolua_function(tolua_S, "getExternalStorageLocation", tolua_GameTemplate_GameUtil_getExternalStorageLocation00);
    tolua_function(tolua_S, "unzip", tolua_GameTemplate_GameUtil_unzip00);
    tolua_function(tolua_S, "convertEncoding", tolua_GameTemplate_GameUtil_convertEncoding00);
    tolua_function(tolua_S, "getAssetFiles", tolua_GameTemplate_GameUtil_getAssetFiles00);
    tolua_function(tolua_S, "checkRecordPermission", tolua_GameTemplate_GameUtil_checkRecordPermission00);
    tolua_function(tolua_S, "setTimeZone", tolua_GameTemplate_GameUtil_setTimeZone00);
    tolua_function(tolua_S, "urlEncode", tolua_GameTemplate_GameUtil_urlEncode00);
    tolua_function(tolua_S, "urlDecode", tolua_GameTemplate_GameUtil_urlDecode00);
    tolua_function(tolua_S, "getMicroSeconds", tolua_GameTemplate_GameUtil_getMicroSeconds00);
    tolua_function(tolua_S, "makeLCPacket", tolua_GameTemplate_GameUtil_makeLCPacket00);
    tolua_function(tolua_S, "getU32", tolua_GameTemplate_GameUtil_getU3200);
    tolua_function(tolua_S, "writeU32", tolua_GameTemplate_GameUtil_writeU3200);
    tolua_function(tolua_S, "zipData", tolua_GameTemplate_GameUtil_zipData00);
    tolua_function(tolua_S, "unzipData", tolua_GameTemplate_GameUtil_unzipData00);
    tolua_endmodule(tolua_S);

    // Forwarding hooks for HTTP classes & CCCrypto (default to Win32 libcurl + OpenSSL bindings)
    const bool anyCustomHttpOrCryptoHook =
        s_hooks.registerCCHttpRequest || s_hooks.registerCCHttpResponse ||
        s_hooks.registerCCHttpClient || s_hooks.registerLuaHttpRequest ||
        s_hooks.registerLuaHttpResponse || s_hooks.registerCCCrypto;

    if (!anyCustomHttpOrCryptoHook) {
        gclient::bindings::registerLuaHttpAndCrypto(tolua_S);
    } else {
        if (s_hooks.registerCCHttpRequest) {
            s_hooks.registerCCHttpRequest(tolua_S);
        } else {
            registerDefaultCCHttpRequest(tolua_S);
        }

        if (s_hooks.registerCCHttpResponse) {
            s_hooks.registerCCHttpResponse(tolua_S);
        } else {
            registerDefaultCCHttpResponse(tolua_S);
        }

        if (s_hooks.registerCCHttpClient) {
            s_hooks.registerCCHttpClient(tolua_S);
        } else {
            registerDefaultCCHttpClient(tolua_S);
        }

        if (s_hooks.registerLuaHttpRequest) {
            s_hooks.registerLuaHttpRequest(tolua_S);
        } else {
            registerDefaultLuaHttpRequest(tolua_S);
        }

        if (s_hooks.registerLuaHttpResponse) {
            s_hooks.registerLuaHttpResponse(tolua_S);
        } else {
            registerDefaultLuaHttpResponse(tolua_S);
        }
    }

    // CTimer
    tolua_cclass(tolua_S, "CTimer", "CTimer", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CTimer");
    tolua_function(tolua_S, "sharedTimer", tolua_GameTemplate_CTimer_sharedTimer00);
    tolua_function(tolua_S, "addEvent", tolua_GameTemplate_CTimer_addEvent00);
    tolua_endmodule(tolua_S);

    if (anyCustomHttpOrCryptoHook) {
        if (s_hooks.registerCCCrypto) {
            s_hooks.registerCCCrypto(tolua_S);
        } else {
            registerDefaultCCCrypto(tolua_S);
        }
    }

    // CConnection (all 7 methods)
    tolua_cclass(tolua_S, "CConnection", "CConnection", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CConnection");
    tolua_function(tolua_S, "send", tolua_GameTemplate_CConnection_send00);
    tolua_function(tolua_S, "connect", tolua_GameTemplate_CConnection_connect00);
    tolua_function(tolua_S, "registerBodyFunc", tolua_GameTemplate_CConnection_registerBodyFunc00);
    tolua_function(tolua_S, "registerHeadFunc", tolua_GameTemplate_CConnection_registerHeadFunc00);
    tolua_function(tolua_S, "registerCloseFunc", tolua_GameTemplate_CConnection_registerCloseFunc00);
    tolua_function(tolua_S, "setHeaderSize", tolua_GameTemplate_CConnection_setHeaderSize00);
    tolua_function(tolua_S, "close", tolua_GameTemplate_CConnection_close00);
    tolua_endmodule(tolua_S);

    // CNetwork (2 methods)
    tolua_cclass(tolua_S, "CNetwork", "CNetwork", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CNetwork");
    tolua_function(tolua_S, "sharedNetwork", tolua_GameTemplate_CNetwork_sharedNetwork00);
    tolua_function(tolua_S, "newConnection", tolua_GameTemplate_CNetwork_newConnection00);
    tolua_endmodule(tolua_S);

    // CCStrokeLabel (3 methods)
    tolua_cclass(tolua_S, "CCStrokeLabel", "CCStrokeLabel", "CCLabelTTF", nullptr);
    tolua_beginmodule(tolua_S, "CCStrokeLabel");
    tolua_function(tolua_S, "create", tolua_GameTemplate_CCStrokeLabel_create00);
    tolua_function(tolua_S, "setStroke", tolua_GameTemplate_CCStrokeLabel_setStroke00);
    tolua_function(tolua_S, "setContrast", tolua_GameTemplate_CCStrokeLabel_setContrast00);
    tolua_endmodule(tolua_S);

    // CTable (getRowById, getColumnName, getColName, getIdsByConditionStr, release)
    tolua_cclass(tolua_S, "CTable", "CTable", "", nullptr);
    tolua_beginmodule(tolua_S, "CTable");
    tolua_function(tolua_S, "getRowById", tolua_GameTemplate_CTable_getRowById00);
    tolua_function(tolua_S, "getColumnName", tolua_GameTemplate_CTable_getColumnName00);
    tolua_function(tolua_S, "getColName", tolua_GameTemplate_CTable_getColName00);
    tolua_function(tolua_S, "getIdsByConditionStr", tolua_GameTemplate_CTable_getIdsByConditionStr00);
    tolua_function(tolua_S, "release", tolua_GameTemplate_CTable_release00);
    tolua_endmodule(tolua_S);

    // CConfigurationManager (2 methods)
    tolua_cclass(tolua_S, "CConfigurationManager", "CConfigurationManager", "", nullptr);
    tolua_beginmodule(tolua_S, "CConfigurationManager");
    tolua_function(tolua_S, "sharedConfigurationManager",
                   tolua_GameTemplate_CConfigurationManager_sharedConfigurationManager00);
    tolua_function(tolua_S, "getTable", tolua_GameTemplate_CConfigurationManager_getTable00);
    tolua_endmodule(tolua_S);

    // SpriteBlur (all 7 methods)
    tolua_cclass(tolua_S, "SpriteBlur", "SpriteBlur", "CCSprite", nullptr);
    tolua_beginmodule(tolua_S, "SpriteBlur");
    tolua_function(tolua_S, "draw", tolua_GameTemplate_SpriteBlur_draw00);
    tolua_function(tolua_S, "initProgram", tolua_GameTemplate_SpriteBlur_initProgram00);
    tolua_function(tolua_S, "setBlurSize", tolua_GameTemplate_SpriteBlur_setBlurSize00);
    tolua_function(tolua_S, "listenBack2Foreground", tolua_GameTemplate_SpriteBlur_listenBack2Foreground00);
    tolua_function(tolua_S, "initWithTexture", tolua_GameTemplate_SpriteBlur_initWithTexture00);
    tolua_function(tolua_S, "create", tolua_GameTemplate_SpriteBlur_create00);
    tolua_function(tolua_S, "createWithTexture", tolua_GameTemplate_SpriteBlur_createWithTexture00);
    tolua_endmodule(tolua_S);

    tolua_endmodule(tolua_S);

    // Global bitwise & diagnostics helpers (matches lines 429-434 of tolua_GameTemplate_open)
    lua_register(tolua_S, "andBit", lua_andBit);
    lua_register(tolua_S, "xorBit", lua_xorBit);
    lua_register(tolua_S, "dumpMemory", lua_dumpMemory);

    return 1;
}
