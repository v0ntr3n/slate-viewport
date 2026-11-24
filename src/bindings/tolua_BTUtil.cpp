#include "tolua_BTUtil.h"
#include "BTUtil.h"

#include "CCLuaEngine.h"
#include "cocos2d.h"
#include "tolua_fix.h"

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

USING_NS_CC;

namespace {

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

CCObject* extractSafeBTCCObject(lua_State* L, int idx) {
    if (!L) return nullptr;
    const int absIdx = (idx < 0 && idx > LUA_REGISTRYINDEX) ? (lua_gettop(L) + idx + 1) : idx;
    if (absIdx <= 0 || absIdx > lua_gettop(L)) return nullptr;

    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, "CCObject", 0, &err)) {
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
                if (tolua_isusertype(L, -1, "CCObject", 0, &err)) {
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
T* getSafeBTCCObject(lua_State* L, int idx) {
    static_assert(std::is_base_of<CCObject, T>::value, "T must inherit CCObject");
    CCObject* obj = extractSafeBTCCObject(L, idx);
    return obj ? dynamic_cast<T*>(obj) : nullptr;
}

void tolua_reg_types_BTUtil(lua_State* tolua_S) {
    tolua_usertype(tolua_S, "CCPoint");
    tolua_usertype(tolua_S, "CCString");
    tolua_usertype(tolua_S, "cocos2d::CCLuaValue");
    tolua_usertype(tolua_S, "ClassInfo");
    tolua_usertype(tolua_S, "BTUtil");
    tolua_usertype(tolua_S, "vector<string>");
    tolua_usertype(tolua_S, "CCInteger");
    tolua_usertype(tolua_S, "cocos2d::CCArray");
    tolua_usertype(tolua_S, "CCObject");
    tolua_usertype(tolua_S, "CCDictionary");
    tolua_usertype(tolua_S, "CCArray");
}

// ============================================================================
// BTUtil bindings (all 23 methods from tolua_BTUtil_open @ 0x349ec8)
// ============================================================================

// 1. BTUtil::randomseed(unsigned int seed)
int tolua_BTUtil_randomseed00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'randomseed'.", &tolua_err);
        return 0;
    }
    const unsigned int seed = static_cast<unsigned int>(tolua_tonumber(tolua_S, 2, 0));
    BTUtil::randomseed(seed);
    return 0;
}

// 2. BTUtil::random() -> double
int tolua_BTUtil_random00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'random'.", &tolua_err);
        return 0;
    }
    const double ret = BTUtil::random();
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(ret));
    return 1;
}

// 3. BTUtil::split(std::string& str, std::string/char delim, vector<string>& out)
//    Preserves exact tolua++ 2-return-value convention: (bool, str).
int tolua_BTUtil_split00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'split'.", &tolua_err);
        return 0;
    }

    size_t strLen = 0;
    const char* strPtr = lua_tolstring(tolua_S, 2, &strLen);
    std::string str(strPtr ? strPtr : "", strLen);

    auto* outVec = (lua_type(tolua_S, 4) == LUA_TUSERDATA &&
                    tolua_isusertype(tolua_S, 4, "vector<string>", 0, &tolua_err))
        ? static_cast<std::vector<std::string>*>(tolua_tousertype(tolua_S, 4, nullptr))
        : nullptr;
    std::vector<std::string> localOut;
    std::vector<std::string>& target = outVec ? *outVec : localOut;

    bool ok = false;
    if (tolua_isnumber(tolua_S, 3, 0, &tolua_err)) {
        const char delim = static_cast<char>(tolua_tonumber(tolua_S, 3, 0));
        ok = BTUtil::split(str, delim, target);
    } else if (tolua_iscppstring(tolua_S, 3, 0, &tolua_err)) {
        size_t delimLen = 0;
        const char* delimPtr = lua_tolstring(tolua_S, 3, &delimLen);
        std::string delim(delimPtr ? delimPtr : "", delimLen);
        ok = BTUtil::split(str, delim, target);
    } else {
        tolua_error(tolua_S, "#ferror in function 'split'.", &tolua_err);
        return 0;
    }

    tolua_pushboolean(tolua_S, ok ? 1 : 0);
    tolua_pushcppstring(tolua_S, str);
    return 2;
}

// 4. BTUtil::cutString(CCString* str, CCString* delim) -> CCArray*
int tolua_BTUtil_cutString00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCString", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 3, "CCString", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'cutString'.", &tolua_err);
        return 0;
    }
    auto* str = getSafeBTCCObject<CCString>(tolua_S, 2);
    auto* delim = getSafeBTCCObject<CCString>(tolua_S, 3);
    CCArray* ret = BTUtil::cutString(str, delim);
    pushCCObject(tolua_S, ret, "CCArray");
    return 1;
}

// 5. BTUtil::splitString(std::string& utf8Str) -> (CCArray*, utf8Str)
//    Preserves exact tolua++ 2-return-value convention.
int tolua_BTUtil_splitString00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'splitString'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    std::string utf8Str(ptr ? ptr : "", len);
    CCArray* ret = BTUtil::splitString(utf8Str);
    pushCCObject(tolua_S, ret, "CCArray");
    tolua_pushcppstring(tolua_S, utf8Str);
    return 2;
}

// 6. BTUtil::checkType(CCObject* obj, std::string& typeName) -> (bool, typeName)
//    Safely handles nil, non-CCObject values, and tolua.inherit `.c_instance` tables!
int tolua_BTUtil_checkType00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 3, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'checkType'.", &tolua_err);
        return 0;
    }
    CCObject* obj = extractSafeBTCCObject(tolua_S, 2);
    std::string typeName(tolua_tocppstring(tolua_S, 3, ""));
    const bool ret = obj ? BTUtil::checkType(obj, typeName) : false;
    tolua_pushboolean(tolua_S, ret ? 1 : 0);
    tolua_pushcppstring(tolua_S, typeName);
    return 2;
}

// 7. BTUtil::getSvrTimeInterval() -> int64_t
int tolua_BTUtil_getSvrTimeInterval00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getSvrTimeInterval'.", &tolua_err);
        return 0;
    }
    const int64_t ret = BTUtil::getSvrTimeInterval();
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(ret));
    return 1;
}

// 8. BTUtil::syncTime(int64_t svrTime)
int tolua_BTUtil_syncTime00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnumber(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'syncTime'.", &tolua_err);
        return 0;
    }
    const int64_t svrTime = static_cast<int64_t>(tolua_tonumber(tolua_S, 2, 0));
    BTUtil::syncTime(svrTime);
    return 0;
}

// 9. BTUtil::getPlatform() -> int
int tolua_BTUtil_getPlatform00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getPlatform'.", &tolua_err);
        return 0;
    }
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(BTUtil::getPlatform()));
    return 1;
}

// 10. BTUtil::setGuideState(bool state)
int tolua_BTUtil_setGuideState00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isboolean(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'setGuideState'.", &tolua_err);
        return 0;
    }
    const bool state = tolua_toboolean(tolua_S, 2, 0) != 0;
    BTUtil::setGuideState(state);
    return 0;
}

// 11. BTUtil::getGuideState() -> bool
int tolua_BTUtil_getGuideState00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getGuideState'.", &tolua_err);
        return 0;
    }
    tolua_pushboolean(tolua_S, BTUtil::getGuideState() ? 1 : 0);
    return 1;
}

// 12. BTUtil::isSimulator() -> bool
int tolua_BTUtil_isSimulator00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'isSimulator'.", &tolua_err);
        return 0;
    }
    tolua_pushboolean(tolua_S, BTUtil::isSimulator() ? 1 : 0);
    return 1;
}

// 13. BTUtil::getDebugStatus() -> bool
int tolua_BTUtil_getDebugStatus00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getDebugStatus'.", &tolua_err);
        return 0;
    }
    tolua_pushboolean(tolua_S, BTUtil::getDebugStatus() ? 1 : 0);
    return 1;
}

// 14. BTUtil::unscheduleAll()
int tolua_BTUtil_unscheduleAll00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'unscheduleAll'.", &tolua_err);
        return 0;
    }
    BTUtil::unscheduleAll();
    return 0;
}

// 15. BTUtil::isAppStore() -> bool
int tolua_BTUtil_isAppStore00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'isAppStore'.", &tolua_err);
        return 0;
    }
    tolua_pushboolean(tolua_S, BTUtil::isAppStore() ? 1 : 0);
    return 1;
}

// 16. BTUtil::getMd5SumByString(std::string& input) -> (md5, input)
int tolua_BTUtil_getMd5SumByString00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getMd5SumByString'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    std::string input(ptr ? ptr : "", len);
    const std::string ret = BTUtil::getMd5SumByString(input);
    tolua_pushcppstring(tolua_S, ret);
    tolua_pushcppstring(tolua_S, input);
    return 2;
}

// 17. BTUtil::getLuaOrigPackagePath() -> std::string
int tolua_BTUtil_getLuaOrigPackagePath00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getLuaOrigPackagePath'.", &tolua_err);
        return 0;
    }
    tolua_pushcppstring(tolua_S, BTUtil::getLuaOrigPackagePath());
    return 1;
}

// 18. BTUtil::insertToSearchPathBegin(const std::string& path) -> std::string
int tolua_BTUtil_insertToSearchPathBegin00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'insertToSearchPathBegin'.", &tolua_err);
        return 0;
    }
    std::string path(tolua_tocppstring(tolua_S, 2, ""));
    tolua_pushcppstring(tolua_S, BTUtil::insertToSearchPathBegin(path));
    return 1;
}

// 19. BTUtil::getBTOnlineType() -> int
int tolua_BTUtil_getBTOnlineType00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'getBTOnlineType'.", &tolua_err);
        return 0;
    }
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(BTUtil::getBTOnlineType()));
    return 1;
}

// 20. BTUtil::sortUrlString(std::string& url) -> (sorted, url)
int tolua_BTUtil_sortUrlString00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'sortUrlString'.", &tolua_err);
        return 0;
    }
    size_t len = 0;
    const char* ptr = lua_tolstring(tolua_S, 2, &len);
    std::string url(ptr ? ptr : "", len);
    const std::string ret = BTUtil::sortUrlString(url);
    tolua_pushcppstring(tolua_S, ret);
    tolua_pushcppstring(tolua_S, url);
    return 2;
}

// 21. BTUtil::exitNow()
int tolua_BTUtil_exitNow00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'exitNow'.", &tolua_err);
        return 0;
    }
    BTUtil::exitNow();
    return 0;
}

// 22. BTUtil::TimeStart()
int tolua_BTUtil_TimeStart00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'TimeStart'.", &tolua_err);
        return 0;
    }
    BTUtil::TimeStart();
    return 0;
}

// 23. BTUtil::TimeEnd() -> uint64_t
int tolua_BTUtil_TimeEnd00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 2, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'TimeEnd'.", &tolua_err);
        return 0;
    }
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(BTUtil::TimeEnd()));
    return 1;
}

// ============================================================================
// ClassInfo::description (5 overloads: CCArray, CCDictionary, CCString, CCInteger, CCPoint)
// ============================================================================

int tolua_BTUtil_ClassInfo_description00(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "ClassInfo", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCArray", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'description'.", &tolua_err);
        return 0;
    }
    auto* arr = getSafeBTCCObject<CCArray>(tolua_S, 2);
    tolua_pushcppstring(tolua_S, ClassInfo::description(arr));
    return 1;
}

int tolua_BTUtil_ClassInfo_description01(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "ClassInfo", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCDictionary", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        return tolua_BTUtil_ClassInfo_description00(tolua_S);
    }
    auto* dict = getSafeBTCCObject<CCDictionary>(tolua_S, 2);
    tolua_pushcppstring(tolua_S, ClassInfo::description(dict));
    return 1;
}

int tolua_BTUtil_ClassInfo_description02(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "ClassInfo", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCString", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        return tolua_BTUtil_ClassInfo_description01(tolua_S);
    }
    auto* str = getSafeBTCCObject<CCString>(tolua_S, 2);
    tolua_pushcppstring(tolua_S, ClassInfo::description(str));
    return 1;
}

int tolua_BTUtil_ClassInfo_description03(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "ClassInfo", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCInteger", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        return tolua_BTUtil_ClassInfo_description02(tolua_S);
    }
    auto* val = getSafeBTCCObject<CCInteger>(tolua_S, 2);
    tolua_pushcppstring(tolua_S, ClassInfo::description(val));
    return 1;
}

int tolua_BTUtil_ClassInfo_description04(lua_State* tolua_S) {
    tolua_Error tolua_err;
    if (!tolua_isusertable(tolua_S, 1, "ClassInfo", 0, &tolua_err) ||
        !tolua_isusertype(tolua_S, 2, "CCPoint", 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 3, &tolua_err)) {
        return tolua_BTUtil_ClassInfo_description03(tolua_S);
    }
    auto* pt = (lua_type(tolua_S, 2) == LUA_TUSERDATA)
        ? static_cast<CCPoint*>(tolua_tousertype(tolua_S, 2, nullptr))
        : nullptr;
    const std::string desc = pt ? ClassInfo::description(*pt) : "CCPoint(null)";
    lua_pushlstring(tolua_S, desc.data(), desc.size());
    return 1;
}

} // namespace

TOLUA_API int tolua_BTUtil_open(lua_State* tolua_S) {
    tolua_open(tolua_S);
    tolua_reg_types_BTUtil(tolua_S);
    tolua_module(tolua_S, nullptr, 0);
    tolua_beginmodule(tolua_S, nullptr);

    tolua_constant(tolua_S, "kBT_PLATFORM_IOS", static_cast<lua_Number>(kBT_PLATFORM_IOS));
    tolua_constant(tolua_S, "kBT_PLATFORM_ANDROID", static_cast<lua_Number>(kBT_PLATFORM_ANDROID));

    tolua_cclass(tolua_S, "BTUtil", "BTUtil", "", nullptr);
    tolua_beginmodule(tolua_S, "BTUtil");
    tolua_function(tolua_S, "randomseed", tolua_BTUtil_randomseed00);
    tolua_function(tolua_S, "random", tolua_BTUtil_random00);
    tolua_function(tolua_S, "split", tolua_BTUtil_split00);
    tolua_function(tolua_S, "cutString", tolua_BTUtil_cutString00);
    tolua_function(tolua_S, "splitString", tolua_BTUtil_splitString00);
    tolua_function(tolua_S, "checkType", tolua_BTUtil_checkType00);
    tolua_function(tolua_S, "getSvrTimeInterval", tolua_BTUtil_getSvrTimeInterval00);
    tolua_function(tolua_S, "syncTime", tolua_BTUtil_syncTime00);
    tolua_function(tolua_S, "getPlatform", tolua_BTUtil_getPlatform00);
    tolua_function(tolua_S, "setGuideState", tolua_BTUtil_setGuideState00);
    tolua_function(tolua_S, "getGuideState", tolua_BTUtil_getGuideState00);
    tolua_function(tolua_S, "isSimulator", tolua_BTUtil_isSimulator00);
    tolua_function(tolua_S, "getDebugStatus", tolua_BTUtil_getDebugStatus00);
    tolua_function(tolua_S, "unscheduleAll", tolua_BTUtil_unscheduleAll00);
    tolua_function(tolua_S, "isAppStore", tolua_BTUtil_isAppStore00);
    tolua_function(tolua_S, "getMd5SumByString", tolua_BTUtil_getMd5SumByString00);
    tolua_function(tolua_S, "getLuaOrigPackagePath", tolua_BTUtil_getLuaOrigPackagePath00);
    tolua_function(tolua_S, "insertToSearchPathBegin", tolua_BTUtil_insertToSearchPathBegin00);
    tolua_function(tolua_S, "getBTOnlineType", tolua_BTUtil_getBTOnlineType00);
    tolua_function(tolua_S, "sortUrlString", tolua_BTUtil_sortUrlString00);
    tolua_function(tolua_S, "exitNow", tolua_BTUtil_exitNow00);
    tolua_function(tolua_S, "TimeStart", tolua_BTUtil_TimeStart00);
    tolua_function(tolua_S, "TimeEnd", tolua_BTUtil_TimeEnd00);
    tolua_endmodule(tolua_S);

    tolua_cclass(tolua_S, "ClassInfo", "ClassInfo", "", nullptr);
    tolua_beginmodule(tolua_S, "ClassInfo");
    tolua_function(tolua_S, "description", tolua_BTUtil_ClassInfo_description04);
    tolua_endmodule(tolua_S);

    tolua_endmodule(tolua_S);
    return 1;
}
