#pragma once
extern "C" {
#include "lua.h"
}
#include "bindings/tolua_BTUtil.h"
#include "bindings/tolua_GameTemplate.h"
#include "platform/tolua_Platform.h"
#include "net/Amf3Module.h"

// Cocos2d-x 2.2.6 built-in Lua extension entry points
extern int tolua_extensions_ccb_open(lua_State* tolua_S);
extern "C" int luaopen_lua_extensions(lua_State* L);

// Optional Lua profiler stub (safe no-op on Win32)
inline int luaopen_luaprofiler(lua_State* /*L*/) { return 0; }
