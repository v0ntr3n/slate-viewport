#pragma once

extern "C" {
#include "lua.h"
}

/**
 * Registers bt::Platform (usertypes CallBack & Platform, all k* constants,
 * and all 69 Platform methods) into the given Cocos2d-x 2.2.6 Lua state.
 * Matches PluginsLuaLoder::loder / tolua_Platform_open from
 * 01_libcocos2dlua_startup_and_bindings.c.
 */
int tolua_Platform_open(lua_State* L);

/**
 * Safe logged stub for PluginManager Lua bindings so legacy scripts referencing
 * PluginManager never crash with nil indexing or missing methods on Win32.
 */
int tolua_PluginManager_open(lua_State* L);

/**
 * Safe logged stub for NotificationManager Lua bindings so legacy scripts
 * scheduling local/push notifications resolve cleanly without crashing on Win32.
 */
int tolua_NotificationManager_open(lua_State* L);

/**
 * Convenience loader matching PluginsLuaLoder::loder(lua_State* L) in
 * 01_libcocos2dlua_startup_and_bindings.c.
 */
int tolua_GCLIENT_Plugins_open(lua_State* L);
