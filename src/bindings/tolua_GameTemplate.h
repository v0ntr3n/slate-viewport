#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "tolua++.h"
#ifdef __cplusplus
}
#endif

// Forwarding hooks for HTTP and Crypto tolua++ class registrations.
// External modules (src/http, src/crypto) may populate any subset of these callbacks
// before calling tolua_GameTemplate_open(L); unset hooks fall back to safe logged stubs
// with all class constants and method names registered.
struct GameTemplateForwardingHooks {
    int (*registerCCHttpRequest)(lua_State* L) = nullptr;
    int (*registerCCHttpResponse)(lua_State* L) = nullptr;
    int (*registerCCHttpClient)(lua_State* L) = nullptr;
    int (*registerLuaHttpRequest)(lua_State* L) = nullptr;
    int (*registerLuaHttpResponse)(lua_State* L) = nullptr;
    int (*registerCCCrypto)(lua_State* L) = nullptr;
};

TOLUA_API void tolua_GameTemplate_set_hooks(const GameTemplateForwardingHooks& hooks);
TOLUA_API int tolua_GameTemplate_open(lua_State* tolua_S);

#ifdef __cplusplus
// Resets and re-schedules WinHttpClient::dispatchCallbacks on CCScheduler if an instance exists.
void gclient_rescheduleHttpClientCallbacks();
#endif
