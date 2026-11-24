#pragma once

struct lua_State;

#ifdef __cplusplus
extern "C" {
#endif

/// Registers `"amf3"` in `package.preload` so Lua scripts can call `local amf3 = require("amf3")`.
/// Matches `luaopen_amf3_extensions` @ 0x2c6138 in `08_libcocos2dlua_custom_classes.c`.
int luaopen_amf3_extensions(lua_State* L);

/// Module loader invoked by `require("amf3")`, returning a table with `encode` and `decode`.
int luaopen_amf3(lua_State* L);

/// `amf3.encode(val) -> binary_string`
int amf3_encode(lua_State* L);

/// `amf3.decode(str, [pos=0]) -> val, new_pos` (0-based byte offset)
int amf3_decode(lua_State* L);

#ifdef __cplusplus
}
#endif
