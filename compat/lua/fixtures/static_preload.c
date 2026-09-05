/*
 * Link the existing Lua fixture modules into the native static programs.
 *
 * This is deliberately a package.preload adapter, not a substitute for the
 * dynamic lane's DSO tests.  It proves that the same module entry points and
 * C-ABI work when they are ordinary application objects in a static link.
 */

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

int luaopen_crabc_probe(lua_State *state);
int luaopen_crabc_fail(lua_State *state);

void crabc_lua_install_static_preloads(lua_State *state)
{
    luaL_getsubtable(state, LUA_REGISTRYINDEX, LUA_PRELOAD_TABLE);
    lua_pushcfunction(state, luaopen_crabc_probe);
    lua_setfield(state, -2, "crabc_probe");
    lua_pushcfunction(state, luaopen_crabc_fail);
    lua_setfield(state, -2, "crabc_fail");
    lua_pop(state, 1);
}
