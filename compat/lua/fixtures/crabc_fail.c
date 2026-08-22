/* Controlled Lua module-initialisation failure for loader/error-path tests. */

#include <lua.h>
#include <lauxlib.h>

int luaopen_crabc_fail(lua_State *state)
{
    return luaL_error(state, "crabc_fail: intentional init failure");
}
