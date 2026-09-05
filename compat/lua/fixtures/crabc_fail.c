/* Controlled Lua module-initialisation failure for dynamic and linked-preload error paths. */

#include "lua.h"
#include "lauxlib.h"

int luaopen_crabc_fail(lua_State *state)
{
    return luaL_error(state, "crabc_fail: intentional init failure");
}
