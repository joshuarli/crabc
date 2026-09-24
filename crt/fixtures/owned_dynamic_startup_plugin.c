/*
 * Runtime-loaded object for the owned dynamic CRT lifecycle probe. Musl
 * finalizes objects in reverse construction-start order, so this plugin's
 * destructor precedes the main image's whenever it was constructed later.
 * Its compiler-generated two-word helper call must be satisfied inside this
 * application DSO. It is not a link-time dependency of the main image, so
 * its helper definitions cannot stand in for the executable's own.
 */
#include <unistd.h>

__attribute__((constructor)) static void plugin_constructor(void)
{
	(void)write(1, "L", 1);
}

__attribute__((destructor)) static void plugin_destructor(void)
{
	(void)write(1, "l", 1);
}

int owned_startup_plugin_value(void)
{
	return 23;
}

unsigned __int128 owned_startup_plugin_quotient(unsigned __int128 dividend, unsigned __int128 divisor)
{
	return dividend / divisor;
}
