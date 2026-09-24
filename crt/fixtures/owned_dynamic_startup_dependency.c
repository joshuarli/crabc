/*
 * Initial DT_NEEDED dependency for the owned dynamic CRT lifecycle probe.
 * Its constructor runs before every main-image constructor; its destructor
 * runs after the main image's. It also owns the runtime plugin open so a
 * dependency constructor can load an object before main construction starts.
 * It deliberately uses no compiler helper: see the plugin.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void mark(char marker)
{
	(void)write(1, &marker, 1);
}

static int scenario(const char *name)
{
	const char *selected = getenv("CRABC_CRT_CASE");
	return selected != 0 && strcmp(selected, name) == 0;
}

void *owned_startup_open_plugin(void)
{
	void *plugin = dlopen("libowned-startup-plugin.so", RTLD_NOW);
	int (*value)(void) = plugin ? (int (*)(void))dlsym(plugin, "owned_startup_plugin_value") : 0;
	if (!value || value() != 23) {
		(void)write(1, "!o", 2);
		_exit(91);
	}
	return plugin;
}

__attribute__((constructor)) static void dependency_constructor(void)
{
	mark('D');
	if (scenario("exit-in-dependency-constructor")) exit(23);
	if (scenario("dlopen-in-dependency-constructor")) owned_startup_open_plugin();
}

__attribute__((destructor)) static void dependency_destructor(void)
{
	mark('d');
}

int owned_startup_dependency_value(void)
{
	return 17;
}
