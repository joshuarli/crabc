/*
 * Initial DT_NEEDED dependency for the owned dynamic CRT lifecycle probe.
 * Its constructor runs before every main-image constructor; its destructor
 * runs after the main image's. It also owns the runtime plugin open so a
 * dependency constructor can load an object before main construction starts.
 * It deliberately uses no compiler helper: see the plugin.
 *
 * Its large zero-initialized array lies past the image's file-backed pages.
 * Loading must leave those pages as untouched anonymous zero fill, as musl
 * does, rather than writing zeros that make every .bss page resident.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void mark(char marker)
{
	(void)write(1, &marker, 1);
}

#define BSS_PAGES 64
static char untouched_bss[BSS_PAGES * 4096] __attribute__((aligned(4096)));

/* Pages other than the first and last may share no byte with other data. */
static void check_untouched_bss(void)
{
	unsigned char resident[BSS_PAGES];
	if (mincore(untouched_bss, sizeof(untouched_bss), resident)) {
		(void)write(1, "!m", 2);
		_exit(92);
	}
	for (int page = 1; page < BSS_PAGES - 1; ++page)
		if ((resident[page] & 1) || untouched_bss[page * 4096]) {
			(void)write(1, "!z", 2);
			_exit(92);
		}
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
	check_untouched_bss();
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
