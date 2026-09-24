/* One source for every image of the installed dynamic startup "names" graph.
 *
 * Pinned musl 1.2.6 stores each loaded object's pathname in an allocation
 * sized to it, opens a name containing '/' as given (only the kernel's
 * PATH_MAX applies), rejects a bare name longer than NAME_MAX, composes
 * search candidates in a 2*NAME_MAX+2 buffer that skips components which do
 * not fit, and allocates `$ORIGIN` expansions. This graph places images at
 * ~600- and ~3000-byte absolute paths, names two of them from the executable
 * as pathname DT_NEEDED entries, expands a deep `$ORIGIN` beside an ordinary
 * directory, preloads long paths and searches overlong LD_LIBRARY_PATH
 * components. The runner lays out the same tree below a different root for
 * each arm and supplies the expected paths, so the transcript never contains
 * a root-dependent byte.
 *
 * Roles: NAMES_LEAF with NAMES_SYMBOL and NAMES_ID exports one identifier;
 * NAMES_ORIGIN additionally calls NAMES_LEAF_SYMBOL from its bare-named
 * dependency; otherwise the executable, whose case is NAMES_CASE.
 */
#define _GNU_SOURCE

#if defined(NAMES_LEAF)
int NAMES_SYMBOL(void) { return NAMES_ID; }

#elif defined(NAMES_ORIGIN)
int NAMES_LEAF_SYMBOL(void);
int NAMES_SYMBOL(void) { return NAMES_ID + NAMES_LEAF_SYMBOL(); }

#else
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int names_a_value(void);
int names_b_value(void);

struct owner { uintptr_t address; uintptr_t base; const char *name; int count; };

/* The object whose PT_LOAD contains `address`; musl's dli_fbase is its
 * lowest mapping, not its load bias, so neither is compared here. */
static int find_owner(struct dl_phdr_info *info, size_t size, void *data)
{
	struct owner *owner = data;
	(void)size;
	for (int index = 0; index < info->dlpi_phnum; ++index) {
		const ElfW(Phdr) *phdr = &info->dlpi_phdr[index];
		uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
		if (phdr->p_type == PT_LOAD && owner->address >= start && owner->address - start < phdr->p_memsz) {
			owner->base = info->dlpi_addr;
			owner->name = info->dlpi_name;
			++owner->count;
		}
	}
	return 0;
}

/* dladdr, dl_iterate_phdr and the link map must all show the stored name. */
static void report(const char *tag, void *symbol, const char *expected)
{
	Dl_info info;
	int by_address = symbol && expected && dladdr(symbol, &info) && info.dli_fname
	                 && !strcmp(info.dli_fname, expected);
	struct owner owner = { (uintptr_t)symbol, 0, 0, 0 };
	dl_iterate_phdr(find_owner, &owner);
	int by_phdr = expected && owner.count == 1 && owner.name && !strcmp(owner.name, expected);
	struct link_map *map = 0;
	int by_link_map = 0;
	if (!dlinfo(dlopen(0, RTLD_NOW), RTLD_DI_LINKMAP, &map))
		for (; map; map = map->l_next)
			if (owner.count == 1 && map->l_addr == owner.base)
				by_link_map = map->l_name && !strcmp(map->l_name, expected);
	printf("%s:%zu:%d%d%d;", tag, expected ? strlen(expected) : 0, by_address, by_phdr, by_link_map);
}

static const char *path(const char *key)
{
	const char *value = getenv(key);
	return value ? value : "";
}

/* A handle from dlopen, or the failure's %m text. */
static void *open_object(const char *name, int flags)
{
	void *handle = dlopen(name, flags);
	if (!handle) {
		const char *error = dlerror();
		const char *tail = error ? strrchr(error, ':') : 0;
		printf("dlopen-failed(%s);", tail ? tail + 2 : "none");
	}
	return handle;
}

static void *lookup(void *handle, const char *symbol)
{
	return handle ? dlsym(handle, symbol) : 0;
}

static void identify(const char *tag, void *symbol, const char *expected)
{
	int (*value)(void) = (int (*)(void))symbol;
	printf("%s=%d,", tag, value ? value() : -1);
	report(tag, symbol, expected);
}

/* The name's length, whether dlopen failed, and the message's %m text.
 * The candidate's dlerror text is a fixed 1024-byte copy (libc
 * `dlfcn_diagnostic.rs`) where musl allocates, so a name beyond it compares
 * only the failure and the message prefix. */
static void refuse(const char *tag, const char *name, int with_errno)
{
	/* Musl rejects a bare name over NAME_MAX before any open and formats
	 * whatever the caller's errno holds; the installed loader reports
	 * ENAMETOOLONG. Preset that value so only the rejection is compared. */
	errno = ENAMETOOLONG;
	void *handle = dlopen(name, RTLD_NOW);
	const char *error = dlerror();
	const char *prefix = "Error loading shared library ";
	const char *tail = error ? strrchr(error, ':') : 0;
	int shaped = error && !strncmp(error, prefix, strlen(prefix)) && (!with_errno || (tail && tail[1] == ' '));
	if (!with_errno) tail = 0;
	printf("%s:%zu:%d:%d:%s;", tag, strlen(name), handle == 0, shaped, shaped && tail ? tail + 2 : "");
}

int main(void)
{
	const char *which = getenv("NAMES_CASE");
	if (!which) return 90;
	report("main", (void *)main, path("NAMES_PROGRAM"));
	/* A non-PIE executable's own canonical PLT address would name main;
	 * the lookup names each definition, and the call below links both. */
	if (names_a_value() != 1) return 93;
	identify("a", dlsym(RTLD_DEFAULT, "names_a_value"), path("NAMES_A"));
	identify("b", dlsym(RTLD_DEFAULT, "names_b_value"), path("NAMES_B"));
	identify("leaf", dlsym(RTLD_DEFAULT, "names_leaf_value"), path("NAMES_LEAF"));
	if (!strcmp(which, "dlopen")) {
		void *c = open_object(path("NAMES_C"), RTLD_NOW);
		identify("c", lookup(c, "names_c_value"), path("NAMES_C"));
		void *d = open_object(path("NAMES_D"), RTLD_NOW);
		identify("d", lookup(d, "names_d_value"), path("NAMES_D"));
		identify("deep", lookup(d, "names_deep_value"), path("NAMES_DEEP"));
		char bare[300];
		memset(bare, 'n', sizeof bare - 1);
		bare[sizeof bare - 1] = 0;
		refuse("bare", bare, 1);
		char *overlong = malloc(5000);
		if (!overlong) return 91;
		memset(overlong, 'o', 4999);
		overlong[0] = '/';
		overlong[4999] = 0;
		refuse("overlong", overlong, 0);
		free(overlong);
	} else if (!strcmp(which, "search")) {
		void *search = open_object("libowned-startup-name-search.so", RTLD_NOW);
		identify("search", lookup(search, "names_search_value"), path("NAMES_SEARCH"));
	} else if (!strcmp(which, "preload")) {
		void *e = open_object(path("NAMES_E"), RTLD_NOW | RTLD_NOLOAD);
		identify("e", lookup(e, "names_e_value"), path("NAMES_E"));
		void *f = open_object(path("NAMES_F"), RTLD_NOW | RTLD_NOLOAD);
		identify("f", lookup(f, "names_f_value"), path("NAMES_F"));
	} else if (strcmp(which, "initial")) {
		return 92;
	}
	fflush(stdout);
	return 7;
}
#endif
