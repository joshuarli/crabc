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
 * Musl formats each dlerror message into a per-thread buffer sized to it,
 * so the dlopen case also reads messages naming a 3000-byte requester and a
 * 5000-byte symbol, resolves a 717-byte C++-mangled-style symbol, and checks
 * that a message is consumed once, stays per-thread, and survives many
 * worker threads that exit with an unread one.
 *
 * Roles: NAMES_LEAF with NAMES_SYMBOL and NAMES_ID exports one identifier;
 * NAMES_ORIGIN additionally calls NAMES_LEAF_SYMBOL from its bare-named
 * dependency; otherwise the executable, whose case is NAMES_CASE.
 */
#define _GNU_SOURCE

#define NAMES_C10 "9component"
#define NAMES_C100 NAMES_C10 NAMES_C10 NAMES_C10 NAMES_C10 NAMES_C10 \
	NAMES_C10 NAMES_C10 NAMES_C10 NAMES_C10 NAMES_C10
#define NAMES_C500 NAMES_C100 NAMES_C100 NAMES_C100 NAMES_C100 NAMES_C100
#define NAMES_LONG_NAME "_ZN5crabc" NAMES_C500 NAMES_C100 NAMES_C100 "5valueEv"
#define NAMES_MISSING_NAME "_ZN5crabc" NAMES_C500 NAMES_C500 NAMES_C500 NAMES_C500 NAMES_C500 \
	NAMES_C500 NAMES_C500 NAMES_C500 NAMES_C500 NAMES_C500 "7missingEv"

#if defined(NAMES_LEAF)
int NAMES_SYMBOL(void) { return NAMES_ID; }
#if defined(NAMES_LONG)
int names_long_value(void) __asm__(NAMES_LONG_NAME);
int names_long_value(void) { return 10 * NAMES_ID; }
#endif

#elif defined(NAMES_ORIGIN)
int NAMES_LEAF_SYMBOL(void);
int NAMES_SYMBOL(void) { return NAMES_ID + NAMES_LEAF_SYMBOL(); }

#else
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
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

static void *open_quietly(const char *name)
{
	return dlopen(name, RTLD_NOW);
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

/* The name's length, whether dlopen failed, whether the message names it
 * in full, and the %m text after it. Musl rejects a bare name over NAME_MAX
 * before any open and formats whatever errno the caller left. */
static void refuse(const char *tag, const char *name, int caller_errno)
{
	errno = caller_errno;
	void *handle = dlopen(name, RTLD_NOW);
	const char *error = dlerror();
	const char *prefix = "Error loading shared library ";
	size_t length = strlen(prefix), name_length = strlen(name);
	int named = error && !strncmp(error, prefix, length) && !strncmp(error + length, name, name_length)
	            && !strncmp(error + length + name_length, ": ", 2);
	printf("%s:%zu:%d:%d:%s;", tag, name_length, handle == 0, named, named ? error + length + name_length + 2 : "");
}

/* Whether `error` is exactly `first second third`, and its length. */
static void message(const char *tag, const char *error, const char *first, const char *second, const char *third)
{
	size_t a = strlen(first), b = strlen(second);
	int exact = error && !strncmp(error, first, a) && !strncmp(error + a, second, b) && !strcmp(error + a + b, third);
	printf("%s(%zu,%d);", tag, error ? strlen(error) : 0, exact);
}

/* A worker's failure is its own; it exits without reading it. */
static void *failing_worker(void *unused)
{
	(void)unused;
	if (dlopen("/names-missing/worker.so", RTLD_NOW)) return (void *)1;
	return 0;
}

static void *reading_worker(void *unused)
{
	(void)unused;
	if (dlerror()) return (void *)1;
	(void)dlopen("/names-missing/reader.so", RTLD_NOW);
	const char *error = dlerror();
	return (void *)(long)(!error || strcmp(error, "Error loading shared library /names-missing/reader.so: "
	                                              "No such file or directory") || dlerror());
}

/* dlerror is consumed once, per thread, across exiting workers. */
static void lifecycle(void)
{
	(void)dlopen("/names-missing/main.so", RTLD_NOW);
	int failures = 0;
	for (int index = 0; index < 64; ++index) {
		pthread_t thread;
		void *result = 0;
		if (pthread_create(&thread, 0, index % 2 ? reading_worker : failing_worker, 0)
		    || pthread_join(thread, &result) || result)
			++failures;
	}
	const char *error = dlerror();
	int own = error && !strcmp(error, "Error loading shared library /names-missing/main.so: No such file or directory");
	printf("lifecycle(%d,%d,%d);", failures, own, dlerror() == 0);
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
		identify("long", lookup(c, NAMES_LONG_NAME), path("NAMES_C"));
		printf("missing=%d,", lookup(c, NAMES_MISSING_NAME) != 0);
		message("missing", dlerror(), "Symbol not found: ", NAMES_MISSING_NAME, "");
		printf("again(%d);", dlerror() == 0);
		/* The dependency is on no search path; the requester's origin
		 * exceeds musl's candidate buffer. */
		printf("g=%d,", open_quietly(path("NAMES_G")) != 0);
		message("needed", dlerror(), "Error loading shared library libowned-startup-name-missing.so: "
		        "No such file or directory (needed by ", path("NAMES_G"), ")");
		char bare[300];
		memset(bare, 'n', sizeof bare - 1);
		bare[sizeof bare - 1] = 0;
		refuse("bare", bare, EXDEV);
		refuse("bare-zero", bare, 0);
		char *overlong = malloc(5000);
		if (!overlong) return 91;
		memset(overlong, 'o', 4999);
		overlong[0] = '/';
		overlong[4999] = 0;
		refuse("overlong", overlong, 0);
		free(overlong);
		lifecycle();
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
