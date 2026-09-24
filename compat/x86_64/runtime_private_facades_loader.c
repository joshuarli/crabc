/*
 * Installed-product differential for crabc-rs's native x86-64 `dl` facade.
 *
 * Each Rust entry reaches only the private RuntimeV1 table. This driver then
 * performs the same request through the product's public dlfcn/link.h API in
 * the same process and requires identical copied values. It also proves that
 * facade failures neither consume this thread's pending dlerror nor change
 * errno, and that the retained-close lifecycle follows pinned musl 1.2.6.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum { TEXT = 1024, IMAGES = 16 };

struct facade_image {
	void *base;
	const void *phdr;
	size_t phnum;
	unsigned long long adds, subs;
	size_t tls_module;
	void *tls_data;
	char name[257];
};

int crabc_rs_x86_64_facade_open_error(const char *, char *, size_t);
int crabc_rs_x86_64_facade_symbol_error(const char *, const char *, char *, size_t);
int crabc_rs_x86_64_facade_symbol(const char *, const char *, void **);
int crabc_rs_x86_64_facade_address(void *, void **, void **, char *, char *, size_t);
int crabc_rs_x86_64_facade_information(const char *, void **, void **, char *, size_t);
int crabc_rs_x86_64_facade_snapshot(struct facade_image *, size_t, size_t *, unsigned long long *);
int crabc_rs_x86_64_facade_lifecycle(void);

static const char missing_dso[] = "libruntime_facade_missing.so";
static const char tls_dso[] = "libruntime_facade_tls.so";
static const char close_dso[] = "libloader_dlfcn_close.so";

static int check(int ok, int code)
{
	if (!ok) {
		printf("x86 runtime private loader facade FAIL %d\n", code);
		fflush(stdout);
	}
	return ok ? 0 : code;
}

#define REQUIRE(condition, code) do { int failed_ = check((condition), (code)); if (failed_) return failed_; } while (0)

struct c_images {
	struct dl_phdr_info records[IMAGES];
	char names[IMAGES][257];
	size_t count;
};

static int copy_image(struct dl_phdr_info *info, size_t size, void *data)
{
	struct c_images *images = data;
	if (size < sizeof *info || images->count == IMAGES) return 1;
	images->records[images->count] = *info;
	snprintf(images->names[images->count], sizeof images->names[0], "%s", info->dlpi_name ? info->dlpi_name : "");
	images->count++;
	return 0;
}

static int diagnostics(void)
{
	char facade[TEXT], expected[TEXT];
	const char *pending;

	/* A pending C diagnostic and errno survive failing facade calls. */
	REQUIRE(dlsym(RTLD_DEFAULT, "crabc_runtime_facade_absent_c") == NULL, 1);
	errno = 77;
	REQUIRE(crabc_rs_x86_64_facade_open_error(missing_dso, facade, sizeof facade) == 0, 2);
	REQUIRE(crabc_rs_x86_64_facade_symbol_error(close_dso, "loader_dlfcn_absent", expected, sizeof expected) == 0, 3);
	REQUIRE(errno == 77, 4);
	pending = dlerror();
	REQUIRE(pending && strcmp(pending, "Symbol not found: crabc_runtime_facade_absent_c") == 0, 5);
	REQUIRE(dlerror() == NULL, 6);

	/* Copied diagnostics equal the public ones for the same requests. */
	REQUIRE(dlopen(missing_dso, RTLD_NOW) == NULL, 7);
	pending = dlerror();
	REQUIRE(pending && strcmp(pending, facade) == 0, 8);
	void *library = dlopen(close_dso, RTLD_NOW);
	REQUIRE(library != NULL, 9);
	REQUIRE(dlsym(library, "loader_dlfcn_absent") == NULL, 10);
	pending = dlerror();
	REQUIRE(pending && strcmp(pending, expected) == 0, 11);
	REQUIRE(crabc_rs_x86_64_facade_symbol_error(NULL, "crabc_runtime_facade_absent_main", facade, sizeof facade) == 0, 12);
	REQUIRE(dlsym(dlopen(NULL, RTLD_NOW), "crabc_runtime_facade_absent_main") == NULL, 13);
	pending = dlerror();
	REQUIRE(pending && strcmp(pending, facade) == 0, 14);
	REQUIRE(dlclose(library) == 0, 15);
	return 0;
}

static int addresses(void)
{
	void *library = dlopen(close_dso, RTLD_NOW);
	void *value = library ? dlsym(library, "loader_dlfcn_value") : NULL;
	void *base, *symbol;
	char image[TEXT], name[TEXT];
	Dl_info info;
	void *targets[] = { value, (char *)value + 1, (void *)&printf };

	REQUIRE(value != NULL, 20);
	for (size_t index = 0; index < sizeof targets / sizeof targets[0]; index++) {
		REQUIRE(crabc_rs_x86_64_facade_address(targets[index], &base, &symbol, image, name, sizeof image) == 0, 21);
		REQUIRE(dladdr(targets[index], &info) != 0, 22);
		REQUIRE(base == info.dli_fbase && symbol == info.dli_saddr, 23);
		REQUIRE(strcmp(image, info.dli_fname ? info.dli_fname : "") == 0, 24);
		REQUIRE(strcmp(name, info.dli_sname ? info.dli_sname : "") == 0, 25);
	}
	/* An unmapped address is an owned lookup failure, as dladdr reports 0. */
	REQUIRE(dladdr((void *)16, &info) == 0, 26);
	REQUIRE(crabc_rs_x86_64_facade_address((void *)16, &base, &symbol, image, name, sizeof image) == 2, 27);
	REQUIRE(dlclose(library) == 0, 28);
	return 0;
}

static int information(const char *request, int code)
{
	void *library = dlopen(request, RTLD_NOW);
	struct link_map *map = NULL;
	void *base, *dynamic;
	char name[TEXT];

	REQUIRE(library != NULL, code);
	REQUIRE(dlinfo(library, RTLD_DI_LINKMAP, &map) == 0 && map != NULL, code + 1);
	REQUIRE(crabc_rs_x86_64_facade_information(request, &base, &dynamic, name, sizeof name) == 0, code + 2);
	REQUIRE(base == (void *)map->l_addr && dynamic == (void *)map->l_ld, code + 3);
	REQUIRE(strcmp(name, map->l_name ? map->l_name : "") == 0, code + 4);
	if (request) REQUIRE(dlclose(library) == 0, code + 5);
	return 0;
}

static int snapshot(void)
{
	static struct facade_image facade[IMAGES];
	static struct c_images images;
	size_t count = 0;
	unsigned long long generation = 0;
	int *(*tls_address)(void);
	void *tls_symbol = NULL;
	void *library = dlopen(tls_dso, RTLD_NOW);

	REQUIRE(library != NULL, 40);
	tls_address = (int *(*)(void))dlsym(library, "runtime_facade_tls_address");
	REQUIRE(tls_address != NULL, 41);
	/* A TLS symbol resolves to the calling thread's object, as with dlsym. */
	REQUIRE(crabc_rs_x86_64_facade_symbol(tls_dso, "runtime_facade_tls_value", &tls_symbol) == 0, 42);
	REQUIRE(tls_symbol == dlsym(library, "runtime_facade_tls_value") && tls_symbol == tls_address(), 43);

	REQUIRE(crabc_rs_x86_64_facade_snapshot(facade, IMAGES, &count, &generation) == 0, 44);
	images.count = 0;
	REQUIRE(dl_iterate_phdr(copy_image, &images) == 0, 45);
	REQUIRE(count == images.count && count >= 3, 46);
	REQUIRE(generation == images.records[0].dlpi_adds + images.records[0].dlpi_subs, 47);
	int saw_tls = 0;
	for (size_t index = 0; index < count; index++) {
		struct dl_phdr_info *expected = &images.records[index];
		REQUIRE(facade[index].base == (void *)expected->dlpi_addr, 48);
		REQUIRE(facade[index].phdr == expected->dlpi_phdr && facade[index].phnum == expected->dlpi_phnum, 49);
		REQUIRE(facade[index].adds == expected->dlpi_adds && facade[index].subs == expected->dlpi_subs, 50);
		REQUIRE(facade[index].tls_module == expected->dlpi_tls_modid && facade[index].tls_data == expected->dlpi_tls_data, 51);
		REQUIRE(strcmp(facade[index].name, images.names[index]) == 0, 52);
		if (facade[index].tls_data == (void *)tls_address()) saw_tls = 1;
	}
	REQUIRE(saw_tls, 53);
	REQUIRE(dlclose(library) == 0, 54);
	return 0;
}

int main(void)
{
	int result;
	if ((result = diagnostics())) return 1;
	if ((result = addresses())) return 1;
	if ((result = information(NULL, 30))) return 1;
	if ((result = information(close_dso, 36))) return 1;
	if ((result = snapshot())) return 1;
	result = crabc_rs_x86_64_facade_lifecycle();
	if (check(result == 0, 60 + result)) return 1;
	puts("x86 runtime private loader facade ok");
	return 0;
}
