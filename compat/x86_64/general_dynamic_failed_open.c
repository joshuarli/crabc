/* A root DSO first reaches a malformed dependency after mapping a TLS image,
 * then reaches an unresolved relocation after that dependency is replaced.
 * Each failure must leave no visible object, module, symbol, or constructor.
 * The final replacement opens the same root successfully. Module IDs are
 * compared relative to the initially loaded modules because the two runtimes
 * have different initial TLS owners. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>

struct image_state { unsigned count; unsigned long long adds; unsigned long tls_module; unsigned long max_module; };

static int image(struct dl_phdr_info *info, size_t size, void *data) {
    struct image_state *state = data;
    (void)size;
    state->adds = info->dlpi_adds;
    if (info->dlpi_tls_modid > state->max_module) state->max_module = info->dlpi_tls_modid;
    if (info->dlpi_name && strstr(info->dlpi_name, "libfo_")) {
        ++state->count;
        if (strstr(info->dlpi_name, "libfo_tls.so")) state->tls_module = info->dlpi_tls_modid;
    }
    return 0;
}

static struct image_state snapshot(void) {
    struct image_state state = {0, 0, 0, 0};
    dl_iterate_phdr(image, &state);
    return state;
}

static int fail_open(const char *label, const char *name, const char *expected, struct image_state before) {
    void *handle = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
    const char *error = dlerror();
    const char *kind = !error ? "none" : strstr(error, "symbol not found") ? "symbol"
        : strstr(error, "Exec format error") ? "malformed" : "other";
    struct image_state after = snapshot();
    int consumed = dlerror() == 0;
    int root_symbol = dlsym(RTLD_DEFAULT, "failed_open_root_value") != 0;
    (void)dlerror();
    int tls_symbol = dlsym(RTLD_DEFAULT, "failed_open_tls_value") != 0;
    (void)dlerror();
    void *noload = dlopen(name, RTLD_NOW | RTLD_NOLOAD);
    const char *noload_error = dlerror();
    printf("%s: handle=%d error=%s count=%u adds=%llu tls=%lu\n", label,
           handle != 0, kind, after.count,
           after.adds - before.adds, after.tls_module);
    printf("%s: error-consumed=%d root-symbol=%d tls-symbol=%d noload=%d\n", label,
           consumed, root_symbol, tls_symbol, noload != 0);
    return handle == 0 && error && after.count == before.count
        && after.adds == before.adds && after.tls_module == before.tls_module
        && after.max_module == before.max_module && consumed && !root_symbol && !tls_symbol
        && !noload && noload_error && !strcmp(kind, expected);
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    setvbuf(stdout, 0, _IONBF, 0);
    struct image_state before = snapshot();
    if (!fail_open("malformed", "libfo_root.so", "malformed", before)) return 3;
    if (!fail_open("malformed-again", "libfo_root.so", "malformed", before)) return 4;
    if (rename(argv[1], argv[3])) return 9;
    if (!fail_open("relocation", "libfo_root.so", "symbol", before)) return 5;
    if (!fail_open("relocation-again", "libfo_root.so", "symbol", before)) return 6;
    if (rename(argv[2], argv[3])) return 7;
    if (dlopen("libfo_root.so", RTLD_NOW | RTLD_NOLOAD)) return 10;
    void *root = dlopen("libfo_root.so", RTLD_NOW | RTLD_GLOBAL);
    const char *pending = dlerror();
    int pending_consumed = dlerror() == 0;
    int (*value)(void) = root ? dlsym(root, "failed_open_root_value") : 0;
    struct image_state after = snapshot();
    printf("retry: handle=%d value=%d count=%u adds=%llu tls-delta=%lu pending=%d consumed=%d\n",
           root != 0, value ? value() : -1, after.count,
           after.adds - before.adds, after.tls_module - before.max_module,
           pending != 0, pending_consumed);
    if (!root || !value || value() != 42 || after.count != before.count + 3
        || after.adds != before.adds + 1 || after.tls_module != before.max_module + 1
        || !pending || !pending_consumed) return 8;
    puts("failed-open transaction: complete");
    return 0;
}
