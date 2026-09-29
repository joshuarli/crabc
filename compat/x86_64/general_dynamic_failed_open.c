/* A root DSO first reaches a malformed dependency after mapping a TLS image,
 * then reaches an unresolved relocation after that dependency is replaced.
 * Each failure must leave no visible object, module, symbol, or constructor.
 * The final replacement opens the same root successfully; close retains the
 * image and NOLOAD reopens it. Module IDs are compared relative to the
 * initially loaded modules because the two runtimes have different initial
 * TLS owners. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct image_state { unsigned count; unsigned maps; unsigned long long adds; unsigned long tls_module; unsigned long max_module; };

/* The candidate inherits a proc directory descriptor across chroot and exec;
 * opening self/maps afterwards observes its current image, not the old shell. */
static unsigned mapped_images(int maps_fd) {
    int fd = maps_fd >= 0 ? openat(maps_fd, "self/maps", O_RDONLY) : open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return ~0u;
    FILE *maps = fdopen(fd, "r");
    if (!maps) { close(fd); return ~0u; }
    unsigned found = 0;
    static unsigned sequence;
    unsigned snapshot = ++sequence;
    fprintf(stderr, "maps-snapshot %u begin\n", snapshot);
    char line[8192];
    while (fgets(line, sizeof line, maps)) {
        fputs(line, stderr);
        if (!strchr(line, '\n') && !feof(maps)) { found = ~0u; break; }
        if (strstr(line, "libfo_root.so")) found |= 1;
        if (strstr(line, "libfo_tls.so")) found |= 2;
        if (strstr(line, "libfo_late.so")) found |= 4;
    }
    fprintf(stderr, "maps-snapshot %u end\n", snapshot);
    if (ferror(maps)) found = ~0u;
    fclose(maps);
    return found;
}

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

static struct image_state snapshot(int maps_fd) {
    struct image_state state = {0, 0, 0, 0, 0};
    dl_iterate_phdr(image, &state);
    state.maps = mapped_images(maps_fd);
    return state;
}

static int fail_open(const char *label, const char *name, const char *expected, struct image_state before, int maps_fd) {
    void *handle = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
    const char *error = dlerror();
    const char *kind = !error ? "none" : strstr(error, "symbol not found") ? "symbol"
        : strstr(error, "Exec format error") ? "malformed" : "other";
    struct image_state after = snapshot(maps_fd);
    int consumed = dlerror() == 0;
    int root_symbol = dlsym(RTLD_DEFAULT, "failed_open_root_value") != 0;
    (void)dlerror();
    int tls_symbol = dlsym(RTLD_DEFAULT, "failed_open_tls_value") != 0;
    (void)dlerror();
    void *noload = dlopen(name, RTLD_NOW | RTLD_NOLOAD);
    const char *noload_error = dlerror();
    printf("%s: handle=%d error=%s count=%u maps=%u adds=%llu tls=%lu\n", label,
           handle != 0, kind, after.count,
           after.maps, after.adds - before.adds, after.tls_module);
    printf("%s: error-consumed=%d root-symbol=%d tls-symbol=%d noload=%d\n", label,
           consumed, root_symbol, tls_symbol, noload != 0);
    return handle == 0 && error && after.count == before.count && after.maps == before.maps
        && after.adds == before.adds && after.tls_module == before.tls_module
        && after.max_module == before.max_module && consumed && !root_symbol && !tls_symbol
        && !noload && noload_error && !strcmp(kind, expected);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int maps_fd = atoi(argv[4]);
    setvbuf(stdout, 0, _IONBF, 0);
    struct image_state before = snapshot(maps_fd);
    if (before.maps != 0) return 11;
    if (!fail_open("malformed", "libfo_root.so", "malformed", before, maps_fd)) return 3;
    if (!fail_open("malformed-again", "libfo_root.so", "malformed", before, maps_fd)) return 4;
    if (rename(argv[1], argv[3])) return 9;
    if (!fail_open("relocation", "libfo_root.so", "symbol", before, maps_fd)) return 5;
    if (!fail_open("relocation-again", "libfo_root.so", "symbol", before, maps_fd)) return 6;
    if (rename(argv[2], argv[3])) return 7;
    if (dlopen("libfo_root.so", RTLD_NOW | RTLD_NOLOAD)) return 10;
    void *root = dlopen("libfo_root.so", RTLD_NOW | RTLD_GLOBAL);
    const char *pending = dlerror();
    int pending_consumed = dlerror() == 0;
    int (*value)(void) = root ? dlsym(root, "failed_open_root_value") : 0;
    struct image_state after = snapshot(maps_fd);
    printf("retry: handle=%d value=%d count=%u maps=%u adds=%llu tls-delta=%lu pending=%d consumed=%d\n",
           root != 0, value ? value() : -1, after.count,
           after.maps, after.adds - before.adds, after.tls_module - before.max_module,
           pending != 0, pending_consumed);
    if (!root || !value || value() != 42 || after.count != before.count + 3
        || after.maps != 7 || after.adds != before.adds + 1 || after.tls_module != before.max_module + 1
        || !pending || !pending_consumed) return 8;
    int closed = dlclose(root);
    struct image_state retained = snapshot(maps_fd);
    printf("retained: close=%d value=%d count=%u maps=%u adds=%llu tls-delta=%lu\n",
           closed, value(), retained.count, retained.maps,
           retained.adds - after.adds, retained.tls_module - before.max_module);
    if (closed || value() != 42 || retained.count != after.count || retained.maps != after.maps
        || retained.adds != after.adds || retained.tls_module != after.tls_module) return 12;
    void *reopened = dlopen("libfo_root.so", RTLD_NOW | RTLD_NOLOAD);
    int (*reopened_value)(void) = reopened ? dlsym(reopened, "failed_open_root_value") : 0;
    struct image_state reopened_state = snapshot(maps_fd);
    printf("reopen: handle=%d same=%d value=%d count=%u maps=%u adds=%llu tls-delta=%lu\n",
           reopened != 0, reopened == root, reopened_value ? reopened_value() : -1,
           reopened_state.count, reopened_state.maps, reopened_state.adds - retained.adds,
           reopened_state.tls_module - before.max_module);
    if (!reopened || reopened != root || !reopened_value || reopened_value() != 42
        || reopened_state.count != after.count || reopened_state.maps != after.maps
        || reopened_state.tls_module != after.tls_module || dlclose(reopened)) return 13;
    puts("failed-open transaction: complete");
    return 0;
}
