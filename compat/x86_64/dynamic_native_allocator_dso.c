#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int __crabc_x86_owned_allocator_lifecycle_test_phase(void);
static void *constructor_block;

static void check(int yes) { if (!yes) _Exit(81); }

__attribute__((constructor)) static void initialize(void)
{
    constructor_block = malloc(257);
    check(constructor_block != 0);
    memset(constructor_block, 0x39, 257);
    check(write(1, "DSO_INIT\n", 9) == 9);
}

int dynamic_native_allocator_dso_live(void)
{
    return constructor_block != 0 && ((unsigned char *)constructor_block)[256] == 0x39;
}

__attribute__((destructor)) static void finalize(void)
{
    int phase = __crabc_x86_owned_allocator_lifecycle_test_phase();
    check(phase == 1 || phase == 2);
    check(dynamic_native_allocator_dso_live());
    free(constructor_block);
    void *after = calloc(13, 31);
    check(after != 0 && ((unsigned char *)after)[402] == 0);
    free(after);
    const char *message = phase == 1 ? "DSO_FINI=1\n" : "DSO_FINI=2\n";
    check(write(1, message, 11) == 11);
}
