#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

extern char **environ;
extern unsigned __int128 __udivmodti4(unsigned __int128, unsigned __int128,
                                    unsigned __int128 *);

static __thread int initialized = 37;
static __thread int zeroed;
static unsigned stage;

static void require(int condition) {
    if (!condition) _Exit(99);
}

static void mark(char value) {
    require(((uintptr_t)__builtin_frame_address(0) & 15) == 0);
    require(write(1, &value, 1) == 1);
}

static void initial_state(void) {
    require(initialized == 37 && zeroed == 0 && errno == 0);
    require(getauxval(AT_PAGESZ) == 4096 && getauxval(AT_PHDR) != 0);
    require(getauxval(AT_PHENT) == 56 && getauxval(AT_PHNUM) != 0);
    char *value = getenv("CRT109_STACK");
    require(value != 0 && strcmp(value, "present") == 0);
    initialized = 41;
    zeroed = 43;
    errno = 47;
}

static void preinit(void) {
#ifdef CRT109_DYNAMIC
    /* Musl's dynamic constructor walk does not dispatch DT_PREINIT_ARRAY. */
    require(0);
#else
    require(stage++ == 0);
    initial_state();
    mark('P');
#endif
}

#ifdef CRT109_DYNAMIC
#define AFTER_PREINIT 0
#else
#define AFTER_PREINIT 1
#endif

static void init_first(void) {
#ifdef CRT109_DYNAMIC
    initial_state();
#endif
    require(stage++ == AFTER_PREINIT && initialized == 41 && zeroed == 43 && errno == 47);
    mark('I');
}

static void init_second(void) {
    require(stage++ == AFTER_PREINIT + 1);
    mark('J');
}

static void at_exit(void) {
    require(stage++ == AFTER_PREINIT + 3 && initialized == 41 && zeroed == 43 && errno == 47);
    mark('A');
}

static void fini_first(void) {
    require(stage++ == AFTER_PREINIT + 5 && errno == 47);
    mark('X');
    mark('\n');
}

static void fini_second(void) {
    require(stage++ == AFTER_PREINIT + 4);
    mark('Y');
}

/* The linker orders numeric suffixes; finalizers must run in reverse order. */
__attribute__((section(".preinit_array"), used))
static void (*const preinit_slot)(void) = preinit;
__attribute__((section(".init_array.0100"), used))
static void (*const init_first_slot)(void) = init_first;
__attribute__((section(".init_array.0200"), used))
static void (*const init_second_slot)(void) = init_second;
__attribute__((section(".fini_array.0100"), used))
static void (*const fini_first_slot)(void) = fini_first;
__attribute__((section(".fini_array.0200"), used))
static void (*const fini_second_slot)(void) = fini_second;

int main(int argc, char **argv, char **envp) {
    require(stage++ == AFTER_PREINIT + 2 && argc == 3 && argv[argc] == 0 && envp == environ);
    require(strcmp(argv[1], "first") == 0 && strcmp(argv[2], "second") == 0);
    require(initialized == 41 && zeroed == 43 && errno == 47);
    char **cursor = envp;
    while (*cursor) cursor++;
    const uintptr_t *auxv = (const uintptr_t *)(cursor + 1);
    unsigned observed = 0;
    for (; auxv[0] != AT_NULL; auxv += 2) {
        if (auxv[0] == AT_PHDR || auxv[0] == AT_PHENT || auxv[0] == AT_PHNUM ||
            auxv[0] == AT_PAGESZ || auxv[0] == AT_RANDOM) {
            require(getauxval(auxv[0]) == auxv[1]);
            observed++;
        }
    }
    require(observed == 5);
    require(atexit(at_exit) == 0);
    volatile unsigned __int128 numerator = ((unsigned __int128)1 << 100) + 17;
    volatile unsigned __int128 denominator = 13;
    unsigned __int128 remainder = 0;
    unsigned __int128 quotient = __udivmodti4(numerator, denominator, &remainder);
    require(quotient * denominator + remainder == numerator && remainder < denominator);
    require(__udivmodti4(numerator, denominator, 0) == quotient);
    mark('M');
    return 0;
}
