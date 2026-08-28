/* Static crabc-libc x86-64 bootstrap-primitives fixture.
 *
 * The same C body first runs through pinned musl 1.2.6, then through a
 * freestanding executable linked solely with the selected crabc `libc.a`.
 * It exercises the selected bulk-memory, floating-environment, and
 * continuation primitives through the installed project declarations. The
 * candidate entry shim provides only the initial TLS scratch required by the
 * archive's errno accessor; it is not a general CRT, pthread/TLS, loader, or
 * application-startup claim.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fenv.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/syscall.h>

enum {
    /* The backwards-overlap matrix reaches source+48+128. Keep enough
     * trailing space to make every probe range valid before it asks the
     * implementation to choose a copy direction. */
    BUFFER_BYTES = 320,
    PAGE_BYTES = 4096,
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long width");
_Static_assert(sizeof(fexcept_t) == 2, "x86 fexcept_t width");
_Static_assert(sizeof(fenv_t) == 32 && _Alignof(fenv_t) == 4,
    "x86 fenv_t layout");
_Static_assert(offsetof(fenv_t, __status_word) == 4,
    "x86 fenv status offset");
_Static_assert(offsetof(fenv_t, __mxcsr) == 28, "x86 fenv MXCSR offset");
_Static_assert(sizeof(jmp_buf) == 200 && _Alignof(jmp_buf) == 8,
    "x86 jmp_buf layout");
_Static_assert(sizeof(sigjmp_buf) == 200 && _Alignof(sigjmp_buf) == 8,
    "x86 sigjmp_buf layout");
_Static_assert(SIGUSR1 == 10 && SIG_SETMASK == 2, "x86 signal constants");
_Static_assert(SYS_mmap == 9 && SYS_mprotect == 10 && SYS_munmap == 11,
    "x86 mapping syscall numbers");
_Static_assert(SYS_rt_sigprocmask == 14, "x86 rt_sigprocmask syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memcpy),
    void *(*)(void *, const void *, size_t)), "memcpy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memmove),
    void *(*)(void *, const void *, size_t)), "memmove declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memset),
    void *(*)(void *, int, size_t)), "memset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memcmp),
    int (*)(const void *, const void *, size_t)), "memcmp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bcmp),
    int (*)(const void *, const void *, size_t)), "bcmp declaration");

/* `__flt_rounds` is musl's C99 helper behind FLT_ROUNDS. */
extern int __flt_rounds(void);
/* This ABI alias is intentionally not part of musl's public header. */
extern int __setjmp(jmp_buf) __attribute__((returns_twice));

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall6(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5, long argument6)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;
    register long register6 __asm__("r9") = argument6;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5), "r"(register6)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_failed(long result)
{
    return result < 0 && result >= -4095;
}

static void *raw_mmap(size_t length)
{
    long result = raw_syscall6(SYS_mmap, 0, (long)length,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    return raw_failed(result) ? MAP_FAILED : (void *)result;
}

static int raw_mprotect(void *address, size_t length, int protection)
{
    return raw_syscall4(SYS_mprotect, (long)address, (long)length,
        protection, 0) == 0 ? 0 : -1;
}

static int raw_munmap(void *address, size_t length)
{
    return raw_syscall4(SYS_munmap, (long)address, (long)length, 0, 0) == 0 ? 0 : -1;
}

static void fill(unsigned char *bytes, size_t length, unsigned seed)
{
    for (size_t index = 0; index < length; index++)
        bytes[index] = (unsigned char)(seed + index * 37U);
}

static int equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    for (size_t index = 0; index < length; index++)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static void reference_copy(unsigned char *destination, const unsigned char *source,
    size_t length)
{
    for (size_t index = 0; index < length; index++)
        destination[index] = source[index];
}

static void reference_move(unsigned char *destination, const unsigned char *source,
    size_t length)
{
    if (destination < source) {
        for (size_t index = 0; index < length; index++)
            destination[index] = source[index];
    } else {
        for (size_t index = length; index != 0; index--)
            destination[index - 1] = source[index - 1];
    }
}

static int direction_flag_is_clear(void)
{
    unsigned long flags;

    __asm__ volatile("pushfq; popq %0" : "=r"(flags));
    return (flags & (1UL << 10)) == 0;
}

static int test_memory(void)
{
    unsigned char source[BUFFER_BYTES + 16];
    unsigned char actual[BUFFER_BYTES + 16];
    unsigned char expected[BUFFER_BYTES + 16];

    for (size_t length = 0; length <= 128; length++) {
        for (size_t source_offset = 0; source_offset < 16; source_offset++) {
            for (size_t destination_offset = 0; destination_offset < 16;
                destination_offset++) {
                fill(source, sizeof source, 17U);
                fill(actual, sizeof actual, 91U);
                reference_copy(expected, actual, sizeof actual);
                reference_copy(expected + destination_offset,
                    source + source_offset, length);
                if (memcpy(actual + destination_offset, source + source_offset,
                    length) != actual + destination_offset)
                    return 1;
                if (!equal(actual, expected, sizeof actual))
                    return 2;
            }
        }
    }

    for (size_t length = 0; length <= 128; length++) {
        for (int displacement = -48; displacement <= 48; displacement++) {
            unsigned char moved[BUFFER_BYTES];
            unsigned char moved_expected[BUFFER_BYTES];
            unsigned char *moved_source = moved + 64;
            unsigned char *expected_source = moved_expected + 64;
            unsigned char *moved_destination = moved_source + displacement;
            unsigned char *expected_destination = expected_source + displacement;

            fill(moved, sizeof moved, 29U);
            reference_copy(moved_expected, moved, sizeof moved);
            reference_move(expected_destination, expected_source, length);
            if (memmove(moved_destination, moved_source, length) != moved_destination)
                return 3;
            if (!equal(moved, moved_expected, sizeof moved) || !direction_flag_is_clear())
                return 4;
        }
    }

    for (size_t length = 0; length <= 128; length++) {
        for (size_t offset = 0; offset < 16; offset++) {
            fill(actual, sizeof actual, 43U);
            reference_copy(expected, actual, sizeof actual);
            for (size_t index = 0; index < length; index++)
                expected[offset + index] = 0xa5;
            if (memset(actual + offset, 0x1a5, length) != actual + offset)
                return 5;
            if (!equal(actual, expected, sizeof actual))
                return 6;
        }
    }

    for (size_t length = 0; length <= 128; length++) {
        fill(source, sizeof source, 53U);
        reference_copy(actual, source, sizeof source);
        if (memcmp(source, actual, length) != 0 || bcmp(source, actual, length) != 0)
            return 12;
        if (length != 0) {
            source[length - 1] = 10;
            actual[length - 1] = 13;
            if (memcmp(source, actual, length) != -3 ||
                bcmp(source, actual, length) != -3)
                return 13;
            actual[length - 1] = 5;
            if (memcmp(source, actual, length) != 5 ||
                bcmp(source, actual, length) != 5)
                return 14;
        }
    }

    {
        unsigned char *source_mapping = raw_mmap(PAGE_BYTES * 2);
        unsigned char *destination_mapping = raw_mmap(PAGE_BYTES * 2);

        if (source_mapping == MAP_FAILED || destination_mapping == MAP_FAILED)
            return 7;
        if (raw_mprotect(source_mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0 ||
            raw_mprotect(destination_mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0)
            return 8;
        for (size_t length = 0; length <= 64; length++) {
            unsigned char *source_end = source_mapping + PAGE_BYTES - length;
            unsigned char *destination_end = destination_mapping + PAGE_BYTES - length;

            fill(source_end, length, 11U);
            if (memcpy(destination_end, source_end, length) != destination_end ||
                !equal(destination_end, source_end, length))
                return 9;
            if (memmove(destination_end, source_end, length) != destination_end ||
                !equal(destination_end, source_end, length))
                return 15;
            if (memcmp(source_end, destination_end, length) != 0 ||
                bcmp(source_end, destination_end, length) != 0)
                return 16;
            if (length != 0) {
                unsigned char *overlap_source =
                    source_mapping + PAGE_BYTES - length - 1;

                source_end[length - 1] = 10;
                destination_end[length - 1] = 13;
                if (memcmp(source_end, destination_end, length) != -3 ||
                    bcmp(source_end, destination_end, length) != -3)
                    return 17;
                fill(overlap_source, length, 19U);
                if (memmove(overlap_source + 1, overlap_source, length) !=
                    overlap_source + 1)
                    return 18;
                if (!direction_flag_is_clear())
                    return 19;
                for (size_t index = 0; index < length; index++)
                    if (overlap_source[index + 1] !=
                        (unsigned char)(19U + index * 37U))
                        return 20;
            }
            if (memset(destination_end, 0xa5, length) != destination_end)
                return 10;
        }
        if (raw_munmap(source_mapping, PAGE_BYTES * 2) != 0 ||
            raw_munmap(destination_mapping, PAGE_BYTES * 2) != 0)
            return 11;
    }

    return 0;
}

static int test_fenv(void)
{
    fenv_t original;
    fenv_t held;
    fexcept_t flags;
    int prior_round;

    if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
        return 1;
    if (fegetround() != FE_TONEAREST || __flt_rounds() != 1 ||
        fetestexcept(FE_ALL_EXCEPT) != 0)
        return 2;
    if (fesetround(FE_DOWNWARD) != 0 || fegetround() != FE_DOWNWARD ||
        __flt_rounds() != 3)
        return 3;
    prior_round = fegetround();
    if (fesetround(0x200) != -1 || fegetround() != prior_round)
        return 4;
    if (feraiseexcept(FE_INVALID | __FE_DENORM | FE_INEXACT) != 0 ||
        fetestexcept(FE_ALL_EXCEPT) != (FE_INVALID | __FE_DENORM | FE_INEXACT))
        return 5;
    if (fegetexceptflag(&flags, FE_ALL_EXCEPT) != 0 ||
        flags != (FE_INVALID | __FE_DENORM | FE_INEXACT))
        return 6;
    flags = FE_DIVBYZERO | FE_OVERFLOW;
    if (fesetexceptflag(&flags, FE_ALL_EXCEPT) != 0 ||
        fetestexcept(FE_ALL_EXCEPT) != flags)
        return 7;
    if (feholdexcept(&held) != 0 || fegetround() != FE_DOWNWARD ||
        fetestexcept(FE_ALL_EXCEPT) != 0)
        return 8;
    if (feraiseexcept(FE_INEXACT) != 0 || feupdateenv(&held) != 0 ||
        fetestexcept(FE_ALL_EXCEPT) !=
            (FE_DIVBYZERO | FE_OVERFLOW | FE_INEXACT))
        return 9;
    if (fesetenv(FE_DFL_ENV) != 0 || fegetround() != FE_TONEAREST ||
        __flt_rounds() != 1 || fetestexcept(FE_ALL_EXCEPT) != 0)
        return 10;
    return fesetenv(&original) == 0 ? 0 : 11;
}

static int raw_signal_mask(const unsigned long *set, unsigned long *old_set)
{
    return raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)set,
        (long)old_set, sizeof(unsigned long)) == 0 ? 0 : -1;
}

static int test_plain_jumps(void)
{
    jmp_buf environment;
    int result = setjmp(environment);

    if (result == 0)
        longjmp(environment, 0);
    if (result != 1)
        return 1;

    result = __setjmp(environment);
    if (result == 0)
        _longjmp(environment, 37);
    if (result != 37)
        return 2;

    result = _setjmp(environment);
    if (result == 0)
        longjmp(environment, -27);
    return result == -27 ? 0 : 3;
}

static int test_sigsetjmp_mask(int save_mask)
{
    const unsigned long usr1_bit = 1UL << (SIGUSR1 - 1);
    sigjmp_buf environment;
    unsigned long original;
    unsigned long unblocked;
    unsigned long blocked;
    unsigned long observed;
    int result;

    if (raw_signal_mask(0, &original) != 0)
        return 1;
    unblocked = original & ~usr1_bit;
    if (raw_signal_mask(&unblocked, 0) != 0)
        return 2;

    result = sigsetjmp(environment, save_mask);
    if (result == 0) {
        blocked = unblocked | usr1_bit;
        if (raw_signal_mask(&blocked, 0) != 0) {
            (void)raw_signal_mask(&original, 0);
            return 3;
        }
        siglongjmp(environment, 29);
    }

    if (raw_signal_mask(0, &observed) != 0) {
        (void)raw_signal_mask(&original, 0);
        return 4;
    }
    if (raw_signal_mask(&original, 0) != 0)
        return 5;
    if (result != 29)
        return 6;
    if (save_mask)
        return (observed & usr1_bit) == 0 ? 0 : 7;
    return (observed & usr1_bit) != 0 ? 0 : 8;
}

static int test_jumps(void)
{
    int result = test_plain_jumps();

    if (result != 0)
        return result;
    result = test_sigsetjmp_mask(1);
    if (result != 0)
        return 10 + result;
    result = test_sigsetjmp_mask(0);
    return result == 0 ? 0 : 20 + result;
}

int crabc_x86_64_bootstrap_primitives_probe(void)
{
    int result;

    errno = 0;
    if (errno != 0)
        return 1;
    result = test_memory();
    if (result != 0)
        return 10 + result;
    result = test_fenv();
    if (result != 0)
        return 30 + result;
    result = test_jumps();
    return result == 0 ? 0 : 50 + result;
}

#ifndef CRABC_BOOTSTRAP_PRIMITIVES_FREESTANDING
int main(void)
{
    return crabc_x86_64_bootstrap_primitives_probe();
}
#endif
