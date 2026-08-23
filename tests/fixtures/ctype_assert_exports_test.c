#define _GNU_SOURCE 1

#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

extern const unsigned short **__ctype_b_loc(void);
extern const int32_t **__ctype_tolower_loc(void);
extern const int32_t **__ctype_toupper_loc(void);
extern void __assert_fail(const char *, const char *, int, const char *);
extern int __libc_current_sigrtmax(void);

static unsigned short musl_ctype_word(unsigned value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (unsigned short)((value >> 8) | (value << 8));
#else
    return (unsigned short)value;
#endif
}

static int ctype_locator_case(void)
{
    const unsigned short *b = *__ctype_b_loc();
    const int32_t *lower = *__ctype_tolower_loc();
    const int32_t *upper = *__ctype_toupper_loc();

    if (!b || !lower || !upper)
        return 1;
    if (b[-128] != 0 || b[255] != 0 || lower[-128] != 0 || lower[255] != 0 ||
        upper[-128] != 0 || upper[255] != 0)
        return 2;
    if (b['\t'] != musl_ctype_word(0x0320) ||
        b['\n'] != musl_ctype_word(0x0220) ||
        b[' '] != musl_ctype_word(0x0160) ||
        b['0'] != musl_ctype_word(0x08d8) ||
        b['A'] != musl_ctype_word(0x08d5) ||
        b['G'] != musl_ctype_word(0x08c5) ||
        b['a'] != musl_ctype_word(0x08d6) ||
        b['g'] != musl_ctype_word(0x08c6))
        return 3;
    if (lower['A'] != 'a' || lower['a'] != 'a' || lower['!'] != '!' ||
        upper['a'] != 'A' || upper['A'] != 'A' || upper['!'] != '!')
        return 4;
    if (__ctype_b_loc() != __ctype_b_loc() ||
        __ctype_tolower_loc() != __ctype_tolower_loc() ||
        __ctype_toupper_loc() != __ctype_toupper_loc())
        return 5;
    return 0;
}

static int fpclassify_case(void)
{
    if (__fpclassifyl(0.0L) != FP_ZERO ||
        __fpclassifyl(1.0L) != FP_NORMAL ||
        __fpclassifyl(INFINITY) != FP_INFINITE ||
        __fpclassifyl(NAN) != FP_NAN)
        return 10;
    return 0;
}

static int assert_child_case(void)
{
    pid_t child = fork();
    int status = 0;
    if (child < 0)
        return 20;
    if (child == 0) {
        __assert_fail("value != 0", "ctype_assert_exports_test.c", 77, "main");
        _exit(99);
    }
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGABRT)
        return 21;
    return 0;
}

int main(void)
{
    int result = ctype_locator_case();
    if (result)
        return result;
    result = fpclassify_case();
    if (result)
        return result;
    if (__libc_current_sigrtmax() != 64)
        return 30;
    result = assert_child_case();
    if (result)
        return result;
    puts("c-abi ctype assert exports ok");
    return 0;
}
