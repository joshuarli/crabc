#define _GNU_SOURCE 1
#include "setjmp.h"
#include "stdio.h"

static jmp_buf env;
static volatile int count;

/* __setjmp is an exported musl ABI alias but is intentionally not public in
 * setjmp.h.  Keep this probe explicit so each alias is called by name. */
extern int __setjmp(jmp_buf) __attribute__((returns_twice));

static int test___setjmp(void) {
    count = 0;
    int r = __setjmp(env);
    if (r == 0) {
        ++count;
        _longjmp(env, 42);
    }
    return r == 42 && count == 1;
}

static int test__setjmp(void) {
    count = 0;
    int r = _setjmp(env);
    if (r == 0) {
        ++count;
        _longjmp(env, 0);
    }
    return r == 1 && count == 1;
}

int main(void) {
    if (!test___setjmp()) return 1;
    if (!test__setjmp()) return 2;

    count = 0;
    int r = setjmp(env);
    if (r == 0) {
        if (++count != 1) return 3;
        longjmp(env, 42);
        return 4;
    }
    if (r != 42) return 5;

    count = 0;
    r = setjmp(env);
    if (r == 0) {
        if (++count != 1) return 6;
        longjmp(env, 0);
        return 7;
    }
    if (r != 1) return 8;

    puts("setjmp aliases ok");
    return 0;
}
