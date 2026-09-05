#include <stdio.h>
#include <stdlib.h>
static void initialize(void) __attribute__((constructor));
static void initialize(void)
{
    puts("constructor exits before completion");
    exit(23);
}
static void finalize(void) __attribute__((destructor));
static void finalize(void) { puts("FAIL: partially constructed object finalized"); }
