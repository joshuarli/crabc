/* Stack-protector failure fixture.  The volatile write must trip the guard. */
#include <string.h>

__attribute__((noinline)) static void smash_stack(void)
{
    char protected_stack[8];
    char *(*volatile copier)(char *, const char *) = strcpy;

    /* Keep this an actual libc call at O0; it overwrites the frame canary. */
    (void)copier(protected_stack, "this string is deliberately longer than eight bytes");
}

int main(void)
{
    smash_stack();
    return 0;
}
