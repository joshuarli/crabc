/* Stack-protector normal-path fixture, including an early constructor. */
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

extern uintptr_t __stack_chk_guard;

__attribute__((constructor, noinline)) static void protected_constructor(void)
{
    volatile char protected_stack[32];

    protected_stack[0] = 1;
    if (protected_stack[0] != 1 || __stack_chk_guard == 0)
        _Exit(110);
}

__attribute__((noinline)) static int protected_main_path(void)
{
    volatile char protected_stack[32];

    protected_stack[0] = 2;
    return protected_stack[0] == 2 && __stack_chk_guard != 0;
}

int main(void)
{
    if (!protected_main_path())
        return 111;
    return write(1, &__stack_chk_guard, sizeof(__stack_chk_guard)) == sizeof(__stack_chk_guard) ? 0 : 112;
}
