#include <stdint.h>

int relro_target(void)
{
    return 19;
}

const int (*const relro_pointer)(void) = relro_target;

int relro_call(void)
{
    return relro_pointer();
}

void relro_write(void)
{
    *(volatile uintptr_t *)(void *)&relro_pointer = 0;
}
