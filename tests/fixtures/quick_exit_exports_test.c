#include <stdlib.h>
#include <unistd.h>

static void first(void)
{
    write(1, "first\n", 6);
}

static void second(void)
{
    write(1, "second\n", 7);
}

int main(void)
{
    if (at_quick_exit(first) || at_quick_exit(second))
        return 1;
    quick_exit(23);
}
