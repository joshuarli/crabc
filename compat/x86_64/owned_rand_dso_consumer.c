/* Dynamic application proving that main and an application DSO share rand state. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

extern int crabc_owned_rand_dso_next(void);

int main(void)
{
    int main_first;
    int dso_second;
    int expected_first;
    int expected_second;

    errno = E2BIG;
    srand(7U);
    if (errno != E2BIG)
        return 1;
    main_first = rand();
    dso_second = crabc_owned_rand_dso_next();

    srand(7U);
    expected_first = rand();
    expected_second = rand();
    if (main_first != expected_first || dso_second != expected_second)
        return 2;
    if (errno != E2BIG)
        return 3;

    printf("main-dso=%u,%u\n", (unsigned)main_first, (unsigned)dso_second);
    return 0;
}
