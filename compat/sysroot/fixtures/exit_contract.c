/* Normal exit, _Exit, and quick_exit separation fixture. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int exit_contract_dso_value(void);

static void ordinary_handler(void)
{
    (void)write(1, "ordinary\n", sizeof("ordinary\n") - 1);
}

static void quick_handler(void)
{
    (void)write(1, "quick\n", sizeof("quick\n") - 1);
}

__attribute__((destructor))
static void executable_fini(void)
{
    (void)write(1, "exe-fini\n", sizeof("exe-fini\n") - 1);
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 90;
    if (exit_contract_dso_value() != 19)
        return 92;
    if (atexit(ordinary_handler) != 0 || at_quick_exit(quick_handler) != 0)
        return 91;
    if (strcmp(argv[1], "exit") == 0)
        exit(74);
    if (strcmp(argv[1], "_Exit") == 0)
        _Exit(75);
    if (strcmp(argv[1], "quick") == 0)
        quick_exit(76);
    return 73;
}
