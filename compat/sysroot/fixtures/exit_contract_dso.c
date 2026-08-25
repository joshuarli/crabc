#include <unistd.h>

int exit_contract_dso_value(void)
{
    return 19;
}

__attribute__((destructor))
static void exit_contract_dso_fini(void)
{
    (void)write(1, "dso-fini\n", sizeof("dso-fini\n") - 1);
}
