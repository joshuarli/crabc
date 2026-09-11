/* Dynamic-linking companion: it must resolve the process libc rand stream. */
#include <stdlib.h>

int crabc_owned_rand_dso_next(void)
{
    return rand();
}
