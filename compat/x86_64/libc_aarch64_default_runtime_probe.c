#include <aio.h>
#include <fenv.h>
#include <math.h>
#include <stdio.h>

int crabc_aarch64_default_runtime_probe(void)
{
    struct aiocb request = {0};
    request.__err = -1;
    if (aio_error(&request) != 0x7fffffff) return 1;
    if (fesetround(FE_DOWNWARD)) return 2;
    volatile long double value = 1.5L;
    if (rintl(value) != 1.0L || sqrtl(4.0L) != 2.0L) return 3;
    if (fesetround(FE_TONEAREST)) return 4;
    FILE *file = fopen("/dev/null", "r");
    if (!file || fclose(file)) return 5;
    file = tmpfile();
    if (!file || fclose(file)) return 6;
    return 0;
}
