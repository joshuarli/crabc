/* Application DSO consumer: its helper must come from the installed archive. */

#include "x86_64_int128_casts_probe.c"

extern int __popcountdi2(unsigned long long);

int crabc_compiler_helper_dso_value(void)
{
    return crabc_x86_64_int128_casts_probe() == 0 ? __popcountdi2(0x8000000000000001ULL) : -1;
}
