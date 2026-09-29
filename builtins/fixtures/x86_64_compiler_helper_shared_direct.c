/* Direct installed-driver consumer of the bounded compiler-helper archive. */

#include "x86_64_int128_casts_probe.c"

extern int __popcountdi2(unsigned long long);

int main(void)
{
    return __popcountdi2(0xf0f0f0f00000000fULL) == 20 ? crabc_x86_64_int128_casts_probe() : 1;
}
