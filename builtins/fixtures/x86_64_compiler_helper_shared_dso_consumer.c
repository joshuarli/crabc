extern int crabc_compiler_helper_dso_value(void);
extern int __popcountdi2(unsigned long long);

#include "x86_64_int128_casts_probe.c"

int main(void)
{
    return crabc_x86_64_int128_casts_probe() == 0
            && __popcountdi2(0xf0f0f0f00000000fULL) == 20
            && crabc_compiler_helper_dso_value() == 2 ? 0 : 1;
}
