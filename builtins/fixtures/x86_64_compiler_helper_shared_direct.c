/* Direct installed-driver consumer of the bounded compiler-helper archive. */

extern int __popcountdi2(unsigned long long);

int main(void)
{
    return __popcountdi2(0xf0f0f0f00000000fULL) == 20 ? 0 : 1;
}
