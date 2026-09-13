/* Application DSO consumer: its helper must come from the installed archive. */

extern int __popcountdi2(unsigned long long);

int crabc_compiler_helper_dso_value(void)
{
    return __popcountdi2(0x8000000000000001ULL);
}
