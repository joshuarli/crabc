extern int crabc_compiler_helper_dso_value(void);

int __popcountdi2(unsigned long long ignored)
{
    (void)ignored;
    return 777;
}

int main(void)
{
    return crabc_compiler_helper_dso_value() == 2 ? 0 : 1;
}
