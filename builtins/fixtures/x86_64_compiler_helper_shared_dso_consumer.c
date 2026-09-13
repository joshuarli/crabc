/* This executable receives its helper-using DSO through the owned link plan. */

extern int crabc_compiler_helper_dso_value(void);

int main(void)
{
    return crabc_compiler_helper_dso_value() == 2 ? 0 : 1;
}
