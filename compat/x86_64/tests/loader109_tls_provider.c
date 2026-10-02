_Thread_local int loader109_tls_value = 41;
int loader109_constructor_calls;

__attribute__((constructor)) static void loader109_initialize(void)
{
    ++loader109_constructor_calls;
}

int *loader109_tls_address(void)
{
    return &loader109_tls_value;
}
