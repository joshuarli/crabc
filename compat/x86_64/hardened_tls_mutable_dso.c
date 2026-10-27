__thread int tls_value = 7;
long mutable_tls_offset = 3;

int *hardened_tls_address(void)
{
    return &tls_value;
}

long hardened_tls_mutable_value(void)
{
    return mutable_tls_offset;
}

int hardened_tls_mutate(void)
{
    mutable_tls_offset = 42;
    return mutable_tls_offset == 42;
}
