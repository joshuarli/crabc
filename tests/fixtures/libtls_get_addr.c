__thread int tls_value = 0x1234;

void *tls_addr(void)
{
    return &tls_value;
}
