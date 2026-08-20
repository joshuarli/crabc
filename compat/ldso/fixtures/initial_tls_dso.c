__thread int initial_tls_value = 7;

int initial_tls_get(void)
{
    return initial_tls_value++;
}
