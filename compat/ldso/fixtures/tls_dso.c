__thread int fixture_tls_value = 5;

int *fixture_tls_slot(void)
{
    return &fixture_tls_value;
}
