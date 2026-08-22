/* Build this source once per index: every shared object owns one TLS module. */
#ifndef TLS_GROWTH_INDEX
#define TLS_GROWTH_INDEX 0
#endif

__thread int tls_growth_value = 100 + TLS_GROWTH_INDEX;

int *tls_growth_slot(void)
{
    return &tls_growth_value;
}
