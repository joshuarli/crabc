/* PT_TLS is outside the first runtime-mapping transaction. */
__thread int bounded_plugin_tls = 9;

int bounded_plugin_tls_value(void) {
    return bounded_plugin_tls;
}
