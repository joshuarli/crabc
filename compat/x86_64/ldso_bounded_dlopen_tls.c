/* The candidate rejects this image before publication; musl supplies the
 * per-thread initialized and zero-filled fields used by the oracle route. */
__thread int bounded_plugin_tls = 9;
__thread int bounded_plugin_tbss;

int bounded_plugin_tls_value(void) {
    return bounded_plugin_tls;
}

int bounded_plugin_tbss_value(void) {
    return bounded_plugin_tbss;
}

void bounded_plugin_tls_set(int initialized, int zero_filled) {
    bounded_plugin_tls = initialized;
    bounded_plugin_tbss = zero_filled;
}
