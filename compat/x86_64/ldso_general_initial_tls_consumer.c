/* A PT_TLS-free dependency must resolve another DSO's initial TLS without
 * acquiring a module ID or a DTV slot of its own. */
extern __thread int general_shared_tls __attribute__((tls_model("global-dynamic")));
extern __thread int general_shared_tbss __attribute__((tls_model("global-dynamic")));

int general_consumer_shared_value(void) {
    return general_shared_tls;
}

int general_consumer_shared_tbss_value(void) {
    return general_shared_tbss;
}

void *general_consumer_shared_address(void) {
    return &general_shared_tls;
}
