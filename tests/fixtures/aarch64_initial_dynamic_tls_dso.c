__thread int ie_value __attribute__((tls_model("initial-exec"))) = 11;
__thread int dynamic_value = 17;

int tls_read(void) { return ie_value + dynamic_value; }
void tls_write(int value) { ie_value = value; dynamic_value = value + 1; }
