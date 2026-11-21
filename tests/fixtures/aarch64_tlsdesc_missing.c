__thread int present;
extern __thread int missing __attribute__((tls_model("initial-exec")));

int read_tls(void) {
    return present + missing;
}
