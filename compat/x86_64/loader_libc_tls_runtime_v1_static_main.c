/*
 * No-PT_INTERP counterpart of loader_libc_tls_runtime_v1_main.c.
 *
 * It links the same private consumer against its explicit static-mode stub.
 * A static executable has no loader-owned RuntimeV1 record, so the consumer
 * must reject without reading the process's FS base or requiring a dynamic
 * loader symbol.
 */

extern int __crabc_x86_loader_tls_runtime_v1_attach(void);

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return __crabc_x86_loader_tls_runtime_v1_attach() == 0 ? 81 : 0;
}
