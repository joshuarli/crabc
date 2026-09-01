/* Force one strong undefined main-image data import of the private record.
 * The general loader must reject it before ARCH_SET_FS: only the consumer's
 * weak undefined main-image GOT import is an allowed RuntimeV1 relocation. */

extern const unsigned char __crabc_x86_64_loader_tls_runtime_v1;

__attribute__((used)) void *general_runtime_v1_strong_main_record(void) {
    return (void *)&__crabc_x86_64_loader_tls_runtime_v1;
}
