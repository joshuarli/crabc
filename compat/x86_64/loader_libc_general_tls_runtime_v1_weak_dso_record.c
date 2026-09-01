/* Force one weak undefined DSO data import of the private record. The weak
 * binding alone is insufficient: RuntimeV1 descriptor relocation is owned by
 * the main image only and must fail before ARCH_SET_FS for this DSO. */

extern const unsigned char __crabc_x86_64_loader_tls_runtime_v1
    __attribute__((weak));

__attribute__((used)) void *general_runtime_v1_weak_dso_record(void) {
    return (void *)&__crabc_x86_64_loader_tls_runtime_v1;
}
