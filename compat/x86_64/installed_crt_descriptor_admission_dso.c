#include <stdint.h>

extern const unsigned char __crabc_x86_64_loader_tls_runtime_v1 __attribute__((weak));

/* Keep the weak descriptor request in this DSO's GOT. The loader must reject
 * it before this function or the application main can run. */
int descriptor_dso_reference(void) {
    return (uintptr_t)(const void *)&__crabc_x86_64_loader_tls_runtime_v1 != 0;
}
