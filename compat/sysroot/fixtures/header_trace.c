/* Application header-isolation fixture, not target-runtime implementation. */
#include <stdint.h>

uint64_t crabc_sysroot_header_trace(uint64_t value) {
    return value + UINT64_C(1);
}
