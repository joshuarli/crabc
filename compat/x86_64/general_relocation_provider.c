#include "general_relocation_fixture.h"
struct copy_payload copied_payload = {
    &copied_payload.sentinel, { 1, 2, 3, 4, 5 }, 0x12345678UL
};
unsigned char copied_bytes[64] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
};
__attribute__((weak)) int scope_value = 7;
__thread __attribute__((aligned(4096))) unsigned char high_tls[65] = { 19, 23 };
__thread __attribute__((aligned(64))) unsigned char zero_tls[513];
__thread int interposed_tls = 7;
__thread __attribute__((visibility("protected"))) int protected_tls = 17;

void *provider_high_address(void) { return high_tls; }
int provider_checks(void) {
    return interposed_tls == 91 && protected_tls == 17
        && copied_payload.self == &copied_payload.sentinel
        && *copied_payload.self == 0x12345678UL && scope_value == EXPECTED_SCOPE;
}
__attribute__((constructor)) static void constructor(void) {
    if (!provider_checks() || high_tls[0] != 19 || high_tls[1] != 23
        || zero_tls[0] || zero_tls[512] || main_tls != 41) _Exit(81);
}
