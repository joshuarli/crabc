#include "general_relocation_fixture.h"
__thread unsigned long main_tls = 41;
__thread int interposed_tls = 91;
#ifdef PROTECTED_COLLISION
__thread int protected_tls = 99;
#endif
extern void (*missing_weak_function)(void) __attribute__((weak));
int main(void) {
    if (right_anchor() != 11 || !provider_checks() || !consumer_checks()
        || scope_value != EXPECTED_SCOPE || &missing_weak_function
        || copied_payload.self != &copied_payload.sentinel
        || copied_payload.bytes[0] != 1 || copied_payload.bytes[4] != 5
        || copied_payload.sentinel != 0x12345678UL
        || provider_high_address() != high_tls || consumer_high_address() != high_tls
        || consumer_main_address() != &main_tls || (unsigned long)high_tls % 4096
        || (unsigned long)zero_tls % 64) _Exit(82);
    for (int index = 0; index < 64; index++) if (copied_bytes[index] != index) _Exit(83);
    for (int index = 2; index < 65; index++) if (high_tls[index]) _Exit(84);
    for (int index = 0; index < 513; index++) if (zero_tls[index]) _Exit(85);
    ((unsigned char *)consumer_high_address())[64] = 37;
    *consumer_main_address() = 97;
    if (((unsigned char *)provider_high_address())[64] != 37 || main_tls != 97) _Exit(86);
    const char message[] = "general relocation pass\n";
    __asm__ volatile("syscall" : : "a"(1L), "D"(1L), "S"(message), "d"(sizeof(message) - 1)
                     : "rcx", "r11", "memory");
    return 33;
}
