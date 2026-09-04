#include "general_relocation_fixture.h"
/* This IE consumer intentionally has no PT_TLS of its own. DF_STATIC_TLS
 * must not be confused with ownership of the provider's retained module. */
#ifdef EARLY_WEAK_SCOPE
__attribute__((weak)) int scope_value = 5;
#endif
void *consumer_high_address(void) { return high_tls; }
unsigned long *consumer_main_address(void) { return &main_tls; }
int consumer_checks(void) {
#ifdef PROTECTED_COLLISION
    const int expected_protected = 99;
#else
    const int expected_protected = 17;
#endif
    return provider_checks() && interposed_tls == 91 && protected_tls == expected_protected
        && scope_value == EXPECTED_SCOPE && high_tls[0] == 19 && high_tls[1] == 23;
}
