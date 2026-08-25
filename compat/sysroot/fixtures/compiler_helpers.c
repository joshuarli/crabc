/*
 * Exercise the C code-generation surface that can otherwise pull a foreign
 * compiler runtime into an owned link.  Keep the arithmetic observable so
 * O0, O2, and O3 each need the same boundary rather than optimizing it away.
 */
#include <complex.h>
#include <limits.h>
#include <math.h>
#include <stdatomic.h>
#include <stdint.h>

static volatile uint64_t seed = UINT64_C(0x123456789abcdef0);

int main(void) {
    unsigned __int128 unsigned_value = ((unsigned __int128)seed << 64) | 17u;
    __int128 signed_value = -((__int128)(seed & UINT64_C(0xffff)) << 48);
    unsigned __int128 unsigned_quotient = unsigned_value / 3u;
    unsigned __int128 unsigned_remainder = unsigned_value % 3u;
    __int128 signed_quotient = signed_value / 7;
    __int128 signed_remainder = signed_value % 7;

    float narrow = 3.5f;
    double widened = (double)narrow;
    volatile long double binary128 = sqrtl(81.0L);
    long double binary128_sum = binary128 + (long double)widened;
    long double binary128_product = binary128_sum * (long double)narrow;
    long double binary128_quotient = binary128_product / (long double)narrow;
    long double binary128_difference = binary128_quotient - binary128;
    float binary128_as_float = (float)binary128_difference;
    double binary128_as_double = (double)binary128_difference;
    double complex value = 3.0 + 4.0 * I;
    double complex squared = value * value;
    double magnitude = cabs(value);

    int overflow_result = 0;
    int overflow = __builtin_add_overflow(INT_MAX, 1, &overflow_result);
    _Atomic uint64_t counter = 0;
    uint64_t previous = atomic_fetch_add_explicit(&counter, 1, memory_order_acq_rel);

    /* -fstack-protector-all protects this real stack object in every mode. */
    volatile char stack_value[32];
    stack_value[0] = (char)unsigned_remainder;

    return unsigned_quotient == 0 || unsigned_remainder >= 3 || signed_quotient == 0
            || signed_remainder <= -7 || signed_remainder >= 7 || widened != 3.5
            || binary128 != 9.0L || binary128_sum != 12.5L || binary128_product != 43.75L
            || binary128_quotient != 12.5L || binary128_difference != 3.5L
            || binary128_as_float != 3.5f || binary128_as_double != 3.5
            || creal(squared) != -7.0 || cimag(squared) != 24.0
            || magnitude != 5.0 || !overflow || overflow_result != INT_MIN || previous != 0
            || atomic_load_explicit(&counter, memory_order_relaxed) != 1 || stack_value[0] < 0;
}
