/*
 * Private x86-64 __udivmodti4 compiler-helper ABI probe.
 *
 * The candidate path calls the archive's unsigned-__int128 helper directly so
 * that its two-word quotient return and writable two-word remainder slot cross
 * the native C ABI. The reference path uses ordinary unsigned C division and
 * remainder, rather than calling __udivmodti4 itself.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef unsigned __int128 unsigned_int128;

#if defined(CRABC_BUILTINS_REFERENCE)
static unsigned_int128 call_udivmodti4(
    unsigned_int128 numerator,
    unsigned_int128 denominator,
    unsigned_int128 *remainder
) {
    *remainder = numerator % denominator;
    return numerator / denominator;
}
#else
extern unsigned_int128 __udivmodti4(
    unsigned_int128 numerator,
    unsigned_int128 denominator,
    unsigned_int128 *remainder
);

__attribute__((noinline))
static unsigned_int128 call_udivmodti4(
    unsigned_int128 numerator,
    unsigned_int128 denominator,
    unsigned_int128 *remainder
) {
    return __udivmodti4(numerator, denominator, remainder);
}
#endif

static int check_case(
    unsigned_int128 numerator,
    unsigned_int128 denominator,
    unsigned_int128 expected_quotient,
    unsigned_int128 expected_remainder,
    int case_number
) {
    unsigned_int128 remainder = ~((unsigned_int128)0);
    unsigned_int128 quotient = call_udivmodti4(numerator, denominator, &remainder);

    if (quotient != expected_quotient) {
        return case_number * 2;
    }
    if (remainder != expected_remainder) {
        return case_number * 2 + 1;
    }
    return 0;
}

int crabc_x86_64_udivmodti4_probe(void) {
    const unsigned_int128 high = ((unsigned_int128)1) << 100;
    const unsigned_int128 word = ((unsigned_int128)1) << 64;
    const unsigned_int128 composed = (((unsigned_int128)1) << 127) + (word << 1) + 1;
    const unsigned_int128 cross_word_denominator = word + 1;
    int result;

    result = check_case(high + 5, 16, ((unsigned_int128)1) << 96, 5, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(high + 123, high, 1, 123, 2);
    if (result != 0) {
        return result;
    }
    result = check_case(7, high, 0, 7, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(
        composed,
        cross_word_denominator,
        (((unsigned_int128)1) << 63) + 1,
        ((unsigned_int128)1) << 63,
        4
    );
    if (result != 0) {
        return result;
    }
    return check_case(
        ~((unsigned_int128)0),
        high,
        (((unsigned_int128)1) << 28) - 1,
        high - 1,
        5
    );
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_udivmodti4_probe();
}
#endif
