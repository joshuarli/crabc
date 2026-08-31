/*
 * Private x86-64 __divmodti4 compiler-helper ABI probe.
 *
 * The candidate path calls the archive's signed-__int128 helper directly so
 * that its two-word quotient return and writable two-word remainder slot cross
 * the native C ABI. The reference path uses ordinary defined signed C division
 * and remainder, rather than calling __divmodti4 itself.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef __int128 signed_int128;

#if defined(CRABC_BUILTINS_REFERENCE)
static signed_int128 call_divmodti4(
    signed_int128 numerator,
    signed_int128 denominator,
    signed_int128 *remainder
) {
    *remainder = numerator % denominator;
    return numerator / denominator;
}
#else
extern signed_int128 __divmodti4(
    signed_int128 numerator,
    signed_int128 denominator,
    signed_int128 *remainder
);

__attribute__((noinline))
static signed_int128 call_divmodti4(
    signed_int128 numerator,
    signed_int128 denominator,
    signed_int128 *remainder
) {
    return __divmodti4(numerator, denominator, remainder);
}
#endif

static int check_case(
    signed_int128 numerator,
    signed_int128 denominator,
    signed_int128 expected_quotient,
    signed_int128 expected_remainder,
    int case_number
) {
    signed_int128 remainder = 17;
    signed_int128 quotient = call_divmodti4(numerator, denominator, &remainder);

    if (quotient != expected_quotient) {
        return case_number * 2;
    }
    if (remainder != expected_remainder) {
        return case_number * 2 + 1;
    }
    return 0;
}

int crabc_x86_64_divmodti4_probe(void) {
    const signed_int128 high = ((signed_int128)1) << 100;
    const signed_int128 positive = high + 5;
    const signed_int128 word = ((signed_int128)1) << 64;
    const signed_int128 cross_word_numerator = (((signed_int128)1) << 126) + (word << 1) + 1;
    const signed_int128 cross_word_denominator = word + 1;
    int result;

    result = check_case(positive, 16, ((signed_int128)1) << 96, 5, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(-positive, 16, -(((signed_int128)1) << 96), -5, 2);
    if (result != 0) {
        return result;
    }
    result = check_case(positive, -16, -(((signed_int128)1) << 96), 5, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(-positive, -16, ((signed_int128)1) << 96, -5, 4);
    if (result != 0) {
        return result;
    }
    result = check_case(7, -3, -2, 1, 5);
    if (result != 0) {
        return result;
    }
    result = check_case(-7, 3, -2, -1, 6);
    if (result != 0) {
        return result;
    }
    return check_case(
        cross_word_numerator,
        cross_word_denominator,
        (((signed_int128)1) << 62) + 1,
        (((signed_int128)3) << 62),
        7
    );
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_divmodti4_probe();
}
#endif
