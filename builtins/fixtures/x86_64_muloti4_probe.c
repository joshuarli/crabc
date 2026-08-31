/*
 * Private x86-64 __muloti4 compiler-helper ABI probe.
 *
 * The candidate path calls the archive's signed-__int128 helper directly so
 * that both its two-word return and writable int overflow slot cross the
 * native C ABI.  The reference path uses GCC's checked-multiply builtin and
 * therefore establishes the same defined result and overflow bit without
 * calling __muloti4.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef __int128 signed_int128;

#if defined(CRABC_BUILTINS_REFERENCE)
static signed_int128 call_muloti4(
    signed_int128 left,
    signed_int128 right,
    int *overflow
) {
    signed_int128 result;
    *overflow = __builtin_mul_overflow(left, right, &result);
    return result;
}
#else
extern signed_int128 __muloti4(signed_int128 left, signed_int128 right, int *overflow);

__attribute__((noinline))
static signed_int128 call_muloti4(
    signed_int128 left,
    signed_int128 right,
    int *overflow
) {
    return __muloti4(left, right, overflow);
}
#endif

static int check_case(
    signed_int128 left,
    signed_int128 right,
    signed_int128 expected_result,
    int expected_overflow,
    int case_number
) {
    int overflow = -77;
    signed_int128 result = call_muloti4(left, right, &overflow);

    if (result != expected_result) {
        return case_number * 2;
    }
    if (overflow != expected_overflow) {
        return case_number * 2 + 1;
    }
    return 0;
}

int crabc_x86_64_muloti4_probe(void) {
    const signed_int128 high = ((signed_int128)1) << 100;
    const signed_int128 two_to_126 = ((signed_int128)1) << 126;
    const signed_int128 maximum = two_to_126 + (two_to_126 - 1);
    const signed_int128 minimum = -two_to_126 - two_to_126;
    int result;

    result = check_case(high, 9, high * 9, 0, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(-high, 7, -high * 7, 0, 2);
    if (result != 0) {
        return result;
    }
    result = check_case(maximum, 2, -2, 1, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, -1, minimum, 1, 4);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, 1, minimum, 0, 5);
    if (result != 0) {
        return result;
    }
    return check_case(-high, -7, high * 7, 0, 6);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_muloti4_probe();
}
#endif
