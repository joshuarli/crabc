/*
 * Private x86-64 __addoti4 compiler-helper ABI probe.
 *
 * The candidate path calls the archive's signed-__int128 helper directly so
 * that its two-word return and writable int overflow slot cross the native C
 * ABI.  The reference path uses GCC's checked-add builtin, which establishes
 * the same defined result and overflow bit without calling __addoti4.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef __int128 signed_int128;

#if defined(CRABC_BUILTINS_REFERENCE)
static signed_int128 call_addoti4(
    signed_int128 left,
    signed_int128 right,
    int *overflow
) {
    signed_int128 result;
    *overflow = __builtin_add_overflow(left, right, &result);
    return result;
}
#else
extern signed_int128 __addoti4(signed_int128 left, signed_int128 right, int *overflow);

__attribute__((noinline))
static signed_int128 call_addoti4(
    signed_int128 left,
    signed_int128 right,
    int *overflow
) {
    return __addoti4(left, right, overflow);
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
    signed_int128 result = call_addoti4(left, right, &overflow);

    if (result != expected_result) {
        return case_number * 2;
    }
    if (overflow != expected_overflow) {
        return case_number * 2 + 1;
    }
    return 0;
}

int crabc_x86_64_addoti4_probe(void) {
    const signed_int128 high = ((signed_int128)1) << 100;
    const signed_int128 two_to_126 = ((signed_int128)1) << 126;
    const signed_int128 maximum = two_to_126 + (two_to_126 - 1);
    const signed_int128 minimum = -two_to_126 - two_to_126;
    int result;

    result = check_case(high, -19, high - 19, 0, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(maximum, 1, minimum, 1, 2);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, -1, maximum, 1, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(maximum, minimum, -1, 0, 4);
    if (result != 0) {
        return result;
    }
    return check_case(-high, -5, -high - 5, 0, 5);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_addoti4_probe();
}
#endif
