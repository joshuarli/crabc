/*
 * Private x86-64 signed-__int128 compiler-helper ABI probe.
 *
 * The volatile inputs and noinline operators deliberately require the native
 * compiler to lower the two operations to __divti3 and __modti3.  Every case
 * has a nonzero divisor and stays away from INT128_MIN / -1, whose C result is
 * not representable.  The fixture therefore observes only defined signed C
 * division and remainder behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef __int128 signed_int128;

static volatile signed_int128 operand_left;
static volatile signed_int128 operand_right;

__attribute__((noinline))
static signed_int128 signed_divide(signed_int128 left, signed_int128 right) {
    return left / right;
}

__attribute__((noinline))
static signed_int128 signed_remainder(signed_int128 left, signed_int128 right) {
    return left % right;
}

static int check_case(
    signed_int128 left,
    signed_int128 right,
    signed_int128 expected_quotient,
    signed_int128 expected_remainder,
    int case_number
) {
    operand_left = left;
    operand_right = right;

    if (signed_divide(operand_left, operand_right) != expected_quotient) {
        return case_number * 2;
    }
    if (signed_remainder(operand_left, operand_right) != expected_remainder) {
        return case_number * 2 + 1;
    }
    return 0;
}

int crabc_x86_64_signed_int128_probe(void) {
    const signed_int128 high = ((signed_int128)1) << 100;
    const signed_int128 positive = high + 5;
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
    return check_case(-7, -3, 2, -1, 7);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_signed_int128_probe();
}
#endif
