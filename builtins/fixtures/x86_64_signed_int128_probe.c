/*
 * Private x86-64 signed-__int128 compiler-helper ABI probe.
 *
 * The volatile inputs and noinline operators deliberately require the native
 * compiler to lower the two operations to __divti3 and __modti3.  Every case
 * has a nonzero divisor. INT128_MIN / -1 has no representable C result, so
 * that ABI edge calls the helpers directly instead of evaluating C / or %.
 * The result bits are written through the Linux write syscall in both images.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef __int128 signed_int128;
typedef unsigned __int128 unsigned_int128;

/* The high word stays below the signed bit, so this construction is defined. */
#define POSITIVE_SIGNED128(high, low) ((((signed_int128)(high)) << 64) | (low))

extern signed_int128 __divti3(signed_int128, signed_int128);
extern signed_int128 __modti3(signed_int128, signed_int128);

static volatile signed_int128 operand_left;
static volatile signed_int128 operand_right;

static void hex_word(char *out, unsigned long word) {
    static const char digits[] = "0123456789abcdef";
    for (int index = 15; index >= 0; --index) {
        out[index] = digits[word & 15];
        word >>= 4;
    }
}

static int emit_result(int case_number, signed_int128 quotient, signed_int128 remainder) {
    char line[69];
    unsigned_int128 quotient_bits = (unsigned_int128)quotient;
    unsigned_int128 remainder_bits = (unsigned_int128)remainder;
    long written;

    line[0] = (char)('0' + case_number / 10);
    line[1] = (char)('0' + case_number % 10);
    line[2] = ' ';
    hex_word(line + 3, (unsigned long)(quotient_bits >> 64));
    hex_word(line + 19, (unsigned long)quotient_bits);
    line[35] = ' ';
    hex_word(line + 36, (unsigned long)(remainder_bits >> 64));
    hex_word(line + 52, (unsigned long)remainder_bits);
    line[68] = '\n';
    __asm__ volatile("syscall" : "=a"(written) : "a"(1), "D"(1), "S"(line), "d"(sizeof line) : "rcx", "r11", "memory");
    return written == (long)sizeof line ? 0 : case_number * 2 + 1;
}

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
    signed_int128 quotient;
    signed_int128 remainder;
    operand_left = left;
    operand_right = right;

    quotient = signed_divide(operand_left, operand_right);
    remainder = signed_remainder(operand_left, operand_right);
    if (quotient != expected_quotient) {
        return case_number * 2;
    }
    if (remainder != expected_remainder) {
        return case_number * 2 + 1;
    }
    return emit_result(case_number, quotient, remainder);
}

/* Call the ABI entries directly because the corresponding C expression overflows. */
static int check_overflow_helper_case(signed_int128 minimum) {
    signed_int128 quotient = __divti3(minimum, -1);
    signed_int128 remainder = __modti3(minimum, -1);
    if (quotient != minimum || remainder != 0) {
        return 32;
    }
    return emit_result(16, quotient, remainder);
}

int crabc_x86_64_signed_int128_probe(void) {
    const signed_int128 high = ((signed_int128)1) << 100;
    const signed_int128 positive = high + 5;
    const signed_int128 minimum = -(((signed_int128)1) << 126) - (((signed_int128)1) << 126);
    const signed_int128 high_divisor = (((signed_int128)1) << 96) + 7;
    const signed_int128 max = -(minimum + 1);
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
    result = check_case(-7, -3, 2, -1, 7);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, 1, minimum, 0, 8);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, 2, -(((signed_int128)1) << 126), 0, 9);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, 3, -POSITIVE_SIGNED128(0x2aaaaaaaaaaaaaaaULL, 0xaaaaaaaaaaaaaaaaULL), -2, 10);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum + 1, -1, max, 0, 11);
    if (result != 0) {
        return result;
    }
    result = check_case(max, -1, -max, 0, 12);
    if (result != 0) {
        return result;
    }
    result = check_case(high_divisor * 5 + 3, high_divisor, 5, 3, 13);
    if (result != 0) {
        return result;
    }
    result = check_case(-(high_divisor * 5 + 3), -high_divisor, 5, -3, 14);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, high_divisor, -0x7fffffff,
                        -POSITIVE_SIGNED128(0xffffffffULL, 0xfffffffc80000007ULL), 15);
    if (result != 0) {
        return result;
    }
    result = check_overflow_helper_case(minimum);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, -high_divisor, 0x7fffffff,
                        -POSITIVE_SIGNED128(0xffffffffULL, 0xfffffffc80000007ULL), 17);
    if (result != 0) {
        return result;
    }
    result = check_case(high_divisor * 5 + 3, -high_divisor, -5, 3, 18);
    if (result != 0) {
        return result;
    }
    result = check_case(minimum, minimum, 1, 0, 19);
    if (result != 0) {
        return result;
    }
    result = check_case(max, minimum, 0, max, 20);
    if (result != 0) {
        return result;
    }
    return check_case(minimum, (((signed_int128)1) << 64) + 3,
                      -0x7ffffffffffffffeLL, -POSITIVE_SIGNED128(0, 0x8000000000000006ULL), 21);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_signed_int128_probe();
}
#endif
