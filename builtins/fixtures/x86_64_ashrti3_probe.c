/*
 * Private x86-64 __ashrti3 compiler-helper ABI probe.
 *
 * The raw helper has signed-shift semantics but passes an explicit two-word
 * Uint128 representation. This fixture uses unsigned __int128 only as that
 * ABI bit carrier. The reference arm reconstructs Uint128::sar through
 * defined word operations; it does not rely on implementation-defined signed
 * C right shifts or ordinary C out-of-range shift expressions.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

#if __SIZEOF_LONG__ != 8
#error "this private compiler-helper fixture requires 64-bit unsigned long words"
#endif

typedef unsigned __int128 unsigned_int128;
typedef unsigned long word;

static unsigned_int128 words(word high, word low) {
    return ((unsigned_int128)high << 64) | low;
}

#if defined(CRABC_BUILTINS_REFERENCE)
static unsigned_int128 call_ashrti3(unsigned_int128 value, int shift) {
    const word high = (word)(value >> 64);
    const word low = (word)value;
    const int negative = (high >> 63) != 0;
    unsigned int count;
    word result_high;
    word result_low;

    if (shift < 0 || shift >= 128) {
        return negative ? words(~(word)0, ~(word)0) : 0;
    }
    if (shift >= 64) {
        count = (unsigned int)shift - 64;
        result_low = high >> count;
        if (negative && count != 0) {
            result_low |= (~(word)0) << (64 - count);
        }
        return words(negative ? ~(word)0 : 0, result_low);
    }
    if (shift == 0) {
        return value;
    }

    count = (unsigned int)shift;
    result_low = (low >> count) | (high << (64 - count));
    result_high = high >> count;
    if (negative) {
        result_high |= (~(word)0) << (64 - count);
    }
    return words(result_high, result_low);
}
#else
extern unsigned_int128 __ashrti3(unsigned_int128 value, int shift);

__attribute__((noinline))
static unsigned_int128 call_ashrti3(unsigned_int128 value, int shift) {
    return __ashrti3(value, shift);
}
#endif

static int check_case(
    unsigned_int128 value,
    int shift,
    unsigned_int128 expected,
    int case_number
) {
    if (call_ashrti3(value, shift) != expected) {
        return case_number;
    }
    return 0;
}

int crabc_x86_64_ashrti3_probe(void) {
    const unsigned_int128 negative_input = words(((word)1 << 63) | 1, 1);
    const unsigned_int128 positive_input = words(0, ((word)1 << 63) | 1);
    const unsigned_int128 all_ones = words(~(word)0, ~(word)0);
    int result;

    result = check_case(negative_input, 0, negative_input, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(
        negative_input,
        1,
        words((word)0xc000000000000000, (word)0x8000000000000000),
        2
    );
    if (result != 0) {
        return result;
    }
    result = check_case(negative_input, 63, words(~(word)0, 2), 3);
    if (result != 0) {
        return result;
    }
    result = check_case(
        negative_input,
        64,
        words(~(word)0, ((word)1 << 63) | 1),
        4
    );
    if (result != 0) {
        return result;
    }
    result = check_case(
        negative_input,
        65,
        words(~(word)0, (word)0xc000000000000000),
        5
    );
    if (result != 0) {
        return result;
    }
    result = check_case(negative_input, 127, all_ones, 6);
    if (result != 0) {
        return result;
    }
    result = check_case(negative_input, 128, all_ones, 7);
    if (result != 0) {
        return result;
    }
    result = check_case(negative_input, 129, all_ones, 8);
    if (result != 0) {
        return result;
    }
    result = check_case(negative_input, -1, all_ones, 9);
    if (result != 0) {
        return result;
    }
    result = check_case(positive_input, 128, 0, 10);
    if (result != 0) {
        return result;
    }
    result = check_case(positive_input, 129, 0, 11);
    if (result != 0) {
        return result;
    }
    return check_case(positive_input, -1, 0, 12);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_ashrti3_probe();
}
#endif
