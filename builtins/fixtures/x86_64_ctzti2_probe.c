/*
 * Private x86-64 __ctzti2 compiler-helper ABI probe.
 *
 * This fixture passes Uint128 through unsigned __int128 solely as the selected
 * two-word ABI bit carrier. Its reference arm counts trailing zero bits with
 * ordinary unsigned-word operations, avoiding a C compiler builtin or any
 * ambient compiler-runtime implementation of __ctzti2.
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
static int trailing_zeros_word(word value) {
    int count = 0;
    word bit = 1;

    while (bit != 0 && (value & bit) == 0) {
        count += 1;
        bit <<= 1;
    }
    return count;
}

static int call_ctzti2(unsigned_int128 value) {
    const word low = (word)value;

    if (low != 0) {
        return trailing_zeros_word(low);
    }
    return 64 + trailing_zeros_word((word)(value >> 64));
}
#else
extern int __ctzti2(unsigned_int128 value);

__attribute__((noinline))
static int call_ctzti2(unsigned_int128 value) {
    return __ctzti2(value);
}
#endif

static int check_case(unsigned_int128 value, int expected, int case_number) {
    if (call_ctzti2(value) != expected) {
        return case_number;
    }
    return 0;
}

int crabc_x86_64_ctzti2_probe(void) {
    int result;

    result = check_case(words(0, 0), 128, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(words(0, 1), 0, 2);
    if (result != 0) {
        return result;
    }
    result = check_case(words(~(word)0, 2), 1, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(words(1, (word)1 << 63), 63, 4);
    if (result != 0) {
        return result;
    }
    result = check_case(words(1, 0), 64, 5);
    if (result != 0) {
        return result;
    }
    result = check_case(words(2, 0), 65, 6);
    if (result != 0) {
        return result;
    }
    return check_case(words((word)1 << 63, 0), 127, 7);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_ctzti2_probe();
}
#endif
