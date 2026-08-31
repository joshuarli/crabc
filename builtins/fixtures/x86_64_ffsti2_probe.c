/*
 * Private x86-64 __ffsti2 compiler-helper ABI probe.
 *
 * This fixture passes Uint128 through unsigned __int128 solely as the selected
 * two-word ABI bit carrier. Its reference arm reconstructs the source's zero
 * branch and __ctzti2-plus-one result with unsigned-word operations, avoiding
 * a C compiler builtin or any ambient compiler-runtime implementation.
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

static int call_ffsti2(unsigned_int128 value) {
    const word low = (word)value;
    const word high = (word)(value >> 64);

    if (low == 0 && high == 0) {
        return 0;
    }
    if (low != 0) {
        return trailing_zeros_word(low) + 1;
    }
    return 64 + trailing_zeros_word(high) + 1;
}
#else
extern int __ffsti2(unsigned_int128 value);

__attribute__((noinline))
static int call_ffsti2(unsigned_int128 value) {
    return __ffsti2(value);
}
#endif

static int check_case(unsigned_int128 value, int expected, int case_number) {
    if (call_ffsti2(value) != expected) {
        return case_number;
    }
    return 0;
}

int crabc_x86_64_ffsti2_probe(void) {
    int result;

    result = check_case(words(0, 0), 0, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(words(0, 1), 1, 2);
    if (result != 0) {
        return result;
    }
    result = check_case(words(~(word)0, 2), 2, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(words(1, (word)1 << 63), 64, 4);
    if (result != 0) {
        return result;
    }
    result = check_case(words(1, 0), 65, 5);
    if (result != 0) {
        return result;
    }
    result = check_case(words(2, 0), 66, 6);
    if (result != 0) {
        return result;
    }
    return check_case(words((word)1 << 63, 0), 128, 7);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_ffsti2_probe();
}
#endif
