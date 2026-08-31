/*
 * Private x86-64 __clzti2 compiler-helper ABI probe.
 *
 * This fixture passes Uint128 through unsigned __int128 solely as the selected
 * two-word ABI bit carrier. Its reference arm counts leading zero bits with
 * ordinary unsigned-word operations, avoiding a C compiler builtin or any
 * ambient compiler-runtime implementation of __clzti2.
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
static int leading_zeros_word(word value) {
    int count = 0;
    word bit = (word)1 << 63;

    while (bit != 0 && (value & bit) == 0) {
        count += 1;
        bit >>= 1;
    }
    return count;
}

static int call_clzti2(unsigned_int128 value) {
    const word high = (word)(value >> 64);

    if (high != 0) {
        return leading_zeros_word(high);
    }
    return 64 + leading_zeros_word((word)value);
}
#else
extern int __clzti2(unsigned_int128 value);

__attribute__((noinline))
static int call_clzti2(unsigned_int128 value) {
    return __clzti2(value);
}
#endif

static int check_case(unsigned_int128 value, int expected, int case_number) {
    if (call_clzti2(value) != expected) {
        return case_number;
    }
    return 0;
}

int crabc_x86_64_clzti2_probe(void) {
    int result;

    result = check_case(words(0, 0), 128, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(words((word)1 << 63, 0), 0, 2);
    if (result != 0) {
        return result;
    }
    result = check_case(words((word)1 << 62, 0), 1, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(words(1, ~(word)0), 63, 4);
    if (result != 0) {
        return result;
    }
    result = check_case(words(0, (word)1 << 63), 64, 5);
    if (result != 0) {
        return result;
    }
    result = check_case(words(0, (word)1 << 62), 65, 6);
    if (result != 0) {
        return result;
    }
    return check_case(words(0, 1), 127, 7);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_clzti2_probe();
}
#endif
