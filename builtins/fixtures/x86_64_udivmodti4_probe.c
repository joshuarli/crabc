/*
 * Native unsigned 128-bit compiler-helper differential.
 *
 * The candidate calls all three owned helpers across the C ABI. The pinned
 * compiler reference evaluates unsigned C division and remainder. Each arm
 * writes the four results for every nonzero divisor to stdout as x86-64
 * little-endian unsigned __int128 words for a byte-for-byte comparison.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef unsigned __int128 unsigned_int128;
typedef unsigned long long unsigned_word;

static unsigned_int128 make_words(unsigned_word hi, unsigned_word lo) {
    return ((unsigned_int128)hi << 64) | lo;
}

#if defined(CRABC_BUILTINS_REFERENCE)
__attribute__((noinline))
static unsigned_int128 call_udivti3(unsigned_int128 numerator, unsigned_int128 denominator) {
    return numerator / denominator;
}

__attribute__((noinline))
static unsigned_int128 call_umodti3(unsigned_int128 numerator, unsigned_int128 denominator) {
    return numerator % denominator;
}

__attribute__((noinline))
static unsigned_int128 call_udivmodti4(
    unsigned_int128 numerator,
    unsigned_int128 denominator,
    unsigned_int128 *remainder
) {
    if (remainder) *remainder = numerator % denominator;
    return numerator / denominator;
}
#else
extern unsigned_int128 __udivti3(unsigned_int128 numerator, unsigned_int128 denominator);
extern unsigned_int128 __umodti3(unsigned_int128 numerator, unsigned_int128 denominator);
extern unsigned_int128 __udivmodti4(
    unsigned_int128 numerator,
    unsigned_int128 denominator,
    unsigned_int128 *remainder
);

__attribute__((noinline))
static unsigned_int128 call_udivti3(unsigned_int128 numerator, unsigned_int128 denominator) {
    return __udivti3(numerator, denominator);
}

__attribute__((noinline))
static unsigned_int128 call_umodti3(unsigned_int128 numerator, unsigned_int128 denominator) {
    return __umodti3(numerator, denominator);
}

__attribute__((noinline))
static unsigned_int128 call_udivmodti4(
    unsigned_int128 numerator,
    unsigned_int128 denominator,
    unsigned_int128 *remainder
) {
    return __udivmodti4(numerator, denominator, remainder);
}
#endif

/* The freestanding image owns its only I/O boundary. */
static long write_results(const unsigned_int128 results[4]) {
    long result;
    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(1L), "D"(1L), "S"(results), "d"(sizeof(unsigned_int128) * 4)
        : "rcx", "r11", "memory"
    );
    return result;
}

static int check_case(unsigned_int128 numerator, unsigned_int128 denominator) {
    unsigned_int128 results[4];
    unsigned_int128 remainder = ~((unsigned_int128)0);

    if (denominator == 0) {
        return 1;
    }
    results[0] = call_udivti3(numerator, denominator);
    results[1] = call_umodti3(numerator, denominator);
    results[2] = call_udivmodti4(numerator, denominator, &remainder);
    results[3] = remainder;
    if (results[0] != results[2] || results[1] != results[3]) {
        return 2;
    }
    if (call_udivmodti4(numerator, denominator, (unsigned_int128 *)0) != results[0]) {
        return 4;
    }
    return write_results(results) == (long)sizeof(results) ? 0 : 3;
}

static unsigned_word next_word(unsigned_word *state) {
    *state ^= *state << 7;
    *state ^= *state >> 9;
    *state ^= *state << 8;
    return *state;
}

int crabc_x86_64_udivmodti4_probe(void) {
    const unsigned_int128 one = 1;
    const unsigned_int128 max = ~((unsigned_int128)0);
    const unsigned_int128 word = one << 64;
    const unsigned_int128 high = one << 127;
    const unsigned_int128 numerators[] = {
        0, 1, 2, max, max - 1, high, high - 1, high + 1,
        word - 1, word, word + 1, (one << 100) + 5,
        make_words(0x8000000000000000ULL, 0xffffffffffffffffULL),
        make_words(0x5555555555555555ULL, 0xaaaaaaaaaaaaaaaaULL)
    };
    const unsigned_int128 denominators[] = {
        1, 2, 3, 7, word - 1, word, word + 1,
        high - 1, high, high + 1, max,
        make_words(0x8000000000000001ULL, 0xffffffffffffffffULL),
        make_words(0x5555555555555555ULL, 0xaaaaaaaaaaaaaaa9ULL)
    };
    unsigned_word state = 0xa064000000000002ULL;
    unsigned int i;
    unsigned int j;

    for (i = 0; i < sizeof(numerators) / sizeof(numerators[0]); ++i) {
        for (j = 0; j < sizeof(denominators) / sizeof(denominators[0]); ++j) {
            if (check_case(numerators[i], denominators[j])) return 1;
        }
    }
    for (i = 0; i < 128; ++i) {
        unsigned_int128 divisor = one << i;
        if (check_case(max, divisor)) return 2;
        if (check_case(divisor - 1, divisor)) return 3;
        if (check_case(divisor, divisor)) return 4;
        if (check_case(divisor + 1, divisor)) return 5;
    }
    for (i = 0; i < 256; ++i) {
        unsigned_word numerator_hi = next_word(&state);
        unsigned_word numerator_lo = next_word(&state);
        unsigned_word denominator_hi = next_word(&state);
        unsigned_word denominator_lo = next_word(&state);
        unsigned_int128 numerator = make_words(numerator_hi, numerator_lo);
        unsigned_int128 denominator = make_words(denominator_hi, denominator_lo) | 1;
        if (check_case(numerator, denominator)) return 6;
    }
    return 0;
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_udivmodti4_probe();
}
#endif
