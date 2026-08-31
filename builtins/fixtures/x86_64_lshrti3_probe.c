/*
 * Private x86-64 __lshrti3 compiler-helper ABI probe.
 *
 * The candidate calls the archive helper directly. The reference arm recreates
 * only the selected source branch in defined unsigned C: a negative or >=128
 * count returns zero, otherwise it performs the in-range logical shift. It
 * does not claim ordinary C semantics for an out-of-range shift expression.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef unsigned __int128 unsigned_int128;

#if defined(CRABC_BUILTINS_REFERENCE)
static unsigned_int128 call_lshrti3(unsigned_int128 value, int shift) {
    if (shift < 0 || shift >= 128) {
        return 0;
    }
    return value >> (unsigned int)shift;
}
#else
extern unsigned_int128 __lshrti3(unsigned_int128 value, int shift);

__attribute__((noinline))
static unsigned_int128 call_lshrti3(unsigned_int128 value, int shift) {
    return __lshrti3(value, shift);
}
#endif

static int check_case(
    unsigned_int128 value,
    int shift,
    unsigned_int128 expected,
    int case_number
) {
    if (call_lshrti3(value, shift) != expected) {
        return case_number;
    }
    return 0;
}

int crabc_x86_64_lshrti3_probe(void) {
    const unsigned_int128 input =
        (((unsigned_int128)1) << 127) + (((unsigned_int128)1) << 64) + 1;
    int result;

    result = check_case(input, 0, input, 1);
    if (result != 0) {
        return result;
    }
    result = check_case(
        input,
        1,
        (((unsigned_int128)1) << 126) + (((unsigned_int128)1) << 63),
        2
    );
    if (result != 0) {
        return result;
    }
    result = check_case(input, 63, (((unsigned_int128)1) << 64) + 2, 3);
    if (result != 0) {
        return result;
    }
    result = check_case(input, 64, (((unsigned_int128)1) << 63) + 1, 4);
    if (result != 0) {
        return result;
    }
    result = check_case(input, 65, ((unsigned_int128)1) << 62, 5);
    if (result != 0) {
        return result;
    }
    result = check_case(input, 127, 1, 6);
    if (result != 0) {
        return result;
    }
    result = check_case(input, 128, 0, 7);
    if (result != 0) {
        return result;
    }
    result = check_case(input, 129, 0, 8);
    if (result != 0) {
        return result;
    }
    return check_case(input, -1, 0, 9);
}

#ifndef CRABC_BUILTINS_FREESTANDING
int main(void) {
    return crabc_x86_64_lshrti3_probe();
}
#endif
