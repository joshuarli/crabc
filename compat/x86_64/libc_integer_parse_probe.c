/* Static x86-64 integer parsing behavior fixture.
 *
 * This is a complete narrow strto* family: its cases ratchet end-pointer
 * movement, stale errno on successful conversion, musl's EINVAL paths, and
 * signed/unsigned range boundaries. atoi/atol/atoll are separately exercised
 * only on inputs whose result is representable in their result type.
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "integer widths");
_Static_assert(sizeof(intmax_t) == sizeof(long), "x86 LP64 intmax_t width");
_Static_assert(sizeof(uintmax_t) == sizeof(unsigned long), "x86 LP64 uintmax_t width");

typedef long (*strtol_fn)(const char *, char **, int);
typedef unsigned long (*strtoul_fn)(const char *, char **, int);
typedef long long (*strtoll_fn)(const char *, char **, int);
typedef unsigned long long (*strtoull_fn)(const char *, char **, int);
typedef intmax_t (*strtoimax_fn)(const char *, char **, int);
typedef uintmax_t (*strtoumax_fn)(const char *, char **, int);

static int expect_long(strtol_fn parse, const char *input, int base,
    long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_long_long(strtoll_fn parse, const char *input, int base,
    long long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_intmax(strtoimax_fn parse, const char *input, int base,
    intmax_t expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_ulong(strtoul_fn parse, const char *input, int base,
    unsigned long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_ulong_long(strtoull_fn parse, const char *input, int base,
    unsigned long long expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_uintmax(strtoumax_fn parse, const char *input, int base,
    uintmax_t expected_value, ptrdiff_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = (char *)0;

    errno = initial_errno;
    if (parse(input, &end, base) != expected_value)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int check_signed_parsers(void)
{
    const strtol_fn parse_long = strtol;
    const strtoll_fn parse_long_long = strtoll;
    const strtoimax_fn parse_intmax = strtoimax;
    int status;

    status = expect_long(parse_long, " \t-42tail", 10, -42L, 5, EINTR, EINTR);
    if (status != 0) return 10 + status;
    status = expect_long(parse_long, "0x2a!", 0, 42L, 4, EDOM, EDOM);
    if (status != 0) return 20 + status;
    status = expect_long(parse_long, "077z", 0, 63L, 3, EILSEQ, EILSEQ);
    if (status != 0) return 30 + status;
    status = expect_long(parse_long, "0Xf?", 16, 15L, 3, EINTR, EINTR);
    if (status != 0) return 40 + status;
    status = expect_long(parse_long, "1012", 2, 5L, 3, EDOM, EDOM);
    if (status != 0) return 50 + status;
    status = expect_long(parse_long, "0x", 0, 0L, 1, EINTR, EINTR);
    if (status != 0) return 60 + status;
    status = expect_long(parse_long, "0xg", 0, 0L, 1, EDOM, EDOM);
    if (status != 0) return 65 + status;
    status = expect_long(parse_long, "+", 10, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 70 + status;
    status = expect_long(parse_long, "\xa0", 10, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 80 + status;
    status = expect_long(parse_long, "42", 1, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 90 + status;
    status = expect_long(parse_long, "42", -1, 0L, 0, EDOM, EINVAL);
    if (status != 0) return 95 + status;
    status = expect_long(parse_long, "z!", 36, 35L, 1, EDOM, EDOM);
    if (status != 0) return 98 + status;
    status = expect_long(parse_long, "9223372036854775807", 10, LONG_MAX, 19,
        EINTR, EINTR);
    if (status != 0) return 100 + status;
    status = expect_long(parse_long, "9223372036854775808", 10, LONG_MAX, 19,
        EDOM, ERANGE);
    if (status != 0) return 110 + status;
    status = expect_long(parse_long, "-9223372036854775808", 10, LONG_MIN, 20,
        EINTR, EINTR);
    if (status != 0) return 120 + status;
    status = expect_long(parse_long, "-9223372036854775809", 10, LONG_MIN, 20,
        EDOM, ERANGE);
    if (status != 0) return 130 + status;

    status = expect_long_long(parse_long_long, "-9223372036854775808", 10,
        LLONG_MIN, 20, EINTR, EINTR);
    if (status != 0) return 140 + status;
    status = expect_long_long(parse_long_long, "9223372036854775808", 10,
        LLONG_MAX, 19, EDOM, ERANGE);
    if (status != 0) return 150 + status;
    status = expect_intmax(parse_intmax, "-9223372036854775808", 10,
        INTMAX_MIN, 20, EINTR, EINTR);
    if (status != 0) return 160 + status;
    status = expect_intmax(parse_intmax, "9223372036854775808", 10,
        INTMAX_MAX, 19, EDOM, ERANGE);
    return status == 0 ? 0 : 170 + status;
}

static int check_unsigned_parsers(void)
{
    const strtoul_fn parse_ulong = strtoul;
    const strtoull_fn parse_ulong_long = strtoull;
    const strtoumax_fn parse_uintmax = strtoumax;
    int status;

    status = expect_ulong(parse_ulong, "-1", 10, ULONG_MAX, 2, EINTR, EINTR);
    if (status != 0) return 10 + status;
    status = expect_ulong(parse_ulong, "0xFf!", 0, 255UL, 4, EDOM, EDOM);
    if (status != 0) return 20 + status;
    status = expect_ulong(parse_ulong, "0x", 16, 0UL, 1, EINTR, EINTR);
    if (status != 0) return 30 + status;
    status = expect_ulong(parse_ulong, "-0xF!", 0, ULONG_MAX - 14UL, 4,
        EDOM, EDOM);
    if (status != 0) return 35 + status;
    status = expect_ulong(parse_ulong, "18446744073709551615", 10, ULONG_MAX, 20,
        EINTR, EINTR);
    if (status != 0) return 40 + status;
    status = expect_ulong(parse_ulong, "18446744073709551616", 10, ULONG_MAX, 20,
        EDOM, ERANGE);
    if (status != 0) return 50 + status;
    status = expect_ulong(parse_ulong, "-18446744073709551616", 10, ULONG_MAX, 21,
        EDOM, ERANGE);
    if (status != 0) return 60 + status;
    status = expect_ulong(parse_ulong, "$", 10, 0UL, 0, EDOM, EINVAL);
    if (status != 0) return 70 + status;

    status = expect_ulong_long(parse_ulong_long, "18446744073709551615", 10,
        ULLONG_MAX, 20, EINTR, EINTR);
    if (status != 0) return 80 + status;
    status = expect_ulong_long(parse_ulong_long, "18446744073709551616", 10,
        ULLONG_MAX, 20, EDOM, ERANGE);
    if (status != 0) return 90 + status;
    status = expect_uintmax(parse_uintmax, "18446744073709551615", 10,
        UINTMAX_MAX, 20, EINTR, EINTR);
    if (status != 0) return 100 + status;
    status = expect_uintmax(parse_uintmax, "18446744073709551616", 10,
        UINTMAX_MAX, 20, EDOM, ERANGE);
    return status == 0 ? 0 : 110 + status;
}

static int check_convenience_parsers(void)
{
    errno = EDOM;
    if (atoi(" \t-42tail") != -42 || errno != EDOM)
        return 1;
    errno = EINTR;
    if (atoi("-2147483648") != INT_MIN || errno != EINTR)
        return 2;
    errno = EDOM;
    if (atol("-9223372036854775808") != LONG_MIN || errno != EDOM)
        return 3;
    errno = EINTR;
    if (atoll("-9223372036854775808") != LLONG_MIN || errno != EINTR)
        return 4;
    errno = EDOM;
    if (atoi("0x10") != 0 || errno != EDOM)
        return 5;
    return 0;
}

static long raw_mmap(size_t length)
{
    register long flags __asm__("r10") = 0x22; /* MAP_PRIVATE | MAP_ANONYMOUS */
    register long offset __asm__("r8") = -1;
    register long zero __asm__("r9") = 0;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(9L), "D"(0L), "S"((long)length), "d"(3L),
          "r"(flags), "r"(offset), "r"(zero)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_mprotect(void *address, size_t length, int protection)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(10L), "D"((long)address), "S"((long)length),
          "d"((long)protection)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_munmap(void *address, size_t length)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(11L), "D"((long)address), "S"((long)length)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_write(const void *buffer, size_t length)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(1L), "D"(1L), "S"((long)buffer), "d"((long)length)
        : "rcx", "r11", "memory");
    return result;
}

static uint64_t hash_word(uint64_t hash, uint64_t value)
{
    unsigned int byte;
    for (byte = 0; byte < 8; byte++) {
        hash = (hash ^ (unsigned char)value) * UINT64_C(1099511628211);
        value >>= 8;
    }
    return hash;
}

/* The NUL is the last readable byte, so every scan also checks its read bound. */
static int check_guarded_differential(void)
{
    enum { PAGE_BYTES = 4096 };
    static const char *const inputs[] = {
        "", " ", "\t\r\n\v\f+", "-", "+0", "-0", "00", "08", "0x",
        "0Xg", "-0x", "+0X1f!", "0x1g", "0b101", "--1", "1+2",
        "\x80" "42", "\xa0" "7", "zZ!", "  -0XfFz", "  +00129!",
        "7fffffff", "80000000", "-80000000", "-80000001",
        "9223372036854775807", "9223372036854775808",
        "-9223372036854775808", "-9223372036854775809",
        "18446744073709551615", "18446744073709551616",
        "-18446744073709551615", "-18446744073709551616",
        "ffffffffffffffff", "10000000000000000",
        "9999999999999999999999999999999999999999999999999999999999tail"
    };
    static const int bases[] = { -1, 0, 1, 2, 3, 7, 8, 10, 11, 16, 17, 35, 36, 37 };
    unsigned char *mapping;
    uint64_t hash = UINT64_C(14695981039346656037);
    size_t sample, basis;
    char line[] = "integer-parse-differential-fnv1a64=0000000000000000\n";
    static const char hex[] = "0123456789abcdef";
    int status = 0;

    long mapped = raw_mmap(PAGE_BYTES * 2);
    if (mapped < 0) return 1;
    mapping = (unsigned char *)mapped;
    if (raw_mprotect(mapping + PAGE_BYTES, PAGE_BYTES, 0) != 0) {
        raw_munmap(mapping, PAGE_BYTES * 2);
        return 2;
    }

    for (sample = 0; sample < sizeof inputs / sizeof inputs[0]; sample++) {
        const char *literal = inputs[sample];
        size_t length = 0, index;
        char *input;
        while (literal[length]) length++;
        if (length + 1 > PAGE_BYTES) { status = 3; break; }
        input = (char *)(mapping + PAGE_BYTES - length - 1);
        for (index = 0; index <= length; index++) input[index] = literal[index];
        for (basis = 0; basis < sizeof bases / sizeof bases[0]; basis++) {
            int base = bases[basis];
            char *end;
            uint64_t value;
            hash = hash_word(hash, sample);
            hash = hash_word(hash, (unsigned int)base);
#define RECORD_PARSE(parser) do { \
    errno = EDOM; \
    end = (char *)0; \
    value = (uint64_t)(parser)(input, &end, base); \
    if ((uintptr_t)end < (uintptr_t)input || \
        (uintptr_t)end > (uintptr_t)(input + length)) { status = 4; break; } \
    hash = hash_word(hash, value); \
    hash = hash_word(hash, (uintptr_t)end - (uintptr_t)input); \
    hash = hash_word(hash, (unsigned int)errno); \
} while (0)
            RECORD_PARSE(strtol);
            RECORD_PARSE(strtoul);
            RECORD_PARSE(strtoll);
            RECORD_PARSE(strtoull);
            RECORD_PARSE(strtoimax);
            RECORD_PARSE(strtoumax);
#undef RECORD_PARSE
            if (status) break;
        }
        if (status) break;
    }
    if (raw_munmap(mapping, PAGE_BYTES * 2) != 0) return 5;
    if (status) return status;
    for (sample = 0; sample < 16; sample++)
        line[sizeof line - 18 + sample] = hex[(hash >> ((15 - sample) * 4)) & 15];
    return raw_write(line, sizeof line - 1) == (long)(sizeof line - 1) ? 0 : 6;
}

int crabc_x86_64_integer_parse_probe(void)
{
    int status = check_signed_parsers();
    if (status != 0)
        return status;
    status = check_unsigned_parsers();
    if (status != 0)
        return 200 + status;
    status = check_convenience_parsers();
    if (status != 0)
        return 400 + status;
    status = check_guarded_differential();
    return status == 0 ? 0 : 500 + status;
}

#ifndef CRABC_INTEGER_PARSE_FREESTANDING
int main(void)
{
    return crabc_x86_64_integer_parse_probe();
}
#endif
