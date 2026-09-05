/*
 * Installed Linux/x86-64 binary80 scalar-math differential consumer.
 *
 * Pinned musl 1.2.6 is the behavior oracle for exactly fmal, hypotl, and
 * log1pl. Calls use project-header function-pointer types, every case resets
 * all four floating directions, and each fixed-size record retains the ten
 * defined bytes of the x87 binary80 result plus requested/observed fenv state.
 *
 * The Rust target providers are already fixed musl translations: fmal and
 * hypotl live in math_elementary_long_double_musl_x86_64.S through Rust
 * global_asm!, while log1pl is the pinned x87 leaf in math_x87_extended.rs.
 * This fixture supplies an installed owned-static boundary; it introduces no
 * target C/assembly math provider.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this consumer requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#if !defined(CRABC_OWNED_STATIC_BINARY80_MATH_FREESTANDING)
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
    "x86 binary80 storage");
_Static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
    "x86 binary80 format");

enum {
    FMAL_CASES = 12,
    HYPOTL_CASES = 16,
    LOG1PL_CASES = 21,
    ROUNDING_CASES = 4,
    RECORD_COUNT = ROUNDING_CASES * (FMAL_CASES + HYPOTL_CASES + LOG1PL_CASES),
};

enum record_kind {
    RECORD_FMAL = 1,
    RECORD_HYPOTL = 2,
    RECORD_LOG1PL = 3,
};

struct l_pair { long double left; long double right; };
struct l_triple { long double first; long double second; long double third; };

struct __attribute__((packed)) binary80_record {
    uint16_t kind;
    uint16_t case_index;
    uint32_t requested_rounding;
    uint32_t observed_rounding;
    uint32_t exceptions;
    uint32_t result_kind;
    unsigned char result[20];
};
_Static_assert(sizeof(struct binary80_record) == 40, "stable binary80 record ABI");

static const int rounding_modes[ROUNDING_CASES] = {
    FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static const struct l_triple fmal_inputs[FMAL_CASES] = {
    {1.0L, 1.0L, 0.0L}, {1.0L, 2.0L, -2.0L},
    {-1.0L, 2.0L, 2.0L}, {1.5L, 2.0L, -3.0L},
    {LDBL_MIN, 0.5L, -LDBL_TRUE_MIN},
    {LDBL_MAX, 0.5L, LDBL_MAX / 2.0L},
    {INFINITY, 0.0L, 1.0L}, {INFINITY, 2.0L, -INFINITY},
    {__builtin_nanl("0x1234"), 1.0L, 2.0L}, {0.0L, INFINITY, 1.0L},
    {-0.0L, 2.0L, 0.0L}, {LDBL_TRUE_MIN, 1.0L, LDBL_TRUE_MIN},
};

static const struct l_pair hypotl_inputs[HYPOTL_CASES] = {
    {-7.0L, 2.0L}, {-5.0L, 2.0L}, {-2.0L, 0.5L}, {-1.0L, 3.0L},
    {-0.0L, 2.0L}, {0.0L, -0.0L}, {LDBL_TRUE_MIN, -LDBL_TRUE_MIN},
    {LDBL_MIN, 2.0L}, {LDBL_MAX / 2.0L, 2.0L}, {1.0L, 0.0L},
    {INFINITY, 2.0L}, {2.0L, INFINITY}, {-INFINITY, 3.0L},
    {__builtin_nanl("0x1234"), 2.0L},
    {2.0L, __builtin_nanl("0x5678")}, {1.5L, -2.25L},
};

static const long double log1pl_inputs[LOG1PL_CASES] = {
    -INFINITY, -LDBL_MAX, -8.0L, -2.0L, -1.5L, -1.0L, -0.5L,
    -LDBL_TRUE_MIN, -0.0L, 0.0L, LDBL_TRUE_MIN, LDBL_MIN, 0.25L,
    0.5L, 1.0L, 1.5L, 2.0L, 8.0L, LDBL_MAX, INFINITY,
    __builtin_nanl("0x1234"),
};

static long double (*volatile direct_fmal)(long double, long double, long double) = (fmal);
static long double (*volatile direct_hypotl)(long double, long double) = (hypotl);
static long double (*volatile direct_log1pl)(long double) = (log1pl);
static struct binary80_record binary80_records[RECORD_COUNT];

static int write_all(const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;
    while (length != 0) {
#if defined(CRABC_OWNED_STATIC_BINARY80_MATH_FREESTANDING)
        long written;
        __asm__ volatile (
            "syscall"
            : "=a" (written)
            : "a" (1), "D" (1), "S" (cursor), "d" (length)
            : "rcx", "r11", "memory"
        );
#else
        ssize_t written = write(1, cursor, length);
#endif
        if (written <= 0 || (size_t)written > length)
            return 1;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int prepare_record(int mode)
{
    return fesetround(mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0;
}

static void copy_binary80(unsigned char result[20], long double value)
{
    union { long double value; unsigned char bytes[16]; } bits = { .value = value };
    size_t index;

    for (index = 0; index < 10; index++)
        result[index] = bits.bytes[index];
    for (; index < 20; index++)
        result[index] = 0;
}

static void save_record(size_t *cursor, enum record_kind kind, size_t case_index,
    int requested_rounding, long double result)
{
    struct binary80_record *record = &binary80_records[*cursor];

    record->kind = (uint16_t)kind;
    record->case_index = (uint16_t)case_index;
    record->requested_rounding = (uint32_t)requested_rounding;
    record->observed_rounding = (uint32_t)fegetround();
    record->exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
    record->result_kind = 1;
    copy_binary80(record->result, result);
    *cursor += 1;
}

static int record_fmal(size_t *cursor, int mode, size_t index)
{
    const struct l_triple input = fmal_inputs[index];

    if (prepare_record(mode))
        return 1;
    save_record(cursor, RECORD_FMAL, index, mode,
        direct_fmal(input.first, input.second, input.third));
    return 0;
}

static int record_hypotl(size_t *cursor, int mode, size_t index)
{
    const struct l_pair input = hypotl_inputs[index];

    if (prepare_record(mode))
        return 1;
    save_record(cursor, RECORD_HYPOTL, index, mode,
        direct_hypotl(input.left, input.right));
    return 0;
}

static int record_log1pl(size_t *cursor, int mode, size_t index)
{
    if (prepare_record(mode))
        return 1;
    save_record(cursor, RECORD_LOG1PL, index, mode,
        direct_log1pl(log1pl_inputs[index]));
    return 0;
}

int main(void)
{
    size_t cursor = 0;
    size_t mode_index;
    size_t case_index;

    for (mode_index = 0; mode_index < ROUNDING_CASES; mode_index++) {
        for (case_index = 0; case_index < FMAL_CASES; case_index++)
            if (record_fmal(&cursor, rounding_modes[mode_index], case_index))
                return 1;
        for (case_index = 0; case_index < HYPOTL_CASES; case_index++)
            if (record_hypotl(&cursor, rounding_modes[mode_index], case_index))
                return 1;
        for (case_index = 0; case_index < LOG1PL_CASES; case_index++)
            if (record_log1pl(&cursor, rounding_modes[mode_index], case_index))
                return 1;
    }
    return cursor != RECORD_COUNT ||
        write_all(binary80_records, sizeof(binary80_records));
}
