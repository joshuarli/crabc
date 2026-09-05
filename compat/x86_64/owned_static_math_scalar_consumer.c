/*
 * Installed Linux/x86-64 scalar-math differential consumer.
 *
 * The same raw-bit record stream is produced once by pinned musl 1.2.6 and
 * again by the supplied sealed crabc static driver.  It deliberately calls
 * only the binary32/binary64 scalar completion: fma/fmaf, hypot/hypotf, and
 * log1p/log1pf.  Every case runs under all four MXCSR directions and records
 * both the result representation and IEEE exception state.  The fmal,
 * hypotl, and log1pl binary80 ABI is intentionally absent.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this consumer requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#if !defined(CRABC_MATH_SCALAR_COMPLETION_FREESTANDING)
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

enum {
    FMA64_CASES = 12,
    FMA32_CASES = 12,
    HYPOT64_CASES = 12,
    HYPOT32_CASES = 12,
    LOG1P64_CASES = 14,
    LOG1P32_CASES = 14,
    ROUNDING_CASES = 4,
    RECORD_COUNT = ROUNDING_CASES * (FMA64_CASES + FMA32_CASES +
        HYPOT64_CASES + HYPOT32_CASES + LOG1P64_CASES + LOG1P32_CASES),
};

enum record_kind {
    RECORD_FMA64 = 1,
    RECORD_FMA32 = 2,
    RECORD_HYPOT64 = 3,
    RECORD_HYPOT32 = 4,
    RECORD_LOG1P64 = 5,
    RECORD_LOG1P32 = 6,
};

struct triple64 { uint64_t x, y, z; };
struct triple32 { uint32_t x, y, z; };
struct pair64 { uint64_t x, y; };
struct pair32 { uint32_t x, y; };

struct scalar_record {
    uint64_t kind;
    uint64_t x;
    uint64_t y;
    uint64_t z;
    uint64_t result;
    uint64_t rounding;
    uint64_t exceptions;
};

_Static_assert(sizeof(struct scalar_record) == 56,
    "raw scalar record ABI");

static const struct triple64 fma64_inputs[FMA64_CASES] = {
    { UINT64_C(0x3ff0000000000000), UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000) },
    { UINT64_C(0x8000000000000000), UINT64_C(0x4000000000000000), UINT64_C(0x0000000000000000) },
    { UINT64_C(0x3ff0000000000001), UINT64_C(0x3ff0000000000001), UINT64_C(0xbff0000000000002) },
    { UINT64_C(0x3ff0000000000001), UINT64_C(0x3ff0000000000001), UINT64_C(0xbff0000000000001) },
    { UINT64_C(0x0010000000000000), UINT64_C(0x3fe0000000000000), UINT64_C(0x0000000000000001) },
    { UINT64_C(0x0000000000000001), UINT64_C(0x3ff0000000000000), UINT64_C(0x8000000000000001) },
    { UINT64_C(0x7fefffffffffffff), UINT64_C(0x4000000000000000), UINT64_C(0xffefffffffffffff) },
    { UINT64_C(0x7fefffffffffffff), UINT64_C(0x3ff0000000000000), UINT64_C(0xffefffffffffffff) },
    { UINT64_C(0x7ff0000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x3ff0000000000000) },
    { UINT64_C(0x7ff0000000000000), UINT64_C(0x3ff0000000000000), UINT64_C(0xfff0000000000000) },
    { UINT64_C(0x7ff8000000000041), UINT64_C(0x3ff0000000000000), UINT64_C(0x3ff0000000000000) },
    { UINT64_C(0x7ff0000000000042), UINT64_C(0x3ff0000000000000), UINT64_C(0x3ff0000000000000) },
};

static const struct triple32 fma32_inputs[FMA32_CASES] = {
    { UINT32_C(0x3f800000), UINT32_C(0x3f800000), UINT32_C(0xbf800000) },
    { UINT32_C(0x80000000), UINT32_C(0x40000000), UINT32_C(0x00000000) },
    { UINT32_C(0x3f800001), UINT32_C(0x3f800001), UINT32_C(0xbf800002) },
    { UINT32_C(0x3f800001), UINT32_C(0x3f800001), UINT32_C(0xbf800001) },
    { UINT32_C(0x00800000), UINT32_C(0x3f000000), UINT32_C(0x00000001) },
    { UINT32_C(0x00000001), UINT32_C(0x3f800000), UINT32_C(0x80000001) },
    { UINT32_C(0x7f7fffff), UINT32_C(0x40000000), UINT32_C(0xff7fffff) },
    { UINT32_C(0x7f7fffff), UINT32_C(0x3f800000), UINT32_C(0xff7fffff) },
    { UINT32_C(0x7f800000), UINT32_C(0x00000000), UINT32_C(0x3f800000) },
    { UINT32_C(0x7f800000), UINT32_C(0x3f800000), UINT32_C(0xff800000) },
    { UINT32_C(0x7fc00041), UINT32_C(0x3f800000), UINT32_C(0x3f800000) },
    { UINT32_C(0x7f800042), UINT32_C(0x3f800000), UINT32_C(0x3f800000) },
};

static const struct pair64 hypot64_inputs[HYPOT64_CASES] = {
    { UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000) },
    { UINT64_C(0x4008000000000000), UINT64_C(0x4010000000000000) },
    { UINT64_C(0x7fefffffffffffff), UINT64_C(0x7fefffffffffffff) },
    { UINT64_C(0x0010000000000000), UINT64_C(0x0010000000000000) },
    { UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001) },
    { UINT64_C(0x7fe0000000000000), UINT64_C(0x0010000000000000) },
    { UINT64_C(0x3ff0000000000000), UINT64_C(0x3bf0000000000000) },
    { UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff8000000000041) },
    { UINT64_C(0x7ff8000000000041), UINT64_C(0x3ff0000000000000) },
    { UINT64_C(0x7ff0000000000042), UINT64_C(0x3ff0000000000000) },
    { UINT64_C(0xbff0000000000000), UINT64_C(0x4000000000000000) },
    { UINT64_C(0x4340000000000000), UINT64_C(0x3ff0000000000000) },
};

static const struct pair32 hypot32_inputs[HYPOT32_CASES] = {
    { UINT32_C(0x00000000), UINT32_C(0x80000000) },
    { UINT32_C(0x40400000), UINT32_C(0x40800000) },
    { UINT32_C(0x7f7fffff), UINT32_C(0x7f7fffff) },
    { UINT32_C(0x00800000), UINT32_C(0x00800000) },
    { UINT32_C(0x00000001), UINT32_C(0x00000001) },
    { UINT32_C(0x7f000000), UINT32_C(0x00800000) },
    { UINT32_C(0x3f800000), UINT32_C(0x33800000) },
    { UINT32_C(0x7f800000), UINT32_C(0x7fc00041) },
    { UINT32_C(0x7fc00041), UINT32_C(0x3f800000) },
    { UINT32_C(0x7f800042), UINT32_C(0x3f800000) },
    { UINT32_C(0xbf800000), UINT32_C(0x40000000) },
    { UINT32_C(0x5a000000), UINT32_C(0x3f800000) },
};

static const uint64_t log1p64_inputs[LOG1P64_CASES] = {
    UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
    UINT64_C(0x0000000000000001), UINT64_C(0x8000000000000001),
    UINT64_C(0x3ca0000000000000), UINT64_C(0x3fd62e4200000000),
    UINT64_C(0xbfd2bec400000000), UINT64_C(0xbff0000000000000),
    UINT64_C(0xbff0000000000001), UINT64_C(0x3ff0000000000000),
    UINT64_C(0x4340000000000000), UINT64_C(0x7ff0000000000000),
    UINT64_C(0x7ff8000000000041), UINT64_C(0x7ff0000000000042),
};

static const uint32_t log1p32_inputs[LOG1P32_CASES] = {
    UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
    UINT32_C(0x80000001), UINT32_C(0x33800000), UINT32_C(0x3ed413d0),
    UINT32_C(0xbe95f619), UINT32_C(0xbf800000), UINT32_C(0xbf800001),
    UINT32_C(0x3f800000), UINT32_C(0x4b800000), UINT32_C(0x7f800000),
    UINT32_C(0x7fc00041), UINT32_C(0x7f800042),
};

static const int rounding_modes[ROUNDING_CASES] = {
    FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static double (*volatile direct_fma)(double, double, double) = (fma);
static float (*volatile direct_fmaf)(float, float, float) = (fmaf);
static double (*volatile direct_hypot)(double, double) = (hypot);
static float (*volatile direct_hypotf)(float, float) = (hypotf);
static double (*volatile direct_log1p)(double) = (log1p);
static float (*volatile direct_log1pf)(float) = (log1pf);
static struct scalar_record scalar_records[RECORD_COUNT];

static double double_from_bits(uint64_t bits)
{
    union { uint64_t bits; double value; } view = { .bits = bits };
    return view.value;
}

static float float_from_bits(uint32_t bits)
{
    union { uint32_t bits; float value; } view = { .bits = bits };
    return view.value;
}

static uint64_t double_bits(double value)
{
    union { uint64_t bits; double value; } view = { .value = value };
    return view.bits;
}

static uint32_t float_bits(float value)
{
    union { uint32_t bits; float value; } view = { .value = value };
    return view.bits;
}

static int prepare_record(int mode)
{
    return fesetround(mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0;
}

static void save_record(size_t *cursor, enum record_kind kind, uint64_t x,
    uint64_t y, uint64_t z, uint64_t result, int requested_mode)
{
    struct scalar_record *record = &scalar_records[*cursor];

    record->kind = (uint64_t)kind;
    record->x = x;
    record->y = y;
    record->z = z;
    record->result = result;
    record->rounding = ((uint64_t)(uint32_t)requested_mode << 32) |
        (uint32_t)fegetround();
    record->exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
    *cursor += 1;
}

static int record_fma64(size_t *cursor, int mode, struct triple64 input)
{
    double result;

    if (prepare_record(mode))
        return 1;
    result = direct_fma(double_from_bits(input.x), double_from_bits(input.y),
        double_from_bits(input.z));
    save_record(cursor, RECORD_FMA64, input.x, input.y, input.z,
        double_bits(result), mode);
    return 0;
}

static int record_fma32(size_t *cursor, int mode, struct triple32 input)
{
    float result;

    if (prepare_record(mode))
        return 1;
    result = direct_fmaf(float_from_bits(input.x), float_from_bits(input.y),
        float_from_bits(input.z));
    save_record(cursor, RECORD_FMA32, input.x, input.y, input.z,
        float_bits(result), mode);
    return 0;
}

static int record_hypot64(size_t *cursor, int mode, struct pair64 input)
{
    double result;

    if (prepare_record(mode))
        return 1;
    result = direct_hypot(double_from_bits(input.x), double_from_bits(input.y));
    save_record(cursor, RECORD_HYPOT64, input.x, input.y, 0,
        double_bits(result), mode);
    return 0;
}

static int record_hypot32(size_t *cursor, int mode, struct pair32 input)
{
    float result;

    if (prepare_record(mode))
        return 1;
    result = direct_hypotf(float_from_bits(input.x), float_from_bits(input.y));
    save_record(cursor, RECORD_HYPOT32, input.x, input.y, 0,
        float_bits(result), mode);
    return 0;
}

static int record_log1p64(size_t *cursor, int mode, uint64_t input)
{
    double result;

    if (prepare_record(mode))
        return 1;
    result = direct_log1p(double_from_bits(input));
    save_record(cursor, RECORD_LOG1P64, input, 0, 0, double_bits(result), mode);
    return 0;
}

static int record_log1p32(size_t *cursor, int mode, uint32_t input)
{
    float result;

    if (prepare_record(mode))
        return 1;
    result = direct_log1pf(float_from_bits(input));
    save_record(cursor, RECORD_LOG1P32, input, 0, 0, float_bits(result), mode);
    return 0;
}

static int write_all(const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;

    while (length != 0) {
#if defined(CRABC_MATH_SCALAR_COMPLETION_FREESTANDING)
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

        if (written <= 0)
            return 1;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

int main(void)
{
    fenv_t original;
    size_t cursor = 0;
    size_t index;
    size_t mode_index;
    int status = 0;

    if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
        return 1;
    for (mode_index = 0; mode_index < ROUNDING_CASES && status == 0;
        ++mode_index) {
        int mode = rounding_modes[mode_index];

        for (index = 0; index < FMA64_CASES && status == 0; ++index)
            status = record_fma64(&cursor, mode, fma64_inputs[index]);
        for (index = 0; index < FMA32_CASES && status == 0; ++index)
            status = record_fma32(&cursor, mode, fma32_inputs[index]);
        for (index = 0; index < HYPOT64_CASES && status == 0; ++index)
            status = record_hypot64(&cursor, mode, hypot64_inputs[index]);
        for (index = 0; index < HYPOT32_CASES && status == 0; ++index)
            status = record_hypot32(&cursor, mode, hypot32_inputs[index]);
        for (index = 0; index < LOG1P64_CASES && status == 0; ++index)
            status = record_log1p64(&cursor, mode, log1p64_inputs[index]);
        for (index = 0; index < LOG1P32_CASES && status == 0; ++index)
            status = record_log1p32(&cursor, mode, log1p32_inputs[index]);
    }
    if (cursor != RECORD_COUNT && status == 0)
        status = 2;
    if (fesetenv(&original) != 0 && status == 0)
        status = 3;
    if (status != 0)
        return status;
    return write_all(scalar_records, sizeof(scalar_records));
}
