/* Exact-vector test transport. All arithmetic under test crosses C ABI calls;
 * integer records and raw syscalls keep the harness independent of libc state.
 */
#include <fenv.h>
#include <math.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

struct record { uint64_t kind, mode, sticky, x[2], y[2], z[2]; };
struct result { uint64_t lo, hi, flags, mode; };
union f32 { uint32_t bits; float value; };
union f80 { uint64_t bits[2]; long double value; };
_Static_assert(sizeof(long double) == 16, "native SysV binary80 storage");
static float (*volatile call_fmaf)(float, float, float) = fmaf;
static long double (*volatile call_fmal)(long double, long double, long double) = fmal;
static long double (*volatile call_nextafterl)(long double, long double) = nextafterl;
static float (*volatile call_powf)(float, float) = powf;

static long transfer(long operation, long fd, void *buffer, unsigned long size)
{
    long value;
    __asm__ volatile("syscall" : "=a"(value) : "a"(operation), "D"(fd), "S"(buffer), "d"(size) : "rcx", "r11", "memory");
    return value;
}

int math_scalar_corrections_probe(void)
{
    struct record input;
    for (;;) {
        unsigned long offset = 0;
        while (offset < sizeof(input)) {
            long count = transfer(0, 0, (char *)&input + offset, sizeof(input) - offset);
            if (count == 0) return offset ? 91 : 0;
            if (count < 0) return 92;
            offset += count;
        }
        union f32 x = { .bits = input.x[0] }, y = { .bits = input.y[0] }, z = { .bits = input.z[0] }, f;
        union f80 lx = { .bits = { input.x[0], input.x[1] } }, ly = { .bits = { input.y[0], input.y[1] } }, lz = { .bits = { input.z[0], input.z[1] } }, l;
        struct result result = {0};
        if (fesetround(input.mode)) return 93;
        feclearexcept(FE_ALL_EXCEPT);
        if (input.sticky) feraiseexcept(input.sticky);
        if (input.kind == 0) {
            f.value = call_fmaf(x.value, y.value, z.value);
            result.lo = f.bits;
        } else if (input.kind == 1) {
            l.value = call_fmal(lx.value, ly.value, lz.value);
            result.lo = l.bits[0];
            result.hi = l.bits[1] & 0xffff;
        } else if (input.kind == 2) {
            f.value = call_powf(x.value, y.value);
            result.lo = f.bits;
        } else if (input.kind == 3) {
            l.value = call_nextafterl(lx.value, ly.value);
            result.lo = l.bits[0];
            result.hi = l.bits[1] & 0xffff;
        } else return 94;
        result.flags = fetestexcept(FE_ALL_EXCEPT);
        result.mode = fegetround();
        offset = 0;
        while (offset < sizeof(result)) {
            long count = transfer(1, 1, (char *)&result + offset, sizeof(result) - offset);
            if (count <= 0) return 95;
            offset += count;
        }
    }
}
