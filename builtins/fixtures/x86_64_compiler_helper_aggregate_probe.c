/*
 * Finite native x86-64 compiler-helper aggregate ABI probe.
 *
 * The candidate object names every reviewed helper directly.  The reference
 * object uses ordinary C arithmetic, checked-overflow builtins, and defined
 * unsigned loops instead; it is a distinct compiler/musl oracle object, never
 * a same-object claim.  The two-word `unsigned __int128` carrier crosses the
 * System V AMD64 ABI by value; the Rust source owns its corresponding
 * low-word/high-word `Uint128` representation.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this private compiler-helper fixture requires Linux x86-64 LP64"
#endif

typedef unsigned __int128 u128;
typedef __int128 i128;
typedef double _Complex complex_double;

typedef u128 (*binary_u128)(u128, u128);
typedef u128 (*shift_u128)(u128, int);
typedef int (*count_u128)(u128);

#ifdef CRABC_HELPER_REFERENCE
static u128 ref_multi3(u128 a, u128 b) { return a * b; }
static complex_double ref_muldc3(double a, double b, double c, double d) {
    return __builtin_complex(a * c - b * d, a * d + b * c);
}
static u128 ref_udivti3(u128 a, u128 b) { return a / b; }
static u128 ref_umodti3(u128 a, u128 b) { return a % b; }
static u128 ref_udivmodti4(u128 a, u128 b, u128 *r) { *r = a % b; return a / b; }
static i128 ref_divti3(i128 a, i128 b) { return a / b; }
static i128 ref_modti3(i128 a, i128 b) { return a % b; }
static i128 ref_divmodti4(i128 a, i128 b, i128 *r) { *r = a % b; return a / b; }
static u128 ref_ashlti3(u128 v, int s) { return s < 0 || s >= 128 ? 0 : v << (unsigned)s; }
static u128 ref_lshrti3(u128 v, int s) { return s < 0 || s >= 128 ? 0 : v >> (unsigned)s; }
static u128 ref_ashrti3(i128 v, int s) { return s < 0 || s >= 128 ? (v < 0 ? (u128)-1 : 0) : (u128)(v >> (unsigned)s); }
static int ref_clzti2(u128 v) { int n = 0; if (!v) return 128; while (!(v & ((u128)1 << 127))) { ++n; v <<= 1; } return n; }
static int ref_ctzti2(u128 v) { int n = 0; if (!v) return 128; while (!(v & 1)) { ++n; v >>= 1; } return n; }
static int ref_ffsti2(u128 v) { return v ? ref_ctzti2(v) + 1 : 0; }
static int ref_popcountti2(u128 v) { int n = 0; while (v) { n += (int)(v & 1); v >>= 1; } return n; }
static int ref_popcountdi2(unsigned long v) { int n = 0; while (v) { n += (int)(v & 1); v >>= 1; } return n; }
static int ref_parityti2(u128 v) { return ref_popcountti2(v) & 1; }
static unsigned ref_bswapsi2(unsigned v) { return (v >> 24) | ((v >> 8) & 0xff00U) | ((v << 8) & 0xff0000U) | (v << 24); }
static unsigned long ref_bswapdi2(unsigned long v) {
    unsigned long r = 0; int i; for (i = 0; i < 8; ++i) { r = (r << 8) | (v & 0xffUL); v >>= 8; } return r;
}
static u128 ref_bswapti2(u128 v) { return ((u128)ref_bswapdi2((unsigned long)(v >> 64))) | ((u128)ref_bswapdi2((unsigned long)v) << 64); }
static i128 ref_addoti4(i128 a, i128 b, int *o) { i128 r; *o = __builtin_add_overflow(a, b, &r); return r; }
static i128 ref_suboti4(i128 a, i128 b, int *o) { i128 r; *o = __builtin_sub_overflow(a, b, &r); return r; }
static i128 ref_muloti4(i128 a, i128 b, int *o) { i128 r; *o = __builtin_mul_overflow(a, b, &r); return r; }
#define CALL_BINARY(name) ref_ ## name
#define CALL_SHIFT(name) ref_ ## name
#define CALL_COUNT(name) ref_ ## name
#define CALL_POPCOUNTDI2 ref_popcountdi2
#define CALL_BSWAPSI2 ref_bswapsi2
#define CALL_BSWAPDI2 ref_bswapdi2
#define CALL_BSWAPTI2 ref_bswapti2
#define CALL_ADDOTI4 ref_addoti4
#define CALL_SUBOTI4 ref_suboti4
#define CALL_MULOTI4 ref_muloti4
#else
extern u128 __multi3(u128, u128);
extern complex_double __muldc3(double, double, double, double);
extern u128 __udivti3(u128, u128);
extern u128 __umodti3(u128, u128);
extern u128 __udivmodti4(u128, u128, u128 *);
extern i128 __divti3(i128, i128);
extern i128 __modti3(i128, i128);
extern i128 __divmodti4(i128, i128, i128 *);
extern u128 __ashlti3(u128, int);
extern u128 __lshrti3(u128, int);
extern u128 __ashrti3(i128, int);
extern int __clzti2(u128);
extern int __ctzti2(u128);
extern int __ffsti2(u128);
extern int __popcountti2(u128);
extern int __popcountdi2(unsigned long);
extern int __parityti2(u128);
extern unsigned __bswapsi2(unsigned);
extern unsigned long __bswapdi2(unsigned long);
extern u128 __bswapti2(u128);
extern i128 __addoti4(i128, i128, int *);
extern i128 __suboti4(i128, i128, int *);
extern i128 __muloti4(i128, i128, int *);
#define CALL_BINARY(name) __ ## name
#define CALL_SHIFT(name) __ ## name
#define CALL_COUNT(name) __ ## name
#define CALL_POPCOUNTDI2 __popcountdi2
#define CALL_BSWAPSI2 __bswapsi2
#define CALL_BSWAPDI2 __bswapdi2
#define CALL_BSWAPTI2 __bswapti2
#define CALL_ADDOTI4 __addoti4
#define CALL_SUBOTI4 __suboti4
#define CALL_MULOTI4 __muloti4
#endif

static int equal_complex(complex_double value, double real, double imaginary) {
    return __real__ value == real && __imag__ value == imaginary;
}

int crabc_x86_64_compiler_helper_aggregate_probe(void) {
    const u128 one = 1;
    const u128 word = one << 64;
    const u128 pattern = ((u128)0x0123456789abcdefUL << 64) | 0xfedcba9876543210UL;
    const i128 high = (i128)one << 100;
    const i128 maximum = (i128)(((u128)one << 127) - 1);
    const i128 minimum = -maximum - 1;
    u128 remainder;
    i128 signed_remainder;
    int overflow;

    if (CALL_BINARY(multi3)(3, 5) != 15) return 1;
    if (!equal_complex(CALL_BINARY(muldc3)(2.0, 3.0, 4.0, -1.0), 11.0, 10.0)) return 2;
    if (CALL_BINARY(udivti3)(word + 9, 7) != (word + 9) / 7) return 3;
    if (CALL_BINARY(umodti3)(word + 9, 7) != (word + 9) % 7) return 4;
    if (CALL_BINARY(udivmodti4)(word + 9, 7, &remainder) != (word + 9) / 7 || remainder != (word + 9) % 7) return 5;
    if (CALL_BINARY(divti3)(-high - 5, 16) != -((i128)one << 96)) return 6;
    if (CALL_BINARY(modti3)(-high - 5, 16) != -5) return 7;
    if (CALL_BINARY(divmodti4)(-high - 5, 16, &signed_remainder) != -((i128)one << 96) || signed_remainder != -5) return 8;
    if (CALL_SHIFT(ashlti3)(one, 64) != word || CALL_SHIFT(ashlti3)(one, -1) != 0) return 9;
    if (CALL_SHIFT(lshrti3)(word, 64) != one || CALL_SHIFT(lshrti3)(word, 128) != 0) return 10;
    if (CALL_SHIFT(ashrti3)(-word, 64) != (u128)-1 || CALL_SHIFT(ashrti3)(-word, 128) != (u128)-1) return 11;
    if (CALL_COUNT(clzti2)(one) != 127 || CALL_COUNT(ctzti2)(word) != 64 || CALL_COUNT(ffsti2)(word) != 65) return 12;
    if (CALL_COUNT(popcountti2)(pattern) != 64 || CALL_POPCOUNTDI2(0xfedcba9876543210UL) != 32 || CALL_COUNT(parityti2)(pattern) != 0) return 13;
    if (CALL_BSWAPSI2(0x01234567U) != 0x67452301U || CALL_BSWAPDI2(0x0123456789abcdefUL) != 0xefcdab8967452301UL) return 14;
    if (CALL_BSWAPTI2(pattern) != (((u128)0x1032547698badcfeUL << 64) | 0xefcdab8967452301UL)) return 15;
    if (CALL_ADDOTI4(maximum, 1, &overflow) != minimum || overflow != 1) return 16;
    if (CALL_SUBOTI4(minimum, 1, &overflow) != maximum || overflow != 1) return 17;
    if (CALL_MULOTI4(maximum, 2, &overflow) != -2 || overflow != 1) return 18;
    return 0;
}

#ifndef CRABC_BUILTINS_FREESTANDING
extern long write(int, const void *, unsigned long);
int main(void) {
    static const char transcript[] = "compiler-helper-aggregate-ok\n";
    int status = crabc_x86_64_compiler_helper_aggregate_probe();
    if (status == 0 && write(1, transcript, sizeof(transcript) - 1) != (long)(sizeof(transcript) - 1)) return 127;
    return status;
}
#endif
