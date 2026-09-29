/* Exact selected rand48 transitions against pinned musl's public C ABI. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "requires native Linux/x86-64 LP64"
#endif
#ifndef CRABC_LRAND48_FREESTANDING
#include <errno.h>
#endif
#include <lrand48.h>
#include <stdint.h>

typedef long (*long0)(void);
typedef long (*long1)(unsigned short *);
typedef double (*double0)(void);
typedef double (*double1)(unsigned short *);
typedef void (*void1s)(unsigned short *);
typedef void (*void1l)(long);
typedef unsigned short *(*seed1)(unsigned short *);
_Static_assert(__builtin_types_compatible_p(__typeof__(&lrand48), long0), "lrand48 ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nrand48), long1), "nrand48 ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&drand48), double0), "drand48 ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&erand48), double1), "erand48 ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&seed48), seed1), "seed48 ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&srand48), void1l), "srand48 ABI");
_Static_assert(sizeof(long) == 8, "LP64 long");

static uint64_t trace[96];
static unsigned trace_len;
static void record(uint64_t value) { trace[trace_len++] = value; }
static uint64_t words(const unsigned short x[3]) {
 return x[0] | ((uint64_t)x[1] << 16) | ((uint64_t)x[2] << 32);
}
static uint64_t next(unsigned short x[3], const unsigned short p[4]) {
 uint64_t v = words(x);
 uint64_t a = words(p);
 v = a * v + p[3];
 x[0] = v; x[1] = v >> 16; x[2] = v >> 32;
 return v & 0xffffffffffffULL;
}
static uint64_t bits(double value) {
 union { double d; uint64_t u; } repr = { .d = value };
 return repr.u;
}
static uint64_t fraction(uint64_t value) {
 union { double d; uint64_t u; } repr = { .u = 0x3ff0000000000000ULL | (value << 4) };
 return bits(repr.d - 1.0);
}
static int same3(const unsigned short a[3], const unsigned short b[3]) {
 return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
}
static int emit_trace(void) {
 const unsigned char *data = (const unsigned char *)trace;
 unsigned long count = trace_len * sizeof(trace[0]);
 long written;
 /* This fixture's direct write is independent of either libc's output API. */
 __asm__ volatile("syscall" : "=a"(written) : "a"(1L), "D"(1L), "S"(data), "d"(count) : "rcx", "r11", "memory");
 return written == (long)count ? 0 : 90;
}
#define CHECK_LONG(api, expected, code) do { \
 long got = (api); record((uint64_t)got); \
 if (got != (expected)) return (code); \
} while (0)
#define CHECK_DOUBLE(api, expected, code) do { \
 uint64_t got = bits(api); record(got); \
 if (got != (expected)) return (code); \
} while (0)
#define CHECK_STATE(actual, expected, code) do { \
 record(words(actual)); if (!same3((actual), (expected))) return (code); \
} while (0)

int crabc_x86_64_lrand48_probe(void) {
 unsigned short model[7] = {0, 0, 0, 0xe66d, 0xdeec, 5, 0xb};
 unsigned short caller[3] = {0, 0, 0}, caller_model[3] = {0, 0, 0};
 unsigned short fresh[3] = {0x1234, 0x5678, 0x9abc};
 unsigned short fresh_expected[3] = {0x1234, 0x5678, 0x9abc};
 unsigned short second[3] = {4, 5, 6}, second_expected[3] = {4, 5, 6}, before[3];
 unsigned short custom[7] = {7, 8, 9, 3, 0, 0, 1};
 unsigned short *old, *again;
 uint64_t value;
#ifndef CRABC_LRAND48_FREESTANDING
 errno = E2BIG;
#endif
 /* Default state, then a seed reset and interleaved caller-owned state. */
 value = next(model, model + 3);
 CHECK_LONG(lrand48(), (long)(value >> 17), 1);
 value = next(model, model + 3);
 CHECK_DOUBLE(drand48(), fraction(value), 2);
 srand48(1); model[0] = 0x330e; model[1] = 1; model[2] = 0;
 value = next(model, model + 3);
 CHECK_LONG(lrand48(), (long)(value >> 17), 3);
 value = next(caller_model, model + 3);
 CHECK_LONG(nrand48(caller), (long)(value >> 17), 4);
 CHECK_STATE(caller, caller_model, 5);
 value = next(caller_model, model + 3);
 CHECK_DOUBLE(erand48(caller), fraction(value), 6);
 CHECK_STATE(caller, caller_model, 7);
 value = next(model, model + 3);
 CHECK_DOUBLE(drand48(), fraction(value), 8);
 value = next(model, model + 3);
 CHECK_LONG(mrand48(), (long)(int32_t)(value >> 16), 9);
 value = next(caller_model, model + 3);
 CHECK_LONG(jrand48(caller), (long)(int32_t)(value >> 16), 10);
 CHECK_STATE(caller, caller_model, 11);
 /* seed48 returns the old global seed in a reused buffer; caller words stay owned. */
 for (int i = 0; i < 3; i++) before[i] = model[i];
 old = seed48(fresh);
 CHECK_STATE(old, before, 12);
 old[0] ^= 0xffff;
 CHECK_STATE(fresh, fresh_expected, 13);
 for (int i = 0; i < 3; i++) model[i] = fresh[i];
 value = next(model, model + 3);
 CHECK_LONG(lrand48(), (long)(value >> 17), 14);
 again = seed48(second);
 if (again != old) return 15;
 CHECK_STATE(again, model, 16);
 CHECK_STATE(second, second_expected, 24);
 for (int i = 0; i < 3; i++) model[i] = second[i];
 value = next(model, model + 3);
 CHECK_DOUBLE(drand48(), fraction(value), 17);
 /* Changed parameters affect caller state too; seed setters preserve them. */
 lcong48(custom);
 for (int i = 0; i < 7; i++) model[i] = custom[i];
 value = next(caller_model, model + 3);
 CHECK_LONG(nrand48(caller), (long)(value >> 17), 18);
 CHECK_STATE(caller, caller_model, 19);
 srand48(-1); model[0] = 0x330e; model[1] = 0xffff; model[2] = 0xffff;
 value = next(model, model + 3);
 CHECK_LONG(lrand48(), (long)(value >> 17), 20);
 value = next(caller_model, model + 3);
 CHECK_DOUBLE(erand48(caller), fraction(value), 21);
 CHECK_STATE(caller, caller_model, 22);
#ifndef CRABC_LRAND48_FREESTANDING
 if (errno != E2BIG) return 23;
#endif
 return emit_trace();
}
#ifndef CRABC_LRAND48_FREESTANDING
int main(void) { return crabc_x86_64_lrand48_probe(); }
#endif
