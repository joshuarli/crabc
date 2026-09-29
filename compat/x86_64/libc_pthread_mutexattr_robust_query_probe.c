/* Native x86-64 mutex-attribute robustness record and transition differential.
 *
 * Pinned musl and the freestanding crabc archive execute this same sequence.
 * Each line records a setter result, getter result, output value, full raw
 * attribute word, and surrounding canaries. The runner compares the raw traces.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

_Static_assert(sizeof(unsigned) == 4 && sizeof(int) == 4,
    "x86 mutexattr robust scalar widths");
_Static_assert(sizeof(pthread_mutexattr_t) == 4 && _Alignof(pthread_mutexattr_t) == 4,
    "musl x86-64 pthread_mutexattr_t ABI");
_Static_assert(__builtin_offsetof(pthread_mutexattr_t, __attr) == 0,
    "public pthread_mutexattr_t word offset");
_Static_assert(PTHREAD_MUTEX_STALLED == 0 && PTHREAD_MUTEX_ROBUST == 1,
    "musl robustness vocabulary");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutexattr_getrobust),
    int (*)(const pthread_mutexattr_t *, int *)),
    "pthread_mutexattr_getrobust declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutexattr_setrobust),
    int (*)(pthread_mutexattr_t *, int)),
    "pthread_mutexattr_setrobust declaration");

struct guarded_attribute {
    unsigned before;
    pthread_mutexattr_t attr;
    unsigned after;
};

struct guarded_result {
    unsigned before;
    int result;
    unsigned after;
};

_Static_assert(__builtin_offsetof(struct guarded_attribute, attr) == 4 &&
    sizeof(struct guarded_attribute) == 12,
    "attribute guards border exactly one public word");
_Static_assert(__builtin_offsetof(struct guarded_result, result) == 4 &&
    sizeof(struct guarded_result) == 12,
    "result guards border exactly one int");

/* The candidate has no CRT or stdio; one direct Linux write keeps both traces
 * byte-identical without selecting another libc entry point. */
static void write_trace(const char *text, unsigned length)
{
    long written;

    __asm__ __volatile__("syscall" : "=a"(written) : "0"(1L), "D"(1L),
        "S"(text), "d"((unsigned long)length) : "rcx", "r11", "memory");
    (void)written;
}

static void put_hex(char *destination, unsigned value)
{
    static const char digits[] = "0123456789abcdef";
    unsigned index;

    for (index = 0; index != 8; ++index)
        destination[index] = digits[(value >> (28 - 4 * index)) & 15U];
}

static int step(unsigned ordinal, struct guarded_attribute *attribute,
    int set, int value)
{
    struct guarded_result output = { 0x87654321U, 0x5a5a5a5a, 0x12345678U };
    int set_result = set ? pthread_mutexattr_setrobust(&attribute->attr, value) : 0;
    int get_result = pthread_mutexattr_getrobust(&attribute->attr, &output.result);
    char line[81];

    put_hex(line, ordinal);
    line[8] = ' ';
    put_hex(line + 9, (unsigned)set_result);
    line[17] = ' ';
    put_hex(line + 18, (unsigned)get_result);
    line[26] = ' ';
    put_hex(line + 27, (unsigned)output.result);
    line[35] = ' ';
    put_hex(line + 36, attribute->attr.__attr);
    line[44] = ' ';
    put_hex(line + 45, attribute->before);
    line[53] = ' ';
    put_hex(line + 54, attribute->after);
    line[62] = ' ';
    put_hex(line + 63, output.before);
    line[71] = ' ';
    put_hex(line + 72, output.after);
    line[80] = '\n';
    write_trace(line, sizeof line);

    if (attribute->before != 0x13579bdfU || attribute->after != 0x2468ace0U ||
        output.before != 0x87654321U || output.after != 0x12345678U)
        return 1;
    return 0;
}

int crabc_x86_64_pthread_mutexattr_robust_query_probe(void)
{
    struct guarded_attribute attribute = { 0x13579bdfU, { 0U }, 0x2468ace0U };
    unsigned ordinal = 0;
    int failed = 0;

#define STEP(set, value) (failed |= step(++ordinal, &attribute, (set), (value)))
    STEP(0, 0);
    STEP(1, PTHREAD_MUTEX_ROBUST);
    STEP(1, 2);
    STEP(1, -1);
    STEP(1, PTHREAD_MUTEX_STALLED);
    STEP(1, 0x7fffffff);
    STEP(1, PTHREAD_MUTEX_ROBUST);
    STEP(1, (-0x7fffffff - 1));
    STEP(1, PTHREAD_MUTEX_ROBUST);
    STEP(1, PTHREAD_MUTEX_STALLED);

    attribute.attr.__attr = 0xfffffffbU;
    STEP(0, 0);
    STEP(1, PTHREAD_MUTEX_ROBUST);
    STEP(1, 2);
    STEP(1, PTHREAD_MUTEX_STALLED);

    attribute.attr.__attr = 0xfffffff4U;
    STEP(0, 0);
    STEP(1, PTHREAD_MUTEX_ROBUST);
    STEP(1, -1);
    STEP(1, PTHREAD_MUTEX_STALLED);
#undef STEP

    return failed;
}

#if !defined(CRABC_PTHREAD_MUTEXATTR_ROBUST_QUERY_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_mutexattr_robust_query_probe();
}
#endif
