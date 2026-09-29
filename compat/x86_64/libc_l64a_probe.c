/* Static Linux/x86-64 l64a C ABI and behavior fixture.
 *
 * One X/Open 700 project-header C body runs through pinned musl 1.2.6 and
 * then through a selected one-member `-nostdlib -static` crabc archive. It
 * proves l64a's low-32-bit, low-to-high radix-64 encoder and its one shared
 * seven-byte static result buffer, including a second task in the same
 * address space. It leaves sibling a64l decoding and general numeric
 * conversion outside this artifact.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>
#include <stdint.h>

#ifndef CRABC_L64A_FREESTANDING
#include <errno.h>
#endif

typedef char *(*l64a_signature)(long);

_Static_assert(sizeof(long) == 8, "x86 LP64 long");
_Static_assert(__builtin_types_compatible_p(__typeof__(&l64a), l64a_signature),
    "l64a declaration");

static int text_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int check_alphabet_and_order(l64a_signature function)
{
    if (!text_equal(function(0), "")) return 1;
    if (!text_equal(function(1), "/")) return 2;
    if (!text_equal(function(2), "0") || !text_equal(function(11), "9")) return 3;
    if (!text_equal(function(12), "A") || !text_equal(function(37), "Z")) return 4;
    if (!text_equal(function(38), "a") || !text_equal(function(63), "z")) return 5;
    if (!text_equal(function(64), "./")) return 6;
    if (!text_equal(function((1L << 6) | (2L << 12) | (12L << 18) |
                             (63L << 24)), "./0Az")) return 7;
    return 0;
}

static int check_low_32_bits(l64a_signature function)
{
    if (!text_equal(function(-1L), "zzzzz1")) return 1;
    if (!text_equal(function(1L << 32), "")) return 2;
    if (!text_equal(function((1L << 32) | 64L), "./")) return 3;
    return 0;
}

static int check_shared_buffer(l64a_signature function)
{
    char *first = function(1);
    char *second;

    if (!first || !text_equal(first, "/")) return 1;
    second = function(64);
    if (!second || second != first || !text_equal(second, "./")) return 2;
    if (!text_equal(first, "./")) return 3;
    if (function(0) != first || !text_equal(first, "")) return 4;
    return 0;
}

/* Each fixed-width record preserves the LP64 input and every output byte.
 * The same body runs against pinned musl and the selected freestanding owner.
 */
struct l64a_record {
    unsigned long input;
    unsigned char output[7];
    unsigned char length;
};

_Static_assert(sizeof(struct l64a_record) == 16, "l64a record width");

static int emit_record(unsigned long input, const unsigned char output[7],
                       unsigned char length)
{
    struct l64a_record record = { input, { 0, 0, 0, 0, 0, 0, 0 }, length };
    long written;
    unsigned int index;

    for (index = 0; index < 7; ++index)
        record.output[index] = output[index];
    __asm__ volatile("syscall" : "=a"(written)
                     : "a"(1L), "D"(1L), "S"(&record), "d"(sizeof(record))
                     : "rcx", "r11", "memory");
    return written == (long)sizeof(record) ? 0 : 1;
}

static int record_value(l64a_signature function, long value)
{
    unsigned char bytes[7] = { 0, 0, 0, 0, 0, 0, 0 };
    char *result = function(value);
    unsigned int index = 0;

    if (!result)
        return 1;
    while (index < 7 && result[index]) {
        bytes[index] = (unsigned char)result[index];
        ++index;
    }
    if (index > 6 || result[index] != 0)
        return 2;
    return emit_record((unsigned long)value, bytes, (unsigned char)index);
}

static unsigned char worker_stack[65536] __attribute__((aligned(16)));
static int worker_stage;
static char *worker_result;

extern long crabc_l64a_spawn_shared_worker(void *stack_top);

void crabc_l64a_shared_worker(void)
{
    worker_result = l64a(64);
    __atomic_store_n(&worker_stage, 1, __ATOMIC_RELEASE);
}

static int check_cross_task_storage(l64a_signature function)
{
    char *main_result = function(1);
    unsigned long spins = 0;
    unsigned char outcome[7] = { 0, 0, 0, 0, 0, 0, 0 };

    if (!main_result || !text_equal(main_result, "/"))
        return 1;
    __atomic_store_n(&worker_stage, 0, __ATOMIC_RELAXED);
    if (crabc_l64a_spawn_shared_worker(worker_stack + sizeof(worker_stack)) <= 0)
        return 2;
    while (!__atomic_load_n(&worker_stage, __ATOMIC_ACQUIRE)) {
        if (++spins == 1000000000UL)
            return 3;
        __asm__ volatile("pause");
    }
    outcome[0] = worker_result == main_result;
    outcome[1] = text_equal(main_result, "./");
    if (!outcome[0] || !outcome[1])
        return 4;
    return emit_record(0xffffffffffffffffUL, outcome, 2);
}

static int check_differential(l64a_signature function)
{
    static const long boundaries[] = {
        0L, 1L, -1L, 0x7fffffffL, 0x80000000L, -2147483648L,
        0xffffffffL, 0x100000000L, 0x100000001L,
        0x7fffffffffffffffL, (-0x7fffffffffffffffL - 1L),
        -0x100000000L, -0x100000001L
    };
    unsigned int index;
    unsigned int position;

    for (index = 0; index < sizeof(boundaries) / sizeof(boundaries[0]); ++index)
        if (record_value(function, boundaries[index]))
            return 1;
    for (position = 0; position < 6; ++position) {
        for (index = 0; index < 64; ++index) {
            unsigned long value = (unsigned long)index << (position * 6);
            if (record_value(function, (long)value))
                return 2;
            if (position < 5 && record_value(function,
                    (long)(value | 0xa5a5a5a500000000UL)))
                return 3;
        }
    }
    return check_cross_task_storage(function) ? 4 : 0;
}

int crabc_x86_64_l64a_probe(void)
{
    const l64a_signature function = l64a;
    int result;

#ifndef CRABC_L64A_FREESTANDING
    errno = E2BIG;
#endif

    result = check_alphabet_and_order(function);
    if (result != 0) return result;
    result = check_low_32_bits(function);
    if (result != 0) return 10 + result;
    result = check_shared_buffer(function);
    if (result != 0) return 20 + result;
    result = check_differential(function);
    if (result != 0) return 30 + result;

#ifndef CRABC_L64A_FREESTANDING
    if (errno != E2BIG) return 40;
#endif
    return 0;
}

#ifndef CRABC_L64A_FREESTANDING
int main(void)
{
    return crabc_x86_64_l64a_probe();
}
#endif
