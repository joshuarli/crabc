/* Pinned-musl/x86 static BSD random-state differential fixture. */

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <stdlib.h>

typedef long (*random_signature)(void);
typedef void (*srandom_signature)(unsigned);
typedef char *(*initstate_signature)(unsigned, char *, size_t);
typedef char *(*setstate_signature)(char *);

_Static_assert(sizeof(unsigned) == 4, "BSD random seed word");
_Static_assert(sizeof(long) == 8, "BSD random return word");
_Static_assert(__builtin_types_compatible_p(__typeof__(&random), random_signature),
    "random declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&srandom), srandom_signature),
    "srandom declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&initstate), initstate_signature),
    "initstate declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setstate), setstate_signature),
    "setstate declaration");

union state_buffer {
    unsigned long alignment;
    unsigned char bytes[272];
};

/* `_start` writes this exact trace after `crabc_x86_64_bsd_random_probe`.
 * It contains no process addresses, so the pinned-musl and extracted-provider
 * executions can compare it byte-for-byte. */
uint32_t crabc_x86_64_bsd_random_trace[1024];

static unsigned trace_count;
static int trace_overflow;

static void record(unsigned long value)
{
    if (trace_count < sizeof(crabc_x86_64_bsd_random_trace) /
                          sizeof(crabc_x86_64_bsd_random_trace[0]))
        crabc_x86_64_bsd_random_trace[trace_count++] = (uint32_t)value;
    else
        trace_overflow = 1;
}

static void clear_state(union state_buffer *state)
{
    size_t index;

    for (index = 0; index < sizeof(state->bytes); index++)
        state->bytes[index] = 0;
}

static int record_stream(unsigned count)
{
    unsigned index;

    for (index = 0; index < count; index++) {
        long value = random();
        if (value < 0 || value > 0x7fffffffL)
            return 1;
        record((unsigned long)value);
        if (trace_overflow)
            return 2;
    }
    return 0;
}

int crabc_x86_64_bsd_random_probe(void)
{
    static const size_t sizes[] = { 8, 31, 32, 63, 64, 127, 128, 255, 256, 272 };
    union state_buffer first;
    union state_buffer second;
    union state_buffer boundary;
    random_signature next = random;
    srandom_signature seed = srandom;
    initstate_signature initialize = initstate;
    setstate_signature switch_state = setstate;
    char *first_state;
    char *second_state;
    char *default_state = NULL;
    char *returned;
    long preserved;
    size_t index;

    /* Default storage begins at musl's fixed initialized state. */
    if (record_stream(4) != 0)
        return 1;
    seed(0U);
    if (record_stream(4) != 0)
        return 2;
    seed(1U);
    if (record_stream(4) != 0)
        return 3;
    seed(0x80000000U);
    if (record_stream(4) != 0)
        return 4;
    seed(0xffffffffU);
    if (record_stream(4) != 0)
        return 5;

    /* `size < 8` is the only source-defined initstate error. Every boundary
     * through seven leaves active state alone; the installed test additionally
     * checks that it leaves errno untouched. */
    for (index = 0; index < 8; index++) {
        seed(0x13579bdfU);
        preserved = next();
        seed(0x13579bdfU);
        if (initialize(7U, boundary.bytes, index) != NULL)
            return 6;
        if (next() != preserved)
            return 7;
        record((unsigned long)preserved);
    }

    for (index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++) {
        clear_state(&boundary);
        returned = initialize((unsigned)(0x10203040U + index), boundary.bytes, sizes[index]);
        if (returned == NULL)
            return 8;
        if (index == 0)
            default_state = returned;
        /* initstate saves source n/i/j in the leading state word. */
        record((unsigned long)((uint32_t *)boundary.bytes)[0]);
        /* Every ring class crosses its n-word wrap boundary twice. */
        if (record_stream(sizes[index] < 32 ? 2U :
                          sizes[index] < 64 ? 16U :
                          sizes[index] < 128 ? 32U :
                          sizes[index] < 256 ? 64U : 128U) != 0)
            return 9;
    }

    clear_state(&first);
    clear_state(&second);
    (void)initialize(0x2468ace0U, first.bytes, 256);
    first_state = first.bytes;
    if (record_stream(130) != 0)
        return 10;
    returned = initialize(0x89abcdefU, second.bytes, 64);
    second_state = second.bytes;
    if (returned != first_state)
        return 11;
    if (record_stream(34) != 0)
        return 12;
    returned = switch_state(first_state);
    if (returned != second_state)
        return 13;
    if (record_stream(130) != 0)
        return 14;
    returned = switch_state(returned);
    if (returned != first_state)
        return 15;
    if (record_stream(34) != 0)
        return 16;

    /* Saving before loading makes setstate(active_state) return itself. */
    returned = switch_state(second_state);
    if (returned != second_state)
        return 17;
    if (record_stream(34) != 0)
        return 18;
    /* No automatic state lifetime exists: restore the original static state
     * before the three automatic buffers become invalid on return. */
    returned = switch_state(default_state);
    if (returned != second_state)
        return 19;
    if (trace_overflow)
        return 20;
    record(trace_count);
    return trace_overflow ? 21 : 0;
}

#ifndef CRABC_BSD_RANDOM_FREESTANDING
#include <unistd.h>

int main(void)
{
    int result = crabc_x86_64_bsd_random_probe();

    if (result != 0)
        return result;
    return write(1, crabc_x86_64_bsd_random_trace,
                 sizeof(crabc_x86_64_bsd_random_trace)) ==
                   (ssize_t)sizeof(crabc_x86_64_bsd_random_trace) ? 0 : 22;
}
#endif
