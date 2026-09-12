#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "x86_64_workload_protocol.h"
#include "fixtures/diagnostic_marker.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum primitive_kind {
    PRIMITIVE_MEMCPY,
    PRIMITIVE_MEMSET,
    PRIMITIVE_STRLEN,
    PRIMITIVE_MEMCHR,
    PRIMITIVE_STRSTR,
    PRIMITIVE_MEMMEM,
};

enum primitive_variant {
    VARIANT_EMPTY,
    VARIANT_SHORT31_UNALIGNED,
    VARIANT_GUARD63,
};

enum {
    SHORT_BYTES = 31,
    GUARD_BYTES = 63,
    NEEDLE_BYTES = 6,
};

static void *(*volatile copied_memcpy)(void *, const void *, size_t) = memcpy;
static void *(*volatile copied_memset)(void *, int, size_t) = memset;
static size_t (*volatile copied_strlen)(const char *) = strlen;
static void *(*volatile copied_memchr)(const void *, int, size_t) = memchr;
static char *(*volatile copied_strstr)(const char *, const char *) = strstr;
static void *(*volatile copied_memmem)(const void *, size_t, const void *,
    size_t) = memmem;

static const unsigned char needle[NEEDLE_BYTES] = {'n', 'e', 'e', 'd', 'l', 'e'};
static const char needle_text[] = "needle";

static int
parse_primitive(const char *text, enum primitive_kind *result)
{
    if (strcmp(text, "memcpy") == 0)
        *result = PRIMITIVE_MEMCPY;
    else if (strcmp(text, "memset") == 0)
        *result = PRIMITIVE_MEMSET;
    else if (strcmp(text, "strlen") == 0)
        *result = PRIMITIVE_STRLEN;
    else if (strcmp(text, "memchr") == 0)
        *result = PRIMITIVE_MEMCHR;
    else if (strcmp(text, "strstr") == 0)
        *result = PRIMITIVE_STRSTR;
    else if (strcmp(text, "memmem") == 0)
        *result = PRIMITIVE_MEMMEM;
    else
        return 0;
    return 1;
}

static int
parse_variant(const char *text, enum primitive_variant *result)
{
    if (strcmp(text, "empty") == 0)
        *result = VARIANT_EMPTY;
    else if (strcmp(text, "short31_unaligned") == 0)
        *result = VARIANT_SHORT31_UNALIGNED;
    else if (strcmp(text, "guard63") == 0)
        *result = VARIANT_GUARD63;
    else
        return 0;
    return 1;
}

static unsigned char
pattern_byte(size_t offset)
{
    return (unsigned char)((offset * 19U + 7U) & 0xffU);
}

static void
fill_bytes(unsigned char *data, size_t bytes)
{
    size_t offset;

    for (offset = 0; offset < bytes; offset++)
        data[offset] = pattern_byte(offset);
}

static int
check_bytes(const unsigned char *data, const unsigned char *expected,
    size_t bytes)
{
    return memcmp(data, expected, bytes) == 0;
}

struct empty_state {
    unsigned char source;
    unsigned char destination;
    char text[1];
};

static int
empty_operation(enum primitive_kind primitive, struct empty_state *state)
{
    void *result;

    switch (primitive) {
    case PRIMITIVE_MEMCPY:
        result = copied_memcpy(&state->destination, &state->source, 0);
        if (result != &state->destination || state->destination != 0xa5 ||
            state->source != 0x3c)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        return 1;
    case PRIMITIVE_MEMSET:
        result = copied_memset(&state->destination, 0x5a, 0);
        if (result != &state->destination || state->destination != 0xa5)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        return 1;
    case PRIMITIVE_STRLEN:
        if (copied_strlen(state->text) != 0)
            return 0;
        crabc_perf_consume_uintptr(0);
        return 1;
    case PRIMITIVE_MEMCHR:
        result = copied_memchr(&state->source, 'z', 0);
        if (result != NULL)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        return 1;
    case PRIMITIVE_STRSTR:
        result = copied_strstr(state->text, state->text);
        if (result != state->text)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        return 1;
    case PRIMITIVE_MEMMEM:
        result = copied_memmem(&state->source, 0, &state->destination, 0);
        if (result != &state->source)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        return 1;
    }
    return 0;
}

static int
run_empty(unsigned long iterations, enum primitive_kind primitive,
    const struct crabc_perf_observer *observer)
{
    struct empty_state state = {0x3c, 0xa5, {'\0'}};
    unsigned long index;

    for (index = 0; index < iterations; index++) {
        if (!empty_operation(primitive, &state))
            return 0;
    }
    return crabc_perf_observer_reach(observer);
}

struct short_state {
    unsigned char source_backing[SHORT_BYTES + 3];
    unsigned char destination_backing[SHORT_BYTES + 3];
    unsigned char range_backing[SHORT_BYTES + 3];
    char text_backing[SHORT_BYTES + 3];
    unsigned char copy_expected[SHORT_BYTES];
    unsigned char fill_expected[SHORT_BYTES];
    unsigned char *source;
    unsigned char *destination;
    unsigned char *range;
    char *text;
};

static void
short_state_initialize(struct short_state *state)
{
    size_t tail = SHORT_BYTES - NEEDLE_BYTES;

    memset(state, 0, sizeof *state);
    state->source = state->source_backing + 1;
    state->destination = state->destination_backing + 1;
    state->range = state->range_backing + 1;
    state->text = state->text_backing + 1;
    state->source[-1] = 0x31;
    state->source[SHORT_BYTES] = 0x32;
    state->destination[-1] = 0x41;
    state->destination[SHORT_BYTES] = 0x42;
    state->range[-1] = 0x51;
    state->range[SHORT_BYTES] = 0x52;
    state->text[-1] = 0x61;
    state->text[SHORT_BYTES + 1] = 0x62;
    fill_bytes(state->source, SHORT_BYTES);
    memcpy(state->copy_expected, state->source, SHORT_BYTES);
    memset(state->fill_expected, 0x5a, SHORT_BYTES);
    memset(state->destination, 0xa5, SHORT_BYTES);
    memset(state->range, 'a', SHORT_BYTES);
    state->range[SHORT_BYTES - 1] = 'z';
    memset(state->text, 'a', SHORT_BYTES);
    memcpy(state->text + tail, needle, NEEDLE_BYTES);
    state->text[SHORT_BYTES] = '\0';
}

static int
short_state_has_canaries(const struct short_state *state)
{
    return state->source[-1] == 0x31 &&
        state->source[SHORT_BYTES] == 0x32 &&
        state->destination[-1] == 0x41 &&
        state->destination[SHORT_BYTES] == 0x42 &&
        state->range[-1] == 0x51 &&
        state->range[SHORT_BYTES] == 0x52 &&
        state->text[-1] == 0x61 &&
        state->text[SHORT_BYTES] == '\0' &&
        state->text[SHORT_BYTES + 1] == 0x62;
}

static int
short_operation(enum primitive_kind primitive, struct short_state *state)
{
    size_t tail = SHORT_BYTES - NEEDLE_BYTES;
    void *result;

    switch (primitive) {
    case PRIMITIVE_MEMCPY:
        result = copied_memcpy(state->destination, state->source, SHORT_BYTES);
        if (result != state->destination ||
            !check_bytes(state->destination, state->copy_expected,
                SHORT_BYTES))
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_MEMSET:
        result = copied_memset(state->destination, 0x5a, SHORT_BYTES);
        if (result != state->destination ||
            !check_bytes(state->destination, state->fill_expected,
                SHORT_BYTES))
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_STRLEN:
        if (copied_strlen(state->text) != SHORT_BYTES)
            return 0;
        crabc_perf_consume_uintptr(SHORT_BYTES);
        break;
    case PRIMITIVE_MEMCHR:
        result = copied_memchr(state->range, 'z', SHORT_BYTES);
        if (result != state->range + SHORT_BYTES - 1)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_STRSTR:
        result = copied_strstr(state->text, needle_text);
        if (result != state->text + tail)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_MEMMEM:
        result = copied_memmem(state->text, SHORT_BYTES, needle, NEEDLE_BYTES);
        if (result != state->text + tail)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    }
    return short_state_has_canaries(state);
}

static int
run_short31(unsigned long iterations, enum primitive_kind primitive,
    const struct crabc_perf_observer *observer)
{
    struct short_state state;
    unsigned long index;

    short_state_initialize(&state);
    for (index = 0; index < iterations; index++) {
        if (!short_operation(primitive, &state))
            return 0;
    }
    return crabc_perf_observer_reach(observer);
}

struct guarded_buffer {
    unsigned char *mapping;
    size_t page_bytes;
    unsigned char *window;
};

static int
guarded_buffer_create(struct guarded_buffer *buffer)
{
    long raw_page_bytes;
    size_t page_bytes;
    unsigned char *mapping;

    if (!buffer)
        return 0;
    memset(buffer, 0, sizeof *buffer);
    raw_page_bytes = sysconf(_SC_PAGESIZE);
    if (raw_page_bytes <= GUARD_BYTES)
        return 0;
    page_bytes = (size_t)raw_page_bytes;
    if (page_bytes > SIZE_MAX / 2)
        return 0;
    mapping = mmap(NULL, page_bytes * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;
    if (mprotect(mapping + page_bytes, page_bytes, PROT_NONE) != 0) {
        munmap(mapping, page_bytes * 2);
        return 0;
    }
    buffer->mapping = mapping;
    buffer->page_bytes = page_bytes;
    buffer->window = mapping + page_bytes - GUARD_BYTES;
    buffer->window[-1] = 0x6d;
    return 1;
}

static void
guarded_buffer_destroy(struct guarded_buffer *buffer)
{
    if (buffer && buffer->mapping)
        munmap(buffer->mapping, buffer->page_bytes * 2);
}

struct guard_state {
    enum primitive_kind primitive;
    struct guarded_buffer first;
    struct guarded_buffer second;
    unsigned char fill_expected[GUARD_BYTES];
};

static int
guard_state_initialize(struct guard_state *state, enum primitive_kind primitive)
{
    size_t string_tail = (GUARD_BYTES - 1) - NEEDLE_BYTES;
    size_t range_tail = GUARD_BYTES - NEEDLE_BYTES;

    memset(state, 0, sizeof *state);
    state->primitive = primitive;
    if (!guarded_buffer_create(&state->first))
        return 0;
    if (primitive == PRIMITIVE_MEMCPY &&
        !guarded_buffer_create(&state->second)) {
        guarded_buffer_destroy(&state->first);
        return 0;
    }
    switch (primitive) {
    case PRIMITIVE_MEMCPY:
        fill_bytes(state->first.window, GUARD_BYTES);
        memset(state->second.window, 0xa5, GUARD_BYTES);
        break;
    case PRIMITIVE_MEMSET:
        memset(state->first.window, 0xa5, GUARD_BYTES);
        memset(state->fill_expected, 0x5a, sizeof state->fill_expected);
        break;
    case PRIMITIVE_STRLEN:
        memset(state->first.window, 'a', GUARD_BYTES - 1);
        state->first.window[GUARD_BYTES - 1] = '\0';
        break;
    case PRIMITIVE_MEMCHR:
        memset(state->first.window, 'a', GUARD_BYTES);
        state->first.window[GUARD_BYTES - 1] = 'z';
        break;
    case PRIMITIVE_STRSTR:
        memset(state->first.window, 'a', GUARD_BYTES - 1);
        memcpy(state->first.window + string_tail, needle, NEEDLE_BYTES);
        state->first.window[GUARD_BYTES - 1] = '\0';
        break;
    case PRIMITIVE_MEMMEM:
        memset(state->first.window, 'a', GUARD_BYTES);
        memcpy(state->first.window + range_tail, needle, NEEDLE_BYTES);
        break;
    }
    return 1;
}

static void
guard_state_destroy(struct guard_state *state)
{
    guarded_buffer_destroy(&state->second);
    guarded_buffer_destroy(&state->first);
}

static int
guard_state_has_canaries(const struct guard_state *state)
{
    return state->first.window[-1] == 0x6d &&
        (!state->second.window || state->second.window[-1] == 0x6d);
}

static int
guard_operation(struct guard_state *state)
{
    size_t string_tail = (GUARD_BYTES - 1) - NEEDLE_BYTES;
    size_t range_tail = GUARD_BYTES - NEEDLE_BYTES;
    void *result;

    switch (state->primitive) {
    case PRIMITIVE_MEMCPY:
        result = copied_memcpy(state->second.window, state->first.window,
            GUARD_BYTES);
        if (result != state->second.window ||
            !check_bytes(state->second.window, state->first.window,
                GUARD_BYTES))
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_MEMSET:
        result = copied_memset(state->first.window, 0x5a, GUARD_BYTES);
        if (result != state->first.window ||
            !check_bytes(state->first.window, state->fill_expected,
                GUARD_BYTES))
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_STRLEN:
        if (copied_strlen((const char *)state->first.window) != GUARD_BYTES - 1)
            return 0;
        crabc_perf_consume_uintptr(GUARD_BYTES - 1);
        break;
    case PRIMITIVE_MEMCHR:
        result = copied_memchr(state->first.window, 'z', GUARD_BYTES);
        if (result != state->first.window + GUARD_BYTES - 1)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_STRSTR:
        result = copied_strstr((const char *)state->first.window, needle_text);
        if (result != state->first.window + string_tail)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    case PRIMITIVE_MEMMEM:
        result = copied_memmem(state->first.window, GUARD_BYTES, needle,
            NEEDLE_BYTES);
        if (result != state->first.window + range_tail)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)result);
        break;
    }
    return guard_state_has_canaries(state);
}

static int
run_guard63(unsigned long iterations, enum primitive_kind primitive,
    const struct crabc_perf_observer *observer)
{
    struct guard_state state;
    unsigned long index;
    int valid = 1;

    if (!guard_state_initialize(&state, primitive))
        return 0;
    for (index = 0; index < iterations; index++) {
        if (!guard_operation(&state)) {
            valid = 0;
            break;
        }
    }
    /*
     * The selected valid window and its adjacent PROT_NONE page remain mapped
     * through acknowledgement; teardown is outside the declared plateau.
     */
    if (valid && !crabc_perf_observer_reach(observer))
        valid = 0;
    guard_state_destroy(&state);
    return valid;
}

int
main(int argc, char **argv)
{
    unsigned long iterations;
    enum primitive_kind primitive;
    enum primitive_variant variant;
    struct crabc_perf_observer observer;
    int marker_fd;
    int passed;

    if (!crabc_perf_observer_from_environment(&observer))
        return 2;
    if (argc != 5 || strcmp(argv[1], "primitive") != 0 ||
        !crabc_perf_parse_positive(argv[2], &iterations) ||
        !parse_primitive(argv[3], &primitive) ||
        !parse_variant(argv[4], &variant))
        return 2;
    marker_fd = diagnostic_marker_fd();
    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_BEGIN,
            sizeof(DIAGNOSTIC_MARKER_BEGIN) - 1);
    switch (variant) {
    case VARIANT_EMPTY:
        passed = run_empty(iterations, primitive, &observer);
        break;
    case VARIANT_SHORT31_UNALIGNED:
        passed = run_short31(iterations, primitive, &observer);
        break;
    case VARIANT_GUARD63:
        passed = run_guard63(iterations, primitive, &observer);
        break;
    default:
        return 2;
    }
    if (!passed)
        return 1;
    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_END,
            sizeof(DIAGNOSTIC_MARKER_END) - 1);
    puts("ok");
    return 0;
}
