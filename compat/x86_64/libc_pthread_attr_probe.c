/* Static crabc-libc x86-64 pthread-attribute metadata fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6 and
 * then as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves the standard pthread_attr_t record
 * lifecycle and metadata accessors: defaults, detach, stack/guard, scope,
 * inherited scheduling, and stored policy/priority. It deliberately does not
 * pass an attribute record to pthread_create, select GNU default attributes,
 * inspect a live thread, or establish general pthread lifecycle behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>

_Static_assert(sizeof(pthread_attr_t) == 56 && _Alignof(pthread_attr_t) == 8,
    "musl x86-64 pthread_attr_t ABI");
_Static_assert(sizeof(struct sched_param) == 48 &&
    _Alignof(struct sched_param) == 8,
    "musl x86-64 sched_param ABI");
_Static_assert(PTHREAD_STACK_MIN == 2048,
    "musl x86-64 pthread stack minimum");
_Static_assert(PTHREAD_CREATE_JOINABLE == 0 && PTHREAD_CREATE_DETACHED == 1,
    "musl pthread detach vocabulary");
_Static_assert(PTHREAD_SCOPE_SYSTEM == 0 && PTHREAD_SCOPE_PROCESS == 1,
    "musl pthread scope vocabulary");
_Static_assert(PTHREAD_INHERIT_SCHED == 0 && PTHREAD_EXPLICIT_SCHED == 1,
    "musl pthread inherited-scheduling vocabulary");
_Static_assert(EINVAL == 22 && ENOTSUP == 95,
    "Linux/musl pthread status vocabulary");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_init),
    int (*)(pthread_attr_t *)), "pthread_attr_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_destroy),
    int (*)(pthread_attr_t *)), "pthread_attr_destroy declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_setdetachstate), int (*)(pthread_attr_t *, int)),
    "pthread_attr_setdetachstate declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getdetachstate),
    int (*)(const pthread_attr_t *, int *)),
    "pthread_attr_getdetachstate declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_setstacksize), int (*)(pthread_attr_t *, size_t)),
    "pthread_attr_setstacksize declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getstacksize),
    int (*)(const pthread_attr_t *, size_t *)),
    "pthread_attr_getstacksize declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_setstack),
    int (*)(pthread_attr_t *, void *, size_t)), "pthread_attr_setstack declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_getstack),
    int (*)(const pthread_attr_t *, void **, size_t *)),
    "pthread_attr_getstack declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_setguardsize), int (*)(pthread_attr_t *, size_t)),
    "pthread_attr_setguardsize declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getguardsize),
    int (*)(const pthread_attr_t *, size_t *)),
    "pthread_attr_getguardsize declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_setscope),
    int (*)(pthread_attr_t *, int)), "pthread_attr_setscope declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_getscope),
    int (*)(const pthread_attr_t *, int *)), "pthread_attr_getscope declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_setinheritsched), int (*)(pthread_attr_t *, int)),
    "pthread_attr_setinheritsched declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getinheritsched),
    int (*)(const pthread_attr_t *, int *)),
    "pthread_attr_getinheritsched declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_setschedpolicy), int (*)(pthread_attr_t *, int)),
    "pthread_attr_setschedpolicy declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getschedpolicy),
    int (*)(const pthread_attr_t *, int *)),
    "pthread_attr_getschedpolicy declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_setschedparam),
    int (*)(pthread_attr_t *, const struct sched_param *)),
    "pthread_attr_setschedparam declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getschedparam),
    int (*)(const pthread_attr_t *, struct sched_param *)),
    "pthread_attr_getschedparam declaration");

enum { CRABC_ATTR_ERRNO_SENTINEL = E2BIG };

static unsigned char crabc_caller_stack[PTHREAD_STACK_MIN];

static void fill_bytes(void *address, size_t length, unsigned char value)
{
    unsigned char *bytes = address;
    size_t index;

    for (index = 0; index != length; ++index)
        bytes[index] = value;
}

static int attrs_equal(const pthread_attr_t *left, const pthread_attr_t *right)
{
    unsigned int index;

    for (index = 0; index != 7; ++index) {
        if (left->__u.__s[index] != right->__u.__s[index])
            return 0;
    }
    return 1;
}

static int expect_default_record(const pthread_attr_t *attributes)
{
    unsigned int index;

    if (attributes->__u.__s[0] != 131072UL ||
        attributes->__u.__s[1] != 8192UL)
        return 1;
    for (index = 2; index != 7; ++index) {
        if (attributes->__u.__s[index] != 0)
            return 2;
    }
    return 0;
}

static int run_pthread_attr_metadata(void)
{
    pthread_attr_t attributes;
    pthread_attr_t before;
    struct sched_param parameters;
    void *stack_address;
    size_t stack_size;
    size_t guard_size;
    size_t maximum_stack = SIZE_MAX / 4 + PTHREAD_STACK_MIN;
    size_t maximum_guard = SIZE_MAX / 8;
    unsigned char *parameter_bytes = (unsigned char *)&parameters;
    unsigned int index;
    int value;

#if !defined(CRABC_PTHREAD_ATTR_FREESTANDING)
    errno = CRABC_ATTR_ERRNO_SENTINEL;
#endif
    fill_bytes(&attributes, sizeof(attributes), 0x5a);
    if (pthread_attr_init(&attributes) != 0 ||
        expect_default_record(&attributes) != 0)
        return 10;

    stack_address = (void *)(uintptr_t)1;
    stack_size = 123;
    if (pthread_attr_getstack(&attributes, &stack_address, &stack_size) != EINVAL ||
        stack_address != (void *)(uintptr_t)1 || stack_size != 123)
        return 11;
    if (pthread_attr_getdetachstate(&attributes, &value) != 0 ||
        value != PTHREAD_CREATE_JOINABLE ||
        pthread_attr_getstacksize(&attributes, &stack_size) != 0 ||
        stack_size != 131072 ||
        pthread_attr_getguardsize(&attributes, &guard_size) != 0 ||
        guard_size != 8192 ||
        pthread_attr_getscope(&attributes, &value) != 0 ||
        value != PTHREAD_SCOPE_SYSTEM ||
        pthread_attr_getinheritsched(&attributes, &value) != 0 ||
        value != PTHREAD_INHERIT_SCHED ||
        pthread_attr_getschedpolicy(&attributes, &value) != 0 || value != 0)
        return 12;

    fill_bytes(&parameters, sizeof(parameters), 0x5a);
    if (pthread_attr_getschedparam(&attributes, &parameters) != 0 ||
        parameters.sched_priority != 0)
        return 13;
    for (index = sizeof(parameters.sched_priority); index != sizeof(parameters); ++index) {
        if (parameter_bytes[index] != 0x5a)
            return 14;
    }

    before = attributes;
    if (pthread_attr_setdetachstate(&attributes, -1) != EINVAL ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setdetachstate(&attributes, 2) != EINVAL ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setinheritsched(&attributes, -1) != EINVAL ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setinheritsched(&attributes, 2) != EINVAL ||
        !attrs_equal(&attributes, &before))
        return 15;
    if (pthread_attr_setinheritsched(&attributes, PTHREAD_EXPLICIT_SCHED) != 0 ||
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) != 0 ||
        pthread_attr_getinheritsched(&attributes, &value) != 0 ||
        value != PTHREAD_EXPLICIT_SCHED ||
        pthread_attr_getdetachstate(&attributes, &value) != 0 ||
        value != PTHREAD_CREATE_DETACHED ||
        attributes.__u.__s[3] != ((1UL << 32) | 1UL))
        return 16;

    before = attributes;
    if (pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN - 1) != EINVAL ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setstacksize(&attributes, maximum_stack + 1) != EINVAL ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setstacksize(&attributes, maximum_stack) != 0 ||
        pthread_attr_getstacksize(&attributes, &stack_size) != 0 ||
        stack_size != maximum_stack)
        return 17;

    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setstack(&attributes, crabc_caller_stack,
            PTHREAD_STACK_MIN - 1) != EINVAL)
        return 18;
    if (pthread_attr_setstack(&attributes, crabc_caller_stack,
            PTHREAD_STACK_MIN) != 0 ||
        pthread_attr_getstack(&attributes, &stack_address, &stack_size) != 0 ||
        stack_address != crabc_caller_stack || stack_size != PTHREAD_STACK_MIN)
        return 19;
    if (pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN) != 0 ||
        pthread_attr_getstack(&attributes, &stack_address, &stack_size) != EINVAL)
        return 20;
    before = attributes;
    if (pthread_attr_setstack(&attributes, crabc_caller_stack,
            maximum_stack + 1) != EINVAL ||
        !attrs_equal(&attributes, &before))
        return 21;

    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setguardsize(&attributes, maximum_guard) != 0 ||
        pthread_attr_getguardsize(&attributes, &guard_size) != 0 ||
        guard_size != maximum_guard)
        return 22;
    before = attributes;
    if (pthread_attr_setguardsize(&attributes, maximum_guard + 1) != EINVAL ||
        !attrs_equal(&attributes, &before))
        return 23;

    before = attributes;
    if (pthread_attr_setscope(&attributes, PTHREAD_SCOPE_SYSTEM) != 0 ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setscope(&attributes, PTHREAD_SCOPE_PROCESS) != ENOTSUP ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setscope(&attributes, -1) != EINVAL ||
        !attrs_equal(&attributes, &before) ||
        pthread_attr_setscope(&attributes, 2) != EINVAL ||
        !attrs_equal(&attributes, &before))
        return 24;

    if (pthread_attr_setschedpolicy(&attributes, -7) != 0 ||
        pthread_attr_getschedpolicy(&attributes, &value) != 0 || value != -7)
        return 25;
    fill_bytes(&parameters, sizeof(parameters), 0x5a);
    parameters.sched_priority = INT_MIN;
    if (pthread_attr_setschedparam(&attributes, &parameters) != 0)
        return 26;
    fill_bytes(&parameters, sizeof(parameters), 0x5a);
    if (pthread_attr_getschedparam(&attributes, &parameters) != 0 ||
        parameters.sched_priority != INT_MIN)
        return 27;
    for (index = sizeof(parameters.sched_priority); index != sizeof(parameters); ++index) {
        if (parameter_bytes[index] != 0x5a)
            return 28;
    }

    before = attributes;
    if (pthread_attr_destroy(&attributes) != 0 || !attrs_equal(&attributes, &before))
        return 29;
#if !defined(CRABC_PTHREAD_ATTR_FREESTANDING)
    if (errno != CRABC_ATTR_ERRNO_SENTINEL)
        return 30;
#endif
    return 0;
}

int crabc_x86_64_pthread_attr_probe(void)
{
    return run_pthread_attr_metadata();
}

#if !defined(CRABC_PTHREAD_ATTR_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_attr_probe();
}
#endif
