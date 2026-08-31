/* Static crabc-libc x86-64 bounded pthread condition-attribute clock fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6, then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only pthread_condattr_setclock and
 * pthread_condattr_getclock over the public four-byte attribute word: accepted
 * clock IDs replace exactly the low thirty-one bits while retaining bit 31;
 * negative and CPU-clock IDs leave the complete word unchanged.
 *
 * This fixture deliberately constructs caller-owned raw record words and does
 * not call the separate init/destroy pair, set process sharing, or call
 * pthread_cond_init. It does not select condition operation, timed waiting,
 * clock observation, threads, TCB/TLS ownership, lifecycle, synchronization,
 * cancellation, CRT, loader, sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <time.h>

_Static_assert(sizeof(unsigned) == 4 && sizeof(int) == 4 && sizeof(clockid_t) == 4,
    "x86 condattr clock scalar widths");
_Static_assert(sizeof(pthread_condattr_t) == 4 && _Alignof(pthread_condattr_t) == 4,
    "musl x86-64 pthread_condattr_t ABI");
_Static_assert(__builtin_offsetof(pthread_condattr_t, __attr) == 0,
    "public pthread_condattr_t word offset");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1,
    "musl accepted condition clocks");
_Static_assert(CLOCK_PROCESS_CPUTIME_ID == 2 && CLOCK_THREAD_CPUTIME_ID == 3,
    "musl rejected CPU condition clocks");
_Static_assert(EINVAL == 22, "Linux x86 EINVAL");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_condattr_setclock),
    int (*)(pthread_condattr_t *, clockid_t)), "pthread_condattr_setclock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_condattr_getclock),
    int (*)(const pthread_condattr_t *, clockid_t *)), "pthread_condattr_getclock declaration");

#define CRABC_SHARED_MONOTONIC_WORD 0x80000001U
#define CRABC_PRIVATE_RAW_CLOCK_WORD 0x12345678U
#define CRABC_SHARED_RAW_CLOCK_WORD 0x92345678U
#define CRABC_MUTATED_COND_ATTRIBUTE_WORD 0xa5a50083U

static int expect_clock(const pthread_condattr_t *attr, clockid_t expected)
{
    clockid_t observed = -1;

    if (pthread_condattr_getclock(attr, &observed) != 0)
        return 1;
    return observed == expected ? 0 : 2;
}

int crabc_x86_64_pthread_condattr_clock_probe(void)
{
    pthread_condattr_t attr;
    unsigned preserved;

    attr.__attr = 0x80000000U;
    if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0)
        return 1;
    if (attr.__attr != CRABC_SHARED_MONOTONIC_WORD)
        return 2;
    if (expect_clock(&attr, CLOCK_MONOTONIC) != 0)
        return 3;

    attr.__attr = 0U;
    if (pthread_condattr_setclock(&attr, (clockid_t)CRABC_PRIVATE_RAW_CLOCK_WORD) != 0)
        return 4;
    if (attr.__attr != CRABC_PRIVATE_RAW_CLOCK_WORD)
        return 5;
    if (expect_clock(&attr, (clockid_t)CRABC_PRIVATE_RAW_CLOCK_WORD) != 0)
        return 6;

    /* Musl's getter masks the high process-sharing bit and returns low bits. */
    attr.__attr = CRABC_SHARED_RAW_CLOCK_WORD;
    if (expect_clock(&attr, (clockid_t)CRABC_PRIVATE_RAW_CLOCK_WORD) != 0)
        return 7;

    attr.__attr = CRABC_MUTATED_COND_ATTRIBUTE_WORD;
    preserved = attr.__attr;
    if (pthread_condattr_setclock(&attr, -1) != EINVAL)
        return 8;
    if (attr.__attr != preserved)
        return 9;
    if (pthread_condattr_setclock(&attr, CLOCK_PROCESS_CPUTIME_ID) != EINVAL)
        return 10;
    if (attr.__attr != preserved)
        return 11;
    if (pthread_condattr_setclock(&attr, CLOCK_THREAD_CPUTIME_ID) != EINVAL)
        return 12;
    if (attr.__attr != preserved)
        return 13;
    return 0;
}

#if !defined(CRABC_PTHREAD_CONDATTR_CLOCK_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_condattr_clock_probe();
}
#endif
