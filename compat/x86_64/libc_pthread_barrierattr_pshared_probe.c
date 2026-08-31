/* Static crabc-libc x86-64 bounded pthread barrier-attribute pshared fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6, then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only pthread_barrierattr_setpshared and
 * pthread_barrierattr_getpshared over the public four-byte attribute word:
 * valid private/shared values replace the complete word with 0/INT_MIN,
 * invalid values leave it unchanged, and any nonzero word queries as shared.
 *
 * This fixture deliberately constructs raw caller-owned record words and does
 * not call the separate init/destroy pair. It does not select barrier
 * initialization or operation, process-shared barrier operation, threads,
 * TCB/TLS ownership, lifecycle, synchronization, cancellation, CRT, loader,
 * sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>

_Static_assert(sizeof(unsigned) == 4 && sizeof(int) == 4,
    "x86 barrierattr pshared scalar widths");
_Static_assert(sizeof(pthread_barrierattr_t) == 4 && _Alignof(pthread_barrierattr_t) == 4,
    "musl x86-64 pthread_barrierattr_t ABI");
_Static_assert(__builtin_offsetof(pthread_barrierattr_t, __attr) == 0,
    "public pthread_barrierattr_t word offset");
_Static_assert(PTHREAD_PROCESS_PRIVATE == 0 && PTHREAD_PROCESS_SHARED == 1,
    "musl pthread process-sharing encodings");
_Static_assert(EINVAL == 22, "Linux x86 EINVAL");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrierattr_setpshared),
    int (*)(pthread_barrierattr_t *, int)), "pthread_barrierattr_setpshared declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrierattr_getpshared),
    int (*)(const pthread_barrierattr_t *, int *)), "pthread_barrierattr_getpshared declaration");

#define CRABC_MUTATED_BARRIER_ATTRIBUTE_WORD 0xa5a50083U
#define CRABC_SHARED_BARRIER_ATTRIBUTE_WORD 0x80000000U

static int expect_pshared(const pthread_barrierattr_t *attr, int expected)
{
    int observed = -1;

    if (pthread_barrierattr_getpshared(attr, &observed) != 0)
        return 1;
    return observed == expected ? 0 : 2;
}

int crabc_x86_64_pthread_barrierattr_pshared_probe(void)
{
    pthread_barrierattr_t attr;
    unsigned preserved;

    attr.__attr = CRABC_MUTATED_BARRIER_ATTRIBUTE_WORD;
    if (pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_PRIVATE) != 0)
        return 1;
    if (attr.__attr != 0)
        return 2;
    if (expect_pshared(&attr, PTHREAD_PROCESS_PRIVATE) != 0)
        return 3;

    attr.__attr = CRABC_MUTATED_BARRIER_ATTRIBUTE_WORD;
    if (pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0)
        return 4;
    if (attr.__attr != CRABC_SHARED_BARRIER_ATTRIBUTE_WORD)
        return 5;
    if (expect_pshared(&attr, PTHREAD_PROCESS_SHARED) != 0)
        return 6;

    /* Musl's getter canonicalizes every nonzero public record to shared. */
    attr.__attr = CRABC_MUTATED_BARRIER_ATTRIBUTE_WORD;
    if (expect_pshared(&attr, PTHREAD_PROCESS_SHARED) != 0)
        return 7;
    attr.__attr = 0;
    if (expect_pshared(&attr, PTHREAD_PROCESS_PRIVATE) != 0)
        return 8;

    attr.__attr = CRABC_MUTATED_BARRIER_ATTRIBUTE_WORD;
    preserved = attr.__attr;
    if (pthread_barrierattr_setpshared(&attr, 2) != EINVAL)
        return 9;
    if (attr.__attr != preserved)
        return 10;
    if (pthread_barrierattr_setpshared(&attr, -1) != EINVAL)
        return 11;
    if (attr.__attr != preserved)
        return 12;
    return 0;
}

#if !defined(CRABC_PTHREAD_BARRIERATTR_PSHARED_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_barrierattr_pshared_probe();
}
#endif
