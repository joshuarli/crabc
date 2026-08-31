/* Static crabc-libc x86-64 bounded pthread mutex-attribute type-query fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6, then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only pthread_mutexattr_gettype's raw
 * four-byte attribute-record projection: low bits 0 and 1 are returned,
 * including the raw value 3, while caller-owned storage remains unchanged.
 *
 * This fixture deliberately constructs raw record words and never invokes
 * pthread_mutexattr_settype, any attribute lifecycle function, mutex
 * initialization/operation, threads, TCB/TLS ownership, synchronization,
 * cancellation, CRT, loader, sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

_Static_assert(sizeof(unsigned) == 4 && sizeof(int) == 4,
    "x86 mutexattr type-query scalar widths");
_Static_assert(sizeof(pthread_mutexattr_t) == 4 && _Alignof(pthread_mutexattr_t) == 4,
    "musl x86-64 pthread_mutexattr_t ABI");
_Static_assert(__builtin_offsetof(pthread_mutexattr_t, __attr) == 0,
    "public pthread_mutexattr_t word offset");
_Static_assert(PTHREAD_MUTEX_NORMAL == 0 && PTHREAD_MUTEX_DEFAULT == 0 &&
    PTHREAD_MUTEX_RECURSIVE == 1 && PTHREAD_MUTEX_ERRORCHECK == 2,
    "musl mutex type vocabulary");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutexattr_gettype),
    int (*)(const pthread_mutexattr_t *, int *)),
    "pthread_mutexattr_gettype declaration");

#define CRABC_TYPE_ZERO_WORD 0xfffffffcU
#define CRABC_TYPE_RECURSIVE_WORD 0xfffffffdU
#define CRABC_TYPE_ERRORCHECK_WORD 0xfffffffeU
#define CRABC_TYPE_RAW_THREE_WORD 0xffffffffU

static int expect_type(pthread_mutexattr_t *attr, int expected)
{
    unsigned preserved = attr->__attr;
    int observed = -1;

    if (pthread_mutexattr_gettype(attr, &observed) != 0)
        return 1;
    if (attr->__attr != preserved)
        return 2;
    return observed == expected ? 0 : 3;
}

int crabc_x86_64_pthread_mutexattr_type_query_probe(void)
{
    pthread_mutexattr_t attr;

    attr.__attr = 0U;
    if (expect_type(&attr, PTHREAD_MUTEX_NORMAL) != 0)
        return 1;

    attr.__attr = 1U;
    if (expect_type(&attr, PTHREAD_MUTEX_RECURSIVE) != 0)
        return 2;

    attr.__attr = 2U;
    if (expect_type(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0)
        return 3;

    attr.__attr = CRABC_TYPE_ZERO_WORD;
    if (expect_type(&attr, PTHREAD_MUTEX_NORMAL) != 0)
        return 4;

    attr.__attr = CRABC_TYPE_RECURSIVE_WORD;
    if (expect_type(&attr, PTHREAD_MUTEX_RECURSIVE) != 0)
        return 5;

    attr.__attr = CRABC_TYPE_ERRORCHECK_WORD;
    if (expect_type(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0)
        return 6;

    attr.__attr = CRABC_TYPE_RAW_THREE_WORD;
    if (expect_type(&attr, 3) != 0)
        return 7;

    return 0;
}

#if !defined(CRABC_PTHREAD_MUTEXATTR_TYPE_QUERY_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_mutexattr_type_query_probe();
}
#endif
