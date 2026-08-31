/* Static crabc-libc x86-64 bounded pthread mutex-attribute type-setter fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6, then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only pthread_mutexattr_settype's raw
 * four-byte attribute-record update: accepted 0/1/2 values replace low bits
 * 0..1 while retaining every other caller-owned bit. Invalid values return
 * EINVAL before touching even a null record pointer.
 *
 * This fixture deliberately calls no getter, attribute lifecycle function,
 * mutex initialization/operation, thread, TCB/TLS, synchronization,
 * cancellation, CRT, loader, sysroot, or public-x86 path.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>

_Static_assert(sizeof(unsigned) == 4 && sizeof(int) == 4,
    "x86 mutexattr type-setter scalar widths");
_Static_assert(sizeof(pthread_mutexattr_t) == 4 && _Alignof(pthread_mutexattr_t) == 4,
    "musl x86-64 pthread_mutexattr_t ABI");
_Static_assert(__builtin_offsetof(pthread_mutexattr_t, __attr) == 0,
    "public pthread_mutexattr_t word offset");
_Static_assert(PTHREAD_MUTEX_NORMAL == 0 && PTHREAD_MUTEX_DEFAULT == 0 &&
    PTHREAD_MUTEX_RECURSIVE == 1 && PTHREAD_MUTEX_ERRORCHECK == 2,
    "musl mutex type vocabulary");
_Static_assert(EINVAL == 22, "Linux/musl EINVAL vocabulary");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutexattr_settype),
    int (*)(pthread_mutexattr_t *, int)),
    "pthread_mutexattr_settype declaration");

#define CRABC_TYPE_HIGH_BITS 0xfffffffcU
#define CRABC_TYPE_PRESERVED_WORD 0x5a5a5a5aU

static int expect_valid(pthread_mutexattr_t *attr, int type, unsigned expected)
{
    if (pthread_mutexattr_settype(attr, type) != 0)
        return 1;
    return attr->__attr == expected ? 0 : 2;
}

static int expect_invalid(pthread_mutexattr_t *attr, int type, unsigned preserved)
{
#if !defined(CRABC_PTHREAD_MUTEXATTR_TYPE_SETTER_FREESTANDING)
    errno = EBUSY;
#endif
    if (pthread_mutexattr_settype(attr, type) != EINVAL)
        return 1;
    if (attr && attr->__attr != preserved)
        return 2;
#if !defined(CRABC_PTHREAD_MUTEXATTR_TYPE_SETTER_FREESTANDING)
    if (errno != EBUSY)
        return 3;
#endif
    return 0;
}

int crabc_x86_64_pthread_mutexattr_type_setter_probe(void)
{
    pthread_mutexattr_t attr;

    attr.__attr = CRABC_TYPE_HIGH_BITS | 3U;
    if (expect_valid(&attr, PTHREAD_MUTEX_NORMAL, CRABC_TYPE_HIGH_BITS) != 0)
        return 1;

    attr.__attr = CRABC_TYPE_HIGH_BITS;
    if (expect_valid(&attr, PTHREAD_MUTEX_RECURSIVE,
            CRABC_TYPE_HIGH_BITS | 1U) != 0)
        return 2;

    attr.__attr = CRABC_TYPE_HIGH_BITS | 1U;
    if (expect_valid(&attr, PTHREAD_MUTEX_ERRORCHECK,
            CRABC_TYPE_HIGH_BITS | 2U) != 0)
        return 3;

    attr.__attr = CRABC_TYPE_PRESERVED_WORD;
    if (expect_invalid(&attr, -1, CRABC_TYPE_PRESERVED_WORD) != 0)
        return 4;
    if (expect_invalid(&attr, 3, CRABC_TYPE_PRESERVED_WORD) != 0)
        return 5;
    if (expect_invalid(&attr, INT_MIN, CRABC_TYPE_PRESERVED_WORD) != 0)
        return 6;
    if (expect_invalid(&attr, INT_MAX, CRABC_TYPE_PRESERVED_WORD) != 0)
        return 7;
    if (expect_invalid(0, -1, 0) != 0)
        return 8;
    if (expect_invalid(0, 3, 0) != 0)
        return 9;

    return 0;
}

#if !defined(CRABC_PTHREAD_MUTEXATTR_TYPE_SETTER_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_mutexattr_type_setter_probe();
}
#endif
