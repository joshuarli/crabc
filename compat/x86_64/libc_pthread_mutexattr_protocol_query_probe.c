/* Static crabc-libc x86-64 bounded pthread mutex-attribute protocol-query fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6, then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only pthread_mutexattr_getprotocol's raw
 * four-byte attribute-record projection: bit 3 maps to PTHREAD_PRIO_INHERIT
 * and every other bit is ignored without modifying caller-owned storage.
 *
 * This fixture deliberately constructs raw record words and never invokes
 * pthread_mutexattr_setprotocol, any attribute lifecycle function, mutex
 * initialization/operation, futex-PI observation, threads, TCB/TLS ownership,
 * synchronization, cancellation, CRT, loader, sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

_Static_assert(sizeof(unsigned) == 4 && sizeof(int) == 4,
    "x86 mutexattr protocol-query scalar widths");
_Static_assert(sizeof(pthread_mutexattr_t) == 4 && _Alignof(pthread_mutexattr_t) == 4,
    "musl x86-64 pthread_mutexattr_t ABI");
_Static_assert(__builtin_offsetof(pthread_mutexattr_t, __attr) == 0,
    "public pthread_mutexattr_t word offset");
_Static_assert(PTHREAD_PRIO_NONE == 0 && PTHREAD_PRIO_INHERIT == 1 &&
    PTHREAD_PRIO_PROTECT == 2, "musl protocol-query result vocabulary");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutexattr_getprotocol),
    int (*)(const pthread_mutexattr_t *, int *)),
    "pthread_mutexattr_getprotocol declaration");

#define CRABC_PROTOCOL_CLEAR_WORD 0xfffffff7U
#define CRABC_PROTOCOL_SET_WORD 0xfffffff8U

static int expect_protocol(pthread_mutexattr_t *attr, int expected)
{
    unsigned preserved = attr->__attr;
    int observed = -1;

    if (pthread_mutexattr_getprotocol(attr, &observed) != 0)
        return 1;
    if (attr->__attr != preserved)
        return 2;
    return observed == expected ? 0 : 3;
}

int crabc_x86_64_pthread_mutexattr_protocol_query_probe(void)
{
    pthread_mutexattr_t attr;

    attr.__attr = 0U;
    if (expect_protocol(&attr, PTHREAD_PRIO_NONE) != 0)
        return 1;

    attr.__attr = 8U;
    if (expect_protocol(&attr, PTHREAD_PRIO_INHERIT) != 0)
        return 2;

    attr.__attr = CRABC_PROTOCOL_CLEAR_WORD;
    if (expect_protocol(&attr, PTHREAD_PRIO_NONE) != 0)
        return 3;

    attr.__attr = CRABC_PROTOCOL_SET_WORD;
    if (expect_protocol(&attr, PTHREAD_PRIO_INHERIT) != 0)
        return 4;

    return 0;
}

#if !defined(CRABC_PTHREAD_MUTEXATTR_PROTOCOL_QUERY_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_mutexattr_protocol_query_probe();
}
#endif
