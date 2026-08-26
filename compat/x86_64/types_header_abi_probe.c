/*
 * Source-only Linux/x86-64 C public-type ABI probe.
 *
 * It requests the affected types directly from <bits/alltypes.h>, then
 * includes <sys/types.h>. Both paths must agree with the pinned musl 1.2.6
 * x86 C vocabulary. This is a declaration/layout check only: no crabc-libc
 * object is selected or linked.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define __NEED_nlink_t
#define __NEED_blksize_t
#define __NEED_pthread_t
#include <bits/alltypes.h>
#include <sys/types.h>

#define CRABC_TYPE_IS(expression, type) \
	_Generic((expression), type: 1, default: 0)

_Static_assert(CRABC_TYPE_IS((nlink_t)0, unsigned long),
	"musl x86-64 nlink_t is unsigned long");
_Static_assert(CRABC_TYPE_IS((blksize_t)0, long),
	"musl x86-64 blksize_t is signed long");
_Static_assert(__builtin_types_compatible_p(pthread_t, struct __pthread *),
	"musl C pthread_t is an opaque pthread pointer");

_Static_assert(sizeof(pthread_mutexattr_t) == 4,
	"musl x86-64 pthread_mutexattr_t size");
_Static_assert(_Alignof(pthread_mutexattr_t) == 4,
	"musl x86-64 pthread_mutexattr_t alignment");
_Static_assert(sizeof(pthread_condattr_t) == 4,
	"musl x86-64 pthread_condattr_t size");
_Static_assert(_Alignof(pthread_condattr_t) == 4,
	"musl x86-64 pthread_condattr_t alignment");
_Static_assert(sizeof(pthread_rwlockattr_t) == 8,
	"musl x86-64 pthread_rwlockattr_t size");
_Static_assert(_Alignof(pthread_rwlockattr_t) == 4,
	"musl x86-64 pthread_rwlockattr_t alignment");
_Static_assert(sizeof(pthread_barrierattr_t) == 4,
	"musl x86-64 pthread_barrierattr_t size");
_Static_assert(_Alignof(pthread_barrierattr_t) == 4,
	"musl x86-64 pthread_barrierattr_t alignment");

_Static_assert(sizeof(pthread_mutex_t) == 40,
	"musl x86-64 pthread_mutex_t size");
_Static_assert(_Alignof(pthread_mutex_t) == 8,
	"musl x86-64 pthread_mutex_t alignment");
_Static_assert(sizeof(pthread_cond_t) == 48,
	"musl x86-64 pthread_cond_t size");
_Static_assert(_Alignof(pthread_cond_t) == 8,
	"musl x86-64 pthread_cond_t alignment");
_Static_assert(sizeof(pthread_rwlock_t) == 56,
	"musl x86-64 pthread_rwlock_t size");
_Static_assert(_Alignof(pthread_rwlock_t) == 8,
	"musl x86-64 pthread_rwlock_t alignment");
_Static_assert(sizeof(pthread_barrier_t) == 32,
	"musl x86-64 pthread_barrier_t size");
_Static_assert(_Alignof(pthread_barrier_t) == 8,
	"musl x86-64 pthread_barrier_t alignment");
_Static_assert(sizeof(pthread_attr_t) == 56,
	"musl x86-64 pthread_attr_t size");
_Static_assert(_Alignof(pthread_attr_t) == 8,
	"musl x86-64 pthread_attr_t alignment");

int crabc_x86_64_types_header_abi_probe(void)
{
	return 0;
}
