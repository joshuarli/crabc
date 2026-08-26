/*
 * Source-only Linux/x86-64 C++ public-type ABI probe.
 *
 * Musl deliberately uses the integer form of pthread_t for C++ while C uses
 * the opaque pointer form. Keep this check separate from the C probe so a
 * coincidentally pointer-width-compatible declaration cannot erase that API
 * contract difference. No crabc-libc object is selected or linked.
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

static_assert(__is_same(nlink_t, unsigned long),
	"musl x86-64 nlink_t is unsigned long");
static_assert(__is_same(blksize_t, long),
	"musl x86-64 blksize_t is signed long");
static_assert(__is_same(pthread_t, unsigned long),
	"musl C++ pthread_t is unsigned long");

static_assert(sizeof(pthread_mutexattr_t) == 4,
	"musl x86-64 pthread_mutexattr_t size");
static_assert(alignof(pthread_mutexattr_t) == 4,
	"musl x86-64 pthread_mutexattr_t alignment");
static_assert(sizeof(pthread_condattr_t) == 4,
	"musl x86-64 pthread_condattr_t size");
static_assert(alignof(pthread_condattr_t) == 4,
	"musl x86-64 pthread_condattr_t alignment");
static_assert(sizeof(pthread_rwlockattr_t) == 8,
	"musl x86-64 pthread_rwlockattr_t size");
static_assert(alignof(pthread_rwlockattr_t) == 4,
	"musl x86-64 pthread_rwlockattr_t alignment");
static_assert(sizeof(pthread_barrierattr_t) == 4,
	"musl x86-64 pthread_barrierattr_t size");
static_assert(alignof(pthread_barrierattr_t) == 4,
	"musl x86-64 pthread_barrierattr_t alignment");

static_assert(sizeof(pthread_mutex_t) == 40,
	"musl x86-64 pthread_mutex_t size");
static_assert(alignof(pthread_mutex_t) == 8,
	"musl x86-64 pthread_mutex_t alignment");
static_assert(sizeof(pthread_cond_t) == 48,
	"musl x86-64 pthread_cond_t size");
static_assert(alignof(pthread_cond_t) == 8,
	"musl x86-64 pthread_cond_t alignment");
static_assert(sizeof(pthread_rwlock_t) == 56,
	"musl x86-64 pthread_rwlock_t size");
static_assert(alignof(pthread_rwlock_t) == 8,
	"musl x86-64 pthread_rwlock_t alignment");
static_assert(sizeof(pthread_barrier_t) == 32,
	"musl x86-64 pthread_barrier_t size");
static_assert(alignof(pthread_barrier_t) == 8,
	"musl x86-64 pthread_barrier_t alignment");
static_assert(sizeof(pthread_attr_t) == 56,
	"musl x86-64 pthread_attr_t size");
static_assert(alignof(pthread_attr_t) == 8,
	"musl x86-64 pthread_attr_t alignment");

int crabc_x86_64_types_header_abi_probe()
{
	return 0;
}
