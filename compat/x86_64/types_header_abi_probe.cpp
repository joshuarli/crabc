/*
 * Source-only Linux/x86-64 C++ public-type ABI probe.
 *
 * Musl deliberately uses the integer form of pthread_t for C++ while C uses
 * the opaque pointer form. Keep this plain <sys/types.h> check separate from
 * the C probe so a coincidentally pointer-width-compatible declaration cannot
 * erase that API contract difference. No crabc-libc object is selected or
 * linked.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>

static_assert(__is_same(nlink_t, unsigned long),
	"musl x86-64 nlink_t is unsigned long");
static_assert(__is_same(blksize_t, long),
	"musl x86-64 blksize_t is signed long");
static_assert(__is_same(dev_t, unsigned long) && __is_same(ino_t, unsigned long),
	"musl x86-64 device and inode types are unsigned long");
static_assert(__is_same(mode_t, unsigned int) && __is_same(off_t, long) &&
	__is_same(pid_t, int), "musl x86-64 mode, offset, and pid scalar forms");
static_assert(__is_same(uid_t, unsigned int) && __is_same(gid_t, unsigned int),
	"musl x86-64 user and group identifier forms");
static_assert(__is_same(size_t, unsigned long) && __is_same(ssize_t, long),
	"musl x86-64 size scalars retain their LP64 forms");
static_assert(__is_same(blkcnt_t, long) && __is_same(fsblkcnt_t, unsigned long) &&
	__is_same(fsfilcnt_t, unsigned long),
	"musl x86-64 filesystem counters retain their public forms");
static_assert(__is_same(id_t, unsigned int) && __is_same(key_t, int),
	"musl x86-64 IPC identifier forms");
static_assert(__is_same(time_t, long) && __is_same(clock_t, long) &&
	__is_same(clockid_t, int), "musl x86-64 time scalar forms");
static_assert(__is_same(timer_t, void *) && __is_same(suseconds_t, long) &&
	__is_same(useconds_t, unsigned int),
	"musl x86-64 timer and microsecond forms");
static_assert(__is_same(pthread_t, unsigned long),
	"musl C++ pthread_t is unsigned long");
static_assert(__is_same(pthread_once_t, int) &&
	__is_same(pthread_key_t, unsigned int) &&
	__is_same(pthread_spinlock_t, int),
	"musl x86-64 pthread scalar forms");

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
using crabc_select_signature = int (*)(
	int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict,
	struct timeval *__restrict);
using crabc_pselect_signature = int (*)(
	int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict,
	const struct timespec *__restrict, const sigset_t *__restrict);

static_assert(__is_same(int8_t, signed char) && __is_same(int16_t, signed short) &&
	__is_same(int32_t, signed int) && __is_same(int64_t, long),
	"musl GNU/BSD signed integer vocabulary");
static_assert(__is_same(u_int64_t, unsigned long) && __is_same(register_t, long),
	"musl GNU/BSD unsigned and register vocabulary");
static_assert(__is_same(u_int8_t, unsigned char) &&
	__is_same(u_int16_t, unsigned short) && __is_same(u_int32_t, unsigned int),
	"musl GNU/BSD fixed-width aliases");
static_assert(__is_same(caddr_t, char *) && __is_same(u_char, unsigned char) &&
	__is_same(u_short, unsigned short) && __is_same(ushort, unsigned short),
	"musl GNU/BSD historical pointer and short aliases");
static_assert(__is_same(u_int, unsigned int) && __is_same(uint, unsigned int) &&
	__is_same(u_long, unsigned long) && __is_same(ulong, unsigned long),
	"musl GNU/BSD historical integer aliases");
static_assert(__is_same(quad_t, long long) &&
	__is_same(u_quad_t, unsigned long long), "musl GNU/BSD quad aliases");
static_assert(BYTE_ORDER == LITTLE_ENDIAN && PDP_ENDIAN == 3412,
	"musl GNU/BSD endian vocabulary");
static_assert(__is_same(fd_mask, unsigned long) && FD_SETSIZE == 1024 &&
	NFDBITS == 8 * static_cast<int>(sizeof(long)),
	"musl GNU/BSD select vocabulary");
static_assert(sizeof(fd_set) == 128 && sizeof(struct timeval) == 16 &&
	sizeof(struct timespec) == 16 && sizeof(sigset_t) == 128,
	"musl GNU/BSD select record layouts");
static_assert(__is_same(decltype(&select), crabc_select_signature),
	"musl GNU/BSD select declaration");
static_assert(__is_same(decltype(&pselect), crabc_pselect_signature),
	"musl GNU/BSD pselect declaration");
#endif

#if defined(_LARGEFILE64_SOURCE)
static_assert(__is_same(blkcnt64_t, long) &&
	__is_same(fsblkcnt64_t, unsigned long) &&
	__is_same(fsfilcnt64_t, unsigned long), "musl large-file counter aliases");
static_assert(__is_same(ino64_t, unsigned long) && __is_same(off64_t, long),
	"musl large-file inode and offset aliases");
#endif

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
