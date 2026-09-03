/*
 * Source-only Linux/x86-64 C public-type ABI probe.
 *
 * It includes <sys/types.h> without pre-seeding any internal type request.
 * The header must therefore request its complete pinned-musl 1.2.6 x86 C
 * vocabulary itself. This is a declaration/layout check only: no crabc-libc
 * object is selected or linked.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>

#define CRABC_TYPE_IS(expression, type) \
	_Generic((expression), type: 1, default: 0)

_Static_assert(CRABC_TYPE_IS((nlink_t)0, unsigned long),
	"musl x86-64 nlink_t is unsigned long");
_Static_assert(CRABC_TYPE_IS((blksize_t)0, long),
	"musl x86-64 blksize_t is signed long");
_Static_assert(CRABC_TYPE_IS((dev_t)0, unsigned long),
	"musl x86-64 dev_t is unsigned long");
_Static_assert(CRABC_TYPE_IS((ino_t)0, unsigned long),
	"musl x86-64 ino_t is unsigned long");
_Static_assert(CRABC_TYPE_IS((mode_t)0, unsigned int),
	"musl x86-64 mode_t is unsigned int");
_Static_assert(CRABC_TYPE_IS((off_t)0, long),
	"musl x86-64 off_t is signed long");
_Static_assert(CRABC_TYPE_IS((pid_t)0, int),
	"musl x86-64 pid_t is int");
_Static_assert(CRABC_TYPE_IS((uid_t)0, unsigned int) &&
	CRABC_TYPE_IS((gid_t)0, unsigned int),
	"musl x86-64 uid_t and gid_t are unsigned int");
_Static_assert(CRABC_TYPE_IS((size_t)0, unsigned long) &&
	CRABC_TYPE_IS((ssize_t)0, long),
	"musl x86-64 size_t and ssize_t are LP64 scalars");
_Static_assert(CRABC_TYPE_IS((blkcnt_t)0, long) &&
	CRABC_TYPE_IS((fsblkcnt_t)0, unsigned long) &&
	CRABC_TYPE_IS((fsfilcnt_t)0, unsigned long),
	"musl x86-64 filesystem counters retain their public scalar forms");
_Static_assert(CRABC_TYPE_IS((id_t)0, unsigned int) &&
	CRABC_TYPE_IS((key_t)0, int),
	"musl x86-64 IPC identifier types retain their scalar forms");
_Static_assert(CRABC_TYPE_IS((time_t)0, long) &&
	CRABC_TYPE_IS((clock_t)0, long) &&
	CRABC_TYPE_IS((clockid_t)0, int),
	"musl x86-64 time scalars retain their public forms");
_Static_assert(CRABC_TYPE_IS((timer_t)0, void *) &&
	CRABC_TYPE_IS((suseconds_t)0, long) &&
	CRABC_TYPE_IS((useconds_t)0, unsigned int),
	"musl x86-64 timer and microsecond types retain their public forms");
_Static_assert(__builtin_types_compatible_p(pthread_t, struct __pthread *),
	"musl C pthread_t is an opaque pthread pointer");
_Static_assert(CRABC_TYPE_IS((pthread_once_t)0, int) &&
	CRABC_TYPE_IS((pthread_key_t)0, unsigned int) &&
	CRABC_TYPE_IS((pthread_spinlock_t)0, int),
	"musl x86-64 pthread scalar types retain their public forms");

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef int (*crabc_select_signature)(
	int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict,
	struct timeval *__restrict);
typedef int (*crabc_pselect_signature)(
	int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict,
	const struct timespec *__restrict, const sigset_t *__restrict);

_Static_assert(CRABC_TYPE_IS((int8_t)0, signed char) &&
	CRABC_TYPE_IS((int16_t)0, signed short) &&
	CRABC_TYPE_IS((int32_t)0, signed int) &&
	CRABC_TYPE_IS((int64_t)0, long),
	"musl GNU/BSD signed integer vocabulary");
_Static_assert(CRABC_TYPE_IS((u_int64_t)0, unsigned long) &&
	CRABC_TYPE_IS((register_t)0, long),
	"musl GNU/BSD unsigned and register vocabulary");
_Static_assert(CRABC_TYPE_IS((u_int8_t)0, unsigned char) &&
	CRABC_TYPE_IS((u_int16_t)0, unsigned short) &&
	CRABC_TYPE_IS((u_int32_t)0, unsigned int),
	"musl GNU/BSD fixed-width aliases");
_Static_assert(CRABC_TYPE_IS((caddr_t)0, char *) &&
	CRABC_TYPE_IS((u_char)0, unsigned char) &&
	CRABC_TYPE_IS((u_short)0, unsigned short) &&
	CRABC_TYPE_IS((ushort)0, unsigned short),
	"musl GNU/BSD historical pointer and short aliases");
_Static_assert(CRABC_TYPE_IS((u_int)0, unsigned int) &&
	CRABC_TYPE_IS((uint)0, unsigned int) &&
	CRABC_TYPE_IS((u_long)0, unsigned long) &&
	CRABC_TYPE_IS((ulong)0, unsigned long),
	"musl GNU/BSD historical integer aliases");
_Static_assert(CRABC_TYPE_IS((quad_t)0, long long) &&
	CRABC_TYPE_IS((u_quad_t)0, unsigned long long),
	"musl GNU/BSD quad aliases");
_Static_assert(BYTE_ORDER == LITTLE_ENDIAN && PDP_ENDIAN == 3412,
	"musl GNU/BSD endian vocabulary");
_Static_assert(CRABC_TYPE_IS((fd_mask)0, unsigned long) &&
	FD_SETSIZE == 1024 && NFDBITS == 8 * (int)sizeof(long),
	"musl GNU/BSD select vocabulary");
_Static_assert(sizeof(fd_set) == 128 && sizeof(struct timeval) == 16 &&
	sizeof(struct timespec) == 16 && sizeof(sigset_t) == 128,
	"musl GNU/BSD select record layouts");
_Static_assert(__builtin_types_compatible_p(__typeof__(&select),
	crabc_select_signature), "musl GNU/BSD select declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pselect),
	crabc_pselect_signature), "musl GNU/BSD pselect declaration");
#endif

#if defined(_LARGEFILE64_SOURCE)
_Static_assert(CRABC_TYPE_IS((blkcnt64_t)0, long) &&
	CRABC_TYPE_IS((fsblkcnt64_t)0, unsigned long) &&
	CRABC_TYPE_IS((fsfilcnt64_t)0, unsigned long),
	"musl large-file counter aliases");
_Static_assert(CRABC_TYPE_IS((ino64_t)0, unsigned long) &&
	CRABC_TYPE_IS((off64_t)0, long),
	"musl large-file inode and offset aliases");
#endif

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
