/*
 * Linux/x86-64 C pthread/C11-thread public-header ABI probe.
 *
 * The companion runner compiles this exact translation unit against pinned
 * musl 1.2.6 and then against the project header tree in each named feature
 * profile.  It deliberately has no link step: these checks establish only
 * declarations, feature visibility, opaque-object layout, and macro/type
 * identity.  They do not select a crabc-libc artifact or pthread runtime.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

/* Both public include orders must name the same sched_param declaration. */
#if defined(CRABC_PTHREAD_C11_SCHED_FIRST)
#include <sched.h>
#include <pthread.h>
#else
#include <pthread.h>
#include <sched.h>
#endif
#include <signal.h>
#include <threads.h>
#include <time.h>

#ifndef PTHREAD_CANCEL_MASKED
#error "musl pthread.h exposes PTHREAD_CANCEL_MASKED"
#endif

#ifndef pthread_equal
#error "musl C pthread.h supplies the pthread_equal macro"
#endif

#ifndef thrd_equal
#error "musl C threads.h supplies the thrd_equal macro"
#endif

#ifndef thread_local
#error "musl C threads.h supplies the thread_local macro"
#endif

#if PTHREAD_CANCEL_MASKED != 2
#error "musl PTHREAD_CANCEL_MASKED is 2"
#endif

#if PTHREAD_CREATE_JOINABLE != 0 || PTHREAD_CREATE_DETACHED != 1
#error "unexpected musl pthread detach-state constants"
#endif

#if PTHREAD_MUTEX_NORMAL != 0 || PTHREAD_MUTEX_RECURSIVE != 1 || \
	PTHREAD_MUTEX_ERRORCHECK != 2
#error "unexpected musl pthread mutex-type constants"
#endif

#if PTHREAD_MUTEX_STALLED != 0 || PTHREAD_MUTEX_ROBUST != 1
#error "unexpected musl pthread robust-mutex constants"
#endif

#if PTHREAD_PROCESS_PRIVATE != 0 || PTHREAD_PROCESS_SHARED != 1
#error "unexpected musl pthread process-sharing constants"
#endif

#if PTHREAD_INHERIT_SCHED != 0 || PTHREAD_EXPLICIT_SCHED != 1
#error "unexpected musl pthread scheduling-inheritance constants"
#endif

#if PTHREAD_BARRIER_SERIAL_THREAD != -1
#error "unexpected musl pthread barrier result"
#endif

#if TSS_DTOR_ITERATIONS != 4
#error "unexpected musl C11 TSS destructor iteration count"
#endif

#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)

/* musl intentionally presents an opaque pointer pthread_t to C callers. */
_Static_assert(CRABC_TYPE_IS(pthread_t, struct __pthread *),
	"musl C pthread_t is struct __pthread *");
_Static_assert(CRABC_TYPE_IS(thrd_t, pthread_t),
	"musl C thrd_t has pthread_t identity");
_Static_assert(CRABC_TYPE_IS(once_flag, pthread_once_t),
	"musl C once_flag has pthread_once_t identity");
_Static_assert(CRABC_TYPE_IS(tss_t, pthread_key_t),
	"musl C tss_t has pthread_key_t identity");

/* The C11 synchronization records deliberately are not pthread typedefs. */
_Static_assert(!CRABC_TYPE_IS(mtx_t, pthread_mutex_t),
	"musl C mtx_t remains distinct from pthread_mutex_t");
_Static_assert(!CRABC_TYPE_IS(cnd_t, pthread_cond_t),
	"musl C cnd_t remains distinct from pthread_cond_t");

_Static_assert(sizeof(pthread_mutexattr_t) == 4 && _Alignof(pthread_mutexattr_t) == 4,
	"musl x86-64 pthread_mutexattr_t ABI");
_Static_assert(sizeof(pthread_condattr_t) == 4 && _Alignof(pthread_condattr_t) == 4,
	"musl x86-64 pthread_condattr_t ABI");
_Static_assert(sizeof(pthread_rwlockattr_t) == 8 && _Alignof(pthread_rwlockattr_t) == 4,
	"musl x86-64 pthread_rwlockattr_t ABI");
_Static_assert(sizeof(pthread_barrierattr_t) == 4 && _Alignof(pthread_barrierattr_t) == 4,
	"musl x86-64 pthread_barrierattr_t ABI");
_Static_assert(sizeof(pthread_mutex_t) == 40 && _Alignof(pthread_mutex_t) == 8,
	"musl x86-64 pthread_mutex_t ABI");
_Static_assert(sizeof(pthread_cond_t) == 48 && _Alignof(pthread_cond_t) == 8,
	"musl x86-64 pthread_cond_t ABI");
_Static_assert(sizeof(pthread_rwlock_t) == 56 && _Alignof(pthread_rwlock_t) == 8,
	"musl x86-64 pthread_rwlock_t ABI");
_Static_assert(sizeof(pthread_barrier_t) == 32 && _Alignof(pthread_barrier_t) == 8,
	"musl x86-64 pthread_barrier_t ABI");
_Static_assert(sizeof(pthread_attr_t) == 56 && _Alignof(pthread_attr_t) == 8,
	"musl x86-64 pthread_attr_t ABI");
_Static_assert(sizeof(mtx_t) == 40 && _Alignof(mtx_t) == 8,
	"musl x86-64 mtx_t ABI");
_Static_assert(sizeof(cnd_t) == 48 && _Alignof(cnd_t) == 8,
	"musl x86-64 cnd_t ABI");
_Static_assert(sizeof(once_flag) == 4 && _Alignof(once_flag) == 4,
	"musl x86-64 once_flag ABI");
_Static_assert(sizeof(tss_t) == 4 && _Alignof(tss_t) == 4,
	"musl x86-64 tss_t ABI");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
	"musl x86-64 timespec ABI used by pthread/C11 timed calls");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
	"musl x86-64 sigset_t ABI used by pthread_sigmask");
_Static_assert(sizeof(struct sched_param) == 48 && _Alignof(struct sched_param) == 8,
	"musl x86-64 sched_param ABI used by pthread scheduling calls");
_Static_assert(thrd_success == 0 && thrd_busy == 1 && thrd_error == 2
	&& thrd_nomem == 3 && thrd_timedout == 4,
	"musl C11 thread result vocabulary");
_Static_assert(mtx_plain == 0 && mtx_recursive == 1 && mtx_timed == 2,
	"musl C11 mutex-kind vocabulary");

typedef int (*crabc_pthread_create_signature)(
	pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
typedef int (*crabc_pthread_detach_signature)(pthread_t);
typedef int (*crabc_pthread_equal_signature)(pthread_t, pthread_t);
typedef int (*crabc_pthread_getcpuclockid_signature)(pthread_t, clockid_t *);
typedef int (*crabc_pthread_key_create_signature)(
	pthread_key_t *, void (*)(void *));
typedef int (*crabc_pthread_key_delete_signature)(pthread_key_t);
typedef void *(*crabc_pthread_getspecific_signature)(pthread_key_t);
typedef int (*crabc_pthread_setspecific_signature)(pthread_key_t, const void *);
typedef int (*crabc_pthread_sigmask_signature)(int, const sigset_t *, sigset_t *);
typedef int (*crabc_pthread_mutex_init_signature)(
	pthread_mutex_t *, const pthread_mutexattr_t *);
typedef int (*crabc_pthread_mutex_destroy_signature)(pthread_mutex_t *);
typedef int (*crabc_pthread_mutex_lock_signature)(pthread_mutex_t *);
typedef int (*crabc_pthread_mutex_trylock_signature)(pthread_mutex_t *);
typedef int (*crabc_pthread_mutex_unlock_signature)(pthread_mutex_t *);
typedef int (*crabc_pthread_cond_init_signature)(
	pthread_cond_t *, const pthread_condattr_t *);
typedef int (*crabc_pthread_cond_destroy_signature)(pthread_cond_t *);
typedef int (*crabc_pthread_cond_wait_signature)(pthread_cond_t *, pthread_mutex_t *);
typedef int (*crabc_pthread_cond_signal_signature)(pthread_cond_t *);
typedef int (*crabc_pthread_cond_broadcast_signature)(pthread_cond_t *);
typedef void (*crabc_once_init_signature)(void);
typedef int (*crabc_pthread_once_signature)(
	pthread_once_t *, crabc_once_init_signature);
typedef int (*crabc_thrd_create_signature)(thrd_t *, thrd_start_t, void *);
typedef int (*crabc_thrd_detach_signature)(thrd_t);
typedef int (*crabc_thrd_join_signature)(thrd_t, int *);
typedef void (*crabc_thrd_exit_signature)(int) __attribute__((noreturn));
typedef int (*crabc_thrd_sleep_signature)(const struct timespec *,
	struct timespec *);
typedef thrd_t (*crabc_thrd_current_signature)(void);
typedef int (*crabc_thrd_equal_signature)(thrd_t, thrd_t);
typedef void (*crabc_call_once_signature)(once_flag *, crabc_once_init_signature);
typedef int (*crabc_mtx_init_signature)(mtx_t *, int);
typedef void (*crabc_mtx_destroy_signature)(mtx_t *);
typedef int (*crabc_mtx_lock_signature)(mtx_t *);
typedef int (*crabc_mtx_trylock_signature)(mtx_t *);
typedef int (*crabc_mtx_unlock_signature)(mtx_t *);
typedef int (*crabc_mtx_timedlock_signature)(mtx_t *, const struct timespec *);
typedef int (*crabc_cnd_init_signature)(cnd_t *);
typedef void (*crabc_cnd_destroy_signature)(cnd_t *);
typedef int (*crabc_cnd_wait_signature)(cnd_t *, mtx_t *);
typedef int (*crabc_cnd_signal_signature)(cnd_t *);
typedef int (*crabc_cnd_broadcast_signature)(cnd_t *);
typedef int (*crabc_cnd_timedwait_signature)(
	cnd_t *, mtx_t *, const struct timespec *);
typedef int (*crabc_tss_create_signature)(tss_t *, tss_dtor_t);
typedef void (*crabc_tss_delete_signature)(tss_t);
typedef void *(*crabc_tss_get_signature)(tss_t);
typedef int (*crabc_tss_set_signature)(tss_t, void *);

_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_create), crabc_pthread_create_signature),
	"pthread_create signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_detach), crabc_pthread_detach_signature),
	"pthread_detach signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_equal), crabc_pthread_equal_signature),
	"pthread_equal signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_getcpuclockid),
	crabc_pthread_getcpuclockid_signature), "pthread_getcpuclockid signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_create),
	crabc_pthread_key_create_signature), "pthread_key_create signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_delete),
	crabc_pthread_key_delete_signature), "pthread_key_delete signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_getspecific),
	crabc_pthread_getspecific_signature), "pthread_getspecific signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_setspecific),
	crabc_pthread_setspecific_signature), "pthread_setspecific signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_mutex_init),
	crabc_pthread_mutex_init_signature), "pthread_mutex_init signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_mutex_destroy),
	crabc_pthread_mutex_destroy_signature), "pthread_mutex_destroy signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_mutex_lock),
	crabc_pthread_mutex_lock_signature), "pthread_mutex_lock signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_mutex_trylock),
	crabc_pthread_mutex_trylock_signature), "pthread_mutex_trylock signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_mutex_unlock),
	crabc_pthread_mutex_unlock_signature), "pthread_mutex_unlock signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cond_init),
	crabc_pthread_cond_init_signature), "pthread_cond_init signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cond_destroy),
	crabc_pthread_cond_destroy_signature), "pthread_cond_destroy signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cond_wait),
	crabc_pthread_cond_wait_signature), "pthread_cond_wait signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cond_signal),
	crabc_pthread_cond_signal_signature), "pthread_cond_signal signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cond_broadcast),
	crabc_pthread_cond_broadcast_signature), "pthread_cond_broadcast signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_once), crabc_pthread_once_signature),
	"pthread_once signature");
#if defined(CRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS)
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_sigmask),
	crabc_pthread_sigmask_signature), "pthread_sigmask signature");
#endif
_Static_assert(CRABC_TYPE_IS(__typeof__(&thrd_create), crabc_thrd_create_signature),
	"thrd_create signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&thrd_detach), crabc_thrd_detach_signature),
	"thrd_detach signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&thrd_join), crabc_thrd_join_signature),
	"thrd_join signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&thrd_exit), crabc_thrd_exit_signature),
	"thrd_exit noreturn signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&thrd_sleep), crabc_thrd_sleep_signature),
	"thrd_sleep signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&thrd_current), crabc_thrd_current_signature),
	"thrd_current signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&thrd_equal), crabc_thrd_equal_signature),
	"thrd_equal signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&call_once), crabc_call_once_signature),
	"call_once signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_init), crabc_mtx_init_signature),
	"mtx_init signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_destroy), crabc_mtx_destroy_signature),
	"mtx_destroy signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_lock), crabc_mtx_lock_signature),
	"mtx_lock signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_trylock), crabc_mtx_trylock_signature),
	"mtx_trylock signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_unlock), crabc_mtx_unlock_signature),
	"mtx_unlock signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_timedlock), crabc_mtx_timedlock_signature),
	"mtx_timedlock signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_init), crabc_cnd_init_signature),
	"cnd_init signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_destroy), crabc_cnd_destroy_signature),
	"cnd_destroy signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_wait), crabc_cnd_wait_signature),
	"cnd_wait signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_signal), crabc_cnd_signal_signature),
	"cnd_signal signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_broadcast), crabc_cnd_broadcast_signature),
	"cnd_broadcast signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_timedwait), crabc_cnd_timedwait_signature),
	"cnd_timedwait signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_create), crabc_tss_create_signature),
	"tss_create signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_delete), crabc_tss_delete_signature),
	"tss_delete signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_get), crabc_tss_get_signature),
	"tss_get signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_set), crabc_tss_set_signature),
	"tss_set signature");

static pthread_mutex_t crabc_pthread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crabc_pthread_condition = PTHREAD_COND_INITIALIZER;
static pthread_rwlock_t crabc_pthread_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_once_t crabc_pthread_once = PTHREAD_ONCE_INIT;
static once_flag crabc_c11_once = ONCE_FLAG_INIT;

static void crabc_cleanup(void *argument)
{
	(void)argument;
}

static void crabc_cleanup_macro_shape(void)
{
	pthread_cleanup_push(crabc_cleanup, 0);
	pthread_cleanup_pop(0);
}

#if defined(CRABC_EXPECT_GNU_PTHREAD_EXTENSIONS)
typedef int (*crabc_pthread_timedjoin_signature)(
	pthread_t, void **, const struct timespec *);
typedef int (*crabc_pthread_getaffinity_np_signature)(
	pthread_t, size_t, struct cpu_set_t *);
typedef int (*crabc_pthread_setaffinity_np_signature)(
	pthread_t, size_t, const struct cpu_set_t *);
typedef int (*crabc_pthread_getattr_np_signature)(pthread_t, pthread_attr_t *);
typedef int (*crabc_pthread_setname_np_signature)(pthread_t, const char *);
typedef int (*crabc_pthread_getname_np_signature)(pthread_t, char *, size_t);

_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_getaffinity_np),
	crabc_pthread_getaffinity_np_signature), "pthread_getaffinity_np signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_setaffinity_np),
	crabc_pthread_setaffinity_np_signature), "pthread_setaffinity_np signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_getattr_np),
	crabc_pthread_getattr_np_signature), "pthread_getattr_np signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_setname_np),
	crabc_pthread_setname_np_signature), "pthread_setname_np signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_getname_np),
	crabc_pthread_getname_np_signature), "pthread_getname_np signature");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_timedjoin_np),
	crabc_pthread_timedjoin_signature), "pthread_timedjoin_np signature");
#endif

int crabc_x86_64_pthread_c11_header_abi_probe(void)
{
	/* Retain the initializer and macro expressions in the C object. */
	return pthread_equal(PTHREAD_NULL, PTHREAD_NULL)
		+ thrd_equal((thrd_t)0, (thrd_t)0)
		+ (int)crabc_pthread_once
		+ (int)crabc_c11_once
		+ (int)(sizeof(crabc_pthread_mutex)
			+ sizeof(crabc_pthread_condition)
			+ sizeof(crabc_pthread_rwlock));
}
