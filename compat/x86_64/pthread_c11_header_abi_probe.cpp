/*
 * Linux/x86-64 C++17 pthread/C11-thread public-header ABI probe.
 *
 * The companion runner builds this source without linking under pinned musl
 * and project-header-first inputs.  Its object-level undefined-symbol check
 * additionally proves that the public pthread declarations request C, not
 * C++, linkage.  No crabc runtime artifact is selected.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

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

static_assert(__is_same(pthread_t, unsigned long),
	"musl C++ pthread_t is unsigned long");
static_assert(__is_same(thrd_t, pthread_t),
	"musl C++ thrd_t has pthread_t identity");
static_assert(__is_same(once_flag, pthread_once_t),
	"musl C++ once_flag has pthread_once_t identity");
static_assert(__is_same(tss_t, pthread_key_t),
	"musl C++ tss_t has pthread_key_t identity");
static_assert(!__is_same(mtx_t, pthread_mutex_t),
	"musl C++ mtx_t remains distinct from pthread_mutex_t");
static_assert(!__is_same(cnd_t, pthread_cond_t),
	"musl C++ cnd_t remains distinct from pthread_cond_t");

static_assert(sizeof(pthread_mutexattr_t) == 4 && alignof(pthread_mutexattr_t) == 4,
	"musl x86-64 pthread_mutexattr_t ABI");
static_assert(sizeof(pthread_condattr_t) == 4 && alignof(pthread_condattr_t) == 4,
	"musl x86-64 pthread_condattr_t ABI");
static_assert(sizeof(pthread_rwlockattr_t) == 8 && alignof(pthread_rwlockattr_t) == 4,
	"musl x86-64 pthread_rwlockattr_t ABI");
static_assert(sizeof(pthread_barrierattr_t) == 4 && alignof(pthread_barrierattr_t) == 4,
	"musl x86-64 pthread_barrierattr_t ABI");
static_assert(sizeof(pthread_mutex_t) == 40 && alignof(pthread_mutex_t) == 8,
	"musl x86-64 pthread_mutex_t ABI");
static_assert(sizeof(pthread_cond_t) == 48 && alignof(pthread_cond_t) == 8,
	"musl x86-64 pthread_cond_t ABI");
static_assert(sizeof(pthread_rwlock_t) == 56 && alignof(pthread_rwlock_t) == 8,
	"musl x86-64 pthread_rwlock_t ABI");
static_assert(sizeof(pthread_barrier_t) == 32 && alignof(pthread_barrier_t) == 8,
	"musl x86-64 pthread_barrier_t ABI");
static_assert(sizeof(pthread_attr_t) == 56 && alignof(pthread_attr_t) == 8,
	"musl x86-64 pthread_attr_t ABI");
static_assert(sizeof(mtx_t) == 40 && alignof(mtx_t) == 8,
	"musl x86-64 mtx_t ABI");
static_assert(sizeof(cnd_t) == 48 && alignof(cnd_t) == 8,
	"musl x86-64 cnd_t ABI");
static_assert(sizeof(once_flag) == 4 && alignof(once_flag) == 4,
	"musl x86-64 once_flag ABI");
static_assert(sizeof(tss_t) == 4 && alignof(tss_t) == 4,
	"musl x86-64 tss_t ABI");
static_assert(sizeof(timespec) == 16 && alignof(timespec) == 8,
	"musl x86-64 timespec ABI used by pthread/C11 timed calls");
static_assert(sizeof(sigset_t) == 128 && alignof(sigset_t) == 8,
	"musl x86-64 sigset_t ABI used by pthread_sigmask");
static_assert(sizeof(sched_param) == 48 && alignof(sched_param) == 8,
	"musl x86-64 sched_param ABI used by pthread scheduling calls");
static_assert(thrd_success == 0 && thrd_busy == 1 && thrd_error == 2
	&& thrd_nomem == 3 && thrd_timedout == 4,
	"musl C11 thread result vocabulary");
static_assert(mtx_plain == 0 && mtx_recursive == 1 && mtx_timed == 2,
	"musl C11 mutex-kind vocabulary");

using crabc_pthread_create_signature = int (*)(
	pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
using crabc_pthread_detach_signature = int (*)(pthread_t);
using crabc_pthread_self_signature = pthread_t (*)();
using crabc_pthread_equal_signature = int (*)(pthread_t, pthread_t);
using crabc_pthread_getcpuclockid_signature = int (*)(pthread_t, clockid_t *);
using crabc_pthread_key_create_signature = int (*)(
	pthread_key_t *, void (*)(void *));
using crabc_pthread_key_delete_signature = int (*)(pthread_key_t);
using crabc_pthread_getspecific_signature = void *(*)(pthread_key_t);
using crabc_pthread_setspecific_signature = int (*)(pthread_key_t, const void *);
using crabc_pthread_sigmask_signature = int (*)(int, const sigset_t *, sigset_t *);
using crabc_pthread_mutex_init_signature = int (*)(
	pthread_mutex_t *, const pthread_mutexattr_t *);
using crabc_pthread_mutexattr_getprotocol_signature = int (*)(
	const pthread_mutexattr_t *, int *);
using crabc_pthread_mutexattr_getrobust_signature = int (*)(
	const pthread_mutexattr_t *, int *);
using crabc_pthread_mutex_destroy_signature = int (*)(pthread_mutex_t *);
using crabc_pthread_mutex_lock_signature = int (*)(pthread_mutex_t *);
using crabc_pthread_mutex_trylock_signature = int (*)(pthread_mutex_t *);
using crabc_pthread_mutex_unlock_signature = int (*)(pthread_mutex_t *);
using crabc_pthread_cond_init_signature = int (*)(
	pthread_cond_t *, const pthread_condattr_t *);
using crabc_pthread_cond_destroy_signature = int (*)(pthread_cond_t *);
using crabc_pthread_cond_wait_signature = int (*)(pthread_cond_t *, pthread_mutex_t *);
using crabc_pthread_cond_signal_signature = int (*)(pthread_cond_t *);
using crabc_pthread_cond_broadcast_signature = int (*)(pthread_cond_t *);
using crabc_pthread_rwlock_init_signature = int (*)
	(pthread_rwlock_t *, const pthread_rwlockattr_t *);
using crabc_pthread_rwlock_destroy_signature = int (*)(pthread_rwlock_t *);
using crabc_pthread_rwlock_rdlock_signature = int (*)(pthread_rwlock_t *);
using crabc_pthread_rwlock_tryrdlock_signature = int (*)(pthread_rwlock_t *);
using crabc_pthread_rwlock_timedrdlock_signature = int (*)
	(pthread_rwlock_t *, const timespec *);
using crabc_pthread_rwlock_wrlock_signature = int (*)(pthread_rwlock_t *);
using crabc_pthread_rwlock_trywrlock_signature = int (*)(pthread_rwlock_t *);
using crabc_pthread_rwlock_timedwrlock_signature = int (*)
	(pthread_rwlock_t *, const timespec *);
using crabc_pthread_rwlock_unlock_signature = int (*)(pthread_rwlock_t *);
using crabc_pthread_rwlockattr_init_signature = int (*)(pthread_rwlockattr_t *);
using crabc_pthread_rwlockattr_destroy_signature = int (*)(pthread_rwlockattr_t *);
using crabc_pthread_rwlockattr_setpshared_signature = int (*)
	(pthread_rwlockattr_t *, int);
using crabc_pthread_rwlockattr_getpshared_signature = int (*)
	(const pthread_rwlockattr_t *, int *);
using crabc_pthread_barrierattr_setpshared_signature = int (*)
	(pthread_barrierattr_t *, int);
using crabc_pthread_barrierattr_getpshared_signature = int (*)
	(const pthread_barrierattr_t *, int *);
using crabc_pthread_condattr_setpshared_signature = int (*)
	(pthread_condattr_t *, int);
using crabc_pthread_condattr_getpshared_signature = int (*)
	(const pthread_condattr_t *, int *);
using crabc_pthread_condattr_setclock_signature = int (*)
	(pthread_condattr_t *, clockid_t);
using crabc_pthread_condattr_getclock_signature = int (*)
	(const pthread_condattr_t *, clockid_t *);
using crabc_once_init_signature = void (*)();
using crabc_pthread_once_signature = int (*)(
	pthread_once_t *, crabc_once_init_signature);
using crabc_thrd_create_signature = int (*)(thrd_t *, thrd_start_t, void *);
using crabc_thrd_detach_signature = int (*)(thrd_t);
using crabc_thrd_join_signature = int (*)(thrd_t, int *);
using crabc_thrd_exit_signature = void (*)(int);
using crabc_thrd_sleep_signature = int (*)(const timespec *, timespec *);
using crabc_thrd_yield_signature = void (*)();
using crabc_thrd_current_signature = thrd_t (*)();
using crabc_thrd_equal_signature = int (*)(thrd_t, thrd_t);
using crabc_call_once_signature = void (*)(once_flag *, crabc_once_init_signature);
using crabc_mtx_init_signature = int (*)(mtx_t *, int);
using crabc_mtx_destroy_signature = void (*)(mtx_t *);
using crabc_mtx_lock_signature = int (*)(mtx_t *);
using crabc_mtx_trylock_signature = int (*)(mtx_t *);
using crabc_mtx_unlock_signature = int (*)(mtx_t *);
using crabc_mtx_timedlock_signature = int (*)(mtx_t *, const timespec *);
using crabc_cnd_init_signature = int (*)(cnd_t *);
using crabc_cnd_destroy_signature = void (*)(cnd_t *);
using crabc_cnd_wait_signature = int (*)(cnd_t *, mtx_t *);
using crabc_cnd_signal_signature = int (*)(cnd_t *);
using crabc_cnd_broadcast_signature = int (*)(cnd_t *);
using crabc_cnd_timedwait_signature = int (*)(cnd_t *, mtx_t *, const timespec *);
using crabc_tss_create_signature = int (*)(tss_t *, tss_dtor_t);
using crabc_tss_delete_signature = void (*)(tss_t);
using crabc_tss_get_signature = void *(*)(tss_t);
using crabc_tss_set_signature = int (*)(tss_t, void *);

static_assert(__is_same(decltype(&pthread_create), crabc_pthread_create_signature),
	"pthread_create signature");
static_assert(__is_same(decltype(&pthread_detach), crabc_pthread_detach_signature),
	"pthread_detach signature");
static_assert(__is_same(decltype(&pthread_self), crabc_pthread_self_signature),
	"pthread_self signature");
static_assert(__is_same(decltype(&pthread_equal), crabc_pthread_equal_signature),
	"pthread_equal signature");
static_assert(__is_same(decltype(&pthread_getcpuclockid),
	crabc_pthread_getcpuclockid_signature), "pthread_getcpuclockid signature");
static_assert(__is_same(decltype(&pthread_key_create),
	crabc_pthread_key_create_signature), "pthread_key_create signature");
static_assert(__is_same(decltype(&pthread_key_delete),
	crabc_pthread_key_delete_signature), "pthread_key_delete signature");
static_assert(__is_same(decltype(&pthread_getspecific),
	crabc_pthread_getspecific_signature), "pthread_getspecific signature");
static_assert(__is_same(decltype(&pthread_setspecific),
	crabc_pthread_setspecific_signature), "pthread_setspecific signature");
static_assert(__is_same(decltype(&pthread_mutex_init),
	crabc_pthread_mutex_init_signature), "pthread_mutex_init signature");
static_assert(__is_same(decltype(&pthread_mutexattr_getprotocol),
	crabc_pthread_mutexattr_getprotocol_signature), "pthread_mutexattr_getprotocol signature");
static_assert(__is_same(decltype(&pthread_mutexattr_getrobust),
	crabc_pthread_mutexattr_getrobust_signature), "pthread_mutexattr_getrobust signature");
static_assert(__is_same(decltype(&pthread_mutex_destroy),
	crabc_pthread_mutex_destroy_signature), "pthread_mutex_destroy signature");
static_assert(__is_same(decltype(&pthread_mutex_lock),
	crabc_pthread_mutex_lock_signature), "pthread_mutex_lock signature");
static_assert(__is_same(decltype(&pthread_mutex_trylock),
	crabc_pthread_mutex_trylock_signature), "pthread_mutex_trylock signature");
static_assert(__is_same(decltype(&pthread_mutex_unlock),
	crabc_pthread_mutex_unlock_signature), "pthread_mutex_unlock signature");
static_assert(__is_same(decltype(&pthread_cond_init),
	crabc_pthread_cond_init_signature), "pthread_cond_init signature");
static_assert(__is_same(decltype(&pthread_cond_destroy),
	crabc_pthread_cond_destroy_signature), "pthread_cond_destroy signature");
static_assert(__is_same(decltype(&pthread_cond_wait),
	crabc_pthread_cond_wait_signature), "pthread_cond_wait signature");
static_assert(__is_same(decltype(&pthread_cond_signal),
	crabc_pthread_cond_signal_signature), "pthread_cond_signal signature");
static_assert(__is_same(decltype(&pthread_cond_broadcast),
	crabc_pthread_cond_broadcast_signature), "pthread_cond_broadcast signature");
static_assert(__is_same(decltype(&pthread_rwlock_init),
	crabc_pthread_rwlock_init_signature), "pthread_rwlock_init signature");
static_assert(__is_same(decltype(&pthread_rwlock_destroy),
	crabc_pthread_rwlock_destroy_signature), "pthread_rwlock_destroy signature");
static_assert(__is_same(decltype(&pthread_rwlock_rdlock),
	crabc_pthread_rwlock_rdlock_signature), "pthread_rwlock_rdlock signature");
static_assert(__is_same(decltype(&pthread_rwlock_tryrdlock),
	crabc_pthread_rwlock_tryrdlock_signature), "pthread_rwlock_tryrdlock signature");
static_assert(__is_same(decltype(&pthread_rwlock_timedrdlock),
	crabc_pthread_rwlock_timedrdlock_signature), "pthread_rwlock_timedrdlock signature");
static_assert(__is_same(decltype(&pthread_rwlock_wrlock),
	crabc_pthread_rwlock_wrlock_signature), "pthread_rwlock_wrlock signature");
static_assert(__is_same(decltype(&pthread_rwlock_trywrlock),
	crabc_pthread_rwlock_trywrlock_signature), "pthread_rwlock_trywrlock signature");
static_assert(__is_same(decltype(&pthread_rwlock_timedwrlock),
	crabc_pthread_rwlock_timedwrlock_signature), "pthread_rwlock_timedwrlock signature");
static_assert(__is_same(decltype(&pthread_rwlock_unlock),
	crabc_pthread_rwlock_unlock_signature), "pthread_rwlock_unlock signature");
static_assert(__is_same(decltype(&pthread_rwlockattr_init),
	crabc_pthread_rwlockattr_init_signature), "pthread_rwlockattr_init signature");
static_assert(__is_same(decltype(&pthread_rwlockattr_destroy),
	crabc_pthread_rwlockattr_destroy_signature), "pthread_rwlockattr_destroy signature");
static_assert(__is_same(decltype(&pthread_rwlockattr_setpshared),
	crabc_pthread_rwlockattr_setpshared_signature), "pthread_rwlockattr_setpshared signature");
static_assert(__is_same(decltype(&pthread_rwlockattr_getpshared),
	crabc_pthread_rwlockattr_getpshared_signature), "pthread_rwlockattr_getpshared signature");
static_assert(__is_same(decltype(&pthread_barrierattr_setpshared),
	crabc_pthread_barrierattr_setpshared_signature), "pthread_barrierattr_setpshared signature");
static_assert(__is_same(decltype(&pthread_barrierattr_getpshared),
	crabc_pthread_barrierattr_getpshared_signature), "pthread_barrierattr_getpshared signature");
static_assert(__is_same(decltype(&pthread_condattr_setpshared),
	crabc_pthread_condattr_setpshared_signature), "pthread_condattr_setpshared signature");
static_assert(__is_same(decltype(&pthread_condattr_getpshared),
	crabc_pthread_condattr_getpshared_signature), "pthread_condattr_getpshared signature");
static_assert(__is_same(decltype(&pthread_condattr_setclock),
	crabc_pthread_condattr_setclock_signature), "pthread_condattr_setclock signature");
static_assert(__is_same(decltype(&pthread_condattr_getclock),
	crabc_pthread_condattr_getclock_signature), "pthread_condattr_getclock signature");
static_assert(__is_same(decltype(&pthread_once), crabc_pthread_once_signature),
	"pthread_once signature");
#if defined(CRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS)
static_assert(__is_same(decltype(&pthread_sigmask),
	crabc_pthread_sigmask_signature), "pthread_sigmask signature");
#endif
static_assert(__is_same(decltype(&thrd_create), crabc_thrd_create_signature),
	"thrd_create signature");
static_assert(__is_same(decltype(&thrd_detach), crabc_thrd_detach_signature),
	"thrd_detach signature");
static_assert(__is_same(decltype(&thrd_join), crabc_thrd_join_signature),
	"thrd_join signature");
static_assert(__is_same(decltype(&thrd_exit), crabc_thrd_exit_signature),
	"thrd_exit noreturn signature");
static_assert(__is_same(decltype(&thrd_sleep), crabc_thrd_sleep_signature),
	"thrd_sleep signature");
static_assert(__is_same(decltype(&thrd_yield), crabc_thrd_yield_signature),
	"thrd_yield signature");
static_assert(__is_same(decltype(&thrd_current), crabc_thrd_current_signature),
	"thrd_current signature");
static_assert(__is_same(decltype(&thrd_equal), crabc_thrd_equal_signature),
	"thrd_equal signature");
static_assert(__is_same(decltype(&call_once), crabc_call_once_signature),
	"call_once signature");
static_assert(__is_same(decltype(&mtx_init), crabc_mtx_init_signature),
	"mtx_init signature");
static_assert(__is_same(decltype(&mtx_destroy), crabc_mtx_destroy_signature),
	"mtx_destroy signature");
static_assert(__is_same(decltype(&mtx_lock), crabc_mtx_lock_signature),
	"mtx_lock signature");
static_assert(__is_same(decltype(&mtx_trylock), crabc_mtx_trylock_signature),
	"mtx_trylock signature");
static_assert(__is_same(decltype(&mtx_unlock), crabc_mtx_unlock_signature),
	"mtx_unlock signature");
static_assert(__is_same(decltype(&mtx_timedlock), crabc_mtx_timedlock_signature),
	"mtx_timedlock signature");
static_assert(__is_same(decltype(&cnd_init), crabc_cnd_init_signature),
	"cnd_init signature");
static_assert(__is_same(decltype(&cnd_destroy), crabc_cnd_destroy_signature),
	"cnd_destroy signature");
static_assert(__is_same(decltype(&cnd_wait), crabc_cnd_wait_signature),
	"cnd_wait signature");
static_assert(__is_same(decltype(&cnd_signal), crabc_cnd_signal_signature),
	"cnd_signal signature");
static_assert(__is_same(decltype(&cnd_broadcast), crabc_cnd_broadcast_signature),
	"cnd_broadcast signature");
static_assert(__is_same(decltype(&cnd_timedwait), crabc_cnd_timedwait_signature),
	"cnd_timedwait signature");
static_assert(__is_same(decltype(&tss_create), crabc_tss_create_signature),
	"tss_create signature");
static_assert(__is_same(decltype(&tss_delete), crabc_tss_delete_signature),
	"tss_delete signature");
static_assert(__is_same(decltype(&tss_get), crabc_tss_get_signature),
	"tss_get signature");
static_assert(__is_same(decltype(&tss_set), crabc_tss_set_signature),
	"tss_set signature");

static pthread_mutex_t crabc_pthread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crabc_pthread_condition = PTHREAD_COND_INITIALIZER;
static pthread_rwlock_t crabc_pthread_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_once_t crabc_pthread_once = PTHREAD_ONCE_INIT;
static once_flag crabc_c11_once = ONCE_FLAG_INIT;

/* `used` keeps the declaration-linkage evidence in the otherwise unlinked object. */
static crabc_pthread_create_signature const crabc_force_pthread_create
	__attribute__((used)) = &pthread_create;
static crabc_pthread_detach_signature const crabc_force_pthread_detach
	__attribute__((used)) = &pthread_detach;
static crabc_pthread_self_signature const crabc_force_pthread_self
	__attribute__((used)) = &pthread_self;
static crabc_pthread_equal_signature const crabc_force_pthread_equal
	__attribute__((used)) = &pthread_equal;
static crabc_pthread_getcpuclockid_signature const crabc_force_pthread_getcpuclockid
	__attribute__((used)) = &pthread_getcpuclockid;
static crabc_pthread_key_create_signature const crabc_force_pthread_key_create
	__attribute__((used)) = &pthread_key_create;
static crabc_pthread_key_delete_signature const crabc_force_pthread_key_delete
	__attribute__((used)) = &pthread_key_delete;
static crabc_pthread_getspecific_signature const crabc_force_pthread_getspecific
	__attribute__((used)) = &pthread_getspecific;
static crabc_pthread_setspecific_signature const crabc_force_pthread_setspecific
	__attribute__((used)) = &pthread_setspecific;
static crabc_pthread_mutex_init_signature const crabc_force_pthread_mutex_init
	__attribute__((used)) = &pthread_mutex_init;
static crabc_pthread_mutexattr_getprotocol_signature const crabc_force_pthread_mutexattr_getprotocol
	__attribute__((used)) = &pthread_mutexattr_getprotocol;
static crabc_pthread_mutexattr_getrobust_signature const crabc_force_pthread_mutexattr_getrobust
	__attribute__((used)) = &pthread_mutexattr_getrobust;
static crabc_pthread_mutex_destroy_signature const crabc_force_pthread_mutex_destroy
	__attribute__((used)) = &pthread_mutex_destroy;
static crabc_pthread_mutex_lock_signature const crabc_force_pthread_mutex_lock
	__attribute__((used)) = &pthread_mutex_lock;
static crabc_pthread_mutex_trylock_signature const crabc_force_pthread_mutex_trylock
	__attribute__((used)) = &pthread_mutex_trylock;
static crabc_pthread_mutex_unlock_signature const crabc_force_pthread_mutex_unlock
	__attribute__((used)) = &pthread_mutex_unlock;
static crabc_pthread_cond_init_signature const crabc_force_pthread_cond_init
	__attribute__((used)) = &pthread_cond_init;
static crabc_pthread_cond_destroy_signature const crabc_force_pthread_cond_destroy
	__attribute__((used)) = &pthread_cond_destroy;
static crabc_pthread_cond_wait_signature const crabc_force_pthread_cond_wait
	__attribute__((used)) = &pthread_cond_wait;
static crabc_pthread_cond_signal_signature const crabc_force_pthread_cond_signal
	__attribute__((used)) = &pthread_cond_signal;
static crabc_pthread_cond_broadcast_signature const crabc_force_pthread_cond_broadcast
	__attribute__((used)) = &pthread_cond_broadcast;
static crabc_pthread_rwlock_init_signature const crabc_force_pthread_rwlock_init
	__attribute__((used)) = &pthread_rwlock_init;
static crabc_pthread_rwlock_destroy_signature const crabc_force_pthread_rwlock_destroy
	__attribute__((used)) = &pthread_rwlock_destroy;
static crabc_pthread_rwlock_rdlock_signature const crabc_force_pthread_rwlock_rdlock
	__attribute__((used)) = &pthread_rwlock_rdlock;
static crabc_pthread_rwlock_tryrdlock_signature const crabc_force_pthread_rwlock_tryrdlock
	__attribute__((used)) = &pthread_rwlock_tryrdlock;
static crabc_pthread_rwlock_timedrdlock_signature const crabc_force_pthread_rwlock_timedrdlock
	__attribute__((used)) = &pthread_rwlock_timedrdlock;
static crabc_pthread_rwlock_wrlock_signature const crabc_force_pthread_rwlock_wrlock
	__attribute__((used)) = &pthread_rwlock_wrlock;
static crabc_pthread_rwlock_trywrlock_signature const crabc_force_pthread_rwlock_trywrlock
	__attribute__((used)) = &pthread_rwlock_trywrlock;
static crabc_pthread_rwlock_timedwrlock_signature const crabc_force_pthread_rwlock_timedwrlock
	__attribute__((used)) = &pthread_rwlock_timedwrlock;
static crabc_pthread_rwlock_unlock_signature const crabc_force_pthread_rwlock_unlock
	__attribute__((used)) = &pthread_rwlock_unlock;
static crabc_pthread_rwlockattr_init_signature const crabc_force_pthread_rwlockattr_init
	__attribute__((used)) = &pthread_rwlockattr_init;
static crabc_pthread_rwlockattr_destroy_signature const crabc_force_pthread_rwlockattr_destroy
	__attribute__((used)) = &pthread_rwlockattr_destroy;
static crabc_pthread_rwlockattr_setpshared_signature const crabc_force_pthread_rwlockattr_setpshared
	__attribute__((used)) = &pthread_rwlockattr_setpshared;
static crabc_pthread_rwlockattr_getpshared_signature const crabc_force_pthread_rwlockattr_getpshared
	__attribute__((used)) = &pthread_rwlockattr_getpshared;
static crabc_pthread_barrierattr_setpshared_signature const crabc_force_pthread_barrierattr_setpshared
	__attribute__((used)) = &pthread_barrierattr_setpshared;
static crabc_pthread_barrierattr_getpshared_signature const crabc_force_pthread_barrierattr_getpshared
	__attribute__((used)) = &pthread_barrierattr_getpshared;
static crabc_pthread_condattr_setpshared_signature const crabc_force_pthread_condattr_setpshared
	__attribute__((used)) = &pthread_condattr_setpshared;
static crabc_pthread_condattr_getpshared_signature const crabc_force_pthread_condattr_getpshared
	__attribute__((used)) = &pthread_condattr_getpshared;
static crabc_pthread_condattr_setclock_signature const crabc_force_pthread_condattr_setclock
	__attribute__((used)) = &pthread_condattr_setclock;
static crabc_pthread_condattr_getclock_signature const crabc_force_pthread_condattr_getclock
	__attribute__((used)) = &pthread_condattr_getclock;
static crabc_pthread_once_signature const crabc_force_pthread_once
	__attribute__((used)) = &pthread_once;
static crabc_thrd_create_signature const crabc_force_thrd_create
	__attribute__((used)) = &thrd_create;
static crabc_thrd_detach_signature const crabc_force_thrd_detach
	__attribute__((used)) = &thrd_detach;
static crabc_thrd_join_signature const crabc_force_thrd_join
	__attribute__((used)) = &thrd_join;
static crabc_thrd_exit_signature const crabc_force_thrd_exit
	__attribute__((used)) = &thrd_exit;
static crabc_thrd_sleep_signature const crabc_force_thrd_sleep
	__attribute__((used)) = &thrd_sleep;
static crabc_thrd_yield_signature const crabc_force_thrd_yield
	__attribute__((used)) = &thrd_yield;
static crabc_thrd_current_signature const crabc_force_thrd_current
	__attribute__((used)) = &thrd_current;
static crabc_thrd_equal_signature const crabc_force_thrd_equal
	__attribute__((used)) = &thrd_equal;
static crabc_call_once_signature const crabc_force_call_once
	__attribute__((used)) = &call_once;
static crabc_tss_create_signature const crabc_force_tss_create
	__attribute__((used)) = &tss_create;
static crabc_tss_delete_signature const crabc_force_tss_delete
	__attribute__((used)) = &tss_delete;
static crabc_tss_get_signature const crabc_force_tss_get
	__attribute__((used)) = &tss_get;
static crabc_tss_set_signature const crabc_force_tss_set
	__attribute__((used)) = &tss_set;
static crabc_mtx_init_signature const crabc_force_mtx_init
	__attribute__((used)) = &mtx_init;
static crabc_mtx_destroy_signature const crabc_force_mtx_destroy
	__attribute__((used)) = &mtx_destroy;
static crabc_mtx_lock_signature const crabc_force_mtx_lock
	__attribute__((used)) = &mtx_lock;
static crabc_mtx_trylock_signature const crabc_force_mtx_trylock
	__attribute__((used)) = &mtx_trylock;
static crabc_mtx_unlock_signature const crabc_force_mtx_unlock
	__attribute__((used)) = &mtx_unlock;
static crabc_cnd_init_signature const crabc_force_cnd_init
	__attribute__((used)) = &cnd_init;
static crabc_cnd_destroy_signature const crabc_force_cnd_destroy
	__attribute__((used)) = &cnd_destroy;
static crabc_cnd_wait_signature const crabc_force_cnd_wait
	__attribute__((used)) = &cnd_wait;
static crabc_cnd_signal_signature const crabc_force_cnd_signal
	__attribute__((used)) = &cnd_signal;
static crabc_cnd_broadcast_signature const crabc_force_cnd_broadcast
	__attribute__((used)) = &cnd_broadcast;
#if defined(CRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS)
static crabc_pthread_sigmask_signature const crabc_force_pthread_sigmask
	__attribute__((used)) = &pthread_sigmask;
#endif

#if defined(CRABC_EXPECT_GNU_PTHREAD_EXTENSIONS)
static_assert(sizeof(cpu_set_t) == 128 && alignof(cpu_set_t) == 8,
	"musl x86-64 cpu_set_t ABI used by pthread affinity calls");
using crabc_pthread_timedjoin_signature = int (*)(
	pthread_t, void **, const timespec *);
using crabc_pthread_getaffinity_np_signature = int (*)(
	pthread_t, size_t, struct cpu_set_t *);
using crabc_pthread_setaffinity_np_signature = int (*)(
	pthread_t, size_t, const struct cpu_set_t *);
using crabc_pthread_getattr_np_signature = int (*)(pthread_t, pthread_attr_t *);
using crabc_pthread_setname_np_signature = int (*)(pthread_t, const char *);
using crabc_pthread_getname_np_signature = int (*)(pthread_t, char *, size_t);

static_assert(__is_same(decltype(&pthread_getaffinity_np),
	crabc_pthread_getaffinity_np_signature), "pthread_getaffinity_np signature");
static_assert(__is_same(decltype(&pthread_setaffinity_np),
	crabc_pthread_setaffinity_np_signature), "pthread_setaffinity_np signature");
static_assert(__is_same(decltype(&pthread_getattr_np),
	crabc_pthread_getattr_np_signature), "pthread_getattr_np signature");
static_assert(__is_same(decltype(&pthread_setname_np),
	crabc_pthread_setname_np_signature), "pthread_setname_np signature");
static_assert(__is_same(decltype(&pthread_getname_np),
	crabc_pthread_getname_np_signature), "pthread_getname_np signature");
static_assert(__is_same(decltype(&pthread_timedjoin_np),
	crabc_pthread_timedjoin_signature), "pthread_timedjoin_np signature");

static crabc_pthread_getaffinity_np_signature const crabc_force_pthread_getaffinity_np
	__attribute__((used)) = &pthread_getaffinity_np;
static crabc_pthread_setname_np_signature const crabc_force_pthread_setname_np
	__attribute__((used)) = &pthread_setname_np;
static crabc_pthread_getname_np_signature const crabc_force_pthread_getname_np
	__attribute__((used)) = &pthread_getname_np;
#endif

int crabc_x86_64_pthread_c11_header_abi_probe()
{
	return static_cast<int>(sizeof(crabc_pthread_mutex)
		+ sizeof(crabc_pthread_condition)
		+ sizeof(crabc_pthread_rwlock)
		+ crabc_pthread_once
		+ crabc_c11_once);
}
