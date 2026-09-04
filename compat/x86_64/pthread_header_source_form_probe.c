/* Direct Linux/x86-64 <pthread.h> source-form and ownership witness. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

#if defined(CRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_OWNER)
#include <signal.h>
#endif

#ifndef pthread_equal
#error "C <pthread.h> must retain musl's pthread_equal macro"
#endif

#if PTHREAD_CREATE_JOINABLE != 0 || PTHREAD_CREATE_DETACHED != 1
#error "unexpected pthread creation constants"
#endif
#if PTHREAD_MUTEX_STALLED != 0 || PTHREAD_MUTEX_ROBUST != 1
#error "unexpected pthread robust-mutex constants"
#endif
#if PTHREAD_CANCEL_ENABLE != 0 || PTHREAD_CANCEL_DISABLE != 1 || \
    PTHREAD_CANCEL_MASKED != 2 || PTHREAD_CANCEL_DEFERRED != 0 || \
    PTHREAD_CANCEL_ASYNCHRONOUS != 1
#error "unexpected pthread cancellation constants"
#endif

_Static_assert(sizeof(struct sched_param) == 48 &&
    _Alignof(struct sched_param) == 8, "x86 sched_param ABI");
_Static_assert(__builtin_offsetof(struct sched_param, sched_priority) == 0 &&
    __builtin_offsetof(struct sched_param, __reserved1) == 4 &&
    __builtin_offsetof(struct sched_param, __reserved2) == 8 &&
    __builtin_offsetof(struct sched_param, __reserved3) == 40,
    "x86 sched_param source-owned layout");

typedef int (*crabc_pthread_getschedparam_signature)(pthread_t, int *,
    struct sched_param *);
typedef int (*crabc_pthread_mutex_getprioceiling_signature)(
    const pthread_mutex_t *, int *);
typedef int (*crabc_pthread_mutex_setprioceiling_signature)(
    pthread_mutex_t *, int, int *);
typedef int (*crabc_pthread_mutexattr_get_signature)(
    const pthread_mutexattr_t *, int *);
typedef int (*crabc_pthread_condattr_getclock_signature)(
    const pthread_condattr_t *, clockid_t *);
typedef int (*crabc_pthread_condattr_getpshared_signature)(
    const pthread_condattr_t *, int *);
typedef int (*crabc_pthread_rwlockattr_getpshared_signature)(
    const pthread_rwlockattr_t *, int *);
typedef int (*crabc_pthread_barrierattr_getpshared_signature)(
    const pthread_barrierattr_t *, int *);
typedef int (*crabc_pthread_attr_getsize_signature)(
    const pthread_attr_t *, size_t *);
typedef int (*crabc_pthread_attr_getstack_signature)(
    const pthread_attr_t *, void **, size_t *);
typedef int (*crabc_pthread_attr_getint_signature)(
    const pthread_attr_t *, int *);
typedef int (*crabc_pthread_attr_setschedparam_signature)(pthread_attr_t *,
    const struct sched_param *);
typedef int (*crabc_pthread_attr_getschedparam_signature)(
    const pthread_attr_t *, struct sched_param *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_getschedparam),
    crabc_pthread_getschedparam_signature), "pthread_getschedparam declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_mutex_getprioceiling),
    crabc_pthread_mutex_getprioceiling_signature),
    "pthread_mutex_getprioceiling declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_mutex_setprioceiling),
    crabc_pthread_mutex_setprioceiling_signature),
    "pthread_mutex_setprioceiling declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_mutexattr_gettype), crabc_pthread_mutexattr_get_signature),
    "pthread_mutexattr_gettype declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_mutexattr_getpshared), crabc_pthread_mutexattr_get_signature),
    "pthread_mutexattr_getpshared declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_mutexattr_getprotocol), crabc_pthread_mutexattr_get_signature),
    "pthread_mutexattr_getprotocol declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_mutexattr_getprioceiling),
    crabc_pthread_mutexattr_get_signature),
    "pthread_mutexattr_getprioceiling declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_mutexattr_getrobust), crabc_pthread_mutexattr_get_signature),
    "pthread_mutexattr_getrobust declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_condattr_getclock),
    crabc_pthread_condattr_getclock_signature),
    "pthread_condattr_getclock declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_condattr_getpshared),
    crabc_pthread_condattr_getpshared_signature),
    "pthread_condattr_getpshared declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_rwlockattr_getpshared),
    crabc_pthread_rwlockattr_getpshared_signature),
    "pthread_rwlockattr_getpshared declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_barrierattr_getpshared),
    crabc_pthread_barrierattr_getpshared_signature),
    "pthread_barrierattr_getpshared declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getguardsize), crabc_pthread_attr_getsize_signature),
    "pthread_attr_getguardsize declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getstacksize), crabc_pthread_attr_getsize_signature),
    "pthread_attr_getstacksize declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_getstack),
    crabc_pthread_attr_getstack_signature), "pthread_attr_getstack declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_attr_getscope),
    crabc_pthread_attr_getint_signature), "pthread_attr_getscope declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getinheritsched), crabc_pthread_attr_getint_signature),
    "pthread_attr_getinheritsched declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getschedpolicy), crabc_pthread_attr_getint_signature),
    "pthread_attr_getschedpolicy declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_setschedparam),
    crabc_pthread_attr_setschedparam_signature),
    "pthread_attr_setschedparam declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_attr_getschedparam),
    crabc_pthread_attr_getschedparam_signature),
    "pthread_attr_getschedparam declaration");

#if defined(CRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_WITNESS)
typedef int (*crabc_pthread_sigmask_signature)(int, const sigset_t *, sigset_t *);
typedef int (*crabc_pthread_kill_signature)(pthread_t, int);
__attribute__((used)) static crabc_pthread_sigmask_signature
    crabc_pthread_signal_owner_sigmask = &pthread_sigmask;
__attribute__((used)) static crabc_pthread_kill_signature
    crabc_pthread_signal_owner_kill = &pthread_kill;
#endif

int crabc_x86_64_pthread_header_source_form_probe(void)
{
    return 0;
}
