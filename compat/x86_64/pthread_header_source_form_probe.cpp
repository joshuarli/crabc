/* Direct Linux/x86-64 <pthread.h> C++ source-form and ownership witness. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

#if defined(CRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_OWNER)
#include <signal.h>
#endif

#ifdef pthread_equal
#error "C++ <pthread.h> must retain pthread_equal as a C-linkage function"
#endif

static_assert(sizeof(struct sched_param) == 48 && alignof(struct sched_param) == 8,
    "x86 sched_param ABI");
static_assert(__builtin_offsetof(struct sched_param, sched_priority) == 0 &&
    __builtin_offsetof(struct sched_param, __reserved1) == 4 &&
    __builtin_offsetof(struct sched_param, __reserved2) == 8 &&
    __builtin_offsetof(struct sched_param, __reserved3) == 40,
    "x86 sched_param source-owned layout");

using crabc_pthread_getschedparam_signature = int (*)(pthread_t, int *,
    struct sched_param *);
using crabc_pthread_mutex_getprioceiling_signature = int (*)(
    const pthread_mutex_t *, int *);
using crabc_pthread_mutex_setprioceiling_signature = int (*)(
    pthread_mutex_t *, int, int *);
using crabc_pthread_mutexattr_get_signature = int (*)(
    const pthread_mutexattr_t *, int *);
using crabc_pthread_condattr_getclock_signature = int (*)(
    const pthread_condattr_t *, clockid_t *);
using crabc_pthread_condattr_getpshared_signature = int (*)(
    const pthread_condattr_t *, int *);
using crabc_pthread_rwlockattr_getpshared_signature = int (*)(
    const pthread_rwlockattr_t *, int *);
using crabc_pthread_barrierattr_getpshared_signature = int (*)(
    const pthread_barrierattr_t *, int *);
using crabc_pthread_attr_getsize_signature = int (*)(
    const pthread_attr_t *, size_t *);
using crabc_pthread_attr_getstack_signature = int (*)(
    const pthread_attr_t *, void **, size_t *);
using crabc_pthread_attr_getint_signature = int (*)(
    const pthread_attr_t *, int *);
using crabc_pthread_attr_setschedparam_signature = int (*)(pthread_attr_t *,
    const struct sched_param *);
using crabc_pthread_attr_getschedparam_signature = int (*)(
    const pthread_attr_t *, struct sched_param *);

static_assert(__is_same(decltype(&pthread_getschedparam),
    crabc_pthread_getschedparam_signature), "pthread_getschedparam declaration");
static_assert(__is_same(decltype(&pthread_mutex_getprioceiling),
    crabc_pthread_mutex_getprioceiling_signature),
    "pthread_mutex_getprioceiling declaration");
static_assert(__is_same(decltype(&pthread_mutex_setprioceiling),
    crabc_pthread_mutex_setprioceiling_signature),
    "pthread_mutex_setprioceiling declaration");
static_assert(__is_same(decltype(&pthread_mutexattr_gettype),
    crabc_pthread_mutexattr_get_signature), "pthread_mutexattr_gettype declaration");
static_assert(__is_same(decltype(&pthread_mutexattr_getpshared),
    crabc_pthread_mutexattr_get_signature), "pthread_mutexattr_getpshared declaration");
static_assert(__is_same(decltype(&pthread_mutexattr_getprotocol),
    crabc_pthread_mutexattr_get_signature), "pthread_mutexattr_getprotocol declaration");
static_assert(__is_same(decltype(&pthread_mutexattr_getprioceiling),
    crabc_pthread_mutexattr_get_signature),
    "pthread_mutexattr_getprioceiling declaration");
static_assert(__is_same(decltype(&pthread_mutexattr_getrobust),
    crabc_pthread_mutexattr_get_signature), "pthread_mutexattr_getrobust declaration");
static_assert(__is_same(decltype(&pthread_condattr_getclock),
    crabc_pthread_condattr_getclock_signature), "pthread_condattr_getclock declaration");
static_assert(__is_same(decltype(&pthread_condattr_getpshared),
    crabc_pthread_condattr_getpshared_signature),
    "pthread_condattr_getpshared declaration");
static_assert(__is_same(decltype(&pthread_rwlockattr_getpshared),
    crabc_pthread_rwlockattr_getpshared_signature),
    "pthread_rwlockattr_getpshared declaration");
static_assert(__is_same(decltype(&pthread_barrierattr_getpshared),
    crabc_pthread_barrierattr_getpshared_signature),
    "pthread_barrierattr_getpshared declaration");
static_assert(__is_same(decltype(&pthread_attr_getguardsize),
    crabc_pthread_attr_getsize_signature), "pthread_attr_getguardsize declaration");
static_assert(__is_same(decltype(&pthread_attr_getstacksize),
    crabc_pthread_attr_getsize_signature), "pthread_attr_getstacksize declaration");
static_assert(__is_same(decltype(&pthread_attr_getstack),
    crabc_pthread_attr_getstack_signature), "pthread_attr_getstack declaration");
static_assert(__is_same(decltype(&pthread_attr_getscope),
    crabc_pthread_attr_getint_signature), "pthread_attr_getscope declaration");
static_assert(__is_same(decltype(&pthread_attr_getinheritsched),
    crabc_pthread_attr_getint_signature), "pthread_attr_getinheritsched declaration");
static_assert(__is_same(decltype(&pthread_attr_getschedpolicy),
    crabc_pthread_attr_getint_signature), "pthread_attr_getschedpolicy declaration");
static_assert(__is_same(decltype(&pthread_attr_setschedparam),
    crabc_pthread_attr_setschedparam_signature),
    "pthread_attr_setschedparam declaration");
static_assert(__is_same(decltype(&pthread_attr_getschedparam),
    crabc_pthread_attr_getschedparam_signature),
    "pthread_attr_getschedparam declaration");

__attribute__((used)) static auto crabc_pthread_exit_reference = &pthread_exit;
__attribute__((used)) static crabc_pthread_getschedparam_signature
    crabc_pthread_getschedparam_reference = &pthread_getschedparam;
__attribute__((used)) static crabc_pthread_mutex_getprioceiling_signature
    crabc_pthread_mutex_getprioceiling_reference = &pthread_mutex_getprioceiling;
__attribute__((used)) static crabc_pthread_mutex_setprioceiling_signature
    crabc_pthread_mutex_setprioceiling_reference = &pthread_mutex_setprioceiling;
__attribute__((used)) static crabc_pthread_mutexattr_get_signature
    crabc_pthread_mutexattr_gettype_reference = &pthread_mutexattr_gettype;
__attribute__((used)) static crabc_pthread_condattr_getclock_signature
    crabc_pthread_condattr_getclock_reference = &pthread_condattr_getclock;
__attribute__((used)) static crabc_pthread_condattr_getpshared_signature
    crabc_pthread_condattr_getpshared_reference = &pthread_condattr_getpshared;
__attribute__((used)) static crabc_pthread_rwlockattr_getpshared_signature
    crabc_pthread_rwlockattr_getpshared_reference = &pthread_rwlockattr_getpshared;
__attribute__((used)) static crabc_pthread_barrierattr_getpshared_signature
    crabc_pthread_barrierattr_getpshared_reference = &pthread_barrierattr_getpshared;
__attribute__((used)) static crabc_pthread_attr_getsize_signature
    crabc_pthread_attr_getguardsize_reference = &pthread_attr_getguardsize;
__attribute__((used)) static crabc_pthread_attr_getstack_signature
    crabc_pthread_attr_getstack_reference = &pthread_attr_getstack;
__attribute__((used)) static crabc_pthread_attr_getint_signature
    crabc_pthread_attr_getscope_reference = &pthread_attr_getscope;
__attribute__((used)) static crabc_pthread_attr_setschedparam_signature
    crabc_pthread_attr_setschedparam_reference = &pthread_attr_setschedparam;
__attribute__((used)) static crabc_pthread_attr_getschedparam_signature
    crabc_pthread_attr_getschedparam_reference = &pthread_attr_getschedparam;

#if defined(_GNU_SOURCE)
using crabc_pthread_getname_np_signature = int (*)(pthread_t, char *, size_t);
__attribute__((used)) static crabc_pthread_getname_np_signature
    crabc_pthread_getname_np_reference = &pthread_getname_np;
#endif

#if defined(CRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_WITNESS)
using crabc_pthread_sigmask_signature = int (*)(int, const sigset_t *, sigset_t *);
using crabc_pthread_kill_signature = int (*)(pthread_t, int);
__attribute__((used)) static crabc_pthread_sigmask_signature
    crabc_pthread_signal_owner_sigmask = &pthread_sigmask;
__attribute__((used)) static crabc_pthread_kill_signature
    crabc_pthread_signal_owner_kill = &pthread_kill;
#endif

extern "C" int crabc_x86_64_pthread_header_source_form_probe_cpp(void)
{
    return 0;
}
