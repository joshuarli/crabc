/* Linux/x86-64 deferred pthread-cancellation header ABI probe.
 *
 * Pinned musl 1.2.6 owns this narrow declaration and constant contract.  The
 * companion runner compares its isolated C profiles with raw-GCC consumers
 * rooted at the project headers.  This is not cancellation behavior, cleanup
 * handler, archive-linkage, or pthread-runtime evidence.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

typedef int (*crabc_pthread_cancel_signature)(pthread_t);
typedef int (*crabc_pthread_setcancelstate_signature)(int, int *);
typedef int (*crabc_pthread_setcanceltype_signature)(int, int *);
typedef void (*crabc_pthread_testcancel_signature)(void);
typedef void (*crabc_pthread_cleanup_callback)(void *);
typedef void (*crabc_pthread_cleanup_push_signature)(struct __ptcb *,
    crabc_pthread_cleanup_callback, void *);
typedef void (*crabc_pthread_cleanup_pop_signature)(struct __ptcb *, int);

_Static_assert(PTHREAD_CANCEL_ENABLE == 0, "PTHREAD_CANCEL_ENABLE value");
_Static_assert(PTHREAD_CANCEL_DISABLE == 1, "PTHREAD_CANCEL_DISABLE value");
_Static_assert(PTHREAD_CANCEL_MASKED == 2, "PTHREAD_CANCEL_MASKED value");
_Static_assert(PTHREAD_CANCEL_DEFERRED == 0, "PTHREAD_CANCEL_DEFERRED value");
_Static_assert(PTHREAD_CANCEL_ASYNCHRONOUS == 1,
               "PTHREAD_CANCEL_ASYNCHRONOUS value");
_Static_assert(__builtin_types_compatible_p(__typeof__(PTHREAD_CANCELED), void *),
               "PTHREAD_CANCELED sentinel type");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_cancel),
                                             crabc_pthread_cancel_signature),
               "pthread_cancel declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_setcancelstate),
                                             crabc_pthread_setcancelstate_signature),
               "pthread_setcancelstate declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_setcanceltype),
                                             crabc_pthread_setcanceltype_signature),
               "pthread_setcanceltype declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_testcancel),
                                             crabc_pthread_testcancel_signature),
               "pthread_testcancel declaration");
_Static_assert(sizeof(struct __ptcb) == 24, "__ptcb size");
_Static_assert(_Alignof(struct __ptcb) == 8, "__ptcb alignment");
_Static_assert(__builtin_offsetof(struct __ptcb, __f) == 0,
               "__ptcb callback offset");
_Static_assert(__builtin_offsetof(struct __ptcb, __x) == 8,
               "__ptcb argument offset");
_Static_assert(__builtin_offsetof(struct __ptcb, __next) == 16,
               "__ptcb link offset");
_Static_assert(__builtin_types_compatible_p(
                   __typeof__(((struct __ptcb *)0)->__f),
                   crabc_pthread_cleanup_callback),
               "__ptcb callback type");
_Static_assert(__builtin_types_compatible_p(
                   __typeof__(& _pthread_cleanup_push),
                   crabc_pthread_cleanup_push_signature),
               "_pthread_cleanup_push declaration");
_Static_assert(__builtin_types_compatible_p(
                   __typeof__(& _pthread_cleanup_pop),
                   crabc_pthread_cleanup_pop_signature),
               "_pthread_cleanup_pop declaration");

static void *const crabc_pthread_canceled = PTHREAD_CANCELED;

static void crabc_cleanup_macro_callback(void *opaque)
{
    int *count = opaque;
    ++*count;
}

int crabc_x86_64_pthread_cancellation_header_abi_probe(void)
{
    int cleanup_count = 0;

    pthread_cleanup_push(crabc_cleanup_macro_callback, &cleanup_count);
    pthread_cleanup_pop(1);

    return crabc_pthread_canceled == PTHREAD_CANCELED && cleanup_count == 1 ? 0 : 1;
}
