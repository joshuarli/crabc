/* Linux/x86-64 deferred pthread-cancellation C++17 header ABI probe.
 *
 * The runner compiles this translation unit only.  Its retained undefined
 * references prove that the selected pthread declarations request unmangled C
 * spellings; they do not prove those symbols link or implement cancellation.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

using crabc_pthread_cancel_signature = int (*)(pthread_t);
using crabc_pthread_setcancelstate_signature = int (*)(int, int *);
using crabc_pthread_setcanceltype_signature = int (*)(int, int *);
using crabc_pthread_testcancel_signature = void (*)(void);
using crabc_pthread_cleanup_callback = void (*)(void *);
using crabc_pthread_cleanup_push_signature = void (*)(struct __ptcb *,
    crabc_pthread_cleanup_callback, void *);
using crabc_pthread_cleanup_pop_signature = void (*)(struct __ptcb *, int);

static_assert(PTHREAD_CANCEL_ENABLE == 0, "PTHREAD_CANCEL_ENABLE value");
static_assert(PTHREAD_CANCEL_DISABLE == 1, "PTHREAD_CANCEL_DISABLE value");
static_assert(PTHREAD_CANCEL_MASKED == 2, "PTHREAD_CANCEL_MASKED value");
static_assert(PTHREAD_CANCEL_DEFERRED == 0, "PTHREAD_CANCEL_DEFERRED value");
static_assert(PTHREAD_CANCEL_ASYNCHRONOUS == 1,
              "PTHREAD_CANCEL_ASYNCHRONOUS value");
static_assert(__is_same(decltype(PTHREAD_CANCELED), void *),
              "PTHREAD_CANCELED sentinel type");
static_assert(__is_same(decltype(&pthread_cancel),
                        crabc_pthread_cancel_signature),
              "pthread_cancel declaration");
static_assert(__is_same(decltype(&pthread_setcancelstate),
                        crabc_pthread_setcancelstate_signature),
              "pthread_setcancelstate declaration");
static_assert(__is_same(decltype(&pthread_setcanceltype),
                        crabc_pthread_setcanceltype_signature),
              "pthread_setcanceltype declaration");
static_assert(__is_same(decltype(&pthread_testcancel),
                        crabc_pthread_testcancel_signature),
              "pthread_testcancel declaration");
static_assert(sizeof(struct __ptcb) == 24, "__ptcb size");
static_assert(alignof(struct __ptcb) == 8, "__ptcb alignment");
static_assert(__builtin_offsetof(struct __ptcb, __f) == 0,
              "__ptcb callback offset");
static_assert(__builtin_offsetof(struct __ptcb, __x) == 8,
              "__ptcb argument offset");
static_assert(__builtin_offsetof(struct __ptcb, __next) == 16,
              "__ptcb link offset");
static_assert(__is_same(decltype(((struct __ptcb *)0)->__f),
                        crabc_pthread_cleanup_callback),
              "__ptcb callback type");
static_assert(__is_same(decltype(&_pthread_cleanup_push),
                        crabc_pthread_cleanup_push_signature),
              "_pthread_cleanup_push declaration");
static_assert(__is_same(decltype(&_pthread_cleanup_pop),
                        crabc_pthread_cleanup_pop_signature),
              "_pthread_cleanup_pop declaration");

static void crabc_cleanup_macro_callback(void *) {}

__attribute__((used)) static void crabc_cleanup_macro_probe()
{
    pthread_cleanup_push(crabc_cleanup_macro_callback, nullptr);
    pthread_cleanup_pop(0);
}

__attribute__((used)) static crabc_pthread_cancel_signature const
    crabc_force_pthread_cancel = &pthread_cancel;
__attribute__((used)) static crabc_pthread_setcancelstate_signature const
    crabc_force_pthread_setcancelstate = &pthread_setcancelstate;
__attribute__((used)) static crabc_pthread_setcanceltype_signature const
    crabc_force_pthread_setcanceltype = &pthread_setcanceltype;
__attribute__((used)) static crabc_pthread_testcancel_signature const
    crabc_force_pthread_testcancel = &pthread_testcancel;
__attribute__((used)) static crabc_pthread_cleanup_push_signature const
    crabc_force_pthread_cleanup_push = &_pthread_cleanup_push;
__attribute__((used)) static crabc_pthread_cleanup_pop_signature const
    crabc_force_pthread_cleanup_pop = &_pthread_cleanup_pop;
