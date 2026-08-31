/* Pinned-musl/project Linux/x86-64 timer_delete declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <time.h>

#if defined(CRABC_TIMER_DELETE_EXPECT_HIDDEN)
/* This branch is compiled only when strict C11 must hide the POSIX name. */
int crabc_x86_64_timer_delete_header_abi_hidden_probe(void)
{
    return timer_delete((timer_t)0);
}
#else
typedef int (*timer_delete_signature)(timer_t);

_Static_assert(sizeof(timer_t) == 8 && _Alignof(timer_t) == 8,
    "x86 opaque timer_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timer_delete),
    timer_delete_signature), "timer_delete declaration");

static timer_delete_signature timer_delete_function __attribute__((used)) =
    timer_delete;

int crabc_x86_64_timer_delete_header_abi_probe(void)
{
    return timer_delete_function != (timer_delete_signature)0 ? 0 : 1;
}
#endif
