/* Source-only Linux/x86-64 <aio.h> aio_error declaration/layout probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <aio.h>

typedef int (*aio_error_signature)(const struct aiocb *);

_Static_assert(sizeof(struct aiocb) == 168, "x86-64 aiocb size");
_Static_assert(_Alignof(struct aiocb) == 8, "x86-64 aiocb alignment");
_Static_assert(__builtin_offsetof(struct aiocb, __err) == 112,
    "x86-64 aiocb error offset");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct aiocb *)0)->__err), volatile int),
    "aiocb error field type");
_Static_assert(__builtin_types_compatible_p(__typeof__(&aio_error),
    aio_error_signature), "aio_error declaration");

static aio_error_signature aio_error_function __attribute__((used)) = aio_error;

#if defined(_LARGEFILE64_SOURCE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&aio_error64),
    aio_error_signature), "aio_error64 alias declaration");
static aio_error_signature aio_error64_function __attribute__((used)) = aio_error64;
#endif

int crabc_x86_64_aio_error_header_abi_probe(void)
{
    return aio_error_function != 0;
}
