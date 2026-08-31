/* C++ companion for the Linux/x86-64 <aio.h> aio_error ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <aio.h>

using aio_error_signature = int (*)(const struct aiocb *);

static_assert(sizeof(struct aiocb) == 168, "x86-64 aiocb size");
static_assert(alignof(struct aiocb) == 8, "x86-64 aiocb alignment");
static_assert(__builtin_offsetof(struct aiocb, __err) == 112,
    "x86-64 aiocb error offset");
static_assert(__is_same(decltype(((struct aiocb *)0)->__err), volatile int),
    "aiocb error field type");
static_assert(__is_same(decltype(&aio_error), aio_error_signature),
    "aio_error declaration");

static aio_error_signature aio_error_function __attribute__((used)) = aio_error;

#if defined(_LARGEFILE64_SOURCE)
static_assert(__is_same(decltype(&aio_error64), aio_error_signature),
    "aio_error64 alias declaration");
static aio_error_signature aio_error64_function __attribute__((used)) = aio_error64;
#endif

int crabc_x86_64_aio_error_header_abi_probe_cpp()
{
    return aio_error_function != nullptr;
}
