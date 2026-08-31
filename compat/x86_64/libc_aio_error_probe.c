/* Static x86-64 aio_error ABI and behavior differential.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through an archive-free `-nostdlib -static` candidate containing only
 * the selected aio_error object. It checks the exact x86 public aiocb layout
 * used by musl's source-level compiler barrier and sign-bit masking. It does
 * not initiate, submit, wait for, cancel, synchronize, or complete AIO.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
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

static const aio_error_signature aio_error_function = aio_error;

static int check_error(struct aiocb *control_block, int stored, int expected)
{
    control_block->__err = stored;
    return aio_error_function(control_block) == expected ? 0 : 1;
}

int crabc_x86_64_aio_error_probe(void)
{
    static struct aiocb control_block;

    if (check_error(&control_block, 0, 0) != 0)
        return 1;
    if (check_error(&control_block, 1, 1) != 0)
        return 2;
    if (check_error(&control_block, 0x7fffffff, 0x7fffffff) != 0)
        return 3;
    if (check_error(&control_block, -1, 0x7fffffff) != 0)
        return 4;
    if (check_error(&control_block, -2147483647 - 1, 0) != 0)
        return 5;
    return 0;
}

#ifndef CRABC_AIO_ERROR_FREESTANDING
int main(void)
{
    return crabc_x86_64_aio_error_probe();
}
#endif
