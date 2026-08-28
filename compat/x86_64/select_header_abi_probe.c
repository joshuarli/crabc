/* Native Linux/x86-64 <sys/select.h> ABI probe. */

#include <stddef.h>
#include <sys/select.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(FD_SETSIZE == 1024, "x86 fd-set capacity");
_Static_assert(sizeof(fd_set) == 128 && _Alignof(fd_set) == 8,
    "x86 fd-set layout");
_Static_assert(sizeof(((fd_set *)0)->fds_bits) == 128,
    "x86 fd-set words");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8,
    "x86 timeval layout");
_Static_assert(offsetof(struct timeval, tv_sec) == 0 &&
    offsetof(struct timeval, tv_usec) == 8,
    "x86 timeval offsets");
_Static_assert(sizeof(struct timespec) == 16 &&
    _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 public signal-set layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&select),
    int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *)),
    "select declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pselect),
    int (*)(int, fd_set *, fd_set *, fd_set *, const struct timespec *,
        const sigset_t *)),
    "pselect declaration");

int crabc_x86_64_select_header_abi_probe(void)
{
    fd_set values;

    FD_ZERO(&values);
    FD_SET(0, &values);
    FD_SET(FD_SETSIZE - 1, &values);
    if (!FD_ISSET(0, &values) || !FD_ISSET(FD_SETSIZE - 1, &values))
        return 1;
    FD_CLR(0, &values);
    return FD_ISSET(0, &values);
}
