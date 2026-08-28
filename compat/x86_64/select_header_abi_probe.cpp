/* C++ companion for the native Linux/x86-64 <sys/select.h> ABI probe. */

#include <stddef.h>
#include <sys/select.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

using select_function = int (*)(int, fd_set *, fd_set *, fd_set *,
    struct timeval *);
using pselect_function = int (*)(int, fd_set *, fd_set *, fd_set *,
    const struct timespec *, const sigset_t *);

static_assert(FD_SETSIZE == 1024, "C++ x86 fd-set capacity");
static_assert(sizeof(fd_set) == 128 && alignof(fd_set) == 8,
    "C++ x86 fd-set layout");
static_assert(sizeof(((fd_set *)0)->fds_bits) == 128,
    "C++ x86 fd-set words");
static_assert(sizeof(struct timeval) == 16 && alignof(struct timeval) == 8,
    "C++ x86 timeval layout");
static_assert(offsetof(struct timeval, tv_sec) == 0 &&
    offsetof(struct timeval, tv_usec) == 8,
    "C++ x86 timeval offsets");
static_assert(sizeof(struct timespec) == 16 && alignof(struct timespec) == 8,
    "C++ x86 timespec layout");
static_assert(sizeof(sigset_t) == 128 && alignof(sigset_t) == 8,
    "C++ x86 signal-set layout");
static_assert(__is_same(decltype(&select), select_function),
    "C++ select declaration");
static_assert(__is_same(decltype(&pselect), pselect_function),
    "C++ pselect declaration");

/* Matching C-linkage redeclarations must not conflict with <sys/select.h>. */
extern "C" int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
extern "C" int pselect(int, fd_set *, fd_set *, fd_set *,
    const struct timespec *, const sigset_t *);

int crabc_x86_64_select_header_abi_probe_cpp()
{
    fd_set values{};

    FD_SET(1, &values);
    return FD_ISSET(1, &values) ? 0 : 1;
}
