/* Source-only C++ companion for the x86-64 <unistd.h> ABI probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _LARGEFILE64_SOURCE

#include <stddef.h>
#include <unistd.h>

static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
    "x86 C++ size and ssize types");
static_assert(sizeof(off_t) == 8 && sizeof(off64_t) == 8,
    "x86 C++ off types");
static_assert(sizeof(pid_t) == 4 && sizeof(uid_t) == 4 && sizeof(gid_t) == 4,
    "x86 C++ process and identity types");
static_assert(STDIN_FILENO == 0 && STDOUT_FILENO == 1 && STDERR_FILENO == 2,
    "C++ standard descriptor values");
static_assert(SEEK_DATA == 3 && SEEK_HOLE == 4,
    "C++ Linux seek extensions");
static_assert(_SC_UIO_MAXIOV == 60 && _SC_V6_LP64_OFF64 == 178,
    "C++ x86 sysconf selectors");
static_assert(__is_same(decltype(NULL), decltype(nullptr)),
    "C++11 NULL is nullptr-compatible");

using read_function = ssize_t (*)(int, void *, size_t);
using pread_function = ssize_t (*)(int, void *, size_t, off_t);
using copy_file_range_function = ssize_t (*)(int, off_t *, int, off_t *,
    size_t, unsigned);
using getgroups_function = int (*)(int, gid_t *);
using lseek64_function = off_t (*)(int, off_t, int);
using gethostname_function = int (*)(char *, size_t);
using sethostname_function = int (*)(const char *, size_t);
using getdomainname_function = int (*)(char *, size_t);
using setdomainname_function = int (*)(const char *, size_t);

static_assert(__is_same(decltype(&read), read_function), "C++ read declaration");
static_assert(__is_same(decltype(&pread), pread_function),
    "C++ pread declaration");
static_assert(__is_same(decltype(&copy_file_range), copy_file_range_function),
    "C++ copy_file_range declaration");
static_assert(__is_same(decltype(&getgroups), getgroups_function),
    "C++ getgroups declaration");
static_assert(__is_same(decltype(&lseek64), lseek64_function),
    "C++ lseek64 alias declaration");
static_assert(__is_same(decltype(&gethostname), gethostname_function),
    "C++ gethostname declaration");
static_assert(__is_same(decltype(&sethostname), sethostname_function),
    "C++ GNU sethostname declaration");
static_assert(__is_same(decltype(&getdomainname), getdomainname_function),
    "C++ GNU getdomainname declaration");
static_assert(__is_same(decltype(&setdomainname), setdomainname_function),
    "C++ GNU setdomainname declaration");

int crabc_x86_64_unistd_header_abi_probe_cpp()
{
    return NULL == nullptr ? 0 : 1;
}
