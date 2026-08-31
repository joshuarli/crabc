/* Source-only Linux/x86-64 <unistd.h> declaration and macro probe. */

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
#include <stdint.h>
#include <unistd.h>

_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
    "x86 size and ssize types");
_Static_assert(sizeof(off_t) == 8 && sizeof(off64_t) == 8,
    "x86 off types");
_Static_assert(sizeof(pid_t) == 4 && sizeof(uid_t) == 4 && sizeof(gid_t) == 4,
    "x86 process and identity types");
_Static_assert(sizeof(intptr_t) == 8, "x86 intptr_t");

_Static_assert(STDIN_FILENO == 0 && STDOUT_FILENO == 1 && STDERR_FILENO == 2,
    "standard descriptor values");
_Static_assert(SEEK_SET == 0 && SEEK_CUR == 1 && SEEK_END == 2,
    "seek values");
_Static_assert(SEEK_DATA == 3 && SEEK_HOLE == 4, "Linux seek extensions");
_Static_assert(F_OK == 0 && X_OK == 1 && W_OK == 2 && R_OK == 4,
    "access values");
_Static_assert(F_ULOCK == 0 && F_LOCK == 1 && F_TLOCK == 2 && F_TEST == 3,
    "lockf values");
_Static_assert(L_SET == 0 && L_INCR == 1 && L_XTND == 2,
    "GNU lock values");

_Static_assert(_POSIX_VERSION == 200809L && _XOPEN_VERSION == 700,
    "POSIX version values");
_Static_assert(_POSIX_V7_LP64_OFF64 == 1, "x86 LP64 POSIX selector");
_Static_assert(_CS_PATH == 0 && _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS == 5,
    "confstr common selectors");
_Static_assert(_CS_POSIX_V6_LP64_OFF64_CFLAGS == 1124 &&
    _CS_POSIX_V7_LP64_OFF64_CFLAGS == 1140,
    "confstr LP64 selectors");
_Static_assert(_PC_PATH_MAX == 4 && _PC_FILESIZEBITS == 13,
    "pathconf selectors");
_Static_assert(_SC_ARG_MAX == 0 && _SC_OPEN_MAX == 4 &&
    _SC_PAGE_SIZE == 30 && _SC_PAGESIZE == 30,
    "sysconf common selectors");
_Static_assert(_SC_UIO_MAXIOV == 60 && _SC_PHYS_PAGES == 85 &&
    _SC_XOPEN_LEGACY == 129 && _SC_STREAMS == 174,
    "x86 historical sysconf selectors");
_Static_assert(_SC_V6_LP64_OFF64 == 178 && _SC_V7_LP64_OFF64 == 239 &&
    _SC_MINSIGSTKSZ == 249 && _SC_SIGSTKSZ == 250,
    "x86 versioned sysconf selectors");
_Static_assert(_SC_CLK_TCK == 2 && _SC_PAGE_SIZE == _SC_PAGESIZE &&
    _SC_PAGE_SIZE == 30, "selected system-configuration selectors");
_Static_assert(_PC_LINK_MAX == 0 && _PC_2_SYMLINKS == 20 &&
    _PC_REC_INCR_XFER_SIZE == 14, "selected pathconf selector range");

#define CRABC_TYPE_IS(expression, type) \
    __builtin_types_compatible_p(__typeof__(expression), type)

_Static_assert(CRABC_TYPE_IS(&pipe, int (*)(int *)), "pipe declaration");
_Static_assert(CRABC_TYPE_IS(&read, ssize_t (*)(int, void *, size_t)),
    "read declaration");
_Static_assert(CRABC_TYPE_IS(&pread, ssize_t (*)(int, void *, size_t, off_t)),
    "pread declaration");
_Static_assert(CRABC_TYPE_IS(&lseek, off_t (*)(int, off_t, int)),
    "lseek declaration");
_Static_assert(CRABC_TYPE_IS(&getpid, pid_t (*)(void)), "getpid declaration");
_Static_assert(CRABC_TYPE_IS(&getuid, uid_t (*)(void)), "getuid declaration");
_Static_assert(CRABC_TYPE_IS(&getgroups, int (*)(int, gid_t *)),
    "getgroups declaration");
_Static_assert(CRABC_TYPE_IS(&gethostname, int (*)(char *, size_t)),
    "gethostname declaration");
_Static_assert(CRABC_TYPE_IS(&sethostname, int (*)(const char *, size_t)),
    "GNU sethostname declaration");
_Static_assert(CRABC_TYPE_IS(&getdomainname, int (*)(char *, size_t)),
    "GNU getdomainname declaration");
_Static_assert(CRABC_TYPE_IS(&setdomainname, int (*)(const char *, size_t)),
    "GNU setdomainname declaration");
_Static_assert(CRABC_TYPE_IS(&getcwd, char *(*)(char *, size_t)),
    "getcwd declaration");
_Static_assert(CRABC_TYPE_IS(&sysconf, long (*)(int)), "sysconf declaration");
_Static_assert(CRABC_TYPE_IS(&confstr, size_t (*)(int, char *, size_t)),
    "confstr declaration");
_Static_assert(CRABC_TYPE_IS(&fpathconf, long (*)(int, int)),
    "fpathconf declaration");
_Static_assert(CRABC_TYPE_IS(&pathconf, long (*)(const char *, int)),
    "pathconf declaration");
_Static_assert(CRABC_TYPE_IS(&getpagesize, int (*)(void)),
    "GNU getpagesize declaration");
_Static_assert(CRABC_TYPE_IS(&getdtablesize, int (*)(void)),
    "GNU getdtablesize declaration");
_Static_assert(CRABC_TYPE_IS(&copy_file_range,
    ssize_t (*)(int, off_t *, int, off_t *, size_t, unsigned)),
    "copy_file_range declaration");
_Static_assert(CRABC_TYPE_IS(&get_current_dir_name, char *(*)(void)),
    "get_current_dir_name declaration");
_Static_assert(CRABC_TYPE_IS(&gettid, pid_t (*)(void)), "gettid declaration");
_Static_assert(CRABC_TYPE_IS(&setgroups, int (*)(size_t, const gid_t *)),
    "setgroups declaration");
_Static_assert(CRABC_TYPE_IS(&daemon, int (*)(int, int)), "daemon declaration");
_Static_assert(CRABC_TYPE_IS(&lseek64, off_t (*)(int, off_t, int)),
    "lseek64 alias declaration");
_Static_assert(CRABC_TYPE_IS(environ, char **),
    "GNU environ declaration");
_Static_assert(CRABC_TYPE_IS(&environ, char ***),
    "GNU environ object declaration");

int crabc_x86_64_unistd_header_abi_probe(void)
{
    return STDIN_FILENO + SEEK_SET + F_OK + (int)sizeof(off64_t);
}
