/*
 * Selected Linux/x86-64 <sys/xattr.h> declaration and scalar ABI facts.
 *
 * Musl 1.2.6 exposes all twelve direct xattr operations and the two setter
 * flags unconditionally.  The runner compiles this exact source in strict,
 * POSIX, X/Open, GNU, and BSD feature profiles so a feature-test regression
 * cannot silently hide a selected operation.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/xattr.h>

typedef ssize_t (*crabc_xattr_get_path_signature)(const char *, const char *,
                                                   void *, size_t);
typedef ssize_t (*crabc_xattr_get_fd_signature)(int, const char *, void *, size_t);
typedef ssize_t (*crabc_xattr_list_path_signature)(const char *, char *, size_t);
typedef ssize_t (*crabc_xattr_list_fd_signature)(int, char *, size_t);
typedef int (*crabc_xattr_set_path_signature)(const char *, const char *,
                                              const void *, size_t, int);
typedef int (*crabc_xattr_set_fd_signature)(int, const char *, const void *,
                                            size_t, int);
typedef int (*crabc_xattr_remove_path_signature)(const char *, const char *);
typedef int (*crabc_xattr_remove_fd_signature)(int, const char *);

_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
               "x86 xattr size scalar ABI");
_Static_assert(XATTR_CREATE == 1 && XATTR_REPLACE == 2,
               "xattr setter flag values");

_Static_assert(__builtin_types_compatible_p(__typeof__(&getxattr),
                                             crabc_xattr_get_path_signature),
               "getxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lgetxattr),
                                             crabc_xattr_get_path_signature),
               "lgetxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fgetxattr),
                                             crabc_xattr_get_fd_signature),
               "fgetxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&listxattr),
                                             crabc_xattr_list_path_signature),
               "listxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&llistxattr),
                                             crabc_xattr_list_path_signature),
               "llistxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&flistxattr),
                                             crabc_xattr_list_fd_signature),
               "flistxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setxattr),
                                             crabc_xattr_set_path_signature),
               "setxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lsetxattr),
                                             crabc_xattr_set_path_signature),
               "lsetxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fsetxattr),
                                             crabc_xattr_set_fd_signature),
               "fsetxattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&removexattr),
                                             crabc_xattr_remove_path_signature),
               "removexattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lremovexattr),
                                             crabc_xattr_remove_path_signature),
               "lremovexattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fremovexattr),
                                             crabc_xattr_remove_fd_signature),
               "fremovexattr declaration");

int crabc_x86_64_xattr_header_abi_probe(void)
{
    return XATTR_CREATE + XATTR_REPLACE;
}
