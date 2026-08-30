/* Selected Linux/x86-64 pathname-lifecycle C header ABI facts.
 *
 * Pinned musl 1.2.6 owns the declaration, type, and constant oracle. This
 * compile-only probe deliberately ratchets only the narrow static archive
 * surface; it says nothing about a complete C filesystem interface or public
 * x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*crabc_chdir_signature)(const char *);
typedef char *(*crabc_getcwd_signature)(char *, size_t);
typedef int (*crabc_mkdir_signature)(const char *, mode_t);
typedef int (*crabc_unlink_signature)(const char *);
typedef int (*crabc_rmdir_signature)(const char *);
typedef int (*crabc_remove_signature)(const char *);
typedef int (*crabc_rename_signature)(const char *, const char *);
typedef int (*crabc_link_signature)(const char *, const char *);
typedef int (*crabc_symlink_signature)(const char *, const char *);
typedef ssize_t (*crabc_readlink_signature)(const char *, char *, size_t);
typedef int (*crabc_chmod_signature)(const char *, mode_t);
typedef int (*crabc_fchmod_signature)(int, mode_t);
typedef int (*crabc_truncate_signature)(const char *, off_t);

_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8 &&
                   __builtin_types_compatible_p(size_t, unsigned long),
               "x86 size_t ABI");
_Static_assert(sizeof(ssize_t) == 8 && _Alignof(ssize_t) == 8 &&
                   __builtin_types_compatible_p(ssize_t, long),
               "x86 ssize_t ABI");
_Static_assert(sizeof(off_t) == 8 && _Alignof(off_t) == 8 &&
                   __builtin_types_compatible_p(off_t, long),
               "x86 off_t ABI");
_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4 &&
                   __builtin_types_compatible_p(mode_t, unsigned int),
               "x86 mode_t ABI");

_Static_assert(F_GETFD == 1 && O_CLOEXEC == 02000000 &&
                   O_PATH == 010000000,
               "x86 fchmod fallback constants");
_Static_assert(S_IFMT == 0170000 && S_IFDIR == 0040000 &&
                   S_IFREG == 0100000 && S_IFLNK == 0120000 &&
                   S_IRUSR == 0400 && S_IWUSR == 0200 && S_IXUSR == 0100 &&
                   S_IRWXU == 0700,
               "x86 selected pathname mode constants");

_Static_assert(__builtin_types_compatible_p(__typeof__(&chdir),
                                             crabc_chdir_signature),
               "chdir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getcwd),
                                             crabc_getcwd_signature),
               "getcwd declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mkdir),
                                             crabc_mkdir_signature),
               "mkdir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&unlink),
                                             crabc_unlink_signature),
               "unlink declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&rmdir),
                                             crabc_rmdir_signature),
               "rmdir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&remove),
                                             crabc_remove_signature),
               "remove declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&rename),
                                             crabc_rename_signature),
               "rename declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&link),
                                             crabc_link_signature),
               "link declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&symlink),
                                             crabc_symlink_signature),
               "symlink declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readlink),
                                             crabc_readlink_signature),
               "readlink declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&chmod),
                                             crabc_chmod_signature),
               "chmod declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fchmod),
                                             crabc_fchmod_signature),
               "fchmod declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&truncate),
                                             crabc_truncate_signature),
               "truncate declaration");

int crabc_x86_64_pathname_lifecycle_header_abi_probe(void)
{
    return S_IFREG + F_GETFD;
}
