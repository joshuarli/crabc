/* C++17 companion for selected Linux/x86-64 pathname-lifecycle headers. */

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

using chdir_signature = int (*)(const char *);
using getcwd_signature = char *(*)(char *, size_t);
using mkdir_signature = int (*)(const char *, mode_t);
using unlink_signature = int (*)(const char *);
using rmdir_signature = int (*)(const char *);
using remove_signature = int (*)(const char *);
using rename_signature = int (*)(const char *, const char *);
using link_signature = int (*)(const char *, const char *);
using symlink_signature = int (*)(const char *, const char *);
using readlink_signature = ssize_t (*)(const char *, char *, size_t);
using chmod_signature = int (*)(const char *, mode_t);
using fchmod_signature = int (*)(int, mode_t);
using truncate_signature = int (*)(const char *, off_t);

static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8 &&
                  __is_same(size_t, unsigned long),
              "C++ x86 size_t ABI");
static_assert(sizeof(ssize_t) == 8 && alignof(ssize_t) == 8 &&
                  __is_same(ssize_t, long),
              "C++ x86 ssize_t ABI");
static_assert(sizeof(off_t) == 8 && alignof(off_t) == 8 &&
                  __is_same(off_t, long),
              "C++ x86 off_t ABI");
static_assert(sizeof(mode_t) == 4 && alignof(mode_t) == 4 &&
                  __is_same(mode_t, unsigned int),
              "C++ x86 mode_t ABI");
static_assert(F_GETFD == 1 && O_CLOEXEC == 02000000 && O_PATH == 010000000,
              "C++ x86 fchmod fallback constants");
static_assert(S_IFMT == 0170000 && S_IFDIR == 0040000 &&
                  S_IFREG == 0100000 && S_IFLNK == 0120000 &&
                  S_IRUSR == 0400 && S_IWUSR == 0200 && S_IXUSR == 0100 &&
                  S_IRWXU == 0700,
              "C++ x86 selected pathname mode constants");

static_assert(__is_same(decltype(&chdir), chdir_signature),
              "C++ chdir declaration");
static_assert(__is_same(decltype(&getcwd), getcwd_signature),
              "C++ getcwd declaration");
static_assert(__is_same(decltype(&mkdir), mkdir_signature),
              "C++ mkdir declaration");
static_assert(__is_same(decltype(&unlink), unlink_signature),
              "C++ unlink declaration");
static_assert(__is_same(decltype(&rmdir), rmdir_signature),
              "C++ rmdir declaration");
static_assert(__is_same(decltype(&remove), remove_signature),
              "C++ remove declaration");
static_assert(__is_same(decltype(&rename), rename_signature),
              "C++ rename declaration");
static_assert(__is_same(decltype(&link), link_signature),
              "C++ link declaration");
static_assert(__is_same(decltype(&symlink), symlink_signature),
              "C++ symlink declaration");
static_assert(__is_same(decltype(&readlink), readlink_signature),
              "C++ readlink declaration");
static_assert(__is_same(decltype(&chmod), chmod_signature),
              "C++ chmod declaration");
static_assert(__is_same(decltype(&fchmod), fchmod_signature),
              "C++ fchmod declaration");
static_assert(__is_same(decltype(&truncate), truncate_signature),
              "C++ truncate declaration");

__attribute__((used)) static chdir_signature crabc_pathname_chdir = chdir;
__attribute__((used)) static getcwd_signature crabc_pathname_getcwd = getcwd;
__attribute__((used)) static mkdir_signature crabc_pathname_mkdir = mkdir;
__attribute__((used)) static unlink_signature crabc_pathname_unlink = unlink;
__attribute__((used)) static rmdir_signature crabc_pathname_rmdir = rmdir;
__attribute__((used)) static remove_signature crabc_pathname_remove = remove;
__attribute__((used)) static rename_signature crabc_pathname_rename = rename;
__attribute__((used)) static link_signature crabc_pathname_link = link;
__attribute__((used)) static symlink_signature crabc_pathname_symlink = symlink;
__attribute__((used)) static readlink_signature crabc_pathname_readlink = readlink;
__attribute__((used)) static chmod_signature crabc_pathname_chmod = chmod;
__attribute__((used)) static fchmod_signature crabc_pathname_fchmod = fchmod;
__attribute__((used)) static truncate_signature crabc_pathname_truncate = truncate;

int crabc_x86_64_pathname_lifecycle_header_abi_probe_cpp()
{
    return S_IFREG + F_GETFD;
}
