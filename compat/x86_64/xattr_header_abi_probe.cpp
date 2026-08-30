/* C++17 companion for the Linux/x86-64 direct <sys/xattr.h> ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/xattr.h>

using xattr_get_path_signature = ssize_t (*)(const char *, const char *, void *,
                                             size_t);
using xattr_get_fd_signature = ssize_t (*)(int, const char *, void *, size_t);
using xattr_list_path_signature = ssize_t (*)(const char *, char *, size_t);
using xattr_list_fd_signature = ssize_t (*)(int, char *, size_t);
using xattr_set_path_signature = int (*)(const char *, const char *, const void *,
                                         size_t, int);
using xattr_set_fd_signature = int (*)(int, const char *, const void *, size_t, int);
using xattr_remove_path_signature = int (*)(const char *, const char *);
using xattr_remove_fd_signature = int (*)(int, const char *);

static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
              "C++ x86 xattr size scalar ABI");
static_assert(XATTR_CREATE == 1 && XATTR_REPLACE == 2,
              "C++ xattr setter flag values");

static_assert(__is_same(decltype(&getxattr), xattr_get_path_signature),
              "C++ getxattr declaration");
static_assert(__is_same(decltype(&lgetxattr), xattr_get_path_signature),
              "C++ lgetxattr declaration");
static_assert(__is_same(decltype(&fgetxattr), xattr_get_fd_signature),
              "C++ fgetxattr declaration");
static_assert(__is_same(decltype(&listxattr), xattr_list_path_signature),
              "C++ listxattr declaration");
static_assert(__is_same(decltype(&llistxattr), xattr_list_path_signature),
              "C++ llistxattr declaration");
static_assert(__is_same(decltype(&flistxattr), xattr_list_fd_signature),
              "C++ flistxattr declaration");
static_assert(__is_same(decltype(&setxattr), xattr_set_path_signature),
              "C++ setxattr declaration");
static_assert(__is_same(decltype(&lsetxattr), xattr_set_path_signature),
              "C++ lsetxattr declaration");
static_assert(__is_same(decltype(&fsetxattr), xattr_set_fd_signature),
              "C++ fsetxattr declaration");
static_assert(__is_same(decltype(&removexattr), xattr_remove_path_signature),
              "C++ removexattr declaration");
static_assert(__is_same(decltype(&lremovexattr), xattr_remove_path_signature),
              "C++ lremovexattr declaration");
static_assert(__is_same(decltype(&fremovexattr), xattr_remove_fd_signature),
              "C++ fremovexattr declaration");

/* `used` retains all header-requested external names for the runner's nm check. */
__attribute__((used)) static xattr_get_path_signature xattr_cxx_get = getxattr;
__attribute__((used)) static xattr_get_path_signature xattr_cxx_lget = lgetxattr;
__attribute__((used)) static xattr_get_fd_signature xattr_cxx_fget = fgetxattr;
__attribute__((used)) static xattr_list_path_signature xattr_cxx_list = listxattr;
__attribute__((used)) static xattr_list_path_signature xattr_cxx_llist = llistxattr;
__attribute__((used)) static xattr_list_fd_signature xattr_cxx_flist = flistxattr;
__attribute__((used)) static xattr_set_path_signature xattr_cxx_set = setxattr;
__attribute__((used)) static xattr_set_path_signature xattr_cxx_lset = lsetxattr;
__attribute__((used)) static xattr_set_fd_signature xattr_cxx_fset = fsetxattr;
__attribute__((used)) static xattr_remove_path_signature xattr_cxx_remove = removexattr;
__attribute__((used)) static xattr_remove_path_signature xattr_cxx_lremove = lremovexattr;
__attribute__((used)) static xattr_remove_fd_signature xattr_cxx_fremove = fremovexattr;

int crabc_x86_64_xattr_header_abi_probe_cpp()
{
    return XATTR_CREATE + XATTR_REPLACE;
}
