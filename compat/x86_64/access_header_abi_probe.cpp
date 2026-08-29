/* C++17 companion for the Linux/x86-64 direct access-header ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <unistd.h>

static_assert(F_OK == 0 && X_OK == 1 && W_OK == 2 && R_OK == 4,
              "access mode values");
static_assert(AT_FDCWD == -100, "x86 AT_FDCWD value");
static_assert(AT_SYMLINK_NOFOLLOW == 0x100, "AT_SYMLINK_NOFOLLOW value");
static_assert(AT_EACCESS == 0x200, "AT_EACCESS value");

using access_signature = int (*)(const char *, int);
using faccessat_signature = int (*)(int, const char *, int, int);

static_assert(__is_same(decltype(&access), access_signature),
              "access C++ declaration");
static_assert(__is_same(decltype(&faccessat), faccessat_signature),
              "faccessat C++ declaration");

__attribute__((used)) static access_signature access_cxx_access = access;
__attribute__((used)) static faccessat_signature access_cxx_faccessat = faccessat;

#if defined(CRABC_ACCESS_REQUIRE_GNU)
static_assert(__is_same(decltype(&eaccess), access_signature),
              "eaccess GNU C++ declaration");
static_assert(__is_same(decltype(&euidaccess), access_signature),
              "euidaccess GNU C++ declaration");

__attribute__((used)) static access_signature access_cxx_eaccess = eaccess;
__attribute__((used)) static access_signature access_cxx_euidaccess = euidaccess;
#endif

/* These opt-in references must fail outside GNU feature selection. */
#if defined(CRABC_ACCESS_REQUIRE_GNU_HIDDEN)
__attribute__((used)) static access_signature access_gnu_eaccess_must_be_hidden =
    eaccess;
__attribute__((used)) static access_signature access_gnu_euidaccess_must_be_hidden =
    euidaccess;
#endif
