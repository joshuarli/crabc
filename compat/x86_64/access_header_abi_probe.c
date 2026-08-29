/* Selected Linux/x86-64 direct <unistd.h>/<fcntl.h> access declarations. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <unistd.h>

_Static_assert(F_OK == 0 && X_OK == 1 && W_OK == 2 && R_OK == 4,
               "access mode values");
_Static_assert(AT_FDCWD == -100, "x86 AT_FDCWD value");
_Static_assert(AT_SYMLINK_NOFOLLOW == 0x100, "AT_SYMLINK_NOFOLLOW value");
_Static_assert(AT_EACCESS == 0x200, "AT_EACCESS value");

typedef int (*access_signature)(const char *, int);
typedef int (*faccessat_signature)(int, const char *, int, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&access), access_signature),
               "access declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&faccessat),
                                             faccessat_signature),
               "faccessat declaration");

#if defined(CRABC_ACCESS_REQUIRE_GNU)
_Static_assert(__builtin_types_compatible_p(__typeof__(&eaccess), access_signature),
               "eaccess GNU declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&euidaccess),
                                             access_signature),
               "euidaccess GNU declaration");
#endif

/* These opt-in references must fail outside GNU feature selection. */
#if defined(CRABC_ACCESS_REQUIRE_GNU_HIDDEN)
static access_signature access_gnu_eaccess_must_be_hidden = eaccess;
static access_signature access_gnu_euidaccess_must_be_hidden = euidaccess;
#endif
