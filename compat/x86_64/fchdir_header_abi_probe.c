/* Pinned-musl/project Linux/x86-64 <unistd.h> fchdir declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_FCHDIR)
typedef int (*fchdir_signature)(int);

_Static_assert(sizeof(int) == 4, "x86 signed int width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fchdir),
    fchdir_signature), "fchdir declaration");

static fchdir_signature fchdir_function __attribute__((used)) = fchdir;
#endif

int crabc_x86_64_fchdir_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_FCHDIR)
    return fchdir_function == (fchdir_signature)0;
#else
    return 0;
#endif
}
