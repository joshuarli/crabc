/* Linux/x86-64 GNU C++17 <sys/mman.h> memfd_create declaration/value probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>
#include <sys/syscall.h>

using memfd_create_signature = int (*)(const char *, unsigned);

static_assert(SYS_memfd_create == 319, "x86 memfd_create syscall number");

#if defined(CRABC_MEMFD_CREATE_REQUIRE_GNU) || \
    defined(CRABC_MEMFD_CREATE_REQUIRE_GNU_HIDDEN)
static_assert(__is_same(decltype(&memfd_create), memfd_create_signature),
    "GNU C++ memfd_create declaration");
static_assert(MFD_CLOEXEC == 0x0001U && MFD_ALLOW_SEALING == 0x0002U &&
    MFD_HUGETLB == 0x0004U, "GNU C++ MFD flag values");
__attribute__((used)) static memfd_create_signature
    crabc_memfd_create_c_linkage = memfd_create;
#else
#ifdef MFD_CLOEXEC
#error "MFD_CLOEXEC must remain hidden outside GNU feature selection"
#endif
#ifdef MFD_ALLOW_SEALING
#error "MFD_ALLOW_SEALING must remain hidden outside GNU feature selection"
#endif
#ifdef MFD_HUGETLB
#error "MFD_HUGETLB must remain hidden outside GNU feature selection"
#endif
#endif

/* This opt-in reference must fail outside GNU feature selection. */
#if defined(CRABC_MEMFD_CREATE_REQUIRE_GNU_HIDDEN)
__attribute__((used)) static memfd_create_signature
    crabc_memfd_create_must_be_hidden = memfd_create;
#endif

int crabc_x86_64_memfd_create_header_abi_probe_cpp()
{
    return SYS_memfd_create;
}
