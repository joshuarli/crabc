/* C++ companion for the Linux/x86-64 explicit_bzero/swab ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <string.h>
#include <unistd.h>

using explicit_bzero_signature = void (*)(void *, size_t);
using swab_signature = void (*)(const void *__restrict, void *__restrict, ssize_t);

static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8, "x86 size_t ABI");
static_assert(sizeof(ssize_t) == 8 && alignof(ssize_t) == 8, "x86 ssize_t ABI");

#if defined(CRABC_EXPECT_EXPLICIT_BZERO)
static_assert(__is_same(decltype(&explicit_bzero), explicit_bzero_signature),
    "explicit_bzero declaration");
#endif
#if defined(CRABC_EXPECT_SWAB)
static_assert(__is_same(decltype(&swab), swab_signature), "swab declaration");
#endif

extern "C" void crabc_memory_special_linkage_witness()
{
#if defined(CRABC_EXPECT_EXPLICIT_BZERO)
    static volatile explicit_bzero_signature explicit_witness = &explicit_bzero;
    (void)explicit_witness;
#endif
#if defined(CRABC_EXPECT_SWAB)
    static volatile swab_signature swab_witness = &swab;
    (void)swab_witness;
#endif
}
