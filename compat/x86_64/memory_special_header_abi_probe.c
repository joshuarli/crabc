/* Linux/x86-64 explicit_bzero/swab declaration and ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>
#include <unistd.h>

typedef void (*explicit_bzero_signature)(void *, size_t);
typedef void (*swab_signature)(const void *__restrict, void *__restrict, ssize_t);

_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8,
    "x86 size_t ABI");
_Static_assert(sizeof(ssize_t) == 8 && _Alignof(ssize_t) == 8,
    "x86 ssize_t ABI");

#if defined(CRABC_EXPECT_EXPLICIT_BZERO)
_Static_assert(__builtin_types_compatible_p(__typeof__(&explicit_bzero),
    explicit_bzero_signature), "explicit_bzero declaration");
static explicit_bzero_signature explicit_bzero_witness = explicit_bzero;
#endif

#if defined(CRABC_EXPECT_SWAB)
_Static_assert(__builtin_types_compatible_p(__typeof__(&swab), swab_signature),
    "swab declaration");
static swab_signature swab_witness = swab;
#endif

/* These branches compile only in expected-failure visibility checks. */
#if defined(CRABC_REQUIRE_EXPLICIT_BZERO_HIDDEN)
static explicit_bzero_signature hidden_explicit_bzero_witness = explicit_bzero;
#endif
#if defined(CRABC_REQUIRE_SWAB_HIDDEN)
static swab_signature hidden_swab_witness = swab;
#endif

int crabc_x86_64_memory_special_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_EXPLICIT_BZERO)
    (void)explicit_bzero_witness;
#endif
#if defined(CRABC_EXPECT_SWAB)
    (void)swab_witness;
#endif
#if defined(CRABC_REQUIRE_EXPLICIT_BZERO_HIDDEN)
    (void)hidden_explicit_bzero_witness;
#endif
#if defined(CRABC_REQUIRE_SWAB_HIDDEN)
    (void)hidden_swab_witness;
#endif
    return 0;
}
