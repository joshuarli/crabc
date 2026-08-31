/* Pinned-musl/project Linux/x86-64 ctermid declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdio.h>

#if defined(CRABC_EXPECT_CTERMID)
#ifndef L_ctermid
#error "ctermid selection must expose L_ctermid"
#endif
_Static_assert(L_ctermid == 20, "musl L_ctermid value");

typedef char *(*ctermid_signature)(char *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&ctermid),
    ctermid_signature), "ctermid declaration");

static ctermid_signature ctermid_function = ctermid;
#endif

/* Opt-in references that must fail when the POSIX/XSI spelling is hidden. */
#if defined(CRABC_REQUIRE_CTERMID_HIDDEN)
#ifdef L_ctermid
#error "strict stdio.h must hide L_ctermid"
#endif
typedef char *(*hidden_ctermid_signature)(char *);
static hidden_ctermid_signature ctermid_must_be_hidden = ctermid;
#endif

/* Unlike the declaration probe above, this must compile in strict mode. */
#if defined(CRABC_REQUIRE_L_CTERMID_HIDDEN)
#ifdef L_ctermid
#error "strict stdio.h must hide L_ctermid"
#endif
#endif

int crabc_x86_64_ctermid_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_CTERMID)
    return ctermid_function != (ctermid_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
