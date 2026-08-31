/* C++17 companion for the Linux/x86-64 ctermid declaration gate. */

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
static_assert(L_ctermid == 20, "musl L_ctermid value");

using ctermid_signature = char *(*)(char *);

static_assert(__is_same(decltype(&ctermid), ctermid_signature),
    "C++ ctermid declaration");

static ctermid_signature ctermid_function = ctermid;
#endif

/* Opt-in references that must fail when the POSIX/XSI spelling is hidden. */
#if defined(CRABC_REQUIRE_CTERMID_HIDDEN)
#ifdef L_ctermid
#error "strict stdio.h must hide L_ctermid"
#endif
using hidden_ctermid_signature = char *(*)(char *);
static hidden_ctermid_signature ctermid_must_be_hidden = ctermid;
#endif

/* Unlike the declaration probe above, this must compile in strict mode. */
#if defined(CRABC_REQUIRE_L_CTERMID_HIDDEN)
#ifdef L_ctermid
#error "strict stdio.h must hide L_ctermid"
#endif
#endif

int crabc_x86_64_ctermid_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_CTERMID)
    return ctermid_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
