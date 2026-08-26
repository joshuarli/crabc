/*
 * Source-only Linux/x86-64 <sys/reg.h> declaration check.
 *
 * The pinned musl 1.2.6 x86-64 headers are the macro-value oracle. This
 * fixture is deliberately compiled with the project include tree first, but
 * never links or selects crabc-libc.
 */

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sys/reg.h>

_Static_assert(R15 == 0, "musl x86-64 R15 index");
_Static_assert(R14 == 1, "musl x86-64 R14 index");
_Static_assert(R13 == 2, "musl x86-64 R13 index");
_Static_assert(R12 == 3, "musl x86-64 R12 index");
_Static_assert(RBP == 4, "musl x86-64 RBP index");
_Static_assert(RBX == 5, "musl x86-64 RBX index");
_Static_assert(R11 == 6, "musl x86-64 R11 index");
_Static_assert(R10 == 7, "musl x86-64 R10 index");
_Static_assert(R9 == 8, "musl x86-64 R9 index");
_Static_assert(R8 == 9, "musl x86-64 R8 index");
_Static_assert(RAX == 10, "musl x86-64 RAX index");
_Static_assert(RCX == 11, "musl x86-64 RCX index");
_Static_assert(RDX == 12, "musl x86-64 RDX index");
_Static_assert(RSI == 13, "musl x86-64 RSI index");
_Static_assert(RDI == 14, "musl x86-64 RDI index");
_Static_assert(ORIG_RAX == 15, "musl x86-64 ORIG_RAX index");
_Static_assert(RIP == 16, "musl x86-64 RIP index");
_Static_assert(CS == 17, "musl x86-64 CS index");
_Static_assert(EFLAGS == 18, "musl x86-64 EFLAGS index");
_Static_assert(RSP == 19, "musl x86-64 RSP index");
_Static_assert(SS == 20, "musl x86-64 SS index");
_Static_assert(FS_BASE == 21, "musl x86-64 FS_BASE index");
_Static_assert(GS_BASE == 22, "musl x86-64 GS_BASE index");
_Static_assert(DS == 23, "musl x86-64 DS index");
_Static_assert(ES == 24, "musl x86-64 ES index");
_Static_assert(FS == 25, "musl x86-64 FS index");
_Static_assert(GS == 26, "musl x86-64 GS index");

int crabc_x86_64_sys_reg_header_abi_probe(void)
{
    return R15 + GS;
}
