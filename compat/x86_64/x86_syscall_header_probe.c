/*
 * Source-only Linux/x86-64 <sys/syscall.h> macro-surface check.
 *
 * The runner compiles this with the project include tree first, then compares
 * every __NR_* and SYS_* macro that preprocessing exposes with the pinned
 * musl 1.2.6 x86-64 header. This fixture carries boundary sentinels so a
 * project header cannot silently select the AArch64 number namespace.
 * It deliberately has no link step and never selects crabc-libc.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/syscall.h>

_Static_assert(__NR_read == 0, "musl x86-64 __NR_read");
_Static_assert(SYS_read == 0, "musl x86-64 SYS_read");
_Static_assert(__NR_arch_prctl == 158, "musl x86-64 __NR_arch_prctl");
_Static_assert(SYS_arch_prctl == 158, "musl x86-64 SYS_arch_prctl");
_Static_assert(__NR_openat == 257, "musl x86-64 __NR_openat");
_Static_assert(SYS_openat == 257, "musl x86-64 SYS_openat");
_Static_assert(__NR_uretprobe == 335, "musl x86-64 __NR_uretprobe");
_Static_assert(SYS_uretprobe == 335, "musl x86-64 SYS_uretprobe");
_Static_assert(__NR_pidfd_send_signal == 424,
	"musl x86-64 post-gap __NR_pidfd_send_signal");
_Static_assert(SYS_pidfd_send_signal == 424,
	"musl x86-64 post-gap SYS_pidfd_send_signal");
_Static_assert(__NR_listns == 470, "musl x86-64 latest __NR_listns");
_Static_assert(SYS_listns == 470, "musl x86-64 latest SYS_listns");

int crabc_x86_64_syscall_header_probe(void)
{
	return SYS_read + SYS_arch_prctl + SYS_openat + SYS_listns;
}
