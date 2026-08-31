/* Freestanding static entry for libc_signalfd_probe.c.
 *
 * This calls the archive-owned Static Initial TLS v1 bootstrap before the
 * fixture uses errno. Its exit_group tail is evidence-only glue, not a CRT.
 */
	.text
#ifdef CRABC_SIGNALFD_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_signalfd_probe
	mov %eax, %edi
	/* exit_group closes unexpected failure paths after fixture cleanup. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
