/* Freestanding static entry for the selected sigpause fixture.
 *
 * The archive owns the first-thread initial-TLS setup. The local restorer is
 * fixture-only raw signal-frame glue so the probe can install its disposable
 * handler without linking the existing signal-action C boundary.
 */
	.text
#ifdef CRABC_SIGPAUSE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_sigpause_probe
	mov %eax, %edi
	/* exit_group closes unexpected fixture failure paths. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start

	.global crabc_x86_64_sigpause_restorer
	.hidden crabc_x86_64_sigpause_restorer
	.type crabc_x86_64_sigpause_restorer,@function
crabc_x86_64_sigpause_restorer:
	mov $15, %eax
	syscall
	ud2
	.size crabc_x86_64_sigpause_restorer, .-crabc_x86_64_sigpause_restorer
#endif
	.section .note.GNU-stack,"",@progbits
