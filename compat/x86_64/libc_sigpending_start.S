/* Freestanding static entry for the selected POSIX sigpending fixture.
 *
 * The archive owns first-thread initial-TLS setup because the probe observes
 * errno. This entry does not install an FS base or provide CRT lifecycle.
 */
	.text
#ifdef CRABC_SIGPENDING_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_sigpending_probe
	mov %eax, %edi
	/* exit_group closes unexpected fixture failure paths. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
