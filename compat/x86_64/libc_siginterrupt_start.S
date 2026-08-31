/* Freestanding static entry for the selected siginterrupt fixture.
 *
 * The archive owns first-thread initial-TLS setup for C errno. The fixture
 * installs no action and supplies no signal restorer; raw action staging stays
 * inside the C body and never delivers a signal.
 */
	.text
#ifdef CRABC_SIGINTERRUPT_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_siginterrupt_probe
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
