/* Freestanding static entry for the selected usleep fixture.
 *
 * The archive owns first-thread initial-TLS setup because the C body observes
 * errno. The local restorer is fixture-only raw signal-frame glue; it neither
 * installs an FS base nor provides CRT, signal-action, or timer runtime state.
 */
	.text
#ifdef CRABC_USLEEP_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_usleep_probe
	mov %eax, %edi
	/* exit_group closes unexpected fixture failure paths. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start

	.global crabc_x86_64_usleep_restorer
	.hidden crabc_x86_64_usleep_restorer
	.type crabc_x86_64_usleep_restorer,@function
crabc_x86_64_usleep_restorer:
	mov $15, %eax
	syscall
	ud2
	.size crabc_x86_64_usleep_restorer, .-crabc_x86_64_usleep_restorer
#endif
	.section .note.GNU-stack,"",@progbits
