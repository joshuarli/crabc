/* Freestanding static entry for the selected SysV signal-helper fixture.
 *
 * The archive owns first-thread initial-TLS setup for C errno. The C body
 * uses raw action/mask staging only to observe the four selected helper calls;
 * it does not install a fixture-private FS base or assert pthread policy.
 */

	.text
#ifdef CRABC_SIGNAL_SYSV_HELPERS_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_signal_sysv_helpers_probe
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
