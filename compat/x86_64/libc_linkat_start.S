/* Freestanding static entry for libc_linkat_probe.c.
 *
 * The selected archive owns its initial-TLS errno datum. This evidence-only
 * shim delegates first-thread setup to that private bootstrap; it is neither
 * a general CRT nor a general TLS runtime.
 */
	.text
#ifdef CRABC_LINKAT_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_linkat_probe
	mov %eax, %edi
	/* exit_group closes the fixture without selecting ordinary C exit. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
