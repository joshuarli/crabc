/* Freestanding static entry for libc_posix_close_probe.c.
 *
 * The selected archive owns its initial-TLS errno datum. This evidence-only
 * shim creates its first-thread slot before the fixture; it is neither a
 * general CRT nor a descriptor-lifecycle runtime.
 */

	.text
#ifdef CRABC_POSIX_CLOSE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_posix_close_probe
	mov %eax, %edi
	/* exit_group ends only this evidence fixture. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
