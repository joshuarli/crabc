/* Freestanding static entry for libc_sethostent_probe.c.
 *
 * This no-state evidence shim is neither a CRT nor a netdb/runtime owner.
 */

	.text
#ifdef CRABC_SETHOSTENT_FREESTANDING
	.global _start
	.type _start,@function
_start:
	call crabc_x86_64_sethostent_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
