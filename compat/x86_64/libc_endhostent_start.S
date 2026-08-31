/* Freestanding static entry for libc_endhostent_probe.c.
 *
 * This no-state evidence shim is neither a CRT nor a network-runtime owner.
 */

	.text
#ifdef CRABC_ENDHOSTENT_FREESTANDING
	.global _start
	.type _start,@function
_start:
	call crabc_x86_64_endhostent_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
