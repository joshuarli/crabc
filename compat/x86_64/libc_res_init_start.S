/* Freestanding static entry for libc_res_init_probe.c.
 *
 * This evidence shim is neither a CRT nor a resolver runtime owner.
 */

	.text
#ifdef CRABC_RES_INIT_FREESTANDING
	.global _start
	.type _start,@function
_start:
	call crabc_x86_64_res_init_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
