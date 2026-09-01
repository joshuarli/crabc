/* Freestanding static entry for the optimized explicit_bzero retention probe. */

	.text
#ifdef CRABC_EXPLICIT_BZERO_DEAD_WIPE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_explicit_bzero_dead_wipe
	xor %edi, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
