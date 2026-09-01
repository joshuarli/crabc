/* Freestanding static entry for the explicit_bzero/swab behavior fixture.
 * The pair owns no errno, TLS, CRT, allocator, or process lifecycle contract.
 */
	.text
#ifdef CRABC_MEMORY_SPECIAL_FREESTANDING
	.global _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_memory_special_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
