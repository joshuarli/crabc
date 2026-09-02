	.text
#ifdef CRABC_SERVICE_LIFECYCLE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_service_lifecycle_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
