/* Freestanding entry for the selected getitimer/setitimer fixture. */
	.text
#ifdef CRABC_INTERVAL_TIMERS_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_interval_timers_probe
	mov %eax, %edi
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
