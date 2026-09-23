/*
 * Freestanding static entry for libc_pthread_c11_once_probe.c.
 *
 * libc owns the actual Static Initial TLS v1 installation. Keep this tiny
 * shim free of fixture-local TLS-base setup so the selected pthread/C11 once
 * candidate proves the same first-thread owner as its worker siblings.
 */
	.text
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_pthread_c11_once_probe
	mov %eax, %edi
	/* exit_group also closes a deliberately failed join path without leaving a
	 * blocked selected worker alive after the probe reports its failure. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start

/* This freestanding C fixture cannot unwind. The selected nightly core object
 * still carries a personality relocation, so the fixture owns an inert
 * endpoint rather than selecting an ambient runtime provider. */
	.global rust_eh_personality
	.type rust_eh_personality,@function
rust_eh_personality:
	ud2
	.size rust_eh_personality, .-rust_eh_personality
	.section .note.GNU-stack,"",@progbits
