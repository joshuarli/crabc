/* Freestanding static entry for libc_auxv_observation_probe.c.
 *
 * Preserve the Linux initial stack for the selected Static Initial TLS v1
 * bootstrap, then pass the real argc/argv and the fixture constructor into
 * bounded crabc __libc_start_main. This is evidence-only entry glue, not a
 * second CRT or loader implementation.
 */

	.text
#ifdef CRABC_AUXV_OBSERVATION_FREESTANDING
	.global _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	mov %rsp, %r12
	and $-16, %rsp
	mov %r12, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne .Lbootstrap_failure

	lea main(%rip), %rdi
	mov (%r12), %esi
	lea 8(%r12), %rdx
	lea crabc_x86_64_auxv_observation_init(%rip), %rcx
	xor %r8d, %r8d
	xor %r9d, %r9d
	call __libc_start_main
	ud2

.Lbootstrap_failure:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
