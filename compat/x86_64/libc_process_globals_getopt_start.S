/* Freestanding static entry for libc_process_globals_getopt_probe.c.
 *
 * The selected archive owns x86 Static Initial TLS v1 and its bounded static
 * __libc_start_main lifecycle. Preserve the untouched Linux entry stack for
 * the TLS owner, then pass the real argc/argv and the fixture constructor to
 * libc startup. This is evidence-only glue, not a second CRT implementation.
 */

	.text
#ifdef CRABC_PROCESS_GLOBALS_GETOPT_FREESTANDING
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
	lea crabc_x86_64_process_globals_getopt_init(%rip), %rcx
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
