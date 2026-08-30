/* Freestanding static entry for libc_sysv_semaphore_probe.c.
 *
 * The selected archive owns the initial-TLS errno datum.  Delegate first
 * thread setup to its private bootstrap before entering the project-header C
 * body; this fixture remains only an evidence shim, not a CRT or TLS runtime.
 */
	.text
	/* The C fixture calls this fixed-arity shim for its final no-vararg
	 * regression.  The public semctl ABI receives its first three integers in
	 * rdi/rsi/rdx; rcx would hold a supplied union semun word.  Enter with a
	 * deliberately nonzero rcx sentinel so the candidate must install r10=0
	 * on its unknown/no-vararg syscall path.  A tail jump leaves the ordinary
	 * C caller's return address and stack alignment intact. */
	.global crabc_x86_64_semctl_poisoned_default_call
	.type crabc_x86_64_semctl_poisoned_default_call,@function
crabc_x86_64_semctl_poisoned_default_call:
	movabs $0x13579bdf2468ace1, %rcx
	jmp semctl
	.size crabc_x86_64_semctl_poisoned_default_call, .-crabc_x86_64_semctl_poisoned_default_call

#ifdef CRABC_SYSV_SEMAPHORE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_sysv_semaphore_probe
	mov %eax, %edi
	/* exit_group closes an unexpected failure path without retaining a
	 * process that owns a SysV semaphore set. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
