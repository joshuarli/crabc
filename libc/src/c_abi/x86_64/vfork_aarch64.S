// musl 1.2.6 src/process/aarch64/vfork.s; MIT license.
.global vfork
.type vfork,%function
vfork:
	mov x8, 220    // SYS_clone
	mov x0, 0x4111 // SIGCHLD | CLONE_VM | CLONE_VFORK
	mov x1, 0
	svc 0
	.hidden __crabc_owned_vfork_result
	b __crabc_owned_vfork_result
