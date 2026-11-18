/* AArch64 translation of pinned native musl; see float_parse.rs for provenance and license. */
/* musl-1.2.6/src/locale/strtod_l.c */
	.arch armv8-a
	.text
	.section	.text.strtof_l,"ax",@progbits
	.align	2
	.global	strtof_l
	.type	strtof_l, %function
strtof_l:
	b	strtof
	.size	strtof_l, .-strtof_l
	.weak	__strtof_l
	.set	__strtof_l,strtof_l
	.section	.text.strtod_l,"ax",@progbits
	.align	2
	.global	strtod_l
	.type	strtod_l, %function
strtod_l:
	b	strtod
	.size	strtod_l, .-strtod_l
	.weak	__strtod_l
	.set	__strtod_l,strtod_l
	.section	.text.strtold_l,"ax",@progbits
	.align	2
	.global	strtold_l
	.type	strtold_l, %function
strtold_l:
	b	strtold
	.size	strtold_l, .-strtold_l
	.weak	__strtold_l
	.set	__strtold_l,strtold_l
	.section	.note.GNU-stack,"",@progbits
