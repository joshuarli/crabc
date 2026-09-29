/*
 * Source-only Linux/x86-64 setjmp ABI fixture.
 *
 * It is compiled once against the pinned musl 1.2.6 headers/runtime and once
 * with the project header tree first plus the isolated crabc x86 assembly
 * object. Both executions must preserve the public control-transfer and
 * signal-mask contract. Neither execution selects crabc-libc.
 */
#define _GNU_SOURCE 1

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <limits.h>

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(__jmp_buf) == 8 * sizeof(unsigned long),
	"musl x86-64 machine save area");
_Static_assert(sizeof(struct __jmp_buf_tag) == 200,
	"musl x86-64 jmp_buf record size");
_Static_assert(_Alignof(struct __jmp_buf_tag) == 8,
	"musl x86-64 jmp_buf record alignment");
_Static_assert(sizeof(jmp_buf) == 200, "musl x86-64 jmp_buf size");
_Static_assert(_Alignof(jmp_buf) == 8, "musl x86-64 jmp_buf alignment");
_Static_assert(sizeof(sigjmp_buf) == 200, "musl x86-64 sigjmp_buf size");
_Static_assert(_Alignof(sigjmp_buf) == 8, "musl x86-64 sigjmp_buf alignment");
_Static_assert(offsetof(struct __jmp_buf_tag, __jb) == 0,
	"x86 machine-save area offset");
_Static_assert(offsetof(struct __jmp_buf_tag, __fl) == 64,
	"x86 sigsetjmp flag/return slot offset");
_Static_assert(offsetof(struct __jmp_buf_tag, __ss) == 72,
	"x86 saved signal-mask offset");
_Static_assert(sizeof(((struct __jmp_buf_tag *)0)->__ss) == 128,
	"musl public saved signal-mask storage");

/* musl exports this ABI alias but intentionally keeps it out of setjmp.h. */
extern int __setjmp(jmp_buf) __attribute__((returns_twice));

/*
 * Keep the saved continuation active while this assembly helper changes all
 * six SysV callee-saved registers. A normal C assertion after setjmp is not
 * sufficient: the compiler may legally repurpose those registers before the
 * assertion executes. This harness proves both saved slots and longjmp's
 * restoration of RBX, RBP, R12-R15, post-return RSP, and a non-null RIP.
 */
extern int crabc_setjmp_callee_saved_probe(jmp_buf);

__asm__(
	".text\n"
	".global crabc_setjmp_callee_saved_probe\n"
	".type crabc_setjmp_callee_saved_probe,@function\n"
	"crabc_setjmp_callee_saved_probe:\n"
	" pushq %rbx\n"
	" pushq %rbp\n"
	" pushq %r12\n"
	" pushq %r13\n"
	" pushq %r14\n"
	" pushq %r15\n"
	" subq $8, %rsp\n"
	" movq %rdi, (%rsp)\n"
	" movabsq $0x1111111111111111, %rbx\n"
	" movabsq $0x2222222222222222, %rbp\n"
	" movabsq $0x3333333333333333, %r12\n"
	" movabsq $0x4444444444444444, %r13\n"
	" movabsq $0x5555555555555555, %r14\n"
	" movabsq $0x6666666666666666, %r15\n"
	" call setjmp\n"
	" testl %eax, %eax\n"
	" jne .Lcrabc_setjmp_resumed\n"
	" movq (%rsp), %rdi\n"
	" movl $41, %esi\n"
	" call longjmp\n"
	".Lcrabc_setjmp_resumed:\n"
	" cmpl $41, %eax\n"
	" jne .Lcrabc_setjmp_failed\n"
	" movq (%rsp), %rdi\n"
	" cmpq %rbx, 0(%rdi)\n"
	" jne .Lcrabc_setjmp_failed\n"
	" cmpq %rbp, 8(%rdi)\n"
	" jne .Lcrabc_setjmp_failed\n"
	" cmpq %r12, 16(%rdi)\n"
	" jne .Lcrabc_setjmp_failed\n"
	" cmpq %r13, 24(%rdi)\n"
	" jne .Lcrabc_setjmp_failed\n"
	" cmpq %r14, 32(%rdi)\n"
	" jne .Lcrabc_setjmp_failed\n"
	" cmpq %r15, 40(%rdi)\n"
	" jne .Lcrabc_setjmp_failed\n"
	" movq 48(%rdi), %rax\n"
	" cmpq %rsp, %rax\n"
	" jne .Lcrabc_setjmp_failed\n"
	" cmpq $0, 56(%rdi)\n"
	" je .Lcrabc_setjmp_failed\n"
	" movl $1, %eax\n"
	" jmp .Lcrabc_setjmp_done\n"
	".Lcrabc_setjmp_failed:\n"
	" xorl %eax, %eax\n"
	".Lcrabc_setjmp_done:\n"
	" addq $8, %rsp\n"
	" popq %r15\n"
	" popq %r14\n"
	" popq %r13\n"
	" popq %r12\n"
	" popq %rbp\n"
	" popq %rbx\n"
	" ret\n"
	".size crabc_setjmp_callee_saved_probe,. - crabc_setjmp_callee_saved_probe\n");

static int test_machine_context(void)
{
	jmp_buf environment;

	int intact = crabc_setjmp_callee_saved_probe(environment);
	printf("machine_context=%d\n", intact);
	return intact;
}

static int test_setjmp_value(int jump_value, int expected)
{
	jmp_buf environment;
	int result = setjmp(environment);

	if (result == 0)
		longjmp(environment, jump_value);
	printf("setjmp(%d)=%d\n", jump_value, result);
	return result == expected;
}

static int test___setjmp_alias(void)
{
	jmp_buf environment;
	int result = __setjmp(environment);

	if (result == 0)
		_longjmp(environment, 0);
	printf("__setjmp/_longjmp(0)=%d\n", result);
	return result == 1;
}

static int test__setjmp_alias(void)
{
	jmp_buf environment;
	int result = _setjmp(environment);

	if (result == 0)
		longjmp(environment, -27);
	printf("_setjmp/longjmp(-27)=%d\n", result);
	return result == -27;
}

static int signal_is_blocked(int signal)
{
	sigset_t current;

	if (sigprocmask(SIG_SETMASK, 0, &current) != 0)
		return -1;
	return sigismember(&current, signal);
}

static int test_sigsetjmp_mask(int savemask)
{
	sigjmp_buf environment;
	sigset_t original;
	sigset_t unblocked;
	sigset_t blocked;
	int result;
	int observed;

	if (sigprocmask(SIG_SETMASK, 0, &original) != 0)
		return 0;
	unblocked = original;
	if (sigdelset(&unblocked, SIGUSR1) != 0
		|| sigprocmask(SIG_SETMASK, &unblocked, 0) != 0)
		return 0;

	result = sigsetjmp(environment, savemask);
	if (result == 0) {
		blocked = unblocked;
		if (sigaddset(&blocked, SIGUSR1) != 0
			|| sigprocmask(SIG_SETMASK, &blocked, 0) != 0) {
			(void)sigprocmask(SIG_SETMASK, &original, 0);
			return 0;
		}
		siglongjmp(environment, 29);
	}

	observed = signal_is_blocked(SIGUSR1);
	if (sigprocmask(SIG_SETMASK, &original, 0) != 0)
		return 0;
	printf("sigsetjmp(%d)/siglongjmp(29)=%d mask=%d\n",
		savemask, result, observed);
	return result == 29 && observed == (savemask ? 0 : 1);
}

static int test_siglongjmp_zero(void)
{
	sigjmp_buf environment;
	int result = sigsetjmp(environment, 1);

	if (result == 0)
		siglongjmp(environment, 0);
	printf("sigsetjmp(1)/siglongjmp(0)=%d\n", result);
	return result == 1;
}

/* Both continuations remain live. The inner return checks its own saved mask;
 * the outer return then checks that the first mask change was also undone. */
static int test_nested_signal_masks(int inner_savemask)
{
	sigjmp_buf outer;
	sigjmp_buf inner;
	sigset_t original;
	sigset_t base;
	sigset_t stage;
	int outer_result;
	int inner_result;
	int inner_usr1;
	int inner_usr2;
	int outer_usr1;
	int outer_usr2;

	if (sigprocmask(SIG_SETMASK, 0, &original) != 0)
		return 0;
	base = original;
	if (sigdelset(&base, SIGUSR1) != 0 || sigdelset(&base, SIGUSR2) != 0
		|| sigprocmask(SIG_SETMASK, &base, 0) != 0)
		return 0;

	outer_result = sigsetjmp(outer, 1);
	if (outer_result == 0) {
		stage = base;
		if (sigaddset(&stage, SIGUSR1) != 0
			|| sigprocmask(SIG_SETMASK, &stage, 0) != 0)
			goto failure;
		inner_result = sigsetjmp(inner, inner_savemask);
		if (inner_result == 0) {
			if (sigaddset(&stage, SIGUSR2) != 0
				|| sigprocmask(SIG_SETMASK, &stage, 0) != 0)
				goto failure;
			siglongjmp(inner, 0);
		}
		inner_usr1 = signal_is_blocked(SIGUSR1);
		inner_usr2 = signal_is_blocked(SIGUSR2);
		printf("nested(%d) inner=%d mask=%d,%d\n", inner_savemask,
			inner_result, inner_usr1, inner_usr2);
		if (inner_result != 1 || inner_usr1 != 1
			|| inner_usr2 != (inner_savemask ? 0 : 1))
			goto failure;
		siglongjmp(outer, -31);
	}
	outer_usr1 = signal_is_blocked(SIGUSR1);
	outer_usr2 = signal_is_blocked(SIGUSR2);
	printf("nested(%d) outer=%d mask=%d,%d\n", inner_savemask,
		outer_result, outer_usr1, outer_usr2);
	if (sigprocmask(SIG_SETMASK, &original, 0) != 0)
		return 0;
	return outer_result == -31 && outer_usr1 == 0 && outer_usr2 == 0;

failure:
	(void)sigprocmask(SIG_SETMASK, &original, 0);
	return 0;
}

int main(void)
{
	if (!test_machine_context())
		return 10;
	if (!test_setjmp_value(0, 1))
		return 15;
	if (!test_setjmp_value(7, 7))
		return 16;
	if (!test_setjmp_value(INT_MIN, INT_MIN))
		return 17;
	if (!test___setjmp_alias())
		return 11;
	if (!test__setjmp_alias())
		return 12;
	if (!test_sigsetjmp_mask(1))
		return 13;
	if (!test_sigsetjmp_mask(0))
		return 14;
	if (!test_siglongjmp_zero())
		return 18;
	if (!test_nested_signal_masks(1))
		return 19;
	if (!test_nested_signal_masks(0))
		return 20;
	return 0;
}
