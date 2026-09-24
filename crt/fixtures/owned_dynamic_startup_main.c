/*
 * Owned dynamic CRT startup and main-lifecycle probe.
 *
 * The same source is linked by the installed owned driver (Scrt1.o or
 * dynamic crt1.o) and by the pinned musl 1.2.6 compiler profile. Each
 * lifecycle callback verifies the process state that startup must publish
 * before it can run, then writes one unbuffered marker. Buffered stdio bytes
 * prove where exit flushes streams relative to finalizers. Pinned musl never
 * dispatches a dynamic executable's DT_PREINIT_ARRAY; the owned CRT does, so
 * only the candidate transcript carries the leading `P`.
 *
 * CRABC_CRT_CASE selects one process scenario; every callback reads it from
 * the environment that libc publishes before any application callback.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

extern char **environ;
extern uintptr_t __stack_chk_guard;
void _start(void);
int owned_startup_dependency_value(void);
void *owned_startup_open_plugin(void);

static __thread int initialized_tls = 42;
static __thread char zero_tls[64];

static void fail(char reason) __attribute__((noreturn));
static void fail(char reason)
{
	char text[2] = {'!', reason};
	(void)write(1, text, sizeof(text));
	_exit(90);
}

static int scenario(const char *name)
{
	const char *selected = getenv("CRABC_CRT_CASE");
	return selected != 0 && strcmp(selected, name) == 0;
}

static uintptr_t thread_canary(void)
{
	uintptr_t value;
	__asm__ volatile("mov %%fs:0x28, %0" : "=r"(value));
	return value;
}

/*
 * Every callback must see the SysV 16-byte call alignment, published TLS,
 * the AT_RANDOM-derived canary with musl's zeroed second byte, and a
 * working errno. Frame pointers are forced for this translation unit.
 */
#define CHECK_CALLBACK_STATE()                                                   \
	do {                                                                     \
		if ((uintptr_t)__builtin_frame_address(0) & 15) fail('s');       \
		if (initialized_tls != 42 || zero_tls[0] || zero_tls[63]) fail('t'); \
		uintptr_t canary = thread_canary();                              \
		if (!canary || canary != __stack_chk_guard || (canary & 0xff00)) fail('g'); \
		int saved = errno;                                               \
		errno = 0x55;                                                    \
		if (errno != 0x55) fail('e');                                    \
		errno = saved;                                                   \
		if (!environ || !getenv("CRABC_CRT_CASE")) fail('v');            \
	} while (0)

static void mark(char marker)
{
	(void)write(1, &marker, 1);
}

static void preinit(void)
{
	CHECK_CALLBACK_STATE();
	mark('P');
}
__attribute__((section(".preinit_array"), used)) static void (*const preinit_entry)(void) = preinit;

static void exit_handler(void)
{
	CHECK_CALLBACK_STATE();
	mark('a');
}

__attribute__((constructor(101))) static void early_constructor(void)
{
	CHECK_CALLBACK_STATE();
	mark('A');
	if (scenario("exit-in-main-constructor")) {
		if (atexit(exit_handler)) fail('x');
		exit(29);
	}
}

__attribute__((constructor)) static void constructor(void)
{
	CHECK_CALLBACK_STATE();
	mark('I');
	if (scenario("dlopen-in-main-constructor")) owned_startup_open_plugin();
}

__attribute__((destructor)) static void destructor(void)
{
	CHECK_CALLBACK_STATE();
	mark('F');
	(void)fputs("f", stdout);
}

__attribute__((destructor(101))) static void late_destructor(void)
{
	CHECK_CALLBACK_STATE();
	mark('Z');
}

static void check_process_handoff(int argc, char **argv, char **envp)
{
	if (argc != 3 || !argv[0] || strcmp(argv[1], "first") || strcmp(argv[2], "second") || argv[3]) fail('a');
	if (envp != environ) fail('n');
	const char *base = strrchr(argv[0], '/');
	base = base ? base + 1 : argv[0];
	if (program_invocation_name != argv[0] || strcmp(program_invocation_short_name, base)) fail('p');
	/* Kernel entry names the executable's _start. A direct interpreter
	 * command's auxv policy belongs to the loader, so the runner requests
	 * this observation only for kernel entry. */
	if (getenv("CRABC_CRT_ENTRY_AUXV"))
		mark(getauxval(AT_ENTRY) == (unsigned long)(uintptr_t)_start ? 'e' : 'x');
	if (getauxval(AT_PAGESZ) != (unsigned long)sysconf(_SC_PAGESIZE)) fail('G');
	if (getauxval(AT_RANDOM) == 0) fail('R');
}

static void write_hex(unsigned __int128 value)
{
	char text[34];
	for (int index = 31; index >= 0; --index) {
		text[index] = "0123456789abcdef"[(unsigned)value & 15];
		value >>= 4;
	}
	text[32] = ';';
	(void)write(1, text, 33);
}

/* Compiler-generated two-word helper calls in the executable image. */
static void compiler_helpers(void)
{
	volatile unsigned __int128 dividend = ((unsigned __int128)0x0123456789abcdefULL << 64) | 0xfedcba9876543210ULL;
	volatile unsigned __int128 divisor = 0x1000000000000003ULL;
	volatile __int128 negative = -(__int128)dividend;
	write_hex(dividend / divisor);
	write_hex(dividend % divisor);
	write_hex((unsigned __int128)(negative / (__int128)divisor));
	write_hex((unsigned __int128)(negative % (__int128)divisor));
	unsigned __int128 (*quotient)(unsigned __int128, unsigned __int128) =
		(unsigned __int128 (*)(unsigned __int128, unsigned __int128))dlsym(owned_startup_open_plugin(),
										    "owned_startup_plugin_quotient");
	if (!quotient) fail('q');
	write_hex(quotient(dividend, divisor));
}

int main(int argc, char **argv, char **envp)
{
	CHECK_CALLBACK_STATE();
	mark('M');
	check_process_handoff(argc, argv, envp);
	if (owned_startup_dependency_value() != 17) fail('d');
	(void)fputs("m", stdout);
	if (atexit(exit_handler)) fail('x');
	if (scenario("immediate-exit")) _Exit(5);
	if (scenario("ordinary") || scenario("exit")) owned_startup_open_plugin();
	if (scenario("helpers")) compiler_helpers();
	if (scenario("exit")) exit(11);
	return 7;
}
