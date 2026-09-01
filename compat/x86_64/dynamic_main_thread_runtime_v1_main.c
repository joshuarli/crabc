/*
 * Real-Scrt1 main image for the private x86 dynamic-main-thread RuntimeV1
 * bridge. The Rust Scrt1.o must attach the main-resident observer before this
 * image's preinit callback or the private dynamic libc's startup body runs.
 */

typedef unsigned long size_t;
typedef int (*lifecycle_hook)(void);

extern int *__errno_location(void);

static volatile int lifecycle_stage;
__thread int dynamic_main_thread_tls
    __attribute__((tls_model("global-dynamic"), aligned(256))) = 7;

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
	__asm__ volatile(
		"syscall"
		:
		: "a"(231UL), "D"((unsigned long)status)
		: "rcx", "r11", "memory");
	__builtin_unreachable();
}

static void raw_write(char event)
{
	long result;
	__asm__ volatile(
		"syscall"
		: "=a"(result)
		: "a"(1UL), "D"(1UL), "S"(&event), "d"(1UL)
		: "rcx", "r11", "memory");
	if (result != 1) raw_exit(90);
}

static void transition(int expected, int next, char event)
{
	if (lifecycle_stage != expected) raw_exit(91);
	lifecycle_stage = next;
	raw_write(event);
}

static void preinit(void) { transition(0, 1, 'P'); }
static void init(void) { transition(1, 2, 'I'); }
static void fini(void) { transition(3, 4, 'F'); }

static void (*const preinit_entry)(void)
	__attribute__((used, section(".preinit_array"))) = preinit;
static void (*const init_entry)(void)
	__attribute__((used, section(".init_array"))) = init;
static void (*const fini_entry)(void)
	__attribute__((used, section(".fini_array"))) = fini;

int main(int argc, char **argv, char **envp)
{
	int *errno_slot;

	if (argc < 1 || !argv || !argv[0] || !envp || lifecycle_stage != 2)
		raw_exit(92);
	errno_slot = __errno_location();
	if (!errno_slot || *errno_slot != 0 || dynamic_main_thread_tls != 7)
		raw_exit(93);
	*errno_slot = 37;
	dynamic_main_thread_tls = 12;
	if (*errno_slot != 37 || dynamic_main_thread_tls != 12)
		raw_exit(94);
	lifecycle_stage = 3;
	raw_write('M');
	return 0;
}

/* The dynamic libc calls this after Scrt1's fini callback and before its own
 * final raw exit. Exporting this one fixture-local result proves it cannot
 * mistake a main callback order failure for a successful process launch. */
int __crabc_dynamic_main_thread_runtime_v1_fini_state(void)
{
	return lifecycle_stage == 4 && dynamic_main_thread_tls == 12;
}
