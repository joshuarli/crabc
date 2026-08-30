/*
 * Freestanding Linux/x86-64 probe for the private Scrt1 lifecycle bridge.
 *
 * This is intentionally not a musl runtime test. It supplies a test-local
 * six-argument __libc_start_main so the candidate's init/fini callbacks are
 * actually invoked; musl's dynamic __libc_start_main owns and runs its own
 * executable lifecycle instead. The link has no interpreter, libc, crti, or
 * crtn, and exits through raw syscalls.
 */

typedef unsigned long size_t;

typedef int (*application_main)(int, char **, char **);
typedef void (*lifecycle_hook)(void);

static char events[9];
static size_t event_count;

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
	__asm__ volatile(
		"syscall"
		:
		: "a"(60UL), "D"((unsigned long)status)
		: "rcx", "r11", "memory");
	__builtin_unreachable();
}

static long raw_write(int descriptor, const char *bytes, size_t length)
{
	long result;
	__asm__ volatile(
		"syscall"
		: "=a"(result)
		: "a"(1UL), "D"((unsigned long)descriptor), "S"(bytes), "d"(length)
		: "rcx", "r11", "memory");
	return result;
}

static void record(char event)
{
	if (event_count == sizeof(events)) raw_exit(90);
	events[event_count++] = event;
}

static void preinit_first(void) { record('P'); }
static void preinit_second(void) { record('Q'); }
static void init_first(void) { record('J'); }
static void init_second(void) { record('K'); }
static void fini_first(void) { record('X'); }
static void fini_second(void) { record('Y'); }

static lifecycle_hook const preinit_one __attribute__((used, section(".preinit_array"))) = preinit_first;
static lifecycle_hook const preinit_two __attribute__((used, section(".preinit_array"))) = preinit_second;
static lifecycle_hook const init_one __attribute__((used, section(".init_array"))) = init_first;
static lifecycle_hook const init_two __attribute__((used, section(".init_array"))) = init_second;
static lifecycle_hook const fini_one __attribute__((used, section(".fini_array"))) = fini_first;
static lifecycle_hook const fini_two __attribute__((used, section(".fini_array"))) = fini_second;

void _init(void) { record('I'); }
void _fini(void) { record('F'); }

int main(int argc, char **argv, char **envp)
{
	if (argc < 1 || !argv || !argv[0] || !envp) raw_exit(91);
	record('M');
	return 0;
}

void __libc_start_main(
	application_main application,
	int argc,
	char **argv,
	lifecycle_hook init,
	lifecycle_hook fini,
	lifecycle_hook rtld_fini) __attribute__((noreturn));

void __libc_start_main(
	application_main application,
	int argc,
	char **argv,
	lifecycle_hook init,
	lifecycle_hook fini,
	lifecycle_hook rtld_fini)
{
	static const char expected[] = "PQIJKMYXF";
	int status;
	size_t index;

	if (!application || !init || !fini || rtld_fini || argc < 1 || !argv || !argv[0]) raw_exit(92);
	init();
	status = application(argc, argv, argv + (size_t)argc + 1);
	fini();
	if (status != 0 || event_count != sizeof(expected) - 1) raw_exit(93);
	for (index = 0; index < sizeof(expected) - 1; index++) {
		if (events[index] != expected[index]) raw_exit(94);
	}
	if (raw_write(1, events, event_count) != (long)event_count) raw_exit(95);
	raw_exit(0);
}
