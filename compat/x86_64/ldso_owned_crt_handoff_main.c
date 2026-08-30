/*
 * Private Linux/x86-64 owned-CRT handoff main image.
 *
 * This deliberately supplies its own tiny six-argument libc boundary.  The
 * candidate interpreter therefore needs neither an ambient libc nor a
 * loader-provided register convention to prove the post-relocation record.
 * Pinned musl is used only for the absent-weak-record route, where this
 * fixture observes the required null finalizer and exits before it selects a
 * libc lifecycle.
 */

typedef unsigned long size_t;
typedef int (*application_main)(int, char **, char **);
typedef void (*lifecycle_hook)(void);

extern int mid_value(void);
extern int mid_initializers_ran(void);

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

/* The two fixed dependency constructors call this public fixture-local
 * recorder.  `D` then `d` proves the existing leaf-before-mid order reaches
 * the CRT callback after executable preinit. */
void crabc_owned_crt_record_dependency(char event)
{
	record(event);
}

static void preinit(void) { record('P'); }
static void init(void) { record('I'); }
static void fini(void) { record('F'); }

static lifecycle_hook const preinit_entry
	__attribute__((used, section(".preinit_array"))) = preinit;
static lifecycle_hook const init_entry
	__attribute__((used, section(".init_array"))) = init;
static lifecycle_hook const fini_entry
	__attribute__((used, section(".fini_array"))) = fini;

int main(int argc, char **argv, char **envp)
{
	if (argc < 1 || !argv || !argv[0] || !envp) raw_exit(91);
	if (mid_value() != 42 || !mid_initializers_ran()) raw_exit(92);
	record('M');
	return 0;
}

void __libc_start_main(
	application_main application,
	int argc,
	char **argv,
	lifecycle_hook init_callback,
	lifecycle_hook fini_callback,
	lifecycle_hook rtld_fini) __attribute__((noreturn));

void __libc_start_main(
	application_main application,
	int argc,
	char **argv,
	lifecycle_hook init_callback,
	lifecycle_hook fini_callback,
	lifecycle_hook rtld_fini)
{
	static const char expected[] = "PDdIMFL";
	int status;
	size_t index;

	/* Pinned musl leaves the weak owned-record import absent.  This explicit
	 * foreign-loader observation must not accidentally reach an ambient libc
	 * or lifecycle convention. */
	if (!rtld_fini) {
		static const char absent[] = "A";
		if (raw_write(1, absent, sizeof(absent) - 1) != (long)(sizeof(absent) - 1))
			raw_exit(93);
		raw_exit(0);
	}
	if (!application || !init_callback || !fini_callback || argc < 1 || !argv || !argv[0])
		raw_exit(94);

#if defined(CRABC_OWNED_CRT_EARLY_FINI)
	/* The interpreter-owned finalizer rejects a lifecycle call before its
	 * one dependency-constructor handoff completes. */
	rtld_fini();
	raw_exit(95);
#else
	init_callback();
	status = application(argc, argv, argv + (size_t)argc + 1);
	fini_callback();
	rtld_fini();
	record('L');
	if (status != 0 || event_count != sizeof(expected) - 1) raw_exit(96);
	for (index = 0; index < sizeof(expected) - 1; ++index)
		if (events[index] != expected[index]) raw_exit(97);
	if (raw_write(1, events, event_count) != (long)event_count) raw_exit(98);
	raw_exit(0);
#endif
}
