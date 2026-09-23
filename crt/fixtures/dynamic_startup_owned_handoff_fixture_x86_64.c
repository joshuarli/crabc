/*
 * Freestanding x86 owned-loader handoff regression fixture.
 *
 * The data symbol is the explicit post-relocation transport.  `_start` never
 * reads it: `Scrt1.o` enters normal Rust startup first, and only that code
 * decodes the versioned record.  A foreign loader leaves the weak symbol
 * unresolved and therefore preserves the pinned-musl null-finalizer path.
 */

typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned long size_t;
typedef int (*application_main)(int, char **, char **);
typedef void (*lifecycle_hook)(void);

struct crabc_x86_64_owned_crt_handoff_v1 {
	u64 magic;
	u32 version;
	u32 abi_size;
	lifecycle_hook dependency_constructors;
	lifecycle_hook process_fini;
};

static char events[11];
static size_t event_count;

static void raw_exit(int status) __attribute__((noreturn));
static void raw_exit(int status)
{
	__asm__ volatile("syscall" : : "a"(60UL), "D"((unsigned long)status) : "rcx", "r11", "memory");
	__builtin_unreachable();
}

static long raw_write(int fd, const char *bytes, size_t length)
{
	long result;
	__asm__ volatile("syscall" : "=a"(result) : "a"(1UL), "D"((unsigned long)fd), "S"(bytes), "d"(length) : "rcx", "r11", "memory");
	return result;
}

static void record(char event)
{
	if (event_count == sizeof(events)) raw_exit(90);
	events[event_count++] = event;
}

static void preinit(void) { record('P'); }
#ifdef CRABC_BAD_INIT_ARRAY_WITH_WORKER
/* The dependency constructor creates a live thread before the CRT rejects a
 * malformed main init-array boundary. A thread-only exit leaves this process
 * running; process-wide exit_group must end both threads with status 127. */
__asm__(
    ".text\n"
    ".type spawn_worker,@function\n"
    "spawn_worker:\n"
    "lea worker_stack+65536(%rip),%rsi\n"
    "mov $0x10f00,%edi\n" /* CLONE_VM|FS|FILES|SIGHAND|THREAD */
    "xor %edx,%edx\n"
    "xor %r10d,%r10d\n"
    "xor %r8d,%r8d\n"
    "mov $56,%eax\n" /* clone */
    "syscall\n"
    "test %rax,%rax\n"
    "jz 1f\n"
    "ret\n"
    "1: mov $34,%eax\n" /* pause */
    "syscall\n"
    "jmp 1b\n"
    ".section .bss\n"
    ".balign 16\n"
    "worker_stack: .skip 65536\n"
    ".text\n"
    ".globl __init_array_start\n"
    ".set __init_array_start, 1\n"
);
extern long spawn_worker(void);
static void dependency(void) { if (spawn_worker() <= 0) raw_exit(96); record('D'); }
#else
static void dependency(void) { record('D'); }
#endif
static void init(void) { record('I'); }
static void fini(void) { record('F'); }
static void loader_fini(void) { record('L'); }

static lifecycle_hook const preinit_entry __attribute__((used, section(".preinit_array"))) = preinit;
static lifecycle_hook const init_entry __attribute__((used, section(".init_array"))) = init;
static lifecycle_hook const fini_entry __attribute__((used, section(".fini_array"))) = fini;

void _init(void) { record('i'); }
void _fini(void) { record('f'); }

const struct crabc_x86_64_owned_crt_handoff_v1
__crabc_x86_64_owned_crt_handoff = {
#ifdef CRABC_BAD_OWNED_HANDOFF
	0,
#else
	0x43524142435f4831UL,
#endif
	1, sizeof(struct crabc_x86_64_owned_crt_handoff_v1), dependency, loader_fini,
};

int main(int argc, char **argv, char **envp)
{
	if (argc < 1 || !argv || !argv[0] || !envp) raw_exit(91);
	record('M');
	return 0;
}

void __libc_start_main(application_main application, int argc, char **argv,
	lifecycle_hook init_callback, lifecycle_hook fini_callback,
	lifecycle_hook rtld_fini) __attribute__((noreturn));

void __libc_start_main(application_main application, int argc, char **argv,
	lifecycle_hook init_callback, lifecycle_hook fini_callback,
	lifecycle_hook rtld_fini)
{
	static const char expected[] = "PDiIMFfL";
	int status;
	size_t index;
	if (!application || !init_callback || !fini_callback || !rtld_fini) raw_exit(92);
	init_callback();
	status = application(argc, argv, argv + (size_t)argc + 1);
	fini_callback();
	rtld_fini();
	if (status != 0 || event_count != sizeof(expected) - 1) raw_exit(93);
	for (index = 0; index < sizeof(expected) - 1; ++index)
		if (events[index] != expected[index]) raw_exit(94);
	if (raw_write(1, events, event_count) != (long)event_count) raw_exit(95);
	raw_exit(0);
}
