/* C11 quick-exit behavior shared by the musl oracle and every owned product. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static _Atomic int concurrent_registered;
static _Atomic int concurrent_release;
static _Atomic int contention_ready;
static _Atomic int contention_release;
static char stdio_buffer[64];

static void fail(void)
{
	static const char message[] = "owned quick-exit probe failure\n";
	(void)write(2, message, sizeof(message) - 1);
	_Exit(127);
}

#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

static void emit(const char *bytes, size_t length)
{
	CHECK(write(1, bytes, length) == (ssize_t)length);
}

static void ordinary_handler(void)
{
	emit("O", 1);
}

__attribute__((destructor)) static void fini_handler(void)
{
	emit("D", 1);
}

static void first_handler(void) { emit("A", 1); }
static void second_handler(void) { emit("B", 1); }
static void third_handler(void) { emit("C", 1); }
static void capacity_handler(void) { emit("X", 1); }
static void refill_handler(void) { emit("N", 1); }
static void filler_handler(void) { emit("F", 1); }
static void inherited_handler(void) { emit("I", 1); }
static void child_handler(void) { emit("C", 1); }
static void parent_handler(void) { emit("P", 1); }
static void worker_handler(void) { emit("W", 1); }
static void concurrent_handler(void) { emit("Q", 1); }

static void reentrant_handler(void)
{
	emit("R", 1);
	CHECK(at_quick_exit(refill_handler) == 0);
}

static void install_exclusion_markers(void)
{
	CHECK(atexit(ordinary_handler) == 0);
	CHECK(setvbuf(stdout, stdio_buffer, _IOFBF, sizeof(stdio_buffer)) == 0);
	CHECK(fputs("S", stdout) >= 0);
}

static void run_lifo(void)
{
	install_exclusion_markers();
	CHECK(at_quick_exit(first_handler) == 0);
	CHECK(at_quick_exit(second_handler) == 0);
	CHECK(at_quick_exit(third_handler) == 0);
	quick_exit(41);
}

static void run_capacity_and_refill(void)
{
	for (int index = 0; index != 31; ++index)
		CHECK(at_quick_exit(filler_handler) == 0);
	CHECK(at_quick_exit(reentrant_handler) == 0);
	errno = 79;
	CHECK(at_quick_exit(capacity_handler) == -1);
	CHECK(errno == 79);
	quick_exit(42);
}

static void run_capacity(void)
{
	for (int index = 0; index != 32; ++index)
		CHECK(at_quick_exit(capacity_handler) == 0);
	errno = 79;
	CHECK(at_quick_exit(filler_handler) == -1);
	CHECK(errno == 79);
	quick_exit(43);
}

static void *quick_exit_worker(void *argument)
{
	(void)argument;
	CHECK(at_quick_exit(worker_handler) == 0);
	quick_exit(44);
}

static void run_worker(void)
{
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, quick_exit_worker, NULL) == 0);
	for (;;)
		pause();
}

static void *concurrent_registration_worker(void *argument)
{
	(void)argument;
	CHECK(at_quick_exit(concurrent_handler) == 0);
	atomic_fetch_add_explicit(&concurrent_registered, 1, memory_order_release);
	while (!atomic_load_explicit(&concurrent_release, memory_order_acquire))
		;
	return NULL;
}

static void *contention_registration_worker(void *argument)
{
	(void)argument;
	atomic_fetch_add_explicit(&contention_ready, 1, memory_order_release);
	while (!atomic_load_explicit(&contention_release, memory_order_acquire))
		;
	CHECK(at_quick_exit(concurrent_handler) == 0);
	return NULL;
}

static void run_concurrent(void)
{
	pthread_t threads[4];
	for (size_t index = 0; index != sizeof(threads) / sizeof(threads[0]); ++index)
		CHECK(pthread_create(&threads[index], NULL, concurrent_registration_worker, NULL) == 0);
	while (atomic_load_explicit(&concurrent_registered, memory_order_acquire) != 4)
		;
	atomic_store_explicit(&concurrent_release, 1, memory_order_release);
	for (size_t index = 0; index != sizeof(threads) / sizeof(threads[0]); ++index)
		CHECK(pthread_join(threads[index], NULL) == 0);
	quick_exit(45);
}

static void run_contention(void)
{
	pthread_t threads[32];
	for (size_t index = 0; index != sizeof(threads) / sizeof(threads[0]); ++index)
		CHECK(pthread_create(&threads[index], NULL, contention_registration_worker, NULL) == 0);
	while (atomic_load_explicit(&contention_ready, memory_order_acquire)
		!= sizeof(threads) / sizeof(threads[0]))
		;
	atomic_store_explicit(&contention_release, 1, memory_order_release);
	for (size_t index = 0; index != sizeof(threads) / sizeof(threads[0]); ++index)
		CHECK(pthread_join(threads[index], NULL) == 0);
	quick_exit(48);
}

static void run_fork(void)
{
	int status;
	CHECK(at_quick_exit(inherited_handler) == 0);
	pid_t child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		CHECK(at_quick_exit(child_handler) == 0);
		quick_exit(46);
	}
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 46);
	CHECK(at_quick_exit(parent_handler) == 0);
	quick_exit(47);
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	if (!strcmp(argv[1], "lifo"))
		run_lifo();
	if (!strcmp(argv[1], "capacity"))
		run_capacity();
	if (!strcmp(argv[1], "reentrant"))
		run_capacity_and_refill();
	if (!strcmp(argv[1], "worker"))
		run_worker();
	if (!strcmp(argv[1], "concurrent"))
		run_concurrent();
	if (!strcmp(argv[1], "contention"))
		run_contention();
	if (!strcmp(argv[1], "fork"))
		run_fork();
	fail();
}
