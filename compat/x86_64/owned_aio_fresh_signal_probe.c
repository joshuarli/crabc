/*
 * Fresh-queue application-signal/close watchdog.
 *
 * A POSIX AIO submit must not restore application signals while it owns an
 * AIO map or queue lock.  Each child starts with SIGUSR1 unblocked, creates a
 * fresh pipe descriptor, arms finite sender threads aimed at its main thread,
 * and calls aio_read for the first time on that descriptor.  The handler
 * writes H, then C immediately before close(fd), and R only after close
 * returns.  The parent alone enforces the deadline and records a killed child
 * as a handler-close-pending observation only when the sender setup checkpoints
 * and H/C-without-R receipt are all present.
 *
 * This is a product-only stress witness.  It deliberately does not claim
 * which instruction delivered SIGUSR1: the pinned-source direct-inclusion
 * witness owns that precise source-order proof.  Sender setup and join
 * timeouts have their own classifications so they cannot be mistaken for the
 * lock-held close observation.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
	default_attempts = 128,
	maximum_attempts = 1024,
	sender_count = 4,
	/* 4 x 8 handlers can emit at most 99 event bytes, below the fixed receipt
	 * buffer. Do not raise this without widening the lossless parent record. */
	sends_per_sender = 8,
	child_deadline_nanoseconds = 1000000000,
};

/* The handler communicates with sender/main threads through C11 atomics, not
 * volatile sig_atomic_t.  The test requires actual lock-free x86 integers so
 * these operations do not acquire a hidden lock from signal context. */
_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
	"fresh signal watchdog requires lock-free C11 int atomics");

struct sender {
	pthread_t target;
	unsigned lane;
};

static _Atomic int senders_ready;
static _Atomic int senders_started;
static _Atomic int senders_stopped;
static _Atomic int sender_failure;
static int event_descriptor = -1;
static int target_descriptor = -1;

static void emit(char event)
{
	ssize_t result;

	do result = write(event_descriptor, &event, 1);
	while (result < 0 && errno == EINTR);
}

static void close_from_signal(int signal_number)
{
	int saved_errno = errno;

	(void)signal_number;
	emit('H');
	emit('C');
	(void)close(target_descriptor);
	emit('R');
	errno = saved_errno;
}

static uint64_t monotonic_nanoseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000)
		+ (uint64_t)now.tv_nsec;
}

/* Stagger each finite burst by a small per-attempt/lane offset.  A signal that
 * arrives before the internal mask can return from close; later sends still
 * exercise the fresh queue creation interval.  The bounded loop is vital:
 * an unbounded sender join was an invalid earlier stress receipt. */
static void wait_until(uint64_t deadline)
{
	while (monotonic_nanoseconds() < deadline)
		;
}

static void *send_signal(void *argument)
{
	const struct sender *sender = argument;
	const uint64_t lane_delay = UINT64_C(250) * sender->lane;
	uint64_t start;

	atomic_fetch_add_explicit(&senders_ready, 1, memory_order_release);
	while (!atomic_load_explicit(&senders_started, memory_order_acquire)) {
		if (atomic_load_explicit(&senders_stopped, memory_order_acquire))
			return 0;
	}
	start = monotonic_nanoseconds();
	/* Give the main thread a chance to enter submit before the first signal;
	 * later finite sends cover the complete short creation interval. */
	wait_until(start + UINT64_C(1000) + lane_delay);
	for (unsigned index = 0; index < sends_per_sender; index++) {
		int result;

		if (atomic_load_explicit(&senders_stopped, memory_order_acquire))
			break;
		result = pthread_kill(sender->target, SIGUSR1);
		if (result) {
			atomic_store_explicit(&sender_failure, result, memory_order_release);
			break;
		}
	}
	return 0;
}

static int wait_for_senders_ready(void)
{
	const uint64_t deadline = monotonic_nanoseconds() + child_deadline_nanoseconds;

	while (atomic_load_explicit(&senders_ready, memory_order_acquire) != sender_count) {
		if (monotonic_nanoseconds() >= deadline)
			return -1;
	}
	return 0;
}

static int child_attempt(int child_event_descriptor)
{
	int descriptors[2];
	struct sigaction action;
	struct aiocb control = { 0 };
	struct sender senders[sender_count];
	pthread_t threads[sender_count];
	sigset_t empty_mask;
	char byte;

	atomic_store_explicit(&senders_ready, 0, memory_order_relaxed);
	atomic_store_explicit(&senders_started, 0, memory_order_relaxed);
	atomic_store_explicit(&senders_stopped, 0, memory_order_relaxed);
	atomic_store_explicit(&sender_failure, 0, memory_order_relaxed);
	event_descriptor = child_event_descriptor;
	if (sigemptyset(&empty_mask)
		|| pthread_sigmask(SIG_SETMASK, &empty_mask, 0))
		return 10;
	if (pipe(descriptors))
		return 11;
	target_descriptor = descriptors[0];
	memset(&action, 0, sizeof action);
	action.sa_handler = close_from_signal;
	if (sigemptyset(&action.sa_mask) || sigaction(SIGUSR1, &action, 0))
		return 12;

	for (unsigned index = 0; index < sender_count; index++) {
		senders[index].target = pthread_self();
		senders[index].lane = index;
		if (pthread_create(&threads[index], 0, send_signal, &senders[index])) {
			atomic_store_explicit(&senders_stopped, 1, memory_order_release);
			for (unsigned joined = 0; joined < index; joined++)
				(void)pthread_join(threads[joined], 0);
			return 13;
		}
	}
	/* S: signal disposition/mask and fresh descriptor ready.  T: all senders
	 * target this main thread.  A is emitted before the release that permits
	 * any sender to invoke pthread_kill, so an H/C receipt necessarily follows
	 * all three setup checkpoints. */
	emit('S');
	if (wait_for_senders_ready()) {
		atomic_store_explicit(&senders_stopped, 1, memory_order_release);
		return 14;
	}
	emit('T');
	emit('A');
	atomic_store_explicit(&senders_started, 1, memory_order_release);

	control.aio_fildes = target_descriptor;
	control.aio_reqprio = 0;
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	(void)aio_read(&control);
	emit('V');
	atomic_store_explicit(&senders_stopped, 1, memory_order_release);
	for (unsigned index = 0; index < sender_count; index++) {
		if (pthread_join(threads[index], 0))
			return 15;
	}
	if (atomic_load_explicit(&sender_failure, memory_order_acquire))
		return 16;
	emit('J');
	return 0;
}

static int make_nonblocking(int descriptor)
{
	int flags = fcntl(descriptor, F_GETFL);

	if (flags < 0)
		return -1;
	return fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
}

static void collect_events(int descriptor, char events[128], size_t *count)
{
	for (;;) {
		ssize_t result;

		if (*count == 127)
			return;
		result = read(descriptor, events + *count, 127 - *count);
		if (result > 0) {
			*count += (size_t)result;
			continue;
		}
		if (result < 0 && errno == EINTR)
			continue;
		return;
	}
}

static int contains(const char *events, char event)
{
	return strchr(events, event) != 0;
}

static int pending_close_receipt(const char *events)
{
	const char *last_close = strrchr(events, 'C');
	const char *last_return = strrchr(events, 'R');

	return contains(events, 'S') && contains(events, 'T') && contains(events, 'A')
		&& contains(events, 'H') && last_close
		&& (!last_return || last_return < last_close);
}

/* Return 1 only for the named handler-close-pending receipt.  Return 0 for a
 * completed child; negative values distinguish setup/join/other watchdog
 * failures from an observed AIO lock problem. */
static int one_attempt(int attempt, char events[128], int *child_signal,
	int *timed_out)
{
	int event_pipe[2];
	pid_t child;
	int status = 0;
	uint64_t deadline;
	size_t event_count = 0;

	if (pipe(event_pipe) || make_nonblocking(event_pipe[0]))
		return -10;
	child = fork();
	if (child < 0)
		return -11;
	if (!child) {
		int result;

		(void)close(event_pipe[0]);
		result = child_attempt(event_pipe[1]);
		(void)close(event_pipe[1]);
		_Exit(result);
	}
	(void)close(event_pipe[1]);
	deadline = monotonic_nanoseconds() + child_deadline_nanoseconds;
	for (;;) {
		pid_t observed;
		struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };

		collect_events(event_pipe[0], events, &event_count);
		events[event_count] = '\0';
		observed = waitpid(child, &status, WNOHANG);
		if (observed == child) {
			collect_events(event_pipe[0], events, &event_count);
			events[event_count] = '\0';
			(void)close(event_pipe[0]);
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
				return 0;
			if (WIFSIGNALED(status))
				*child_signal = WTERMSIG(status);
			return -12;
		}
		if (observed < 0) {
			(void)close(event_pipe[0]);
			return -13;
		}
		if (monotonic_nanoseconds() >= deadline)
			break;
		(void)nanosleep(&pause, 0);
	}
	*timed_out = 1;
	(void)kill(child, SIGKILL);
	if (waitpid(child, &status, 0) != child) {
		(void)close(event_pipe[0]);
		return -14;
	}
	collect_events(event_pipe[0], events, &event_count);
	events[event_count] = '\0';
	(void)close(event_pipe[0]);
	if (WIFSIGNALED(status))
		*child_signal = WTERMSIG(status);
	if (pending_close_receipt(events))
		return 1;
	(void)attempt;
	return -15;
}

int main(int argc, char **argv)
{
	int attempts = default_attempts;

	if (argc == 2) {
		attempts = atoi(argv[1]);
		if (attempts <= 0 || attempts > maximum_attempts)
			return 2;
	} else if (argc != 1) {
		return 2;
	}
	for (int attempt = 0; attempt < attempts; attempt++) {
		char events[128] = { 0 };
		int child_signal = 0;
		int timed_out = 0;
		int result = one_attempt(attempt, events, &child_signal, &timed_out);

		if (result == 1) {
			printf("fresh-signal-handler-close-pending=observed attempt=%d events=%s child-signal=%d timeout=%d\n",
				attempt, events, child_signal, timed_out);
			return 1;
		}
		if (result < 0) {
			fprintf(stderr,
				"fresh-signal-handler-close-pending=invalid attempt=%d result=%d events=%s child-signal=%d timeout=%d\n",
				attempt, result, events, child_signal, timed_out);
			return 3;
		}
	}
	puts("fresh-signal-handler-close-pending=not-observed");
	return 0;
}
