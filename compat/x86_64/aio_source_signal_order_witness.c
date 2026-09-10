/*
 * Instrumented fixed-source witness for musl 1.2.6 src/aio/aio.c ordering.
 *
 * The runner extracts the pinned source archive and places its source root on
 * the include path. This file maps only aio.c's pthread_sigmask call spelling
 * to source_order_pthread_sigmask while that immutable translation unit is
 * included. The wrapper has two controlled placements at submit's real
 * pthread_sigmask(SIG_BLOCK, allmask, &origmask) boundary:
 *
 *   early:    deliver SIGUSR1 immediately before the source call blocks it;
 *   deferred: block it through the source call, deliver it pending, and
 *             observe entry only at the source SIG_SETMASK handoff.
 *
 * This is not an execution of unmodified musl libc and is not a crabc runtime
 * test. The paired runner proves the source/archive identities and private
 * __aio_close binding that make close(handler_fd) enter the included aio.c.
 */
#define _GNU_SOURCE
#include <aio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int source_order_pthread_sigmask(int, const sigset_t *, sigset_t *);
#define pthread_sigmask source_order_pthread_sigmask
#include "musl-1.2.6/src/aio/aio.c"
#undef pthread_sigmask
#undef pthread
#undef malloc
#undef calloc
#undef realloc
#undef free

#define MODE_EARLY 1
#define MODE_DEFERRED 2
#define CHILD_WATCHDOG_MILLISECONDS 3000
#define AIO_WAIT_ATTEMPTS 2000
#define AIO_WAIT_NANOSECONDS 1000000

static volatile sig_atomic_t hook_mode;
static volatile sig_atomic_t hook_fired;
static volatile sig_atomic_t hook_sender_failed;
static volatile sig_atomic_t handoff_seen;
static volatile sig_atomic_t handler_entered;
static volatile sig_atomic_t handler_returned;
static volatile sig_atomic_t handler_close_result;
static volatile sig_atomic_t delivery_before_handoff;
static int event_fd = -1;
static int handler_fd = -1;

static void emit(char event)
{
	ssize_t result;
	do result = write(event_fd, &event, 1); while (result < 0 && errno == EINTR);
}

static void close_handler(int signal_number)
{
	int saved_errno = errno;
	(void)signal_number;

	handler_entered = 1;
	emit('H');
	handler_close_result = close(handler_fd);
	handler_returned = 1;
	emit('R');
	errno = saved_errno;
}

static int source_order_pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int result;

	/*
	 * The seed request keeps the same descriptor queue alive. Therefore its
	 * existing-queue path performs no signal-mask operation, and this first
	 * armed SIG_BLOCK call is submit's source line 313.
	 */
	if (hook_mode && !hook_fired && how == SIG_BLOCK && set &&
		sigismember(set, SIGUSR1) == 1) {
		hook_fired = 1;
		emit('W');
		if (hook_mode == MODE_EARLY) {
			if (raise(SIGUSR1)) hook_sender_failed = 1;
			emit('A');
			return pthread_sigmask(how, set, oldset);
		}

		result = pthread_sigmask(how, set, oldset);
		if (result) return result;
		emit('B');
		if (raise(SIGUSR1)) hook_sender_failed = 1;
		if (handler_entered) delivery_before_handoff = 1;
		emit('P');
		return result;
	}

	/*
	 * aio.c restores the original application mask after pthread_create. A
	 * queued SIGUSR1 must remain pending until the real SIG_SETMASK call below.
	 */
	if (hook_mode == MODE_DEFERRED && hook_fired && !handoff_seen &&
		how == SIG_SETMASK) {
		handoff_seen = 1;
		emit('U');
		result = pthread_sigmask(how, set, oldset);
		emit('V');
		return result;
	}

	return pthread_sigmask(how, set, oldset);
}

static int wait_for_seed_pipe_read(void)
{
	struct timespec nap = { .tv_sec = 0, .tv_nsec = AIO_WAIT_NANOSECONDS };
	int attempt;

	/*
	 * The pipe writer remains open and has no data. A non-main task parked in
	 * a pipe read gives this source-only fixture an observed blocking seed,
	 * rather than inferring it from timing after aio_read returns.
	 */
	for (attempt = 0; attempt < AIO_WAIT_ATTEMPTS; attempt++) {
		DIR *tasks = opendir("/proc/self/task");
		struct dirent *entry;
		if (!tasks) return -1;
		while ((entry = readdir(tasks))) {
			char path[128];
			char wchan[128] = { 0 };
			FILE *file;

			if (entry->d_name[0] == '.') continue;
			if (snprintf(path, sizeof path, "/proc/self/task/%s/wchan",
				entry->d_name) >= (int)sizeof path) {
				closedir(tasks);
				return -1;
			}
			file = fopen(path, "r");
			if (!file) continue;
			(void)fgets(wchan, sizeof wchan, file);
			fclose(file);
			if (strstr(wchan, "pipe_read")) {
				closedir(tasks);
				return 0;
			}
		}
		closedir(tasks);
		nanosleep(&nap, 0);
	}
	return -1;
}

static int wait_done(const struct aiocb *cb)
{
	struct timespec nap = { .tv_sec = 0, .tv_nsec = AIO_WAIT_NANOSECONDS };
	int attempt;

	for (attempt = 0; attempt < AIO_WAIT_ATTEMPTS; attempt++) {
		if (aio_error(cb) != EINPROGRESS) return 0;
		nanosleep(&nap, 0);
	}
	return -1;
}

static int child_run(int mode, int child_event_fd)
{
	int data_pipe[2];
	struct sigaction action;
	struct aiocb seed;
	struct aiocb next;
	char seed_byte;
	char next_byte;
	sigset_t empty_mask;

	event_fd = child_event_fd;
	if (sigemptyset(&empty_mask) || pthread_sigmask(SIG_SETMASK, &empty_mask, 0)) {
		return 20;
	}
	if (pipe(data_pipe)) return 21;
	handler_fd = data_pipe[0];
	memset(&action, 0, sizeof action);
	action.sa_handler = close_handler;
	if (sigemptyset(&action.sa_mask) || sigaction(SIGUSR1, &action, 0)) return 22;
	emit('S');

	memset(&seed, 0, sizeof seed);
	seed.aio_fildes = handler_fd;
	seed.aio_buf = &seed_byte;
	seed.aio_nbytes = 1;
	if (aio_read(&seed)) return 23;
	if (aio_error(&seed) != EINPROGRESS) return 24;
	if (wait_for_seed_pipe_read()) return 25;
	emit('Q');

	hook_mode = mode;
	memset(&next, 0, sizeof next);
	next.aio_fildes = handler_fd;
	next.aio_buf = &next_byte;
	next.aio_nbytes = 1;
	if (aio_read(&next)) return 26;
	if (!hook_fired || hook_sender_failed || !handler_entered || !handler_returned) {
		return 27;
	}
	if (handler_close_result != 0) return 28;
	if (mode == MODE_DEFERRED && (!handoff_seen || delivery_before_handoff)) {
		return 29;
	}
	if (wait_done(&seed) || wait_done(&next)) return 30;
	if (aio_error(&seed) == EINPROGRESS || aio_error(&next) == EINPROGRESS) {
		return 31;
	}
	emit('X');
	return 0;
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0) return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int drain_events(int fd, char *events, size_t *event_count)
{
	for (;;) {
		ssize_t received;
		if (*event_count == 128) return 0;
		received = read(fd, events + *event_count, 128 - *event_count);
		if (received > 0) {
			*event_count += (size_t)received;
			continue;
		}
		if (received == 0) return 0;
		if (errno == EINTR) continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
		return -1;
	}
}

static long elapsed_milliseconds(const struct timespec *start, const struct timespec *now)
{
	return (now->tv_sec - start->tv_sec) * 1000L +
		(now->tv_nsec - start->tv_nsec) / 1000000L;
}

static int contains(const char *events, size_t length, char wanted)
{
	size_t index;
	for (index = 0; index < length; index++) {
		if (events[index] == wanted) return 1;
	}
	return 0;
}

static int index_of(const char *events, size_t length, char wanted)
{
	size_t index;
	for (index = 0; index < length; index++) {
		if (events[index] == wanted) return (int)index;
	}
	return -1;
}

static int ordered(const char *events, size_t length, const char *required)
{
	int previous = -1;
	const char *cursor;

	for (cursor = required; *cursor; cursor++) {
		int current = index_of(events, length, *cursor);
		if (current < 0 || current <= previous) return 0;
		previous = current;
	}
	return 1;
}

static const char *classify(int mode, const char *events, size_t length,
	int timed_out, int pipe_failed, int wait_failed, int child_status)
{
	if (pipe_failed) return "parent-event-pipe-failure";
	if (wait_failed) return "parent-wait-failure";
	if (!contains(events, length, 'S')) return "harness-setup-failure";
	if (!contains(events, length, 'Q')) return "seed-pipe-read-handoff-failure";
	if (!contains(events, length, 'W')) return "source-pre-block-wrapper-not-reached";
	if (!contains(events, length, 'H')) return "sender-or-handler-delivery-failure";
	if (!contains(events, length, 'R')) {
		if (timed_out) return "handler-close-pending";
		return "handler-close-return-failure";
	}
	if (timed_out) return "post-handler-child-timeout";
	if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
		return "child-post-handler-failure";
	}
	if (mode == MODE_EARLY) {
		return ordered(events, length, "SQWHRAX") ?
			"early-close-returned" : "early-order-failure";
	}
	return ordered(events, length, "SQWBPUHRVX") ?
		"deferred-close-returned" : "deferred-order-failure";
}

int main(int argc, char **argv)
{
	int mode;
	int events_pipe[2];
	pid_t child;
	char events[128];
	size_t event_count = 0;
	int child_status = 0;
	int child_done = 0;
	int timed_out = 0;
	int pipe_failed = 0;
	int wait_failed = 0;
	struct timespec start;
	const char *result;

	if (argc != 2) return 2;
	if (!strcmp(argv[1], "early")) mode = MODE_EARLY;
	else if (!strcmp(argv[1], "deferred")) mode = MODE_DEFERRED;
	else return 2;
	if (pipe(events_pipe)) return 3;
	child = fork();
	if (child < 0) return 4;
	if (!child) {
		int child_result;
		close(events_pipe[0]);
		child_result = child_run(mode, events_pipe[1]);
		_exit(child_result);
	}
	close(events_pipe[1]);
	if (set_nonblocking(events_pipe[0])) {
		kill(child, SIGKILL);
		waitpid(child, &child_status, 0);
		close(events_pipe[0]);
		return 5;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &start)) {
		kill(child, SIGKILL);
		waitpid(child, &child_status, 0);
		close(events_pipe[0]);
		return 6;
	}

	while (!child_done) {
		struct pollfd pollfd = {
			.fd = events_pipe[0],
			.events = POLLIN | POLLHUP,
		};
		struct timespec now;
		int poll_result = poll(&pollfd, 1, 25);
		pid_t waited;

		if (poll_result < 0 && errno != EINTR) pipe_failed = 1;
		if (poll_result > 0 && (pollfd.revents & (POLLIN | POLLHUP)) &&
			drain_events(events_pipe[0], events, &event_count)) {
			pipe_failed = 1;
		}
		waited = waitpid(child, &child_status, WNOHANG);
		if (waited == child) child_done = 1;
		else if (waited < 0 && errno != EINTR) wait_failed = 1;
		if (pipe_failed || wait_failed) {
			kill(child, SIGKILL);
			waitpid(child, &child_status, 0);
			child_done = 1;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now)) {
			kill(child, SIGKILL);
			waitpid(child, &child_status, 0);
			child_done = 1;
			wait_failed = 1;
		}
		if (!child_done && elapsed_milliseconds(&start, &now) >=
			CHILD_WATCHDOG_MILLISECONDS) {
			timed_out = 1;
			kill(child, SIGKILL);
			waitpid(child, &child_status, 0);
			child_done = 1;
		}
	}
	if (drain_events(events_pipe[0], events, &event_count)) pipe_failed = 1;
	close(events_pipe[0]);

	result = classify(mode, events, event_count, timed_out, pipe_failed,
		wait_failed, child_status);
	printf("mode=%s events=%.*s child_status=%d timeout=%d classification=%s\n",
		argv[1], (int)event_count, events, child_status, timed_out, result);
	if (mode == MODE_EARLY) return strcmp(result, "early-close-returned") != 0;
	return strcmp(result, "deferred-close-returned") != 0;
}
