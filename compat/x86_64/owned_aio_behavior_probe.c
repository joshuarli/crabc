/*
 * Installed AIO behavior shared by pinned musl and the owned x86 products.
 *
 * The focused defect probes retain source hangs separately. This ordinary
 * transcript covers the supported source-shaped request engine: positioned,
 * append and nonseekable I/O; queued pipe sequencing; completion/error and
 * close cancellation; signal/thread/list notification; LIO_WAIT/NOWAIT;
 * timeout, interruption and cancellation of aio_suspend; and an active AIO
 * request across fork, where the parent remains usable and the child closes
 * inherited state before beginning fresh AIO work.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
	"AIO behavior signal callbacks require lock-free int atomics");

static const struct timespec wait_limit = { .tv_sec = 2, .tv_nsec = 0 };
static const struct timespec short_pause = { .tv_sec = 0, .tv_nsec = 1000000 };

static int wait_control(struct aiocb *control)
{
	const struct aiocb *controls[] = { control };

	for (int attempt = 0; attempt < 4; attempt++) {
		if (aio_error(control) != EINPROGRESS)
			return 0;
		if (aio_suspend(controls, 1, &wait_limit) == 0)
			continue;
		if (errno != EINTR)
			return -1;
	}
	return aio_error(control) == EINPROGRESS ? -1 : 0;
}

static int completed(struct aiocb *control, ssize_t expected)
{
	return wait_control(control) == 0 && aio_error(control) == 0
		&& aio_return(control) == expected;
}

static int canceled(struct aiocb *control)
{
	return aio_error(control) == ECANCELED && aio_return(control) == -1;
}

static int fill_pipe(int descriptor)
{
	char buffer[4096];
	int flags;

	memset(buffer, 'p', sizeof buffer);
	flags = fcntl(descriptor, F_GETFL);
	if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	while (write(descriptor, buffer, sizeof buffer) > 0)
		;
	if (errno != EAGAIN || fcntl(descriptor, F_SETFL, flags) < 0)
		return -1;
	return 0;
}

static int positioned_append_nonseekable(void)
{
	char write_data[] = "xyz";
	char read_data[4] = { 0 };
	char append_data[4] = { 0 };
	char first_byte = 'A';
	char second_byte = 'B';
	char pipe_byte = 0;
	int descriptor;
	int append_descriptor;
	int descriptors[2];
	int stage = 1;
	/*
	 * A valid SIGEV_NONE request need not initialize signo, sigval, or the
	 * sigevent union tail. Keep those bytes indeterminate so the installed
	 * product cannot accidentally require a whole Rust sigevent value.
	 */
	struct aiocb write_control;
	struct aiocb read_control = { 0 };
	struct aiocb sync_control = { 0 };
	struct aiocb first_append = { 0 };
	struct aiocb second_append = { 0 };
	struct aiocb pipe_read = { 0 };

	descriptor = open("/state/owned-aio-positioned", O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (descriptor < 0)
		return -1;
	stage = 2;
	write_control.aio_fildes = descriptor;
	write_control.aio_reqprio = 0;
	write_control.aio_buf = write_data;
	write_control.aio_nbytes = 3;
	write_control.aio_offset = 7;
	write_control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_write(&write_control) || !completed(&write_control, 3))
		goto failure;
	stage = 3;
	read_control.aio_fildes = descriptor;
	read_control.aio_buf = read_data;
	read_control.aio_nbytes = 3;
	read_control.aio_offset = 7;
	read_control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&read_control) || !completed(&read_control, 3)
		|| memcmp(read_data, write_data, 3))
		goto failure;
	stage = 4;
	sync_control.aio_fildes = descriptor;
	sync_control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_fsync(O_DSYNC, &sync_control) || !completed(&sync_control, 0)
		|| close(descriptor) || unlink("/state/owned-aio-positioned"))
		goto failure;

	stage = 5;
	append_descriptor = open("/state/owned-aio-append",
		O_CREAT | O_TRUNC | O_RDWR | O_APPEND, 0600);
	if (append_descriptor < 0 || write(append_descriptor, "S", 1) != 1)
		goto failure;
	stage = 6;
	first_append.aio_fildes = append_descriptor;
	first_append.aio_buf = &first_byte;
	first_append.aio_nbytes = 1;
	first_append.aio_offset = 0;
	first_append.aio_sigevent.sigev_notify = SIGEV_NONE;
	second_append.aio_fildes = append_descriptor;
	second_append.aio_buf = &second_byte;
	second_append.aio_nbytes = 1;
	second_append.aio_offset = 0;
	second_append.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_write(&first_append) || aio_write(&second_append)
		|| !completed(&first_append, 1) || !completed(&second_append, 1)
		|| pread(append_descriptor, append_data, 3, 0) != 3
		|| memcmp(append_data, "SAB", 3)
		|| close(append_descriptor) || unlink("/state/owned-aio-append"))
		goto failure;

	stage = 7;
	if (pipe(descriptors) || write(descriptors[1], "N", 1) != 1)
		goto failure;
	stage = 8;
	pipe_read.aio_fildes = descriptors[0];
	pipe_read.aio_buf = &pipe_byte;
	pipe_read.aio_nbytes = 1;
	pipe_read.aio_offset = 123;
	pipe_read.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&pipe_read) || !completed(&pipe_read, 1) || pipe_byte != 'N'
		|| close(descriptors[0]) || close(descriptors[1]))
		goto failure;
	return 0;

failure:
	fprintf(stderr, "owned-aio-positioned-stage=%d errno=%d\n", stage, errno);
	return -1;
}

static int queued_pipe_sequence(void)
{
	char first_bytes[4096];
	char second_bytes[4096];
	char drained[4096];
	int descriptors[2];
	struct aiocb first = { 0 };
	struct aiocb second = { 0 };

	if (pipe(descriptors) || fill_pipe(descriptors[1]))
		return -1;
	memset(first_bytes, '1', sizeof first_bytes);
	memset(second_bytes, '2', sizeof second_bytes);
	first.aio_fildes = descriptors[1];
	first.aio_buf = first_bytes;
	first.aio_nbytes = sizeof first_bytes;
	first.aio_sigevent.sigev_notify = SIGEV_NONE;
	second.aio_fildes = descriptors[1];
	second.aio_buf = second_bytes;
	second.aio_nbytes = sizeof second_bytes;
	second.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_write(&first) || aio_write(&second)
		|| aio_error(&first) != EINPROGRESS || aio_error(&second) != EINPROGRESS)
		return -1;
	/* Filling uses page-sized writes, so draining one complete page releases
	 * exactly one pipe-buffer slot. The first PIPE_BUF-sized request refills
	 * it; the queued second request cannot begin until the next full drain. */
	if (read(descriptors[0], drained, sizeof drained) != (ssize_t)sizeof drained
		|| !completed(&first, sizeof first_bytes)
		|| aio_error(&second) != EINPROGRESS)
		return -1;
	if (read(descriptors[0], drained, sizeof drained) != (ssize_t)sizeof drained
		|| !completed(&second, sizeof second_bytes)
		|| close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

static int close_cancels_blocking_request(void)
{
	char byte;
	int descriptors[2];
	struct aiocb control = { 0 };

	if (pipe(descriptors))
		return -1;
	control.aio_fildes = descriptors[0];
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&control) || close(descriptors[0]) || !canceled(&control)
		|| close(descriptors[1]))
		return -1;
	return 0;
}

struct suspend_waiter {
	struct aiocb *control;
	_Atomic int entered;
	_Atomic int done;
	int result;
	int error;
};

static void *suspend_one(void *argument)
{
	struct suspend_waiter *waiter = argument;
	const struct aiocb *controls[] = { waiter->control };

	atomic_store_explicit(&waiter->entered, 1, memory_order_release);
	errno = 0;
	waiter->result = aio_suspend(controls, 1, 0);
	waiter->error = errno;
	atomic_store_explicit(&waiter->done, 1, memory_order_release);
	return 0;
}

static _Atomic int interrupt_seen;

static void interrupt_suspend(int signal_number)
{
	(void)signal_number;
	atomic_store_explicit(&interrupt_seen, 1, memory_order_release);
}

static int wait_entered(const _Atomic int *entered)
{
	for (int attempt = 0; attempt < 2000; attempt++) {
		if (atomic_load_explicit(entered, memory_order_acquire))
			return 0;
		(void)nanosleep(&short_pause, 0);
	}
	return -1;
}

static int suspend_timeout_interrupt_cancel(void)
{
	char byte;
	int descriptors[2];
	struct aiocb control = { 0 };
	const struct aiocb *controls[] = { &control };
	const struct timespec timeout = { .tv_sec = 0, .tv_nsec = 10000000 };
	const struct timespec zero_timeout = { 0, 0 };
	struct suspend_waiter waiter = { 0 };
	struct suspend_waiter cancel_waiter = { 0 };
	pthread_t thread;
	void *joined;
	struct sigaction action = { 0 };
	struct sigaction old_action;

	if (aio_suspend(0, 0, &zero_timeout) != -1 || errno != EAGAIN)
		return -1;
	if (pipe(descriptors))
		return -1;
	control.aio_fildes = descriptors[0];
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&control)
		|| aio_suspend(controls, 1, &timeout) != -1 || errno != EAGAIN
		|| aio_cancel(descriptors[0], &control) != AIO_CANCELED || !canceled(&control)
		|| close(descriptors[0]) || close(descriptors[1]))
		return -1;

	if (pipe(descriptors))
		return -1;
	memset(&control, 0, sizeof control);
	control.aio_fildes = descriptors[0];
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&control))
		return -1;
	action.sa_handler = interrupt_suspend;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGUSR1, &action, &old_action))
		return -1;
	atomic_store_explicit(&interrupt_seen, 0, memory_order_relaxed);
	waiter.control = &control;
	atomic_init(&waiter.entered, 0);
	atomic_init(&waiter.done, 0);
	if (pthread_create(&thread, 0, suspend_one, &waiter) || wait_entered(&waiter.entered))
		return -1;
	for (int attempt = 0; attempt < 2000
		&& !atomic_load_explicit(&waiter.done, memory_order_acquire); attempt++) {
		(void)pthread_kill(thread, SIGUSR1);
		(void)nanosleep(&short_pause, 0);
	}
	if (pthread_join(thread, 0) || sigaction(SIGUSR1, &old_action, 0)
		|| !atomic_load_explicit(&interrupt_seen, memory_order_acquire)
		|| waiter.result != -1 || waiter.error != EINTR
		|| aio_cancel(descriptors[0], &control) != AIO_CANCELED || !canceled(&control)
		|| close(descriptors[0]) || close(descriptors[1]))
		return -1;

	if (pipe(descriptors))
		return -1;
	memset(&control, 0, sizeof control);
	control.aio_fildes = descriptors[0];
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&control))
		return -1;
	cancel_waiter.control = &control;
	atomic_init(&cancel_waiter.entered, 0);
	atomic_init(&cancel_waiter.done, 0);
	if (pthread_create(&thread, 0, suspend_one, &cancel_waiter)
		|| wait_entered(&cancel_waiter.entered) || pthread_cancel(thread)
		|| pthread_join(thread, &joined) != 0 || joined != PTHREAD_CANCELED)
		return -1;
	if (aio_cancel(descriptors[0], &control) != AIO_CANCELED || !canceled(&control)
		|| close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

static volatile sig_atomic_t signal_count;
static volatile sig_atomic_t signal_code;
static volatile sig_atomic_t signal_value;

static void signal_notification(int signal_number, siginfo_t *info, void *context)
{
	(void)signal_number;
	(void)context;
	/* Handler writes are signal-local; the main thread waits through the
	 * signal-delivery ordering before checking these sig_atomic_t fields. */
	signal_code = info->si_code;
	signal_value = info->si_value.sival_int;
	signal_count++;
}

struct close_callback_state {
	int descriptor;
	_Atomic int count;
	_Atomic int close_result;
};

struct list_callback_state {
	_Atomic int count;
};

static void close_from_callback(union sigval value)
{
	struct close_callback_state *state = value.sival_ptr;

	atomic_store_explicit(&state->close_result, close(state->descriptor), memory_order_release);
	atomic_fetch_add_explicit(&state->count, 1, memory_order_release);
}

static void list_callback(union sigval value)
{
	struct list_callback_state *state = value.sival_ptr;

	atomic_fetch_add_explicit(&state->count, 1, memory_order_release);
}

static int wait_atomic_count(const _Atomic int *count, int expected)
{
	for (int attempt = 0; attempt < 2000; attempt++) {
		if (atomic_load_explicit(count, memory_order_acquire) >= expected)
			return 0;
		(void)nanosleep(&short_pause, 0);
	}
	return -1;
}

static int notifications_lists_and_errors(void)
{
	char byte = 's';
	char list_first_byte = 'l';
	char list_second_byte = 'm';
	int descriptor;
	int readonly_descriptor;
	struct sigaction action = { 0 };
	struct sigaction old_action;
	struct aiocb signal_control = { 0 };
	/* SIGEV_THREAD leaves sigev_signo intentionally uninitialized. */
	struct aiocb thread_control;
	struct aiocb list_first = { 0 };
	struct aiocb list_second = { 0 };
	struct aiocb list_error = { 0 };
	struct aiocb *list[] = { &list_first, &list_second };
	struct aiocb *error_list[] = { &list_error };
	struct close_callback_state close_state;
	struct list_callback_state list_state;
	/* The LIO_NOWAIT notification follows the same partial-record contract. */
	struct sigevent list_event;

	descriptor = open("/state/owned-aio-notify", O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (descriptor < 0)
		return -1;
	action.sa_sigaction = signal_notification;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGUSR2, &action, &old_action))
		return -1;
	signal_count = 0;
	signal_control.aio_fildes = descriptor;
	signal_control.aio_buf = &byte;
	signal_control.aio_nbytes = 1;
	signal_control.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	signal_control.aio_sigevent.sigev_signo = SIGUSR2;
	signal_control.aio_sigevent.sigev_value.sival_int = 61;
	if (aio_write(&signal_control) || !completed(&signal_control, 1))
		return -1;
	for (int attempt = 0; attempt < 2000 && !signal_count; attempt++)
		(void)nanosleep(&short_pause, 0);
	if (sigaction(SIGUSR2, &old_action, 0)
		|| signal_count != 1 || signal_code != SI_ASYNCIO || signal_value != 61)
		return -1;

	close_state.descriptor = descriptor;
	atomic_init(&close_state.count, 0);
	atomic_init(&close_state.close_result, -1);
	thread_control.aio_fildes = descriptor;
	thread_control.aio_reqprio = 0;
	thread_control.aio_buf = &byte;
	thread_control.aio_nbytes = 1;
	thread_control.aio_offset = 1;
	thread_control.aio_sigevent.sigev_notify = SIGEV_THREAD;
	thread_control.aio_sigevent.sigev_notify_function = close_from_callback;
	thread_control.aio_sigevent.sigev_value.sival_ptr = &close_state;
	thread_control.aio_sigevent.sigev_notify_attributes = 0;
	if (aio_write(&thread_control) || !completed(&thread_control, 1)
		|| wait_atomic_count(&close_state.count, 1)
		|| atomic_load_explicit(&close_state.count, memory_order_acquire) != 1
		|| atomic_load_explicit(&close_state.close_result, memory_order_acquire) != 0
		|| unlink("/state/owned-aio-notify"))
		return -1;

	descriptor = open("/state/owned-aio-list", O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (descriptor < 0)
		return -1;
	list_first.aio_fildes = descriptor;
	list_first.aio_lio_opcode = LIO_WRITE;
	list_first.aio_buf = &list_first_byte;
	list_first.aio_nbytes = 1;
	list_first.aio_offset = 0;
	list_first.aio_sigevent.sigev_notify = SIGEV_NONE;
	list_second.aio_fildes = descriptor;
	list_second.aio_lio_opcode = LIO_WRITE;
	list_second.aio_buf = &list_second_byte;
	list_second.aio_nbytes = 1;
	list_second.aio_offset = 1;
	list_second.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (lio_listio(LIO_WAIT, list, 2, 0)
		|| aio_error(&list_first) != 0 || aio_return(&list_first) != 1
		|| aio_error(&list_second) != 0 || aio_return(&list_second) != 1)
		return -1;

	memset(&list_first, 0, sizeof list_first);
	memset(&list_second, 0, sizeof list_second);
	list_first.aio_fildes = descriptor;
	list_first.aio_lio_opcode = LIO_WRITE;
	list_first.aio_buf = &list_first_byte;
	list_first.aio_nbytes = 1;
	list_first.aio_offset = 2;
	list_first.aio_sigevent.sigev_notify = SIGEV_NONE;
	list_second.aio_fildes = descriptor;
	list_second.aio_lio_opcode = LIO_WRITE;
	list_second.aio_buf = &list_second_byte;
	list_second.aio_nbytes = 1;
	list_second.aio_offset = 3;
	list_second.aio_sigevent.sigev_notify = SIGEV_NONE;
	atomic_init(&list_state.count, 0);
	list_event.sigev_notify = SIGEV_THREAD;
	list_event.sigev_notify_function = list_callback;
	list_event.sigev_value.sival_ptr = &list_state;
	list_event.sigev_notify_attributes = 0;
	if (lio_listio(LIO_NOWAIT, list, 2, &list_event)
		|| !completed(&list_first, 1) || !completed(&list_second, 1)
		|| wait_atomic_count(&list_state.count, 1)
		|| atomic_load_explicit(&list_state.count, memory_order_acquire) != 1)
		return -1;

	readonly_descriptor = open("/state/owned-aio-list", O_RDONLY);
	if (readonly_descriptor < 0)
		return -1;
	list_error.aio_fildes = readonly_descriptor;
	list_error.aio_lio_opcode = LIO_WRITE;
	list_error.aio_buf = &byte;
	list_error.aio_nbytes = 1;
	list_error.aio_sigevent.sigev_notify = SIGEV_NONE;
	errno = 0;
	if (lio_listio(LIO_WAIT, error_list, 1, 0) != -1 || errno != EIO
		|| aio_error(&list_error) != EBADF || aio_return(&list_error) != -1
		|| close(readonly_descriptor) || aio_fsync(-1, &list_error) != -1 || errno != EINVAL
		|| aio_cancel(descriptor + 1, &list_first) != -1 || errno != EINVAL
		|| close(descriptor) || unlink("/state/owned-aio-list"))
		return -1;
	return 0;
}

static int live_aio_fork(void)
{
	char parent_byte;
	int descriptors[2];
	struct aiocb parent_control = { 0 };
	pid_t child;
	int status;

	if (pipe(descriptors))
		return -1;
	parent_control.aio_fildes = descriptors[0];
	parent_control.aio_buf = &parent_byte;
	parent_control.aio_nbytes = 1;
	parent_control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&parent_control))
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		char child_byte = 0;
		int child_descriptors[2];
		struct aiocb child_control = { 0 };

		if (close(descriptors[0]) || close(descriptors[1]) || pipe(child_descriptors)
			|| write(child_descriptors[1], "F", 1) != 1)
			_Exit(10);
		child_control.aio_fildes = child_descriptors[0];
		child_control.aio_buf = &child_byte;
		child_control.aio_nbytes = 1;
		child_control.aio_sigevent.sigev_notify = SIGEV_NONE;
		if (aio_read(&child_control) || !completed(&child_control, 1)
			|| child_byte != 'F' || close(child_descriptors[0]) || close(child_descriptors[1]))
			_Exit(11);
		_Exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
		|| WEXITSTATUS(status) != 0
		|| aio_cancel(descriptors[0], &parent_control) != AIO_CANCELED
		|| !canceled(&parent_control) || close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

int main(void)
{
	alarm(40);
	if (positioned_append_nonseekable()) {
		fputs("owned-aio-behavior-failure=positioned\n", stderr);
		return 1;
	}
	if (queued_pipe_sequence()) {
		fputs("owned-aio-behavior-failure=queue\n", stderr);
		return 1;
	}
	if (close_cancels_blocking_request()) {
		fputs("owned-aio-behavior-failure=close\n", stderr);
		return 1;
	}
	if (suspend_timeout_interrupt_cancel()) {
		fputs("owned-aio-behavior-failure=suspend\n", stderr);
		return 1;
	}
	if (notifications_lists_and_errors()) {
		fputs("owned-aio-behavior-failure=notify-list\n", stderr);
		return 1;
	}
	if (live_aio_fork()) {
		fputs("owned-aio-behavior-failure=fork\n", stderr);
		return 1;
}
	puts("owned-aio behavior positioned/nonseekable/append/cancel/partial-sigevent/notify/list/suspend/fork=ok");
	return 0;
}
