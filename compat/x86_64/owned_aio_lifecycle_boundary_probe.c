/*
 * AIO result lifetime across completion, cancellation, control-block reuse,
 * and fork. Each blocking read has a live pipe writer, so cancellation is
 * deterministic; every aiocb and buffer remains live through aio_return.
 * The same installed-header object runs against pinned musl and owned libc.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const struct timespec wait_limit = { .tv_sec = 2, .tv_nsec = 0 };

/* Keep unrelated descriptors out of musl's known post-completion queue
 * cleanup window. The child deliberately reuses one inherited number below. */
static int fresh_descriptor(int descriptor)
{
	static int next_number = 64;
	int moved;

	if (descriptor < 0)
		return -1;
	moved = fcntl(descriptor, F_DUPFD, next_number);
	if (close(descriptor) || moved < 0)
		return -1;
	next_number = moved + 1;
	return moved;
}

static int fresh_pipe(int descriptors[2])
{
	if (pipe(descriptors))
		return -1;
	descriptors[0] = fresh_descriptor(descriptors[0]);
	descriptors[1] = fresh_descriptor(descriptors[1]);
	return descriptors[0] < 0 || descriptors[1] < 0 ? -1 : 0;
}

static int terminal(struct aiocb *control)
{
	const struct aiocb *list[] = { control };

	for (int attempt = 0; attempt < 8; attempt++) {
		if (aio_error(control) != EINPROGRESS)
			return 0;
		if (aio_suspend(list, 1, &wait_limit) && errno != EINTR)
			return -1;
	}
	return aio_error(control) == EINPROGRESS ? -1 : 0;
}

static int result_is(struct aiocb *control, int expected_error, ssize_t expected_result)
{
	if (terminal(control))
		return -1;
	errno = EDOM;
	if (aio_error(control) != expected_error || errno != EDOM)
		return -1;
	if (aio_return(control) != expected_result || errno != EDOM)
		return -1;
	return 0;
}

static int completed_reuse(void)
{
	static struct aiocb control;
	static char written[] = "abc";
	static char read_back[sizeof written];
	int descriptor = fresh_descriptor(open("/state/owned-aio-lifecycle", O_CREAT | O_TRUNC | O_RDWR, 0600));

	if (descriptor < 0)
		return -1;
	control.aio_fildes = descriptor;
	control.aio_buf = written;
	control.aio_nbytes = 3;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_write(&control) || result_is(&control, 0, 3))
		return -1;
	control.aio_buf = read_back;
	control.aio_nbytes = 3;
	if (aio_read(&control) || result_is(&control, 0, 3)
		|| memcmp(read_back, written, 3))
		return -1;
	if (close(descriptor) || unlink("/state/owned-aio-lifecycle"))
		return -1;
	return 0;
}

static int failed_result(void)
{
	int descriptors[2];
	static char byte;
	static struct aiocb control;
	static struct aiocb rejected;

	rejected.aio_fildes = -1;
	rejected.aio_buf = &byte;
	rejected.aio_nbytes = 1;
	rejected.aio_sigevent.sigev_notify = SIGEV_NONE;
	errno = 0;
	if (aio_read(&rejected) != -1 || errno != EBADF
		|| aio_error(&rejected) != EBADF || aio_return(&rejected) != -1)
		return -1;

	if (fresh_pipe(descriptors))
		return -1;
	control.aio_fildes = descriptors[1];
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&control) || result_is(&control, EBADF, -1)
		|| close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

static int cancellation_errno(void)
{
	int descriptors[2];
	static struct aiocb mismatched;

	if (fresh_pipe(descriptors))
		return -1;
	errno = 0;
	if (aio_cancel(descriptors[0], 0) != AIO_ALLDONE || errno != ENOENT)
		return -1;
	mismatched.aio_fildes = descriptors[1];
	errno = 0;
	if (aio_cancel(descriptors[0], &mismatched) != -1 || errno != EINVAL)
		return -1;
	errno = 0;
	if (aio_cancel(-1, 0) != -1 || errno != EBADF
		|| close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

static int canceled_reuse(void)
{
	int descriptors[2];
	static char byte;
	static struct aiocb control;

	if (fresh_pipe(descriptors))
		return -1;
	control.aio_fildes = descriptors[0];
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&control) || aio_error(&control) != EINPROGRESS
		|| aio_cancel(descriptors[0], &control) != AIO_CANCELED
		|| result_is(&control, ECANCELED, -1))
		return -1;
	if (write(descriptors[1], "R", 1) != 1
		|| aio_read(&control) || result_is(&control, 0, 1)
		|| byte != 'R' || close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

static int active_fork(void)
{
	int descriptors[2];
	static char parent_byte;
	static struct aiocb parent;
	pid_t child;
	int status;

	if (fresh_pipe(descriptors))
		return -1;
	parent.aio_fildes = descriptors[0];
	parent.aio_buf = &parent_byte;
	parent.aio_nbytes = 1;
	parent.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&parent) || aio_error(&parent) != EINPROGRESS)
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		int fresh[2];
		char byte = 0;
		struct aiocb control = { 0 };

		if (close(descriptors[0]) || close(descriptors[1]) || pipe(fresh)
			|| dup2(fresh[0], descriptors[0]) != descriptors[0]
			|| close(fresh[0]) || write(fresh[1], "F", 1) != 1)
			_Exit(10);
		control.aio_fildes = descriptors[0];
		control.aio_buf = &byte;
		control.aio_nbytes = 1;
		control.aio_sigevent.sigev_notify = SIGEV_NONE;
		if (aio_read(&control) || result_is(&control, 0, 1) || byte != 'F'
			|| close(descriptors[0]) || close(fresh[1]))
			_Exit(11);
		_Exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
		|| WEXITSTATUS(status) != 0
		|| aio_cancel(descriptors[0], &parent) != AIO_CANCELED
		|| result_is(&parent, ECANCELED, -1)
		|| close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

int main(void)
{
	alarm(30);
	if (completed_reuse()) {
		fputs("aio-lifecycle-failure=completed-reuse\n", stderr);
		return 1;
	}
	if (failed_result()) {
		fputs("aio-lifecycle-failure=failed-result\n", stderr);
		return 1;
	}
	if (cancellation_errno()) {
		fputs("aio-lifecycle-failure=cancellation-errno\n", stderr);
		return 1;
	}
	if (canceled_reuse()) {
		fputs("aio-lifecycle-failure=canceled-reuse\n", stderr);
		return 1;
	}
	if (active_fork()) {
		fputs("aio-lifecycle-failure=active-fork\n", stderr);
		return 1;
	}
	puts("aio-lifecycle completion/failure/cancellation/reuse/fork=ok");
	return 0;
}
