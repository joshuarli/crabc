/*
 * Lifetime regression for os-test basic/aio/aio_suspend.c.
 *
 * The pinned source at revision 5e9456d510612f83b6ec8b1a0c06d6b1303a2512
 * submits two six-byte writes, calls aio_suspend once on both aiocbs, then
 * reaps only controls already terminal at that instant. POSIX aio_suspend
 * promises one completed request, not completion of every listed request.
 *
 * source_shape_drain keeps the same two-write shape and records the number
 * observed immediately after that one return, but retains both stack aiocbs,
 * their shared buffer, and the FILE descriptor until both are reaped. The
 * number may legitimately be one or two because the second write can finish
 * between aio_suspend's predicate and the observation. controlled_second_live
 * uses an already-readable pipe and a separate empty pipe to prove the one
 * completion boundary without relying on regular-file scheduling.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static const struct timespec wait_limit = { .tv_sec = 2, .tv_nsec = 0 };

static int wait_terminal(struct aiocb *control)
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

static int reap_success(struct aiocb *control, ssize_t expected)
{
	return wait_terminal(control) == 0 && aio_error(control) == 0
		&& aio_return(control) == expected;
}

/* Finish a submitted request before its caller-owned storage can leave scope.
 * The process exits immediately if a diagnostic cleanup cannot establish that
 * boundary; returning through a live aiocb would turn the regression itself
 * into the invalid fixture it is meant to expose. */
static void retire_submitted(int descriptor, struct aiocb *control)
{
	if (aio_error(control) == EINPROGRESS)
		(void)aio_cancel(descriptor, control);
	if (wait_terminal(control) || aio_error(control) == EINPROGRESS)
		_exit(2);
	(void)aio_return(control);
}

static int source_shape_drain(int *completed_after_suspend)
{
	char buffer[6] = { 'F', 'O', 'O', 'B', 'A', 'R' };
	struct aiocb first = { 0 };
	struct aiocb second = { 0 };
	const struct aiocb *controls[] = { &first, &second };
	FILE *stream;
	int descriptor;
	int first_submitted = 0;
	int second_submitted = 0;
	int first_reaped = 0;
	int second_reaped = 0;

	/* The closed runner has no ambient temporary directory. fopen retains the
	 * upstream FILE/fileno/fclose descriptor lifetime without adding that
	 * unrelated temporary-name policy to the test. */
	stream = fopen("/state/aio-suspend-lifetime", "w+");
	if (!stream)
		return -1;
	descriptor = fileno(stream);
	first.aio_fildes = descriptor;
	first.aio_buf = buffer;
	first.aio_nbytes = sizeof buffer;
	first.aio_offset = 0;
	first.aio_sigevent.sigev_notify = SIGEV_NONE;
	second.aio_fildes = descriptor;
	second.aio_buf = buffer;
	second.aio_nbytes = sizeof buffer;
	second.aio_offset = 6;
	second.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_write(&first))
		goto failure;
	first_submitted = 1;
	if (aio_write(&second))
		goto failure;
	second_submitted = 1;
	if (aio_suspend(controls, 2, 0))
		goto failure;
	*completed_after_suspend =
		(aio_error(&first) != EINPROGRESS) + (aio_error(&second) != EINPROGRESS);
	if (*completed_after_suspend == 0 || !reap_success(&first, sizeof buffer))
		goto failure;
	first_reaped = 1;
	if (!reap_success(&second, sizeof buffer))
		goto failure;
	second_reaped = 1;
	if (fclose(stream) || unlink("/state/aio-suspend-lifetime"))
		return -1;
	return 0;

failure:
	if (second_submitted && !second_reaped)
		retire_submitted(descriptor, &second);
	if (first_submitted && !first_reaped)
		retire_submitted(descriptor, &first);
	(void)fclose(stream);
	(void)unlink("/state/aio-suspend-lifetime");
	return -1;
}

static int controlled_second_live(void)
{
	char first_byte = 0;
	char second_byte = 0;
	int first_pipe[2] = { -1, -1 };
	int second_pipe[2] = { -1, -1 };
	struct aiocb first = { 0 };
	struct aiocb second = { 0 };
	const struct aiocb *controls[] = { &first, &second };
	int first_submitted = 0;
	int second_submitted = 0;
	int first_reaped = 0;
	int second_reaped = 0;

	if (pipe(first_pipe) || pipe(second_pipe)
		|| write(first_pipe[1], "a", 1) != 1)
		goto failure;
	first.aio_fildes = first_pipe[0];
	first.aio_buf = &first_byte;
	first.aio_nbytes = 1;
	first.aio_sigevent.sigev_notify = SIGEV_NONE;
	second.aio_fildes = second_pipe[0];
	second.aio_buf = &second_byte;
	second.aio_nbytes = 1;
	second.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&first))
		goto failure;
	first_submitted = 1;
	if (aio_read(&second))
		goto failure;
	second_submitted = 1;
	if (aio_suspend(controls, 2, 0) || aio_error(&first) != 0
		|| aio_error(&second) != EINPROGRESS || aio_return(&first) != 1
		|| first_byte != 'a')
		goto failure;
	first_reaped = 1;
	if (aio_cancel(second_pipe[0], &second) != AIO_CANCELED
		|| wait_terminal(&second) || aio_error(&second) != ECANCELED
		|| aio_return(&second) != -1)
		goto failure;
	second_reaped = 1;
	if (close(first_pipe[0]) || close(first_pipe[1])
		|| close(second_pipe[0]) || close(second_pipe[1]))
		return -1;
	return 0;

failure:
	if (second_submitted && !second_reaped)
		retire_submitted(second_pipe[0], &second);
	if (first_submitted && !first_reaped)
		retire_submitted(first_pipe[0], &first);
	if (first_pipe[0] >= 0)
		(void)close(first_pipe[0]);
	if (first_pipe[1] >= 0)
		(void)close(first_pipe[1]);
	if (second_pipe[0] >= 0)
		(void)close(second_pipe[0]);
	if (second_pipe[1] >= 0)
		(void)close(second_pipe[1]);
	return -1;
}

int main(void)
{
	int source_shape_completed;

	alarm(20);
	if (source_shape_drain(&source_shape_completed) || controlled_second_live()) {
		fputs("aio-suspend-lifetime-failure\n", stderr);
		return 1;
	}
	printf("aio-suspend-lifetime source-shape-completed=%d controlled-second-live=1 drained=2\n",
		source_shape_completed);
	return 0;
}
