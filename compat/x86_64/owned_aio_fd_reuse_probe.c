/*
 * Reused-descriptor AIO queue regression.
 *
 * A completed positioned write first makes the per-fd AIO queue seekable.
 * Immediately after close, pipe(2) should reuse that descriptor number and
 * its AIO read must use read(2), not stale positioned-I/O state. The loop
 * intentionally leaves no scheduling gap between completion, close, reuse,
 * and submission. It is shared unchanged by pinned musl and owned products.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int wait_for(struct aiocb *control)
{
	const struct aiocb *controls[] = { control };

	while (aio_error(control) == EINPROGRESS) {
		if (aio_suspend(controls, 1, 0) && errno != EINTR)
			return -1;
	}
	return 0;
}

static void record_completion(struct aiocb *control, int *error, ssize_t *result)
{
	*error = aio_error(control);
	*result = *error == EINPROGRESS ? -2 : aio_return(control);
}

static void close_if_open(int *descriptor)
{
	if (*descriptor >= 0) {
		(void)close(*descriptor);
		*descriptor = -1;
	}
}

static int fail(const char *step, int attempt, int regular_descriptor,
	int read_descriptor, int write_descriptor, int positioned_submission,
	int positioned_error, ssize_t positioned_result, int pipe_submission,
	int pipe_error, ssize_t pipe_result, char byte, int saved_errno)
{
	fprintf(stderr,
		"fd-reuse-failure step=%s attempt=%d regular=%d pipe-read=%d "
		"pipe-write=%d positioned-submit=%d positioned-error=%d "
		"positioned-return=%zd pipe-submit=%d pipe-error=%d "
		"pipe-return=%zd byte=%d errno=%d\n",
		step, attempt, regular_descriptor, read_descriptor, write_descriptor,
		positioned_submission, positioned_error, positioned_result,
		pipe_submission, pipe_error, pipe_result, (unsigned char)byte,
		saved_errno);
	return 1;
}

int main(int argc, char **argv)
{
	int attempts = argc == 2 ? atoi(argv[1]) : 128;

	if (attempts <= 0 || attempts > 4096)
		return 2;
	alarm(30);
	for (int attempt = 0; attempt < attempts; attempt++) {
		char written = 'R';
		char read_back = 0;
		char received = 0;
		int read_descriptor = -1;
		int write_descriptor = -1;
		int regular_descriptor = -1;
		int regular_number = -1;
		int positioned_submission = -1;
		int positioned_error = -1;
		ssize_t positioned_result = -2;
		int pipe_submission = -1;
		int pipe_error = -1;
		ssize_t pipe_result = -2;
		const char *step = "open-regular";
		struct aiocb positioned = { 0 };
		struct aiocb regular_read = { 0 };
		struct aiocb regular_sync = { 0 };
		struct aiocb pipe_read = { 0 };

		regular_descriptor = open("/state/owned-aio-fd-reuse",
			O_CREAT | O_TRUNC | O_RDWR, 0600);
		if (regular_descriptor < 0)
			goto failure;
		regular_number = regular_descriptor;
		positioned.aio_fildes = regular_descriptor;
		positioned.aio_reqprio = 0;
		positioned.aio_buf = &written;
		positioned.aio_nbytes = 1;
		positioned.aio_offset = 0;
		positioned.aio_sigevent.sigev_notify = SIGEV_NONE;
		step = "submit-positioned-write";
		positioned_submission = aio_write(&positioned);
		if (positioned_submission)
			goto positioned_failure;
		step = "wait-positioned-write";
		if (wait_for(&positioned))
			goto positioned_failure;
		record_completion(&positioned, &positioned_error, &positioned_result);
		if (positioned_error != 0 || positioned_result != 1)
			goto failure;
		regular_read.aio_fildes = regular_descriptor;
		regular_read.aio_reqprio = 0;
		regular_read.aio_buf = &read_back;
		regular_read.aio_nbytes = 1;
		regular_read.aio_offset = 0;
		regular_read.aio_sigevent.sigev_notify = SIGEV_NONE;
		step = "submit-regular-read";
		if (aio_read(&regular_read))
			goto failure;
		step = "wait-regular-read";
		if (wait_for(&regular_read) || aio_error(&regular_read) != 0
			|| aio_return(&regular_read) != 1 || read_back != 'R')
			goto failure;
		regular_sync.aio_fildes = regular_descriptor;
		regular_sync.aio_reqprio = 0;
		regular_sync.aio_sigevent.sigev_notify = SIGEV_NONE;
		step = "submit-regular-sync";
		if (aio_fsync(O_DSYNC, &regular_sync))
			goto failure;
		step = "wait-regular-sync";
		if (wait_for(&regular_sync) || aio_error(&regular_sync) != 0
			|| aio_return(&regular_sync) != 0)
			goto failure;
		step = "close-regular";
		if (close(regular_descriptor))
			goto failure;
		regular_descriptor = -1;
		step = "pipe";
		{
			int descriptors[2];
			if (pipe(descriptors))
				goto failure;
			read_descriptor = descriptors[0];
			write_descriptor = descriptors[1];
		}
		step = "reuse-regular-number";
		if (read_descriptor != regular_number)
			goto failure;
		step = "write-pipe";
		if (write(write_descriptor, "P", 1) != 1)
			goto failure;

		pipe_read.aio_fildes = read_descriptor;
		pipe_read.aio_buf = &received;
		pipe_read.aio_nbytes = 1;
		pipe_read.aio_offset = 0;
		pipe_read.aio_sigevent.sigev_notify = SIGEV_NONE;
		step = "submit-pipe-read";
		pipe_submission = aio_read(&pipe_read);
		if (pipe_submission)
			goto pipe_failure;
		step = "wait-pipe-read";
		if (wait_for(&pipe_read))
			goto pipe_failure;
		record_completion(&pipe_read, &pipe_error, &pipe_result);
		if (pipe_error != 0 || pipe_result != 1 || received != 'P')
			goto failure;
		step = "close-pipe-read";
		if (close(read_descriptor))
			goto failure;
		read_descriptor = -1;
		step = "close-pipe-write";
		if (close(write_descriptor))
			goto failure;
		write_descriptor = -1;
		step = "unlink";
		if (unlink("/state/owned-aio-fd-reuse"))
			goto failure;
		continue;

positioned_failure:
		record_completion(&positioned, &positioned_error, &positioned_result);
		goto failure;
pipe_failure:
		record_completion(&pipe_read, &pipe_error, &pipe_result);
failure:
		{
			int saved_errno = errno;
			int reported_read = read_descriptor;
			int reported_write = write_descriptor;
			close_if_open(&regular_descriptor);
			close_if_open(&read_descriptor);
			close_if_open(&write_descriptor);
			(void)unlink("/state/owned-aio-fd-reuse");
			return fail(step, attempt, regular_number, reported_read,
				reported_write, positioned_submission, positioned_error,
				positioned_result, pipe_submission, pipe_error, pipe_result,
				received, saved_errno);
		}
	}
	puts("fd-reuse-regular-to-pipe=ok");
	return 0;
}
