/*
 * Pinned-musl cancellation-deadlock regression.
 *
 * A full pipe keeps the first append-style write in I/O. A second write on
 * the same nonseekable descriptor waits behind it in aio.c's condition queue.
 * musl 1.2.6 aio_cancel holds q->lock while waiting for that second worker,
 * but pthread_cond_wait cancellation must reacquire q before worker cleanup
 * can publish running=0. The pinned source therefore times out for both a
 * targeted second cancellation and cancel-all. The owned implementation keeps
 * a bounded cursor plus counted stack pins and must finish these cases.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fill_pipe(int descriptor, const char *buffer, size_t length)
{
	if (fcntl(descriptor, F_SETFL, O_NONBLOCK))
		return -1;
	while (write(descriptor, buffer, length) > 0)
		;
	if (errno != EAGAIN || fcntl(descriptor, F_SETFL, 0))
		return -1;
	return 0;
}

static int canceled(const struct aiocb *control)
{
	return aio_error(control) == ECANCELED && aio_return((struct aiocb *)control) == -1;
}

int main(int argc, char **argv)
{
	char buffer[4096];
	int descriptors[2];
	struct aiocb first = {0};
	struct aiocb second = {0};
	int all;
	int result;

	if (argc != 2 || (strcmp(argv[1], "target") && strcmp(argv[1], "all")))
		return 2;
	all = !strcmp(argv[1], "all");
	memset(buffer, 'x', sizeof buffer);
	if (pipe(descriptors) || fill_pipe(descriptors[1], buffer, sizeof buffer))
		return 3;

	first.aio_fildes = descriptors[1];
	first.aio_buf = buffer;
	first.aio_nbytes = 1;
	first.aio_sigevent.sigev_notify = SIGEV_NONE;
	second.aio_fildes = descriptors[1];
	second.aio_buf = buffer + 1;
	second.aio_nbytes = 1;
	second.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_write(&first) || aio_write(&second)
		|| aio_error(&first) != EINPROGRESS || aio_error(&second) != EINPROGRESS)
		return 4;

	result = aio_cancel(descriptors[1], all ? 0 : &second);
	if (result != AIO_CANCELED || !canceled(&second))
		return 5;
	if (!all) {
		if (aio_cancel(descriptors[1], &first) != AIO_CANCELED)
			return 6;
	}
	if (!canceled(&first))
		return 7;
	if (close(descriptors[0]) || close(descriptors[1]))
		return 8;
	printf("queued-cancel-%s=ok\n", all ? "all" : "target");
	return 0;
}
