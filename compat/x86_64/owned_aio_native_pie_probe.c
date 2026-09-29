#define _GNU_SOURCE
#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* One AIO submission must survive detached worker startup on a small stack. */
int main(void)
{
	char byte = 'x';
	struct aiocb control = { 0 };
	const struct aiocb *one[] = { &control };
	const struct timespec limit = { .tv_sec = 2 };
	int descriptor = open("/state/aio-native-pie", O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (descriptor < 0)
		return 1;
	control.aio_fildes = descriptor;
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_write(&control))
		return 2;
	while (aio_error(&control) == EINPROGRESS)
		if (aio_suspend(one, 1, &limit) && errno != EINTR)
			return 3;
	if (aio_error(&control) || aio_return(&control) != 1 || close(descriptor)
		|| unlink("/state/aio-native-pie"))
		return 4;
	if (write(1, "aio-one-write=ok\n", 17) != 17)
		return 5;
	return 0;
}
