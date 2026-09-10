/*
 * Installed POSIX AIO consumer shared by pinned musl and owned x86 products.
 *
 * This intentionally takes the address of every request API before it runs
 * its regular-file slice.  A product cannot pass by providing only the old
 * `aio_error` observation leaf or by letting a linker's lazy archive scan
 * omit one of the seven request-operation symbols.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

_Static_assert(sizeof(struct aiocb) == 168, "x86 aiocb size");
_Static_assert(_Alignof(struct aiocb) == 8, "x86 aiocb alignment");
_Static_assert(offsetof(struct aiocb, __err) == 112, "x86 aiocb error word");

static int (*const aio_read_signature)(struct aiocb *) = aio_read;
static int (*const aio_write_signature)(struct aiocb *) = aio_write;
static int (*const aio_error_signature)(const struct aiocb *) = aio_error;
static ssize_t (*const aio_return_signature)(struct aiocb *) = aio_return;
static int (*const aio_cancel_signature)(int, struct aiocb *) = aio_cancel;
static int (*const aio_suspend_signature)(const struct aiocb *const [], int,
    const struct timespec *) = aio_suspend;
static int (*const aio_fsync_signature)(int, struct aiocb *) = aio_fsync;
static int (*const lio_listio_signature)(int, struct aiocb *restrict const *restrict,
    int, struct sigevent *restrict) = lio_listio;

static int fail(void)
{
	static const char text[] = "owned-aio probe failed\n";
	(void)write(2, text, sizeof text - 1);
	return 1;
}

static void no_notification(struct aiocb *control)
{
	control->aio_sigevent.sigev_notify = SIGEV_NONE;
}

static int wait_for(struct aiocb *control)
{
	const struct aiocb *one[] = { control };
	const struct timespec timeout = { .tv_sec = 2, .tv_nsec = 0 };

	for (;;) {
		if (aio_error_signature(control) != EINPROGRESS)
			return 0;
		if (aio_suspend_signature(one, 1, &timeout) == 0)
			return 0;
		if (errno != EINTR)
			return -1;
	}
}

static int complete(struct aiocb *control, ssize_t expected)
{
	return wait_for(control) == 0
		&& aio_error_signature(control) == 0
		&& aio_return_signature(control) == expected;
}

int main(void)
{
	char readback[4] = { 0, 0, 0, 0 };
	char one[] = "a";
	char two[] = "b";
	char three[] = "c";
	struct aiocb write_control = { 0 };
	struct aiocb sync_control = { 0 };
	struct aiocb read_control = { 0 };
	struct aiocb list_one = { 0 };
	struct aiocb list_two = { 0 };
	struct aiocb *list[] = { &list_one, &list_two };
	int descriptor = open("/state/owned-aio-probe", O_CREAT | O_TRUNC | O_RDWR, 0600);

	/* Keep these hard references live even if a future probe body changes. */
	if (!aio_read_signature || !aio_write_signature || !aio_error_signature
		|| !aio_return_signature || !aio_cancel_signature || !aio_suspend_signature
		|| !aio_fsync_signature || !lio_listio_signature)
		return fail();
	if (descriptor < 0)
		return fail();

	write_control.aio_fildes = descriptor;
	write_control.aio_buf = one;
	write_control.aio_nbytes = 1;
	write_control.aio_offset = 0;
	no_notification(&write_control);
	if (aio_write_signature(&write_control) || !complete(&write_control, 1))
		return fail();

	sync_control.aio_fildes = descriptor;
	no_notification(&sync_control);
	if (aio_fsync_signature(O_SYNC, &sync_control) || !complete(&sync_control, 0))
		return fail();

	read_control.aio_fildes = descriptor;
	read_control.aio_buf = readback;
	read_control.aio_nbytes = 1;
	read_control.aio_offset = 0;
	no_notification(&read_control);
	if (aio_read_signature(&read_control) || !complete(&read_control, 1)
		|| readback[0] != 'a')
		return fail();

	list_one.aio_fildes = descriptor;
	list_one.aio_lio_opcode = LIO_WRITE;
	list_one.aio_buf = two;
	list_one.aio_nbytes = 1;
	list_one.aio_offset = 1;
	no_notification(&list_one);
	list_two.aio_fildes = descriptor;
	list_two.aio_lio_opcode = LIO_WRITE;
	list_two.aio_buf = three;
	list_two.aio_nbytes = 1;
	list_two.aio_offset = 2;
	no_notification(&list_two);
	if (lio_listio_signature(LIO_WAIT, list, 2, 0)
		|| aio_error_signature(&list_one) != 0
		|| aio_error_signature(&list_two) != 0
		|| aio_return_signature(&list_one) != 1
		|| aio_return_signature(&list_two) != 1
		|| aio_cancel_signature(descriptor, &list_one) != AIO_ALLDONE)
		return fail();

	if (close(descriptor) || aio_fsync_signature(-1, &sync_control) != -1
		|| errno != EINVAL)
		return fail();
	(void)unlink("/state/owned-aio-probe");
	if (write(1, "owned-aio basic ok\n", 19) != 19)
		return fail();
	return 0;
}
