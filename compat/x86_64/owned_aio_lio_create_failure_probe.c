/*
 * Source-shaped lio_listio pthread_create failure edge.
 *
 * musl 1.2.6 blocks all application signals before it creates the detached
 * LIO_NOWAIT waiter.  If that creation fails, it frees the list state and
 * returns EAGAIN without restoring the caller mask.  This fixture supplies a
 * copied pthread attribute record whose raw scheduler policy makes
 * pthread_create fail with EINVAL; lio_listio translates that to EAGAIN.
 * It records the source's mask-retention edge while restoring the test's
 * original mask before it waits for the already-submitted write to finish.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
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

int main(void)
{
	char byte = 'x';
	int descriptor;
	pthread_attr_t attributes;
	sigset_t baseline;
	sigset_t original;
	sigset_t after;
	struct sigevent event = { 0 };
	struct aiocb control = { 0 };
	struct aiocb *controls[] = { &control };

	alarm(10);
	if (sigemptyset(&baseline) || sigaddset(&baseline, SIGUSR1)
		|| pthread_sigmask(SIG_SETMASK, &baseline, &original))
		return 1;
	descriptor = open("/state/lio-create-failure", O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (descriptor < 0 || pthread_attr_init(&attributes)
		|| pthread_attr_setinheritsched(&attributes, PTHREAD_EXPLICIT_SCHED)
		|| pthread_attr_setschedpolicy(&attributes, -1))
		return 2;
	control.aio_fildes = descriptor;
	control.aio_lio_opcode = LIO_WRITE;
	control.aio_buf = &byte;
	control.aio_nbytes = 1;
	control.aio_sigevent.sigev_notify = SIGEV_NONE;
	event.sigev_notify = SIGEV_THREAD;
	event.sigev_notify_attributes = &attributes;
	errno = 0;
	if (lio_listio(LIO_NOWAIT, controls, 1, &event) != -1 || errno != EAGAIN
		|| pthread_sigmask(SIG_SETMASK, 0, &after))
		return 3;
	if (!sigismember(&after, SIGUSR1) || !sigismember(&after, SIGUSR2)
		|| !sigismember(&after, SIGRTMIN))
		return 4;
	if (pthread_sigmask(SIG_SETMASK, &original, 0) || wait_for(&control)
		|| aio_error(&control) != 0 || aio_return(&control) != 1
		|| close(descriptor) || unlink("/state/lio-create-failure"))
		return 5;
	puts("lio-create-failure-mask-retained=ok");
	return 0;
}
