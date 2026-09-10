/*
 * Direct regressions for the owned aio_cancel cursor/pin correction.
 *
 * Pinned musl 1.2.6 holds one descriptor queue lock while it waits for each
 * cancellation. That is deadlock-prone for a sequenced worker, so the owned
 * port uses a stack cursor to bound the initial request set and counted pins
 * to retain each worker stack record while q is unlocked. These cases stress
 * the transitions that the ordinary one-caller source-deadlock regression
 * cannot cover: two target cancelers joining one -1 worker, all plus target,
 * and a late submission that must stay before an in-flight cancel-all cursor.
 *
 * This is intentionally a candidate-only correction probe. The source raw
 * target/all deadlocks are recorded by owned_aio_cancel_defect_probe.c.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum {
	concurrent_rounds = 32,
	late_initial_count = 32,
	late_rounds = 32,
};

struct gate {
	_Atomic int ready;
	_Atomic int go;
};

struct cancel_call {
	int descriptor;
	struct aiocb *control;
	struct gate *gate;
	int result;
};

struct all_cancel_call {
	int descriptor;
	_Atomic int started;
	_Atomic int done;
	int result;
};

static int fill_pipe(int descriptor)
{
	char buffer[4096];
	int flags;

	memset(buffer, 'q', sizeof buffer);
	flags = fcntl(descriptor, F_GETFL);
	if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	while (write(descriptor, buffer, sizeof buffer) > 0)
		;
	if (errno != EAGAIN || fcntl(descriptor, F_SETFL, flags) < 0)
		return -1;
	return 0;
}

static int canceled(const struct aiocb *control)
{
	return aio_error(control) == ECANCELED
		&& aio_return((struct aiocb *)control) == -1;
}

static int start_full_chain(int descriptors[2], struct aiocb *controls,
	int count, char *bytes)
{
	if (pipe(descriptors) || fill_pipe(descriptors[1]))
		return -1;
	for (int index = 0; index < count; index++) {
		memset(&controls[index], 0, sizeof controls[index]);
		controls[index].aio_fildes = descriptors[1];
		controls[index].aio_buf = &bytes[index];
		controls[index].aio_nbytes = 1;
		controls[index].aio_sigevent.sigev_notify = SIGEV_NONE;
		if (aio_write(&controls[index])
			|| aio_error(&controls[index]) != EINPROGRESS)
			return -1;
	}
	return 0;
}

static void *cancel_one(void *argument)
{
	struct cancel_call *call = argument;

	atomic_fetch_add_explicit(&call->gate->ready, 1, memory_order_release);
	while (!atomic_load_explicit(&call->gate->go, memory_order_acquire))
		;
	call->result = aio_cancel(call->descriptor, call->control);
	return 0;
}

static void *cancel_all(void *argument)
{
	struct all_cancel_call *call = argument;

	atomic_store_explicit(&call->started, 1, memory_order_release);
	call->result = aio_cancel(call->descriptor, 0);
	atomic_store_explicit(&call->done, 1, memory_order_release);
	return 0;
}

/* Run one pair and say whether both caller results observed live cancellation.
 * The checked request state is stronger than result alone; a scheduler may let
 * a second caller arrive after the first has completed and legitimately report
 * AIO_ALLDONE, so the outer loop requires at least one real joined witness. */
static int concurrent_round(int all_and_target, int *joined_witness)
{
	char bytes[2] = { 'a', 'b' };
	int descriptors[2] = { -1, -1 };
	struct aiocb controls[2];
	struct gate gate;
	struct cancel_call first;
	struct cancel_call second;
	pthread_t first_thread;
	pthread_t second_thread;

	atomic_init(&gate.ready, 0);
	atomic_init(&gate.go, 0);
	if (start_full_chain(descriptors, controls, 2, bytes))
		return -1;
	first = (struct cancel_call) {
		.descriptor = descriptors[1],
		.control = all_and_target ? 0 : &controls[1],
		.gate = &gate,
	};
	second = (struct cancel_call) {
		.descriptor = descriptors[1],
		.control = &controls[1],
		.gate = &gate,
	};
	if (pthread_create(&first_thread, 0, cancel_one, &first)
		|| pthread_create(&second_thread, 0, cancel_one, &second))
		return -1;
	while (atomic_load_explicit(&gate.ready, memory_order_acquire) != 2)
		;
	atomic_store_explicit(&gate.go, 1, memory_order_release);
	if (pthread_join(first_thread, 0) || pthread_join(second_thread, 0))
		return -1;

	if (all_and_target) {
		if (first.result != AIO_CANCELED
			|| (second.result != AIO_CANCELED && second.result != AIO_ALLDONE))
			return -1;
	} else if ((first.result != AIO_CANCELED && first.result != AIO_ALLDONE)
		|| (second.result != AIO_CANCELED && second.result != AIO_ALLDONE)) {
		return -1;
	}
	if (!all_and_target
		&& aio_cancel(descriptors[1], &controls[0]) != AIO_CANCELED)
		return -1;
	if (!canceled(&controls[0]) || !canceled(&controls[1]))
		return -1;
	if (first.result == AIO_CANCELED && second.result == AIO_CANCELED)
		*joined_witness = 1;
	if (close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

static int test_concurrent(int all_and_target)
{
	int joined_witness = 0;

	for (int round = 0; round < concurrent_rounds; round++)
		if (concurrent_round(all_and_target, &joined_witness))
			return -1;
	return joined_witness ? 0 : -1;
}

/* One late round waits until the newest original request has completed, which
 * establishes that cancel-all inserted and advanced its cursor. A late write
 * that returns before cancel-all has returned must remain EINPROGRESS on the
 * still-full pipe; the test then cancels it separately. Repeating bounded
 * rounds makes this scheduling witness observable without private hooks. */
static int late_round(int *cursor_witness)
{
	char initial_bytes[late_initial_count];
	char late_byte = 'z';
	int descriptors[2] = { -1, -1 };
	struct aiocb initial[late_initial_count];
	struct aiocb late = { 0 };
	struct all_cancel_call caller;
	pthread_t thread;
	int late_submitted = 0;

	memset(initial_bytes, 'i', sizeof initial_bytes);
	atomic_init(&caller.started, 0);
	atomic_init(&caller.done, 0);
	caller.descriptor = -1;
	caller.result = AIO_ALLDONE;
	if (start_full_chain(descriptors, initial, late_initial_count, initial_bytes))
		return -1;
	caller.descriptor = descriptors[1];
	if (pthread_create(&thread, 0, cancel_all, &caller))
		return -1;
	while (!atomic_load_explicit(&caller.started, memory_order_acquire))
		;
	while (aio_error(&initial[late_initial_count - 1]) == EINPROGRESS
		&& !atomic_load_explicit(&caller.done, memory_order_acquire)) {
		const struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000 };
		(void)nanosleep(&pause, 0);
	}
	if (!atomic_load_explicit(&caller.done, memory_order_acquire)
		&& aio_error(&initial[late_initial_count - 1]) == ECANCELED) {
		late.aio_fildes = descriptors[1];
		late.aio_buf = &late_byte;
		late.aio_nbytes = 1;
		late.aio_sigevent.sigev_notify = SIGEV_NONE;
		if (aio_write(&late))
			return -1;
		late_submitted = 1;
		if (!atomic_load_explicit(&caller.done, memory_order_acquire))
			*cursor_witness = 1;
	}
	if (pthread_join(thread, 0) || caller.result != AIO_CANCELED)
		return -1;
	for (int index = 0; index < late_initial_count; index++)
		if (!canceled(&initial[index]))
			return -1;
	if (late_submitted) {
		int error = aio_error(&late);

		if (*cursor_witness && error != EINPROGRESS)
			return -1;
		if (error == EINPROGRESS
			&& aio_cancel(descriptors[1], &late) != AIO_CANCELED)
			return -1;
		if (!canceled(&late))
			return -1;
	}
	if (close(descriptors[0]) || close(descriptors[1]))
		return -1;
	return 0;
}

static int test_late_submission(void)
{
	int cursor_witness = 0;

	for (int round = 0; round < late_rounds && !cursor_witness; round++)
		if (late_round(&cursor_witness))
			return -1;
	return cursor_witness ? 0 : -1;
}

int main(int argc, char **argv)
{
	int result;

	if (argc != 2)
		return 2;
	alarm(30);
	if (!strcmp(argv[1], "target-target")) {
		result = test_concurrent(0);
	} else if (!strcmp(argv[1], "all-target")) {
		result = test_concurrent(1);
	} else if (!strcmp(argv[1], "late")) {
		result = test_late_submission();
	} else {
		return 3;
	}
	if (result)
		return 4;
	printf("cancel-cursor-%s=ok\n", argv[1]);
	return 0;
}
