/*
 * Wake-all regression for aio_suspend's two musl futex routes.
 *
 * One control block makes every waiter sleep on its atomic __err word; two
 * controls make every waiter sleep on the shared __aio_fut word. Completion
 * must wake every waiter, not merely the first one. This specifically guards
 * the musl __wake(-1) -> INT_MAX normalization at the raw FUTEX_WAKE boundary.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { waiter_count = 8 };

struct wait_state {
	const struct aiocb *controls[2];
	int count;
	_Atomic int entered;
	_Atomic int release;
	int result[waiter_count];
	int errors[waiter_count];
};

struct waiter_argument {
	struct wait_state *state;
	int index;
};

static void *wait_once(void *argument)
{
	struct waiter_argument *waiter = argument;
	struct wait_state *state = waiter->state;

	atomic_fetch_add_explicit(&state->entered, 1, memory_order_release);
	while (!atomic_load_explicit(&state->release, memory_order_acquire))
		;
	errno = 0;
	state->result[waiter->index] = aio_suspend(state->controls, state->count, 0);
	state->errors[waiter->index] = errno;
	return 0;
}

static int run_case(int list_mode)
{
	char first_byte = 0;
	char second_byte = 0;
	int first_pipe[2];
	int second_pipe[2] = { -1, -1 };
	struct aiocb first = { 0 };
	struct aiocb second = { 0 };
	struct wait_state state = { 0 };
	struct waiter_argument arguments[waiter_count];
	pthread_t waiters[waiter_count];
	const struct timespec settle = { .tv_sec = 0, .tv_nsec = 10000000 };

	if (pipe(first_pipe) || (list_mode && pipe(second_pipe)))
		return 1;
	first.aio_fildes = first_pipe[0];
	first.aio_buf = &first_byte;
	first.aio_nbytes = 1;
	first.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_read(&first))
		return 2;
	state.controls[0] = &first;
	state.count = list_mode ? 2 : 1;
	if (list_mode) {
		second.aio_fildes = second_pipe[0];
		second.aio_buf = &second_byte;
		second.aio_nbytes = 1;
		second.aio_sigevent.sigev_notify = SIGEV_NONE;
		if (aio_read(&second))
			return 3;
		state.controls[1] = &second;
	}
	for (int index = 0; index < waiter_count; index++) {
		arguments[index] = (struct waiter_argument) { .state = &state, .index = index };
		if (pthread_create(&waiters[index], 0, wait_once, &arguments[index]))
			return 4;
	}
	while (atomic_load_explicit(&state.entered, memory_order_acquire) != waiter_count)
		;
	atomic_store_explicit(&state.release, 1, memory_order_release);
	/* Give each released task an opportunity to enter its selected futex wait
	 * before one I/O completion has made the predicate true. */
	(void)nanosleep(&settle, 0);
	if (write(first_pipe[1], "w", 1) != 1)
		return 5;
	for (int index = 0; index < waiter_count; index++)
		if (pthread_join(waiters[index], 0)
			|| state.result[index] != 0)
			return 6;
	if (aio_error(&first) != 0 || aio_return(&first) != 1 || first_byte != 'w')
		return 7;
	if (list_mode) {
		/* musl 1.2.6 aio.c cleanup() wakes aio_cancel before it publishes
		 * ECANCELED, so the final status is read once aio_suspend reports
		 * the canceled request complete (main's alarm bounds that wait). */
		const struct aiocb *canceled[] = { &second };

		if (aio_cancel(second_pipe[0], &second) != AIO_CANCELED
			|| aio_suspend(canceled, 1, 0)
			|| aio_error(&second) != ECANCELED || aio_return(&second) != -1)
			return 8;
	}
	if (close(first_pipe[0]) || close(first_pipe[1])
		|| (list_mode && (close(second_pipe[0]) || close(second_pipe[1]))))
		return 9;
	return 0;
}

int main(void)
{
	int result;

	alarm(20);
	if ((result = run_case(0)) || (result = run_case(1))) {
		fprintf(stderr, "aio-suspend-wake-failure=%d\n", result);
		return 1;
	}
	puts("aio-suspend wake-all single/list=ok");
	return 0;
}
