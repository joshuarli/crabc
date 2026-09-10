/*
 * aio_read/aio_write are not POSIX cancellation points. musl aio.c waits for
 * its stack AioArgs handoff with public sem_wait, whose sem_timedwait path is
 * a cancellation point. Each child first leaves one deferred cancellation
 * request pending on a submitter that is spinning outside any cancellation
 * point, then releases it into aio_read. A join returning PTHREAD_CANCELED
 * before submitter code can publish its normal return proves both the
 * forbidden public cancellation boundary and a possible stack-handoff
 * lifetime escape. The owned implementation must use a private non-canceling
 * handoff wait: aio_read must publish its return first, and the following
 * explicit pthread_testcancel must then deliver the already-pending request.
 */
#define _GNU_SOURCE

#include <aio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

enum { default_attempts = 2000 };

struct attempt {
	int descriptor;
	char buffer;
	struct aiocb control;
	_Atomic int entered;
	_Atomic int release_submit;
	_Atomic int returned;
	int submit_result;
};

static void *submit_one(void *argument)
{
	struct attempt *state = argument;

	state->control.aio_fildes = state->descriptor;
	state->control.aio_buf = &state->buffer;
	state->control.aio_nbytes = 1;
	state->control.aio_sigevent.sigev_notify = SIGEV_NONE;
	atomic_store_explicit(&state->entered, 1, memory_order_release);
	while (!atomic_load_explicit(&state->release_submit, memory_order_acquire))
		;
	state->submit_result = aio_read(&state->control);
	atomic_store_explicit(&state->returned, 1, memory_order_release);
	/* The owned private handoff preserves this pending request. */
	pthread_testcancel();
	return 0;
}

static void one_attempt(void)
{
	int descriptors[2];
	pthread_t submitter;
	void *joined = 0;
	struct attempt state = {0};

	if (pipe(descriptors))
		_Exit(10);
	state.descriptor = descriptors[0];
	if (pthread_create(&submitter, 0, submit_one, &state))
		_Exit(11);
	while (!atomic_load_explicit(&state.entered, memory_order_acquire))
		;
	if (pthread_cancel(submitter))
		_Exit(12);
	atomic_store_explicit(&state.release_submit, 1, memory_order_release);
	if (pthread_join(submitter, &joined))
		_Exit(13);
	if (joined == PTHREAD_CANCELED
		&& !atomic_load_explicit(&state.returned, memory_order_acquire))
		_Exit(90);
	if (joined == PTHREAD_CANCELED
		&& atomic_load_explicit(&state.returned, memory_order_acquire)) {
		if (state.submit_result)
			_Exit(14);
		(void)aio_cancel(descriptors[0], &state.control);
		(void)close(descriptors[0]);
		(void)close(descriptors[1]);
		_Exit(91);
	}
	if (atomic_load_explicit(&state.returned, memory_order_acquire))
		(void)aio_cancel(descriptors[0], &state.control);
	(void)close(descriptors[0]);
	(void)close(descriptors[1]);
	_Exit(15);
}

int main(int argc, char **argv)
{
	int expect_source_defect;
	int attempts = default_attempts;

	if (argc < 2 || argc > 3)
		return 20;
	expect_source_defect = argv[1][0] == 's' && argv[1][1] == '\0';
	if (!expect_source_defect && !(argv[1][0] == 'c' && argv[1][1] == '\0'))
		return 21;
	if (argc == 3) {
		attempts = atoi(argv[2]);
		if (attempts <= 0 || attempts > default_attempts)
			return 22;
	}

	for (int attempt_index = 0; attempt_index < attempts; attempt_index++) {
		pid_t child = fork();
		int status;
		if (child < 0)
			return 23;
		if (!child) {
			alarm(2);
			one_attempt();
		}
		if (waitpid(child, &status, 0) != child)
			return 24;
		if (WIFEXITED(status) && WEXITSTATUS(status) == 90) {
			puts("submit-handoff-cancellation=observed");
			return expect_source_defect ? 0 : 1;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) == 91) {
			if (expect_source_defect)
				return 25;
			continue;
		}
		return 26;
	}
	if (expect_source_defect) {
		puts("submit-handoff-cancellation=not-observed");
		return 1;
	}
	puts("submit-handoff-cancellation=deferred");
	return 0;
}
