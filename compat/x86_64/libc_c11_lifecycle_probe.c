/*
 * Linux/x86-64 bounded static C11 lifecycle probe.
 *
 * The runner executes this exact project-header body first with pinned musl
 * and then as a freestanding crabc-libc archive candidate. It selects only
 * thrd_create/thrd_join/thrd_exit over the private selected-worker Static
 * Initial TLS v1 seam; synchronization, TSS, detached lifecycle, and generic
 * C11 thread behavior remain deliberately outside this probe.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <threads.h>

_Static_assert(INT_MIN == (-2147483647 - 1) && INT_MAX == 2147483647,
	"x86-64 C11 int result boundary");

static void *inline_thread_pointer(void)
{
	void *thread_pointer;

	__asm__ volatile("mov %%fs:0, %0" : "=r"(thread_pointer));
	return thread_pointer;
}

static int wait_until_set(volatile int *value)
{
	unsigned long spins;

	for (spins = 0; spins != 100000000UL; ++spins) {
		if (__atomic_load_n(value, __ATOMIC_ACQUIRE) != 0)
			return 0;
	}
	return 1;
}

struct worker_observation {
	/*
	 * The worker publishes its scalar observations before this release flag.
	 * Each caller checks the opaque handle while it is still valid, before the
	 * successful join that releases the worker's TLS/control mappings.
	 */
	volatile int observed;
	int result;
	int initial_errno;
	thrd_t identity;
	void *thread_pointer;
};

static int normal_worker(void *argument)
{
	struct worker_observation *observation = argument;

	observation->identity = thrd_current();
	observation->thread_pointer = inline_thread_pointer();
	observation->initial_errno = errno;
	errno = E2BIG;
	__atomic_store_n(&observation->observed, 1, __ATOMIC_RELEASE);
	return observation->result;
}

static int explicit_exit_worker(void *argument)
{
	struct worker_observation *observation = argument;

	observation->identity = thrd_current();
	observation->thread_pointer = inline_thread_pointer();
	observation->initial_errno = errno;
	errno = E2BIG;
	__atomic_store_n(&observation->observed, 1, __ATOMIC_RELEASE);
	thrd_exit(observation->result);
}

static int check_observation(
	const struct worker_observation *observation,
	thrd_t handle,
	int expected_result)
{
	if (observation->result != expected_result || observation->initial_errno != 0)
		return 1;
	if (observation->identity != handle)
		return 2;
	if ((void *)handle != observation->thread_pointer || !observation->thread_pointer)
		return 3;
	return 0;
}

static int run_normal_round(int expected_result)
{
	struct worker_observation observation = {
		.observed = 0,
		.result = expected_result,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	thrd_t handle = 0;
	int joined_result = 0;
	int check;

	errno = E2BIG;
	if (thrd_create(&handle, normal_worker, &observation) != thrd_success)
		return 10;
	if (wait_until_set(&observation.observed))
		return 11;
	check = check_observation(&observation, handle, expected_result);
	if (check)
		return 20 + check;
	if (thrd_join(handle, &joined_result) != thrd_success)
		return 12;
	if (errno != E2BIG || joined_result != expected_result)
		return 13;
	return 0;
}

static int run_explicit_exit_round(int expected_result)
{
	struct worker_observation observation = {
		.observed = 0,
		.result = expected_result,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	thrd_t handle = 0;
	int joined_result = 0;
	int check;

	errno = E2BIG;
	if (thrd_create(&handle, explicit_exit_worker, &observation) != thrd_success)
		return 30;
	if (wait_until_set(&observation.observed))
		return 31;
	check = check_observation(&observation, handle, expected_result);
	if (check)
		return 40 + check;
	if (thrd_join(handle, &joined_result) != thrd_success)
		return 32;
	if (errno != E2BIG || joined_result != expected_result)
		return 33;
	return 0;
}

static int run_null_result_round(void)
{
	struct worker_observation observation = {
		.observed = 0,
		.result = -17,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	thrd_t handle = 0;
	int check;

	errno = E2BIG;
	if (thrd_create(&handle, normal_worker, &observation) != thrd_success)
		return 50;
	if (wait_until_set(&observation.observed))
		return 51;
	check = check_observation(&observation, handle, -17);
	if (check)
		return 60 + check;
	if (thrd_join(handle, 0) != thrd_success)
		return 52;
	if (errno != E2BIG)
		return 53;
	return 0;
}

struct held_worker_observation {
	volatile int entered;
	volatile int release;
	int result;
	int initial_errno;
	thrd_t identity;
	void *thread_pointer;
};

static int held_worker(void *argument)
{
	struct held_worker_observation *observation = argument;

	observation->identity = thrd_current();
	observation->thread_pointer = inline_thread_pointer();
	observation->initial_errno = errno;
	errno = E2BIG;
	__atomic_store_n(&observation->entered, 1, __ATOMIC_RELEASE);
	while (__atomic_load_n(&observation->release, __ATOMIC_ACQUIRE) == 0)
		__asm__ volatile("pause" ::: "memory");
	return observation->result;
}

static int run_two_live_workers(void)
{
	struct held_worker_observation first = {
		.entered = 0,
		.release = 0,
		.result = INT_MIN,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	struct held_worker_observation second = {
		.entered = 0,
		.release = 0,
		.result = INT_MAX,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	thrd_t first_handle = 0;
	thrd_t second_handle = 0;
	int first_result = 0;
	int second_result = 0;

	errno = E2BIG;
	if (thrd_create(&first_handle, held_worker, &first) != thrd_success)
		return 70;
	if (thrd_create(&second_handle, held_worker, &second) != thrd_success) {
		__atomic_store_n(&first.release, 1, __ATOMIC_RELEASE);
		(void)thrd_join(first_handle, 0);
		return 71;
	}
	if (wait_until_set(&first.entered) || wait_until_set(&second.entered)) {
		__atomic_store_n(&first.release, 1, __ATOMIC_RELEASE);
		__atomic_store_n(&second.release, 1, __ATOMIC_RELEASE);
		(void)thrd_join(first_handle, 0);
		(void)thrd_join(second_handle, 0);
		return 72;
	}
	if (first.identity != first_handle || second.identity != second_handle ||
		(void *)first_handle != first.thread_pointer ||
		(void *)second_handle != second.thread_pointer ||
		first_handle == second_handle || first_handle == thrd_current() ||
		second_handle == thrd_current() || first.initial_errno != 0 ||
		second.initial_errno != 0) {
		__atomic_store_n(&first.release, 1, __ATOMIC_RELEASE);
		__atomic_store_n(&second.release, 1, __ATOMIC_RELEASE);
		(void)thrd_join(first_handle, 0);
		(void)thrd_join(second_handle, 0);
		return 73;
	}
	__atomic_store_n(&first.release, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&second.release, 1, __ATOMIC_RELEASE);
	if (thrd_join(first_handle, &first_result) != thrd_success ||
		thrd_join(second_handle, &second_result) != thrd_success)
		return 74;
	if (errno != E2BIG || first_result != INT_MIN || second_result != INT_MAX)
		return 75;
	return 0;
}

#if defined(CRABC_C11_LIFECYCLE_FREESTANDING)
/*
 * A null C11 start routine is outside musl's callback precondition, so this
 * candidate-only boundary check does not alter the pinned-musl comparison.
 * The bounded C ABI rejects it as thrd_error without changing errno or the
 * caller's output handle.
 */
static int run_null_start_rejection_round(void)
{
	thrd_t handle = thrd_current();

	errno = E2BIG;
	if (thrd_create(&handle, 0, 0) != thrd_error)
		return 100;
	if (errno != E2BIG || handle != thrd_current())
		return 101;
	return 0;
}

/*
 * This is deliberately candidate-only: a pthread explicit exit from a C11
 * callback is outside the selected C11 route, so the pinned-musl comparison
 * covers only standard normal/thrd_exit behavior. The candidate must reclaim
 * the worker safely and refuse to decode the raw pointer as a C11 result.
 */
static int cross_mode_pthread_exit_worker(void *argument)
{
	struct worker_observation *observation = argument;

	observation->identity = thrd_current();
	observation->thread_pointer = inline_thread_pointer();
	observation->initial_errno = errno;
	errno = E2BIG;
	__atomic_store_n(&observation->observed, 1, __ATOMIC_RELEASE);
	pthread_exit(&observation->result);
}

static int run_cross_mode_pthread_exit_rejection_round(void)
{
	struct worker_observation observation = {
		.observed = 0,
		.result = -41,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	thrd_t handle = 0;
	int joined_result = INT_MIN;
	int check;

	errno = E2BIG;
	if (thrd_create(&handle, cross_mode_pthread_exit_worker, &observation)
		!= thrd_success)
		return 110;
	if (wait_until_set(&observation.observed))
		return 111;
	check = check_observation(&observation, handle, -41);
	if (check)
		return 120 + check;
	if (thrd_join(handle, &joined_result) != thrd_error)
		return 112;
	if (errno != E2BIG || joined_result != INT_MIN)
		return 113;
	return 0;
}

/*
 * Mirror the unsupported cross-mode route above. A C11 explicit exit from a
 * pthread-mode callback must not let pthread_join reinterpret a signed C11
 * result as a pointer. It is candidate-only for the same reason: this bounded
 * lifecycle admits thrd_exit only from thrd_create callbacks.
 */
static void *cross_mode_thrd_exit_worker(void *argument)
{
	struct worker_observation *observation = argument;

	observation->identity = thrd_current();
	observation->thread_pointer = inline_thread_pointer();
	observation->initial_errno = errno;
	errno = E2BIG;
	__atomic_store_n(&observation->observed, 1, __ATOMIC_RELEASE);
	thrd_exit(observation->result);
}

static int run_cross_mode_thrd_exit_rejection_round(void)
{
	struct worker_observation observation = {
		.observed = 0,
		.result = -43,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	pthread_t handle = 0;
	void *joined_result = &observation;

	errno = E2BIG;
	if (pthread_create(&handle, 0, cross_mode_thrd_exit_worker, &observation) != 0)
		return 130;
	if (wait_until_set(&observation.observed))
		return 131;
	if (observation.identity != (thrd_t)handle ||
		(void *)handle != observation.thread_pointer ||
		!observation.thread_pointer || observation.initial_errno != 0)
		return 132;
	if (pthread_join(handle, &joined_result) != EINVAL)
		return 133;
	if (errno != E2BIG || joined_result != &observation)
		return 134;
	return 0;
}
#endif

/* Hold 64 live C11 workers while a 65th runs: the owned registry grows.
 * Run this same observable growth and reclamation contract against musl. */
enum { held_worker_count = 64 };
static int run_registry_growth_round(void)
{
	struct held_worker_observation workers[held_worker_count] = {{0}};
	thrd_t handles[held_worker_count] = {0};
	struct worker_observation additional_observation = {
		.observed = 0,
		.result = 7,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	struct worker_observation reuse_observation = {
		.observed = 0,
		.result = -19,
		.initial_errno = -1,
		.identity = 0,
		.thread_pointer = 0,
	};
	thrd_t additional_handle = 0;
	thrd_t reuse_handle = 0;
	int reuse_result = 0;
	int additional_result = 0;
	unsigned int index;

	for (index = 0; index != held_worker_count; ++index) {
		workers[index].result = (int)index - 31;
		workers[index].initial_errno = -1;
		errno = E2BIG;
		if (thrd_create(&handles[index], held_worker, &workers[index]) != thrd_success)
			return 80;
		if (wait_until_set(&workers[index].entered))
			return 81;
	}
	errno = E2BIG;
	if (thrd_create(&additional_handle, normal_worker, &additional_observation) != thrd_success)
		return 82;
	if (thrd_join(additional_handle, &additional_result) != thrd_success ||
		additional_result != 7 || additional_observation.initial_errno != 0 || errno != E2BIG)
		return 83;
	for (index = 0; index != held_worker_count; ++index)
		__atomic_store_n(&workers[index].release, 1, __ATOMIC_RELEASE);
	for (index = 0; index != held_worker_count; ++index) {
		int joined_result = 0;

		if (thrd_join(handles[index], &joined_result) != thrd_success ||
			joined_result != workers[index].result || workers[index].initial_errno != 0)
			return 84;
	}
	errno = E2BIG;
	if (thrd_create(&reuse_handle, normal_worker, &reuse_observation) != thrd_success)
		return 85;
	if (thrd_join(reuse_handle, &reuse_result) != thrd_success ||
		reuse_result != -19 || reuse_observation.initial_errno != 0 || errno != E2BIG)
		return 86;
	return 0;
}

static int run_c11_lifecycle(void)
{
	int result;

	if ((void *)thrd_current() != inline_thread_pointer())
		return 90;
	if ((result = run_normal_round(INT_MIN)) != 0)
		return result;
	if ((result = run_normal_round(INT_MAX)) != 0)
		return result;
	if ((result = run_explicit_exit_round(INT_MIN)) != 0)
		return result;
	if ((result = run_explicit_exit_round(INT_MAX)) != 0)
		return result;
	if ((result = run_null_result_round()) != 0)
		return result;
	if ((result = run_two_live_workers()) != 0)
		return result;
#if defined(CRABC_C11_LIFECYCLE_FREESTANDING)
	if ((result = run_null_start_rejection_round()) != 0)
		return result;
	if ((result = run_cross_mode_pthread_exit_rejection_round()) != 0)
		return result;
	if ((result = run_cross_mode_thrd_exit_rejection_round()) != 0)
		return result;
#endif
	if ((result = run_registry_growth_round()) != 0)
		return result;
	return 0;
}

#if defined(CRABC_C11_LIFECYCLE_FREESTANDING)
int crabc_x86_64_c11_lifecycle_probe(void)
{
	return run_c11_lifecycle();
}
#else
int main(void)
{
	return run_c11_lifecycle();
}
#endif
