/*
 * Installed-product driver for crabc-rs's native x86-64 `runtime_thread`
 * facade. The Rust scenario reaches only the private RuntimeV1 table; this
 * driver supplies the public pthread_self() identity oracle and proves the
 * facade leaves errno and the public key registry usable.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

int crabc_rs_x86_64_thread_facade_current(unsigned long long *);
int crabc_rs_x86_64_thread_facade_probe(void);

unsigned long long crabc_x86_64_thread_facade_c_self(void)
{
	return (uintptr_t)pthread_self();
}

static int fail(int code)
{
	printf("x86 runtime private thread facade FAIL %d\n", code);
	return 1;
}

int main(void)
{
	unsigned long long id = 0;
	pthread_key_t key;
	int result;

	errno = 91;
	if (crabc_rs_x86_64_thread_facade_current(&id) || id != crabc_x86_64_thread_facade_c_self())
		return fail(100);
	if ((result = crabc_rs_x86_64_thread_facade_probe()))
		return fail(result);
	if (errno != 91)
		return fail(101);
	if (pthread_key_create(&key, 0) || pthread_setspecific(key, &key) || pthread_getspecific(key) != &key
	    || pthread_key_delete(key))
		return fail(102);
	puts("x86 runtime private thread facade ok");
	return 0;
}
