/*
 * Observable dynamically linked Linux/x86-64 CRT fixture.
 *
 * This stays intentionally small: the pinned musl and candidate Scrt1.o
 * links must agree on main-image constructor, main, and destructor order.
 * It does not provide a crabc libc implementation or exercise an owned
 * dynamic linker.
 */

#include <unistd.h>

static void emit(char byte)
{
	if (write(1, &byte, 1) != 1) _exit(91);
}

__attribute__((constructor))
static void fixture_constructor(void)
{
	emit('I');
}

__attribute__((destructor))
static void fixture_destructor(void)
{
	emit('F');
}

int main(int argc, char **argv)
{
	if (argc < 1 || !argv || !argv[0]) return 92;
	emit('M');
	return 0;
}
