/* Pinned-musl Linux/x86-64 timespec ABI reference constants. */
#define _GNU_SOURCE 1
#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif
#include <stddef.h>
#include <time.h>
#include <sys/syscall.h>
_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(_Alignof(struct timespec) == 8, "x86 timespec alignment");
_Static_assert(offsetof(struct timespec, tv_sec) == 0, "x86 tv_sec offset");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8, "x86 tv_nsec offset");
_Static_assert(CLOCK_REALTIME == 0, "CLOCK_REALTIME");
_Static_assert(CLOCK_MONOTONIC == 1, "CLOCK_MONOTONIC");
_Static_assert(CLOCK_MONOTONIC_RAW == 4, "CLOCK_MONOTONIC_RAW");
_Static_assert(SYS_clock_gettime == 228, "x86 clock_gettime syscall");
_Static_assert(SYS_clock_getres == 229, "x86 clock_getres syscall");
int main(void) { return 0; }
