/*
 * Pinned-musl Linux/x86-64 getrandom ABI and behavior reference.
 *
 * This fixture is an oracle/reference executable only. It does not include
 * project headers or link a crabc artifact. The fixed output checks syscall
 * and flag constants plus the observable initialized-length contract without
 * making a probabilistic assertion about random byte values.
 */

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_getrandom == 318, "x86 getrandom syscall number");
_Static_assert(GRND_NONBLOCK == 0x0001, "x86 GRND_NONBLOCK");
_Static_assert(GRND_RANDOM == 0x0002, "x86 GRND_RANDOM");
_Static_assert(GRND_INSECURE == 0x0004, "x86 GRND_INSECURE");

int main(void) {
    unsigned char bytes[64];
    errno = 0;
    long received = syscall(SYS_getrandom, bytes, sizeof(bytes), 0);
    if (received != (long)sizeof(bytes)) {
        return 1;
    }

    errno = 0;
    long empty = syscall(SYS_getrandom, NULL, 0, GRND_NONBLOCK);
    if (empty != 0) {
        return 2;
    }

    puts("syscall=318 flags=1,2,4 bytes=64 empty=0");
    return 0;
}
