/* Source-only Linux/x86-64 <poll.h> declaration/layout probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <poll.h>

_Static_assert(sizeof(nfds_t) == 8 && _Alignof(nfds_t) == 8,
    "x86 nfds_t width/alignment");
_Static_assert(sizeof(struct pollfd) == 8 && _Alignof(struct pollfd) == 4,
    "x86 struct pollfd size/alignment");
_Static_assert(offsetof(struct pollfd, fd) == 0,
    "x86 struct pollfd fd offset");
_Static_assert(offsetof(struct pollfd, events) == 4 &&
    offsetof(struct pollfd, revents) == 6,
    "x86 struct pollfd event offsets");

_Static_assert(POLLIN == 0x001 && POLLPRI == 0x002 && POLLOUT == 0x004,
    "poll input/output values");
_Static_assert(POLLERR == 0x008 && POLLHUP == 0x010 && POLLNVAL == 0x020,
    "poll error values");
_Static_assert(POLLRDNORM == 0x040 && POLLRDBAND == 0x080 &&
    POLLWRNORM == 0x100 && POLLWRBAND == 0x200,
    "poll normal/band values");
_Static_assert(POLLMSG == 0x400 && POLLRDHUP == 0x2000,
    "Linux poll extension values");

_Static_assert(__builtin_types_compatible_p(__typeof__(&poll),
    int (*)(struct pollfd *, nfds_t, int)), "poll declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ppoll),
    int (*)(struct pollfd *, nfds_t, const struct timespec *,
        const sigset_t *)), "ppoll declaration");

int crabc_x86_64_poll_header_abi_probe(void)
{
    struct pollfd value = { .fd = -1, .events = POLLIN, .revents = 0 };
    return value.fd + value.events + value.revents;
}
