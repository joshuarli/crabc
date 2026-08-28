/* C++ source-only companion for the x86-64 <poll.h> ABI probe. */

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

static_assert(sizeof(nfds_t) == 8 && alignof(nfds_t) == 8,
    "x86 nfds_t C++ width/alignment");
static_assert(sizeof(struct pollfd) == 8 && alignof(struct pollfd) == 4,
    "x86 pollfd C++ size/alignment");
static_assert(offsetof(struct pollfd, fd) == 0 &&
    offsetof(struct pollfd, events) == 4 &&
    offsetof(struct pollfd, revents) == 6,
    "x86 pollfd C++ offsets");
static_assert(POLLMSG == 0x400 && POLLRDHUP == 0x2000,
    "Linux poll extension values");

using poll_function = int (*)(struct pollfd *, nfds_t, int);
using ppoll_function = int (*)(struct pollfd *, nfds_t,
    const struct timespec *, const sigset_t *);
static_assert(__is_same(decltype(&poll), poll_function),
    "x86 poll C++ declaration");
static_assert(__is_same(decltype(&ppoll), ppoll_function),
    "x86 ppoll C++ declaration");

/* A matching C-linkage redeclaration must not conflict with <poll.h>. */
extern "C" int poll(struct pollfd *, nfds_t, int);
extern "C" int ppoll(struct pollfd *, nfds_t, const struct timespec *,
    const sigset_t *);

int crabc_x86_64_poll_header_abi_probe_cpp()
{
    pollfd value{};
    value.events = POLLIN;
    return value.events;
}
