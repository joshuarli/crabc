/* Native Linux/x86-64 socket-message/options header ABI probe.
 *
 * This is deliberately a bounded consumer of <sys/socket.h>: it checks the
 * public message records and their feature visibility, not all socket or
 * ancillary-control vocabulary.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>

_Static_assert(SYS_ioctl == 16 && SYS_sendmsg == 46 && SYS_recvmsg == 47 &&
    SYS_setsockopt == 54 && SYS_getsockopt == 55 && SYS_recvmmsg == 299 &&
    SYS_sendmmsg == 307, "x86 socket-message syscall numbers");
_Static_assert(SOL_SOCKET == 1 && SO_REUSEADDR == 2 && SO_TYPE == 3 &&
    SO_RCVBUF == 8 && SO_SNDBUF == 7, "selected socket-option values");
_Static_assert(SCM_RIGHTS == 1 && MSG_CMSG_CLOEXEC == 0x40000000 &&
    SIOCATMARK == 0x8905, "selected ancillary/ioctl values");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8 &&
    offsetof(struct iovec, iov_base) == 0 && offsetof(struct iovec, iov_len) == 8,
    "x86 iovec ABI");
_Static_assert(sizeof(struct msghdr) == 56 && _Alignof(struct msghdr) == 8 &&
    offsetof(struct msghdr, msg_name) == 0 &&
    offsetof(struct msghdr, msg_namelen) == 8 &&
    offsetof(struct msghdr, msg_iov) == 16 &&
    offsetof(struct msghdr, msg_iovlen) == 24 &&
    offsetof(struct msghdr, __pad1) == 28 &&
    offsetof(struct msghdr, msg_control) == 32 &&
    offsetof(struct msghdr, msg_controllen) == 40 &&
    offsetof(struct msghdr, __pad2) == 44 &&
    offsetof(struct msghdr, msg_flags) == 48,
    "x86 public msghdr ABI");
_Static_assert(sizeof(struct cmsghdr) == 16 && _Alignof(struct cmsghdr) == 4 &&
    offsetof(struct cmsghdr, cmsg_len) == 0 &&
    offsetof(struct cmsghdr, __pad1) == 4 &&
    offsetof(struct cmsghdr, cmsg_level) == 8 &&
    offsetof(struct cmsghdr, cmsg_type) == 12,
    "x86 public cmsghdr ABI");
_Static_assert(CMSG_LEN(sizeof(int)) == 20 && CMSG_SPACE(sizeof(int)) == 24,
    "x86 ancillary alignment macros");
#ifndef __CMSG_LEN
#error "musl ancillary length helper is missing"
#endif
#ifndef __CMSG_NEXT
#error "musl ancillary next helper is missing"
#endif
#ifndef __MHDR_END
#error "musl message-end helper is missing"
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(
    __CMSG_LEN((struct cmsghdr *)0)), unsigned long),
    "x86 ancillary length helper result type");
_Static_assert(__builtin_types_compatible_p(__typeof__(
    __CMSG_NEXT((struct cmsghdr *)0)), unsigned char *),
    "x86 ancillary next helper result type");
_Static_assert(__builtin_types_compatible_p(__typeof__(
    __MHDR_END((struct msghdr *)0)), unsigned char *),
    "x86 message-end helper result type");

typedef int (*crabc_setsockopt_signature)(int, int, int, const void *, socklen_t);
typedef int (*crabc_getsockopt_signature)(int, int, int, void *, socklen_t *);
typedef ssize_t (*crabc_sendmsg_signature)(int, const struct msghdr *, int);
typedef ssize_t (*crabc_recvmsg_signature)(int, struct msghdr *, int);
typedef int (*crabc_sockatmark_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&setsockopt),
    crabc_setsockopt_signature), "setsockopt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getsockopt),
    crabc_getsockopt_signature), "getsockopt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sendmsg),
    crabc_sendmsg_signature), "sendmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recvmsg),
    crabc_recvmsg_signature), "recvmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sockatmark),
    crabc_sockatmark_signature), "sockatmark declaration");

#if defined(_GNU_SOURCE)
_Static_assert(sizeof(struct mmsghdr) == 64 && _Alignof(struct mmsghdr) == 8 &&
    offsetof(struct mmsghdr, msg_hdr) == 0 &&
    offsetof(struct mmsghdr, msg_len) == 56,
    "x86 public mmsghdr ABI");

typedef int (*crabc_sendmmsg_signature)(int, struct mmsghdr *, unsigned int,
    unsigned int);
typedef int (*crabc_recvmmsg_signature)(int, struct mmsghdr *, unsigned int,
    unsigned int, struct timespec *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sendmmsg),
    crabc_sendmmsg_signature), "sendmmsg GNU declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recvmmsg),
    crabc_recvmmsg_signature), "recvmmsg GNU declaration");
#endif

_Static_assert(CMSG_ALIGN(5) == 8, "CMSG_ALIGN visibility/value");

int main(void)
{
    _Alignas(struct cmsghdr) unsigned char control[2 * CMSG_SPACE(sizeof(int))] = {0};
    _Alignas(struct cmsghdr) unsigned char boundary_control[2 * CMSG_SPACE(0)] = {0};
    struct msghdr message = {0};
    struct cmsghdr *first;

    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    first = CMSG_FIRSTHDR(&message);
    if (first == 0)
        return 1;
    first->cmsg_len = CMSG_LEN(sizeof(int));
    if (__CMSG_LEN(first) != CMSG_SPACE(sizeof(int)))
        return 2;
    if (__CMSG_NEXT(first) != control + CMSG_SPACE(sizeof(int)))
        return 3;
    if (__MHDR_END(&message) != control + sizeof(control))
        return 4;
    if (CMSG_DATA(first) != control + 16)
        return 5;
    if (CMSG_NXTHDR(&message, first) !=
        (struct cmsghdr *)(control + CMSG_SPACE(sizeof(int))))
        return 6;
    message.msg_control = boundary_control;
    message.msg_controllen = sizeof(boundary_control);
    first = CMSG_FIRSTHDR(&message);
    if (first == 0)
        return 7;
    first->cmsg_len = CMSG_LEN(0);
    if (__CMSG_LEN(first) != CMSG_SPACE(0) ||
        __CMSG_NEXT(first) != boundary_control + CMSG_SPACE(0) ||
        __MHDR_END(&message) != boundary_control + sizeof(boundary_control))
        return 8;
    if (CMSG_NXTHDR(&message, first) != 0)
        return 9;
    return 0;
}
