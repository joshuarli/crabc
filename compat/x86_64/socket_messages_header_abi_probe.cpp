/* C++ companion for the native Linux/x86-64 socket-message/options ABI probe. */

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

static_assert(SYS_ioctl == 16 && SYS_sendmsg == 46 && SYS_recvmsg == 47 &&
    SYS_setsockopt == 54 && SYS_getsockopt == 55 && SYS_recvmmsg == 299 &&
    SYS_sendmmsg == 307, "x86 socket-message syscall numbers");
static_assert(SOL_SOCKET == 1 && SO_REUSEADDR == 2 && SO_TYPE == 3 &&
    SCM_RIGHTS == 1 && MSG_CMSG_CLOEXEC == 0x40000000 && SIOCATMARK == 0x8905,
    "selected socket message constants");
static_assert(sizeof(iovec) == 16 && alignof(iovec) == 8 &&
    offsetof(iovec, iov_base) == 0 && offsetof(iovec, iov_len) == 8,
    "x86 C++ iovec ABI");
static_assert(sizeof(msghdr) == 56 && alignof(msghdr) == 8 &&
    offsetof(msghdr, msg_name) == 0 && offsetof(msghdr, msg_namelen) == 8 &&
    offsetof(msghdr, msg_iov) == 16 && offsetof(msghdr, msg_iovlen) == 24 &&
    offsetof(msghdr, __pad1) == 28 && offsetof(msghdr, msg_control) == 32 &&
    offsetof(msghdr, msg_controllen) == 40 && offsetof(msghdr, __pad2) == 44 &&
    offsetof(msghdr, msg_flags) == 48, "x86 C++ msghdr ABI");
static_assert(sizeof(cmsghdr) == 16 && alignof(cmsghdr) == 4 &&
    offsetof(cmsghdr, cmsg_len) == 0 && offsetof(cmsghdr, __pad1) == 4 &&
    offsetof(cmsghdr, cmsg_level) == 8 && offsetof(cmsghdr, cmsg_type) == 12,
    "x86 C++ cmsghdr ABI");

using setsockopt_signature = int (*)(int, int, int, const void *, socklen_t);
using getsockopt_signature = int (*)(int, int, int, void *, socklen_t *);
using sendmsg_signature = ssize_t (*)(int, const msghdr *, int);
using recvmsg_signature = ssize_t (*)(int, msghdr *, int);
using sockatmark_signature = int (*)(int);

static_assert(__is_same(decltype(&setsockopt), setsockopt_signature),
    "setsockopt C++ declaration");
static_assert(__is_same(decltype(&getsockopt), getsockopt_signature),
    "getsockopt C++ declaration");
static_assert(__is_same(decltype(&sendmsg), sendmsg_signature),
    "sendmsg C++ declaration");
static_assert(__is_same(decltype(&recvmsg), recvmsg_signature),
    "recvmsg C++ declaration");
static_assert(__is_same(decltype(&sockatmark), sockatmark_signature),
    "sockatmark C++ declaration");

extern "C" int setsockopt(int, int, int, const void *, socklen_t);
extern "C" int getsockopt(int, int, int, void *, socklen_t *);
extern "C" ssize_t sendmsg(int, const msghdr *, int);
extern "C" ssize_t recvmsg(int, msghdr *, int);
extern "C" int sockatmark(int);

static setsockopt_signature const crabc_force_setsockopt __attribute__((used)) = &setsockopt;
static getsockopt_signature const crabc_force_getsockopt __attribute__((used)) = &getsockopt;
static sendmsg_signature const crabc_force_sendmsg __attribute__((used)) = &sendmsg;
static recvmsg_signature const crabc_force_recvmsg __attribute__((used)) = &recvmsg;
static sockatmark_signature const crabc_force_sockatmark __attribute__((used)) = &sockatmark;

#if defined(_GNU_SOURCE)
static_assert(sizeof(mmsghdr) == 64 && alignof(mmsghdr) == 8 &&
    offsetof(mmsghdr, msg_hdr) == 0 && offsetof(mmsghdr, msg_len) == 56,
    "x86 C++ mmsghdr ABI");

using sendmmsg_signature = int (*)(int, mmsghdr *, unsigned int, unsigned int);
using recvmmsg_signature = int (*)(int, mmsghdr *, unsigned int, unsigned int,
    timespec *);

static_assert(__is_same(decltype(&sendmmsg), sendmmsg_signature),
    "sendmmsg C++ declaration");
static_assert(__is_same(decltype(&recvmmsg), recvmmsg_signature),
    "recvmmsg C++ declaration");

extern "C" int sendmmsg(int, mmsghdr *, unsigned int, unsigned int);
extern "C" int recvmmsg(int, mmsghdr *, unsigned int, unsigned int, timespec *);

static sendmmsg_signature const crabc_force_sendmmsg __attribute__((used)) = &sendmmsg;
static recvmmsg_signature const crabc_force_recvmmsg __attribute__((used)) = &recvmmsg;
#endif

static_assert(CMSG_ALIGN(5) == 8, "CMSG_ALIGN visibility/value");

int crabc_x86_64_socket_messages_header_abi_probe_cpp()
{
    return static_cast<int>(sizeof(msghdr));
}
