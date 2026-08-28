/* Pinned-musl/raw Linux/x86-64 interface-device ABI and behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * The pinned musl sysroot deliberately exposes its POSIX networking headers,
 * not Linux's optional UAPI header tree. Keep the fixed Linux 5.10 rtnetlink
 * records here so this native probe validates the exact wire bytes consumed
 * by `crabc-rs::net::netdevice` without importing ambient host headers.
 */
struct sockaddr_nl {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

struct nlmsgerr {
    int32_t error;
    struct nlmsghdr msg;
};

struct rtgenmsg {
    uint8_t rtgen_family;
};

struct ifinfomsg {
    uint8_t ifi_family;
    uint8_t ifi_pad;
    uint16_t ifi_type;
    int32_t ifi_index;
    uint32_t ifi_flags;
    uint32_t ifi_change;
};

struct ifaddrmsg {
    uint8_t ifa_family;
    uint8_t ifa_prefixlen;
    uint8_t ifa_flags;
    uint8_t ifa_scope;
    uint32_t ifa_index;
};

struct rtattr {
    uint16_t rta_len;
    uint16_t rta_type;
};

#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(length) (((length) + NLMSG_ALIGNTO - 1U) & ~(NLMSG_ALIGNTO - 1U))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(length) ((int)((length) + NLMSG_HDRLEN))
#define NLMSG_DATA(header) ((void *)((unsigned char *)(header) + NLMSG_HDRLEN))
#define NLMSG_OK(header, remaining) \
    ((remaining) >= (int)sizeof(struct nlmsghdr) && \
     (header)->nlmsg_len >= sizeof(struct nlmsghdr) && \
     (header)->nlmsg_len <= (unsigned int)(remaining))
#define NLMSG_NEXT(header, remaining) \
    ((remaining) -= (int)NLMSG_ALIGN((header)->nlmsg_len), \
     (struct nlmsghdr *)((unsigned char *)(header) + NLMSG_ALIGN((header)->nlmsg_len)))

#define RTA_ALIGNTO 4U
#define RTA_ALIGN(length) (((length) + RTA_ALIGNTO - 1U) & ~(RTA_ALIGNTO - 1U))
#define RTA_DATA(attribute) ((void *)((unsigned char *)(attribute) + sizeof(struct rtattr)))
#define RTA_PAYLOAD(attribute) ((int)((attribute)->rta_len - sizeof(struct rtattr)))
#define RTA_OK(attribute, remaining) \
    ((remaining) >= (int)sizeof(struct rtattr) && \
     (attribute)->rta_len >= sizeof(struct rtattr) && \
     (attribute)->rta_len <= (unsigned int)(remaining))
#define RTA_NEXT(attribute, remaining) \
    ((remaining) -= (int)RTA_ALIGN((attribute)->rta_len), \
     (struct rtattr *)((unsigned char *)(attribute) + RTA_ALIGN((attribute)->rta_len)))
#define IFLA_RTA(link) \
    ((struct rtattr *)((unsigned char *)(link) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_PAYLOAD(header) \
    ((int)((header)->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg))))
#define IFA_RTA(address) \
    ((struct rtattr *)((unsigned char *)(address) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#define IFA_PAYLOAD(header) \
    ((int)((header)->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg))))

enum {
    NETLINK_FAMILY = 16,
    NETLINK_ROUTE = 0,
    NLM_F_REQUEST = 1,
    NLM_F_ROOT = 0x100,
    NLM_F_MATCH = 0x200,
    NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH,
    NLMSG_ERROR = 2,
    NLMSG_DONE = 3,
    RTM_NEWLINK = 16,
    RTM_GETLINK = 18,
    RTM_NEWADDR = 20,
    RTM_GETADDR = 22,
    IFA_ADDRESS = 1,
    IFA_LOCAL = 2,
    IFA_LABEL = 3,
    IFLA_IFNAME = 3,
    ATTRIBUTE_TYPE_MASK = 0x3fff,
};

_Static_assert(SYS_ioctl == 16 && SYS_socket == 41 && SYS_sendto == 44 &&
                   SYS_recvmsg == 47,
               "x86 interface-device syscall numbers");
_Static_assert(SIOCGIFNAME == 0x8910 && SIOCGIFINDEX == 0x8933,
               "Linux interface ioctl values");
_Static_assert(IFNAMSIZ == 16, "Linux interface-name capacity");
_Static_assert(sizeof(struct ifreq) == 40 && _Alignof(struct ifreq) == 8,
               "x86 ifreq ABI");
_Static_assert(offsetof(struct ifreq, ifr_name) == 0 &&
                   offsetof(struct ifreq, ifr_ifru) == 16 &&
                   offsetof(struct ifreq, ifr_ifindex) == 16,
               "x86 ifreq index layout");
_Static_assert(sizeof(((struct ifreq *)0)->ifr_ifindex) == 4,
               "x86 ifreq index width");
_Static_assert(MSG_TRUNC == 0x20, "Linux MSG_TRUNC value");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8 &&
                   offsetof(struct iovec, iov_base) == 0 &&
                   offsetof(struct iovec, iov_len) == 8,
               "x86 iovec ABI");
_Static_assert(sizeof(struct msghdr) == 56 && _Alignof(struct msghdr) == 8 &&
                   offsetof(struct msghdr, msg_name) == 0 &&
                   offsetof(struct msghdr, msg_namelen) == 8 &&
                   offsetof(struct msghdr, msg_iov) == 16 &&
                   offsetof(struct msghdr, msg_iovlen) == 24 &&
                   offsetof(struct msghdr, msg_control) == 32 &&
                   offsetof(struct msghdr, msg_controllen) == 40 &&
                   offsetof(struct msghdr, msg_flags) == 48,
               "x86 recvmsg ABI");
_Static_assert(sizeof(struct sockaddr_nl) == 12 &&
                   _Alignof(struct sockaddr_nl) == 4 &&
                   offsetof(struct sockaddr_nl, nl_family) == 0 &&
                   offsetof(struct sockaddr_nl, nl_pid) == 4 &&
                   offsetof(struct sockaddr_nl, nl_groups) == 8,
               "netlink destination ABI");
_Static_assert(sizeof(struct nlmsghdr) == 16 && _Alignof(struct nlmsghdr) == 4 &&
                   offsetof(struct nlmsghdr, nlmsg_len) == 0 &&
                   offsetof(struct nlmsghdr, nlmsg_type) == 4 &&
                   offsetof(struct nlmsghdr, nlmsg_flags) == 6 &&
                   offsetof(struct nlmsghdr, nlmsg_seq) == 8 &&
                   offsetof(struct nlmsghdr, nlmsg_pid) == 12,
               "netlink header ABI");
_Static_assert(sizeof(struct ifinfomsg) == 16 && _Alignof(struct ifinfomsg) == 4 &&
                   offsetof(struct ifinfomsg, ifi_type) == 2 &&
                   offsetof(struct ifinfomsg, ifi_index) == 4 &&
                   offsetof(struct ifinfomsg, ifi_flags) == 8,
               "rtnetlink link record ABI");
_Static_assert(sizeof(struct ifaddrmsg) == 8 && _Alignof(struct ifaddrmsg) == 4 &&
                   offsetof(struct ifaddrmsg, ifa_family) == 0 &&
                   offsetof(struct ifaddrmsg, ifa_prefixlen) == 1 &&
                   offsetof(struct ifaddrmsg, ifa_flags) == 2 &&
                   offsetof(struct ifaddrmsg, ifa_scope) == 3 &&
                   offsetof(struct ifaddrmsg, ifa_index) == 4,
               "rtnetlink address record ABI");
_Static_assert(sizeof(struct rtattr) == 4 && _Alignof(struct rtattr) == 2 &&
                   offsetof(struct rtattr, rta_len) == 0 &&
                   offsetof(struct rtattr, rta_type) == 2,
               "rtnetlink attribute ABI");
_Static_assert(NETLINK_ROUTE == 0 && NLM_F_REQUEST == 1 && NLM_F_DUMP == 0x300 &&
                   RTM_NEWLINK == 16 && RTM_GETLINK == 18 && RTM_NEWADDR == 20 &&
                   RTM_GETADDR == 22 && IFLA_IFNAME == 3 && IFA_LABEL == 3,
               "rtnetlink dump vocabulary");

enum {
    NETLINK_BUFFER_LEN = 8192,
    MAX_DUMP_PACKETS = 32,
};

struct route_request {
    struct nlmsghdr header;
    struct rtgenmsg message;
    unsigned char padding[3];
};

_Static_assert(sizeof(struct route_request) == 20,
               "the fixed direct RTM_GET* request is 20 bytes");

static void fail(const char *what)
{
    fprintf(stderr, "x86 interface-device reference: %s (errno=%d)\n", what, errno);
    _exit(1);
}

static void need(int condition, const char *what)
{
    if (!condition)
        fail(what);
}

static int raw_socket(int family, int type, int protocol)
{
    return (int)syscall(SYS_socket, family, type, protocol);
}

static int raw_ioctl(int fd, unsigned long request, void *argument)
{
    return (int)syscall(SYS_ioctl, fd, request, argument);
}

static ssize_t raw_sendto(int fd, const void *buffer, size_t length, int flags,
                          const struct sockaddr *address, socklen_t address_length)
{
    return (ssize_t)syscall(SYS_sendto, fd, buffer, length, flags, address,
                            address_length);
}

static ssize_t raw_recvmsg(int fd, struct msghdr *message, int flags)
{
    return (ssize_t)syscall(SYS_recvmsg, fd, message, flags);
}

static ssize_t send_request(int fd, int raw, uint16_t request_type, uint8_t family,
                            uint32_t sequence)
{
    struct route_request request = {
        .header = {
            .nlmsg_len = sizeof(request),
            .nlmsg_type = request_type,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
            .nlmsg_seq = sequence,
        },
        .message = {.rtgen_family = family},
    };
    struct sockaddr_nl kernel = {.nl_family = NETLINK_FAMILY};

    if (raw) {
        return raw_sendto(fd, &request, sizeof(request), 0,
                          (const struct sockaddr *)&kernel, sizeof(kernel));
    }
    return sendto(fd, &request, sizeof(request), 0,
                  (const struct sockaddr *)&kernel, sizeof(kernel));
}

static ssize_t receive_packet(int fd, int raw, unsigned char packet[NETLINK_BUFFER_LEN],
                              int *truncated)
{
    struct iovec iovec = {.iov_base = packet, .iov_len = NETLINK_BUFFER_LEN};
    struct msghdr message = {.msg_iov = &iovec, .msg_iovlen = 1};
    ssize_t received;

    if (raw)
        received = raw_recvmsg(fd, &message, MSG_TRUNC);
    else
        received = recvmsg(fd, &message, MSG_TRUNC);
    *truncated = received > NETLINK_BUFFER_LEN || (message.msg_flags & MSG_TRUNC) != 0;
    return received;
}

static int link_message_has_loopback(const struct nlmsghdr *header, int loopback_index)
{
    const struct ifinfomsg *link;
    struct rtattr *attribute;
    int attributes;

    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*link)))
        return -1;
    link = NLMSG_DATA(header);
    if (link->ifi_index != loopback_index)
        return 0;
    attributes = IFLA_PAYLOAD(header);
    for (attribute = IFLA_RTA(link); RTA_OK(attribute, attributes);
         attribute = RTA_NEXT(attribute, attributes)) {
        const unsigned char *value;
        size_t value_len;

        if ((attribute->rta_type & ATTRIBUTE_TYPE_MASK) != IFLA_IFNAME)
            continue;
        value = RTA_DATA(attribute);
        value_len = RTA_PAYLOAD(attribute);
        if (value_len == 3 && memcmp(value, "lo\0", 3) == 0)
            return 1;
        return -1;
    }
    return -1;
}

static int address_message_has_loopback(const struct nlmsghdr *header,
                                        int loopback_index, uint8_t family)
{
    const struct ifaddrmsg *address;
    struct rtattr *attribute;
    int attributes;

    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*address)))
        return -1;
    address = NLMSG_DATA(header);
    if (address->ifa_family != family || address->ifa_index != (unsigned)loopback_index)
        return 0;
    attributes = IFA_PAYLOAD(header);
    for (attribute = IFA_RTA(address); RTA_OK(attribute, attributes);
         attribute = RTA_NEXT(attribute, attributes)) {
        if ((attribute->rta_type & ATTRIBUTE_TYPE_MASK) != IFA_LOCAL &&
            (attribute->rta_type & ATTRIBUTE_TYPE_MASK) != IFA_ADDRESS)
            continue;
        if (family == AF_INET) {
            uint32_t value;

            if (RTA_PAYLOAD(attribute) != sizeof(value))
                return -1;
            memcpy(&value, RTA_DATA(attribute), sizeof(value));
            if (value == htonl(INADDR_LOOPBACK))
                return 1;
        } else if (family == AF_INET6) {
            const struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
            struct in6_addr value;

            if (RTA_PAYLOAD(attribute) != sizeof(value))
                return -1;
            memcpy(&value, RTA_DATA(attribute), sizeof(value));
            if (memcmp(&value, &loopback, sizeof(value)) == 0)
                return 1;
        } else {
            return -1;
        }
    }
    return 0;
}

static int dump_contains_loopback(int fd, int raw, uint16_t request_type, uint8_t family,
                                  uint32_t sequence, int loopback_index)
{
    unsigned char packet[NETLINK_BUFFER_LEN];
    int saw_loopback = 0;

    need(send_request(fd, raw, request_type, family, sequence) ==
             (ssize_t)sizeof(struct route_request),
         "send rtnetlink dump request");
    for (int packet_count = 0; packet_count < MAX_DUMP_PACKETS; ++packet_count) {
        int truncated = 0;
        ssize_t received = receive_packet(fd, raw, packet, &truncated);
        int remaining;
        struct nlmsghdr *header;

        need(received > 0 && received <= NETLINK_BUFFER_LEN && !truncated,
             "receive complete rtnetlink dump packet");
        remaining = (int)received;
        for (header = (struct nlmsghdr *)packet; NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            int matched = 0;

            need(header->nlmsg_seq == sequence, "match rtnetlink sequence");
            if (header->nlmsg_type == NLMSG_DONE)
                return saw_loopback;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *error;

                need(header->nlmsg_len >= NLMSG_LENGTH(sizeof(*error)),
                     "validate rtnetlink error record");
                error = NLMSG_DATA(header);
                need(error->error == 0, "rtnetlink dump error");
                continue;
            }
            if (request_type == RTM_GETLINK && header->nlmsg_type == RTM_NEWLINK)
                matched = link_message_has_loopback(header, loopback_index);
            if (request_type == RTM_GETADDR && header->nlmsg_type == RTM_NEWADDR)
                matched = address_message_has_loopback(header, loopback_index, family);
            need(matched >= 0, "validate rtnetlink record framing");
            saw_loopback |= matched;
        }
        need(remaining == 0, "consume aligned rtnetlink packet");
    }
    fail("rtnetlink dump did not terminate");
    return 0;
}

static void ioctl_round_trip(int libc_fd, int raw_fd, int *loopback_index)
{
    struct ifreq libc_request = {0};
    struct ifreq raw_request = {0};
    int index;

    memcpy(libc_request.ifr_name, "lo", 3);
    memcpy(raw_request.ifr_name, "lo", 3);
    need(ioctl(libc_fd, SIOCGIFINDEX, &libc_request) == 0,
         "musl SIOCGIFINDEX loopback");
    need(raw_ioctl(raw_fd, SIOCGIFINDEX, &raw_request) == 0,
         "raw SIOCGIFINDEX loopback");
    need(libc_request.ifr_ifindex > 0 &&
             libc_request.ifr_ifindex == raw_request.ifr_ifindex,
         "raw and musl loopback indexes agree");
    index = libc_request.ifr_ifindex;

    memset(&libc_request, 0, sizeof(libc_request));
    memset(&raw_request, 0, sizeof(raw_request));
    libc_request.ifr_ifindex = index;
    raw_request.ifr_ifindex = index;
    *loopback_index = index;
    need(ioctl(libc_fd, SIOCGIFNAME, &libc_request) == 0 &&
             raw_ioctl(raw_fd, SIOCGIFNAME, &raw_request) == 0,
         "SIOCGIFNAME loopback");
    need(memcmp(libc_request.ifr_name, "lo\0", 3) == 0 &&
             memcmp(raw_request.ifr_name, "lo\0", 3) == 0,
         "raw and musl loopback names agree");

    memset(&libc_request, 0, sizeof(libc_request));
    memset(&raw_request, 0, sizeof(raw_request));
    errno = 0;
    need(ioctl(libc_fd, SIOCGIFNAME, &libc_request) == -1 && errno == ENODEV,
         "musl invalid interface index");
    errno = 0;
    need(raw_ioctl(raw_fd, SIOCGIFNAME, &raw_request) == -1 && errno == ENODEV,
         "raw invalid interface index");
}

int main(void)
{
    int libc_ioctl_fd = -1;
    int raw_ioctl_fd = -1;
    int libc_netlink_fd = -1;
    int raw_netlink_fd = -1;
    int loopback_index = 0;

    libc_ioctl_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    raw_ioctl_fd = raw_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    need(libc_ioctl_fd >= 0 && raw_ioctl_fd >= 0, "create ioctl sockets");
    ioctl_round_trip(libc_ioctl_fd, raw_ioctl_fd, &loopback_index);

    libc_netlink_fd = socket(NETLINK_FAMILY, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    raw_netlink_fd = raw_socket(NETLINK_FAMILY, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    need(libc_netlink_fd >= 0 && raw_netlink_fd >= 0, "create NETLINK_ROUTE sockets");
    need(dump_contains_loopback(libc_netlink_fd, 0, RTM_GETLINK, AF_UNSPEC, 1,
                                loopback_index),
         "musl link dump contains loopback");
    need(dump_contains_loopback(raw_netlink_fd, 1, RTM_GETLINK, AF_UNSPEC, 2,
                                loopback_index),
         "raw link dump contains loopback");
    need(dump_contains_loopback(libc_netlink_fd, 0, RTM_GETADDR, AF_INET, 3,
                                loopback_index),
         "musl IPv4 address dump contains loopback");
    need(dump_contains_loopback(raw_netlink_fd, 1, RTM_GETADDR, AF_INET, 4,
                                loopback_index),
         "raw IPv4 address dump contains loopback");
    need(dump_contains_loopback(libc_netlink_fd, 0, RTM_GETADDR, AF_INET6, 5,
                                loopback_index),
         "musl IPv6 address dump contains loopback");
    need(dump_contains_loopback(raw_netlink_fd, 1, RTM_GETADDR, AF_INET6, 6,
                                loopback_index),
         "raw IPv6 address dump contains loopback");

    need(close(libc_ioctl_fd) == 0 && close(raw_ioctl_fd) == 0 &&
             close(libc_netlink_fd) == 0 && close(raw_netlink_fd) == 0,
         "close interface-device sockets");
    puts("syscalls=ioctl:16,socket:41,sendto:44,recvmsg:47 abi=ifreq40:iovec16:msghdr56:netlink16:ifinfomsg16:ifaddrmsg8:rtattr4 ioctl=loopback-index-name:invalid-index-ENODEV rtnetlink=link-dump:ipv4-loopback:ipv6-loopback:truncation-checked raw=matches-musl c-api-selection=excluded");
    return 0;
}
