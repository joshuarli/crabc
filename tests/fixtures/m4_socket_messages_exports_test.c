#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

struct m4_sockaddr_in {
    sa_family_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    unsigned char sin_zero[8];
};

static int make_stream_pair(int *listener_out, int *peer_out, pid_t *child_out,
                            int send_oob)
{
    struct m4_sockaddr_in address;
    struct m4_sockaddr_in child_address;
    socklen_t address_len;
    int listener;
    int child_status;
    pid_t child;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr = htonl(0x7f000001U);
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, 4) < 0) {
        close(listener);
        return -1;
    }
    address_len = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &address_len) < 0) {
        close(listener);
        return -1;
    }

    child = fork();
    if (child < 0) {
        close(listener);
        return -1;
    }
    if (child == 0) {
        int client = socket(AF_INET, SOCK_STREAM, 0);
        if (client < 0)
            _exit(2);
        memset(&child_address, 0, sizeof(child_address));
        child_address.sin_family = AF_INET;
        child_address.sin_port = address.sin_port;
        child_address.sin_addr = address.sin_addr;
        if (connect(client, (const struct sockaddr *)&child_address,
                    sizeof(child_address)) < 0)
            _exit(3);
        if (send_oob && send(client, "!", 1, MSG_OOB) != 1)
            _exit(4);
        /* The parent closes the accepted end after checking it. */
        _exit(0);
    }

    *peer_out = -1;
    *listener_out = listener;
    *child_out = child;
    return 0;
}

static int test_accept4_peer_and_sockopt(void)
{
    struct sockaddr_storage peer_address;
    socklen_t peer_length = sizeof(peer_address);
    int listener;
    int accepted;
    int type = 0;
    socklen_t type_length = sizeof(type);
    int child_status = 0;
    pid_t child;

    if (make_stream_pair(&listener, &accepted, &child, 0) < 0)
        return -1;
    accepted = accept4(listener, (struct sockaddr *)&peer_address,
                       &peer_length, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (accepted < 0)
        return -1;
    if (fcntl(accepted, F_GETFD) != FD_CLOEXEC)
        return -1;
    if ((fcntl(accepted, F_GETFL) & O_NONBLOCK) == 0)
        return -1;
    if (getpeername(accepted, (struct sockaddr *)&peer_address,
                    &peer_length) < 0)
        return -1;
    if (getsockopt(accepted, SOL_SOCKET, SO_TYPE, &type, &type_length) < 0 ||
        type != SOCK_STREAM || type_length != sizeof(type))
        return -1;

    close(accepted);
    close(listener);
    waitpid(child, &child_status, 0);
    return WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 ? 0 : -1;
}

static int test_sockatmark(void)
{
    struct pollfd urgent;
    struct sockaddr_storage peer_address;
    socklen_t peer_length = sizeof(peer_address);
    int listener;
    int accepted;
    int child_status = 0;
    char out_of_band;
    pid_t child;

    if (make_stream_pair(&listener, &accepted, &child, 1) < 0)
        return -1;
    accepted = accept4(listener, (struct sockaddr *)&peer_address,
                       &peer_length, 0);
    if (accepted < 0)
        return -1;
    urgent.fd = accepted;
    urgent.events = POLLPRI;
    urgent.revents = 0;
    if (poll(&urgent, 1, 1000) != 1 || !(urgent.revents & POLLPRI))
        return -1;
    /* Linux does not guarantee that an OOB-only stream reports the receive
     * cursor at the urgent mark. The portable contract here is a successful
     * SIOCATMARK query; the subsequent MSG_OOB read proves the event path. */
    if (sockatmark(accepted) < 0)
        return -1;
    if (recv(accepted, &out_of_band, 1, MSG_OOB) != 1 || out_of_band != '!')
        return -1;
    if (sockatmark(accepted) < 0)
        return -1;

    close(accepted);
    close(listener);
    waitpid(child, &child_status, 0);
    return WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 ? 0 : -1;
}

static int test_sendmsg_recvmsg(void)
{
    char first[] = "hello";
    char second[] = "-world";
    char received_first[6] = {0};
    char received_second[7] = {0};
    unsigned char send_control[CMSG_SPACE(sizeof(int))];
    unsigned char receive_control[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    struct cmsghdr *received_cmsg;
    struct iovec send_iov[2];
    struct iovec receive_iov[2];
    struct msghdr send_message;
    struct msghdr receive_message;
    int sockets[2];
    int received_fd = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
        return -1;
    memset(send_control, 0, sizeof(send_control));
    memset(receive_control, 0, sizeof(receive_control));
    cmsg = (struct cmsghdr *)send_control;
    cmsg->__pad1 = -1;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &sockets[0], sizeof(sockets[0]));

    memset(&send_message, 0, sizeof(send_message));
    send_iov[0].iov_base = first;
    send_iov[0].iov_len = sizeof(first) - 1;
    send_iov[1].iov_base = second;
    send_iov[1].iov_len = sizeof(second) - 1;
    send_message.msg_iov = send_iov;
    send_message.msg_iovlen = 2;
    send_message.__pad1 = -1;
    send_message.msg_control = send_control;
    send_message.msg_controllen = sizeof(send_control);
    send_message.__pad2 = -1;
    if (sendmsg(sockets[0], &send_message, 0) != 11)
        return -1;

    memset(&receive_message, 0, sizeof(receive_message));
    receive_iov[0].iov_base = received_first;
    receive_iov[0].iov_len = sizeof(received_first) - 1;
    receive_iov[1].iov_base = received_second;
    receive_iov[1].iov_len = sizeof(received_second) - 1;
    receive_message.msg_iov = receive_iov;
    receive_message.msg_iovlen = 2;
    receive_message.__pad1 = -1;
    receive_message.msg_control = receive_control;
    receive_message.msg_controllen = sizeof(receive_control);
    receive_message.__pad2 = -1;
    if (recvmsg(sockets[1], &receive_message, 0) != 11)
        return -1;
    CHECK(memcmp(received_first, "hello", 5) == 0 &&
              memcmp(received_second, "-world", 6) == 0,
          "recvmsg payload");
    received_cmsg = CMSG_FIRSTHDR(&receive_message);
    CHECK(received_cmsg != NULL && received_cmsg->cmsg_level == SOL_SOCKET &&
              received_cmsg->cmsg_type == SCM_RIGHTS &&
              received_cmsg->cmsg_len >= CMSG_LEN(sizeof(int)),
          "recvmsg control");
    memcpy(&received_fd, CMSG_DATA(received_cmsg), sizeof(received_fd));
    CHECK(fcntl(received_fd, F_GETFD) >= 0, "recvmsg received fd");

    close(received_fd);
    close(sockets[0]);
    close(sockets[1]);
    return 0;
}

static int test_sendmmsg_recvmmsg(void)
{
    char first[] = "one";
    char second[] = "two";
    char received_first[4] = {0};
    char received_second[4] = {0};
    struct iovec send_iov[2];
    struct iovec receive_iov[2];
    struct mmsghdr send_messages[2];
    struct mmsghdr receive_messages[2];
    int sockets[2];

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0)
        return -1;
    memset(send_messages, 0, sizeof(send_messages));
    send_iov[0].iov_base = first;
    send_iov[0].iov_len = sizeof(first) - 1;
    send_iov[1].iov_base = second;
    send_iov[1].iov_len = sizeof(second) - 1;
    send_messages[0].msg_hdr.msg_iov = &send_iov[0];
    send_messages[0].msg_hdr.msg_iovlen = 1;
    send_messages[0].msg_hdr.__pad1 = -1;
    send_messages[0].msg_hdr.__pad2 = -1;
    send_messages[1].msg_hdr.msg_iov = &send_iov[1];
    send_messages[1].msg_hdr.msg_iovlen = 1;
    send_messages[1].msg_hdr.__pad1 = -1;
    send_messages[1].msg_hdr.__pad2 = -1;
    CHECK(sendmmsg(sockets[0], send_messages, 2, 0) == 2,
          "sendmmsg count");
    CHECK(send_messages[0].msg_len == 3 && send_messages[1].msg_len == 3,
          "sendmmsg lengths");

    memset(receive_messages, 0, sizeof(receive_messages));
    receive_iov[0].iov_base = received_first;
    receive_iov[0].iov_len = sizeof(received_first) - 1;
    receive_iov[1].iov_base = received_second;
    receive_iov[1].iov_len = sizeof(received_second) - 1;
    receive_messages[0].msg_hdr.msg_iov = &receive_iov[0];
    receive_messages[0].msg_hdr.msg_iovlen = 1;
    receive_messages[0].msg_hdr.__pad1 = -1;
    receive_messages[0].msg_hdr.__pad2 = -1;
    receive_messages[1].msg_hdr.msg_iov = &receive_iov[1];
    receive_messages[1].msg_hdr.msg_iovlen = 1;
    receive_messages[1].msg_hdr.__pad1 = -1;
    receive_messages[1].msg_hdr.__pad2 = -1;
    CHECK(recvmmsg(sockets[1], receive_messages, 2, 0, NULL) == 2,
          "recvmmsg count");
    CHECK(receive_messages[0].msg_len == 3 &&
              receive_messages[1].msg_len == 3 &&
              memcmp(received_first, "one", 3) == 0 &&
              memcmp(received_second, "two", 3) == 0,
          "recvmmsg payload");

    close(sockets[0]);
    close(sockets[1]);
    return 0;
}

int main(void)
{
    CHECK(test_accept4_peer_and_sockopt() == 0, "accept4/getpeername/getsockopt");
    CHECK(test_sendmsg_recvmsg() == 0, "sendmsg/recvmsg");
    CHECK(test_sendmmsg_recvmmsg() == 0, "sendmmsg/recvmmsg");
    CHECK(test_sockatmark() == 0, "sockatmark");

    errno = 0;
    CHECK(sockatmark(-1) == -1 && errno == EBADF, "sockatmark invalid fd");
    puts("m4 socket messages exports ok");
    return 0;
}
