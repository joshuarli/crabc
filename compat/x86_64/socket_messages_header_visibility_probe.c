/* GNU-only sendmmsg/recvmmsg visibility check for <sys/socket.h>. */

#include <sys/socket.h>

int crabc_x86_64_socket_messages_visibility(int fd)
{
    struct mmsghdr message = {0};
    return sendmmsg(fd, &message, 0, 0) + recvmmsg(fd, &message, 0, 0, 0);
}
