/* One application object for pinned musl and the owned static resolver. */
#define _GNU_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct addrinfo hints = {0};
    struct addrinfo *result = 0;
    struct addrinfo *item;
    char first_a[INET_ADDRSTRLEN] = "-";
    char first_aaaa[INET6_ADDRSTRLEN] = "-";
    char canonical[256] = "-";
    unsigned count_a = 0;
    unsigned count_aaaa = 0;
    int status;
    int saved_errno;
    int saved_h_errno;

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;
    errno = E2BIG;
    h_errno = NO_RECOVERY;
    status = getaddrinfo("chain", 0, &hints, &result);
    saved_errno = errno;
    saved_h_errno = h_errno;
    for (item = result; item; item = item->ai_next) {
        if (item->ai_canonname && canonical[0] == '-') {
            snprintf(canonical, sizeof(canonical), "%s", item->ai_canonname);
        }
        if (item->ai_family == AF_INET) {
            ++count_a;
            if (count_a == 1)
                inet_ntop(AF_INET, &((struct sockaddr_in *)item->ai_addr)->sin_addr,
                    first_a, sizeof(first_a));
        } else if (item->ai_family == AF_INET6) {
            ++count_aaaa;
            if (count_aaaa == 1)
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)item->ai_addr)->sin6_addr,
                    first_aaaa, sizeof(first_aaaa));
        }
    }
    printf("gai=%d errno=%d h_errno=%d a=%s n4=%u aaaa=%s n6=%u canon=%s\n",
        status, saved_errno, saved_h_errno, first_a, count_a,
        first_aaaa, count_aaaa, canonical);
    if (result) freeaddrinfo(result);
    return 0;
}
