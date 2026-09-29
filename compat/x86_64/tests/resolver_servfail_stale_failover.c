/* One static C workload shared by the pinned musl and owned resolvers. */
#define _GNU_SOURCE 1
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

static int equal(const char *left, const char *right)
{
    while (*left && *right && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

int main(void)
{
    const unsigned char address4[4] = {198, 51, 100, 41};
    const unsigned char address6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x42,
    };
    struct addrinfo hints = {0};
    struct addrinfo *result = 0;
    unsigned count4 = 0, count6 = 0;
    int canonical = 0;

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo("late.test.", 0, &hints, &result) != 0 || !result)
        return 1;
    for (struct addrinfo *item = result; item; item = item->ai_next) {
        if (item->ai_canonname) {
            if (!equal(item->ai_canonname, "late.test")) return 2;
            ++canonical;
        }
        if (item->ai_family == AF_INET) {
            if (!item->ai_addr || memcmp(&((struct sockaddr_in *)item->ai_addr)->sin_addr,
                                         address4, sizeof(address4))) return 3;
            ++count4;
        } else if (item->ai_family == AF_INET6) {
            if (!item->ai_addr || memcmp(&((struct sockaddr_in6 *)item->ai_addr)->sin6_addr,
                                         address6, sizeof(address6))) return 4;
            ++count6;
        } else {
            return 5;
        }
    }
    freeaddrinfo(result);
    return count4 == 2 && count6 == 2 && canonical != 0 ? 0 : 6;
}
