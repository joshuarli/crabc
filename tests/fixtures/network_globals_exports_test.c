#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    int *location;

    if (memcmp(&in6addr_any, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) ||
        ((const unsigned char *)&in6addr_loopback)[15] != 1)
        return 1;
    location = __h_errno_location();
    if (!location || location != &h_errno)
        return 2;
    *location = TRY_AGAIN;
    if (strcmp(hstrerror(h_errno), "Try again"))
        return 3;
    if (strcmp(gai_strerror(EAI_NONAME), "Name does not resolve") ||
        strcmp(gai_strerror(12345), "Unknown error"))
        return 4;
    puts("c-abi network globals exports ok");
    return 0;
}
