#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what)
{
    fprintf(stderr, "resolver: %s\n", what);
    return 1;
}

int main(void)
{
    struct addrinfo hints = {0};
    struct addrinfo *list = NULL;
    struct sockaddr_in address = {0};
    char host[INET_ADDRSTRLEN];
    char service[32];
    unsigned char query[512];
    int query_len;

    if (res_init() != 0)
        return fail("res_init");
    if (!__res_state() || !(_res.options & RES_INIT))
        return fail("resolver state");
    query_len = res_mkquery(QUERY, "example.test", C_IN, T_A,
        NULL, 0, NULL, query, sizeof query);
    if (query_len < 17 || query[12] != 7 || memcmp(query + 13, "example", 7) != 0)
        return fail("res_mkquery");

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo("127.0.0.1", "80", &hints, &list) != 0 || !list)
        return fail("getaddrinfo");
    if (list->ai_family != AF_INET || list->ai_socktype != SOCK_STREAM ||
        list->ai_protocol != IPPROTO_TCP || list->ai_addrlen != sizeof address)
        return fail("addrinfo fields");
    if (ntohs(((struct sockaddr_in *)list->ai_addr)->sin_port) != 80)
        return fail("addrinfo port");
    freeaddrinfo(list);

    address.sin_family = AF_INET;
    address.sin_port = htons(80);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1)
        return fail("inet_pton");
    if (getnameinfo((const struct sockaddr *)&address, sizeof address,
            host, sizeof host, service, sizeof service,
            NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        return fail("getnameinfo");
    if (strcmp(host, "127.0.0.1") != 0 || strcmp(service, "80") != 0)
        return fail("nameinfo fields");

    /* Invalid arguments must fail before any resolver I/O.  Valid calls use
       the configured nameservers and are intentionally not fabricated here. */
    if (res_send(NULL, query_len, query, sizeof query) != -1)
        return fail("res_send invalid arguments");
    if (res_querydomain(NULL, "", C_IN, T_A, query, sizeof query) != -1)
        return fail("res_querydomain invalid arguments");
    if (res_search(NULL, C_IN, T_A, query, sizeof query) != -1)
        return fail("res_search invalid arguments");

    puts("m4 legacy resolver ok");
    return 0;
}
