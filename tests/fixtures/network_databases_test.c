#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    struct hostent *host = gethostbyname("localhost");
    if (!host || host->h_addrtype != AF_INET || host->h_length != 4 ||
        !host->h_name || !host->h_addr_list || !host->h_addr_list[0])
        return 1;
    if (gethostbyaddr(host->h_addr_list[0], 4, AF_INET) == NULL)
        return 2;

    struct hostent host_storage;
    struct hostent *host_result = NULL;
    char host_buffer[1024];
    if (gethostbyname_r("localhost", &host_storage, host_buffer,
                       sizeof(host_buffer), &host_result, &h_errno) != 0 ||
        !host_result || strcmp(host_result->h_name, "localhost") != 0)
        return 3;

    struct protoent *proto = getprotobyname("tcp");
    if (!proto || proto->p_proto != 6 || getprotobynumber(6) == NULL)
        return 4;

    struct netent *network = getnetbyname("loopback");
    if (network && network->n_addrtype != AF_INET)
        return 5;

    struct servent *service = getservbyname("http", "tcp");
    if (service) {
        if (ntohs((unsigned short)service->s_port) != 80)
            return 6;
        struct servent service_storage;
        struct servent *service_result = NULL;
        char service_buffer[1024];
        if (getservbyname_r("http", "tcp", &service_storage, service_buffer,
                            sizeof(service_buffer), &service_result) != 0 ||
            !service_result || ntohs((unsigned short)service_result->s_port) != 80)
            return 7;
    }
    {
        struct servent service_storage;
        struct servent *service_result = (struct servent *)1;
        char service_buffer[32];
        if (getservbyname_r("crabc-service-that-does-not-exist", "tcp",
                            &service_storage, service_buffer,
                            sizeof(service_buffer), &service_result) != 0 ||
            service_result != NULL)
            return 8;
    }

    setprotoent(1);
    (void)getprotoent();
    endprotoent();
    setservent(1);
    (void)getservent();
    endservent();
    setnetent(1);
    (void)getnetent();
    endnetent();
    sethostent(1);
    (void)gethostent();
    endhostent();
    puts("c-abi network databases ok");
    return 0;
}
