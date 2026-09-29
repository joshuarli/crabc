#define _GNU_SOURCE 1
#include <netdb.h>
#include <string.h>

volatile size_t crabc_strlen_observed_length;
volatile struct hostent *crabc_strlen_observed_host;

int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "localhost";
    crabc_strlen_observed_length = strlen(name);
    crabc_strlen_observed_host = gethostbyname(name);
    return crabc_strlen_observed_length == 0 && crabc_strlen_observed_host == 0;
}
