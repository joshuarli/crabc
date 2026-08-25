/* Public-header isolation probe for the packaged sysroot. */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int header_probe(void)
{
    return errno + (int)sizeof(pthread_t) + (int)sizeof(uintptr_t) + STDOUT_FILENO;
}
