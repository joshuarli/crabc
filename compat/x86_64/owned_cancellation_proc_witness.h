#ifndef CRABC_OWNED_CANCELLATION_PROC_WITNESS_H
#define CRABC_OWNED_CANCELLATION_PROC_WITNESS_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Dynamic consumers inherit a read-only /proc directory descriptor through
 * run_pthread_wait_witness.py, so exact blocked-syscall witnesses work inside
 * the private chroot without a proc mount. Ordinary static runs keep their
 * existing /proc path. An invalid supplied descriptor never falls back. */
static int owned_cancellation_open_proc(const char *path)
{
    const char *value=getenv("CRABC_TEST_PROC_FD");
    if (!value) return open(path,O_RDONLY|O_CLOEXEC);
    char *end;
    long descriptor=strtol(value,&end,10);
    if (!*value || *end || descriptor<0 || descriptor>INT_MAX || strncmp(path,"/proc/",6)) {
        errno=EINVAL;
        return -1;
    }
    return openat((int)descriptor,path+6,O_RDONLY|O_CLOEXEC);
}

#endif
