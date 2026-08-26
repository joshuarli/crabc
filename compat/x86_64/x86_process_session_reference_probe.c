/* Pinned-musl Linux/x86-64 process-group/session observation reference. */

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stdio.h>
#include <unistd.h>

int main(void)
{
    pid_t pid = getpid();
    pid_t group = getpgid(0);
    pid_t explicit_group = getpgid(pid);
    pid_t shorthand_group = getpgrp();
    pid_t session = getsid(0);
    pid_t explicit_session = getsid(pid);

    if (pid <= 0 || group <= 0 || explicit_group <= 0 ||
        shorthand_group <= 0 || session <= 0 || explicit_session <= 0)
        return 1;
    if (group != explicit_group || group != shorthand_group ||
        session != explicit_session)
        return 2;
    if (getpid() != pid || getpgid(0) != group || getpgrp() != shorthand_group ||
        getsid(0) != session)
        return 3;

    puts("pid=positive group=stable session=stable");
    return 0;
}
