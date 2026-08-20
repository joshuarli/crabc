#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern int sigandset(sigset_t *, const sigset_t *, const sigset_t *);
extern int sigorset(sigset_t *, const sigset_t *, const sigset_t *);
extern int sigisemptyset(const sigset_t *);

static volatile sig_atomic_t pause_received;

static void pause_handler(int sig)
{
    if (sig == SIGUSR1)
        pause_received = 1;
}

static int set_operations_case(void)
{
    sigset_t left, right, dest;
    unsigned long *l = (unsigned long *)&left;
    unsigned long *r = (unsigned long *)&right;
    unsigned long *d = (unsigned long *)&dest;

    memset(&left, 0, sizeof left);
    memset(&right, 0, sizeof right);
    memset(&dest, 0, sizeof dest);
    l[0] = 0x3;
    r[0] = 0x5;

    if (sigisemptyset(&dest) != 1)
        return 1;
    if (sigandset(&dest, &left, &right) != 0 || d[0] != 1)
        return 2;
    if (sigorset(&dest, &left, &right) != 0 || d[0] != 7)
        return 3;
    if (sigisemptyset(&dest) != 0)
        return 4;
    return 0;
}

static int legacy_mask_case(void)
{
    sigset_t old_mask, mask;
    struct sigaction action;

    memset(&old_mask, 0, sizeof old_mask);
    if (sigprocmask(SIG_SETMASK, NULL, &old_mask) != 0)
        return 10;

    if (sigignore(SIGUSR2) != 0)
        return 11;
    memset(&action, 0, sizeof action);
    if (sigaction(SIGUSR2, NULL, &action) != 0 || action.sa_handler != SIG_IGN)
        return 12;
    if (signal(SIGUSR2, SIG_DFL) == SIG_ERR)
        return 13;

    if (siginterrupt(SIGUSR1, 1) != 0)
        return 14;
    if (sigaction(SIGUSR1, NULL, &action) != 0 || (action.sa_flags & SA_RESTART) != 0)
        return 15;
    if (siginterrupt(SIGUSR1, 0) != 0)
        return 16;
    if (sigaction(SIGUSR1, NULL, &action) != 0 || (action.sa_flags & SA_RESTART) == 0)
        return 17;

    if (sighold(SIGUSR1) != 0)
        return 18;
    memset(&mask, 0, sizeof mask);
    if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0 || !sigismember(&mask, SIGUSR1))
        return 19;
    if (sigrelse(SIGUSR1) != 0)
        return 20;
    memset(&mask, 0, sizeof mask);
    if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0 || sigismember(&mask, SIGUSR1))
        return 21;

    if (sigset(SIGUSR1, SIG_IGN) != SIG_DFL)
        return 22;
    if (sigset(SIGUSR1, SIG_HOLD) != SIG_IGN)
        return 23;
    if (sigset(SIGUSR1, SIG_DFL) != SIG_HOLD)
        return 24;

    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) != 0)
        return 25;
    return 0;
}

static int sigpause_case(void)
{
    sigset_t mask, old_mask;
    pid_t child;

    memset(&old_mask, 0, sizeof old_mask);
    if (sigprocmask(SIG_SETMASK, NULL, &old_mask) != 0)
        return 30;
    if (signal(SIGUSR1, pause_handler) == SIG_ERR)
        return 31;
    if (sigemptyset(&mask) != 0 || sigaddset(&mask, SIGUSR1) != 0 ||
        sigprocmask(SIG_BLOCK, &mask, NULL) != 0)
        return 32;

    child = fork();
    if (child < 0)
        return 33;
    if (child == 0) {
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    errno = 0;
    if (sigpause(SIGUSR1) != -1 || errno != EINTR || !pause_received)
        return 34;
    if (waitpid(child, NULL, 0) != child)
        return 35;
    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) != 0)
        return 36;
    signal(SIGUSR1, SIG_DFL);
    return 0;
}

static int sigqueue_case(void)
{
    sigset_t mask;
    siginfo_t info;
    union sigval value;
    int code, sender, queued_value;

    memset(&mask, 0, sizeof mask);
    if (sigemptyset(&mask) != 0 || sigaddset(&mask, SIGUSR1) != 0 ||
        sigprocmask(SIG_BLOCK, &mask, NULL) != 0)
        return 40;
    value.sival_int = 0x1234;
    memset(&info, 0, sizeof info);
    if (sigqueue(getpid(), SIGUSR1, value) != 0)
        return 41;
    if (sigwaitinfo(&mask, &info) != SIGUSR1)
        return 42;
    code = info.si_code;
    sender = info.si_pid;
    queued_value = info.si_value.sival_int;
    if (code != SI_QUEUE || sender != (int)getpid() || queued_value != 0x1234)
        return 43;
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0)
        return 44;
    return 0;
}

int main(void)
{
    if (set_operations_case() != 0)
        return 1;
    if (strcmp(strsignal(SIGUSR1), "User defined signal 1") != 0 ||
        strcmp(strsignal(0), "Unknown signal") != 0 ||
        strcmp(strsignal(64), "RT64") != 0)
        return 2;
    if (legacy_mask_case() != 0)
        return 3;
    if (sigpause_case() != 0)
        return 4;
    if (sigqueue_case() != 0)
        return 5;
    errno = EAGAIN;
    psignal(SIGUSR1, "notice");
    if (errno != EAGAIN)
        return 6;
    puts("m4 signal helpers ok");
    return 0;
}
