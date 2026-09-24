/* Owned static product filesystem, process, signal, time, and socket consumer.
 *
 * One ordinary C program composes the everyday Unix substrate that an
 * installed static application relies on: pathname and descriptor lifecycle,
 * metadata, directories and working-directory state; child exit, signal,
 * stop/continue, process-group, session, resource-limit, and exec-inheritance
 * behavior; signal information, masks, queuing, handler flags, alternate
 * stacks, and synchronous waits; clocks, sleeps, POSIX and interval timers,
 * and POSIX-TZ calendar conversion; and Unix-domain descriptor passing,
 * credentials, and loopback datagrams.
 *
 * argv[1] names a private existing directory. The program writes one
 * transcript line per observation. Values that vary between runs (times,
 * identifiers, descriptor numbers, ports) are reduced to deterministic facts,
 * so the same source must produce identical bytes for pinned musl and both
 * owned static link modes. It removes everything it creates below argv[1].
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "owned static system composition requires native Linux/x86-64 LP64"
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void emit(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void emit(const char *format, ...)
{
    char line[512];
    va_list arguments;
    int length;

    va_start(arguments, format);
    length = vsnprintf(line, sizeof line, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof line)
        _exit(90);
    for (size_t written = 0; written < (size_t)length;) {
        ssize_t count = write(1, line + written, (size_t)length - written);
        if (count <= 0)
            _exit(91);
        written += (size_t)count;
    }
}

static const char *error_name(int value)
{
    switch (value) {
    case 0: return "0";
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case ESRCH: return "ESRCH";
    case EINTR: return "EINTR";
    case EBADF: return "EBADF";
    case ECHILD: return "ECHILD";
    case EAGAIN: return "EAGAIN";
    case EACCES: return "EACCES";
    case EEXIST: return "EEXIST";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case EINVAL: return "EINVAL";
    case EMFILE: return "EMFILE";
    case ENOTEMPTY: return "ENOTEMPTY";
    case ENOSYS: return "ENOSYS";
    default: return "other";
    }
}

/* Reduce a conventional -1/errno result to "ok" or the errno spelling. */
static const char *outcome(long result)
{
    return result >= 0 ? "ok" : error_name(errno);
}

static void path_join(char *buffer, size_t capacity, const char *directory, const char *name)
{
    int length = snprintf(buffer, capacity, "%s/%s", directory, name);

    if (length < 0 || (size_t)length >= capacity)
        _exit(92);
}

static int timespec_equal(struct timespec value, time_t seconds, long nanoseconds)
{
    return value.tv_sec == seconds && value.tv_nsec == nanoseconds;
}

static long long elapsed_nanoseconds(struct timespec start, struct timespec end)
{
    return (long long)(end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
}

/* Every observation below is computed into a named local in program order
 * before it is emitted: C leaves the evaluation order of function arguments
 * unspecified, and these operations have ordered side effects. */
static void filesystem(const char *base)
{
    char directory[PATH_MAX], file[PATH_MAX], hard[PATH_MAX], renamed[PATH_MAX];
    char symbolic[PATH_MAX], nested[PATH_MAX], working[PATH_MAX], resolved[PATH_MAX];
    char expected[PATH_MAX], text[64], partial[64];
    struct stat status, other;
    const struct timespec stamps[2] = { { 1, 2 }, { 3, 4 } };
    const struct timespec touch[2] = { { 0, UTIME_OMIT }, { 5, 6 } };
    const char *first, *second, *third, *fourth, *fifth;
    int descriptor, directory_descriptor, home, flag, other_flag;
    long long size;
    ssize_t count, other_count, eof;

    path_join(directory, sizeof directory, base, "tree");
    path_join(file, sizeof file, directory, "f");
    path_join(hard, sizeof hard, directory, "g");
    path_join(renamed, sizeof renamed, directory, "h");
    path_join(symbolic, sizeof symbolic, directory, "s");
    path_join(nested, sizeof nested, file, "child");
    umask(022);

    first = outcome(mkdir(directory, 0755));
    second = outcome(mkdir(directory, 0755));
    emit("fs mkdir=%s again=%s\n", first, second);

    descriptor = open(file, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0666);
    first = outcome(descriptor);
    flag = (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0;
    second = outcome(open(file, O_CREAT | O_EXCL | O_WRONLY, 0666));
    emit("fs create=%s cloexec=%d exclusive=%s\n", first, flag, second);
    count = write(descriptor, "hello world", 11);
    other_count = pwrite(descriptor, "WORLD", 5, 6);
    size = (long long)lseek(descriptor, 0, SEEK_END);
    emit("fs write=%zd pwrite=%zd end=%lld\n", count, other_count, size);
    if (fstat(descriptor, &status) != 0)
        _exit(93);
    emit("fs fstat size=%lld mode=%o regular=%d links=%lu\n", (long long)status.st_size,
        (unsigned)(status.st_mode & 07777), S_ISREG(status.st_mode), (unsigned long)status.st_nlink);
    first = outcome(ftruncate(descriptor, 5));
    size = fstat(descriptor, &status) == 0 ? (long long)status.st_size : -1;
    second = outcome(close(descriptor));
    emit("fs ftruncate=%s size=%lld close=%s\n", first, size, second);

    descriptor = open(file, O_RDONLY | O_CLOEXEC);
    memset(text, 0, sizeof text);
    memset(partial, 0, sizeof partial);
    count = read(descriptor, text, sizeof text - 1);
    other_count = pread(descriptor, partial, 3, 1);
    eof = read(descriptor, expected, sizeof expected);
    first = outcome(close(descriptor));
    emit("fs read=%zd text=%s pread=%zd ptext=%s eof=%zd close=%s\n", count, text, other_count,
        partial, eof, first);

    first = outcome(link(file, hard));
    unsigned long links = stat(file, &status) == 0 ? (unsigned long)status.st_nlink : 0;
    second = outcome(symlink("f", symbolic));
    memset(text, 0, sizeof text);
    count = readlink(symbolic, text, sizeof text - 1);
    flag = lstat(symbolic, &status) == 0 && S_ISLNK(status.st_mode);
    other_flag = stat(symbolic, &status) == 0 && stat(file, &other) == 0 &&
        status.st_ino == other.st_ino && status.st_dev == other.st_dev;
    emit("fs link=%s links=%lu symlink=%s readlink=%zd target=%s lstat-link=%d same-inode=%d\n",
        first, links, second, count, text, flag, other_flag);
    first = outcome(rename(hard, renamed));
    second = outcome(access(renamed, R_OK));
    third = outcome(access(hard, F_OK));
    emit("fs rename=%s access=%s old=%s\n", first, second, third);

    directory_descriptor = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    first = outcome(directory_descriptor);
    second = outcome(faccessat(directory_descriptor, "h", W_OK, 0));
    flag = fstatat(directory_descriptor, "s", &status, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(status.st_mode);
    emit("fs dirfd=%s faccessat=%s fstatat-link=%d\n", first, second, flag);
    first = outcome(chmod(file, 0600));
    unsigned first_mode = stat(file, &status) == 0 ? (unsigned)(status.st_mode & 07777) : 0;
    second = outcome(fchmodat(directory_descriptor, "f", 0640, 0));
    unsigned second_mode = stat(file, &status) == 0 ? (unsigned)(status.st_mode & 07777) : 0;
    emit("fs chmod=%s mode=%o fchmodat=%s mode=%o\n", first, first_mode, second, second_mode);
    first = outcome(utimensat(AT_FDCWD, file, stamps, 0));
    flag = stat(file, &status) == 0 && timespec_equal(status.st_atim, 1, 2) &&
        timespec_equal(status.st_mtim, 3, 4);
    descriptor = open(file, O_WRONLY | O_CLOEXEC);
    second = outcome(futimens(descriptor, touch));
    other_flag = fstat(descriptor, &status) == 0 && timespec_equal(status.st_atim, 1, 2) &&
        timespec_equal(status.st_mtim, 5, 6);
    third = outcome(close(descriptor));
    emit("fs utimensat=%s stamps=%d futimens=%s omit=%d close=%s\n", first, flag, second, other_flag, third);

    first = outcome(truncate(file, 10));
    descriptor = open(file, O_RDONLY | O_CLOEXEC);
    memset(text, 0x7f, sizeof text);
    count = read(descriptor, text, sizeof text);
    flag = count == 10 && memcmp(text, "hello\0\0\0\0\0", 10) == 0;
    second = outcome(close(descriptor));
    emit("fs truncate=%s read=%zd zero-fill=%d close=%s\n", first, count, flag, second);
    descriptor = openat(directory_descriptor, "x", O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    first = outcome(descriptor);
    second = outcome(close(descriptor));
    third = outcome(unlinkat(directory_descriptor, "x", 0));
    fourth = outcome(unlinkat(directory_descriptor, "x", 0));
    fifth = outcome(mkdirat(directory_descriptor, "sub", 0700));
    emit("fs openat=%s close=%s unlinkat=%s again=%s mkdirat=%s rmdirat=%s\n", first, second, third,
        fourth, fifth, outcome(unlinkat(directory_descriptor, "sub", AT_REMOVEDIR)));
    first = outcome(rmdir(directory));
    second = outcome(open(nested, O_RDONLY));
    third = outcome(open(directory, O_WRONLY));
    fourth = outcome(close(-1));
    emit("fs errors nonempty=%s notdir=%s isdir=%s badf=%s\n", first, second, third, fourth);

    DIR *stream = opendir(directory);
    char names[8][8];
    size_t entries = 0, listed = 0, again = 0;
    struct dirent *entry;

    while (stream != NULL && (entry = readdir(stream)) != NULL) {
        ++entries;
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 && listed < 8)
            snprintf(names[listed++], sizeof names[0], "%s", entry->d_name);
    }
    for (size_t left = 0; left < listed; ++left) {
        for (size_t right = left + 1; right < listed; ++right) {
            if (strcmp(names[left], names[right]) > 0) {
                char swap[8];

                memcpy(swap, names[left], sizeof swap);
                memcpy(names[left], names[right], sizeof swap);
                memcpy(names[right], swap, sizeof swap);
            }
        }
    }
    if (stream != NULL) {
        rewinddir(stream);
        while (readdir(stream) != NULL)
            ++again;
    }
    flag = stream != NULL && dirfd(stream) >= 0;
    first = outcome(stream != NULL ? closedir(stream) : -1);
    emit("fs readdir entries=%zu names=", entries);
    for (size_t index = 0; index < listed; ++index)
        emit("%s%s", index ? "," : "", names[index]);
    emit(" rewind=%zu dirfd=%d close=%s\n", again, flag, first);

    home = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    first = outcome(chdir(directory));
    flag = getcwd(working, sizeof working) != NULL && strcmp(working, directory) == 0;
    other_flag = realpath("s", resolved) != NULL && strcmp(resolved, file) == 0;
    second = outcome(fchdir(home));
    int returned = getcwd(working, sizeof working) != NULL && realpath(".", expected) != NULL &&
        strcmp(working, expected) == 0 && strcmp(working, directory) != 0;
    close(home);
    emit("fs chdir=%s cwd=%d realpath=%d fchdir=%s returned=%d\n", first, flag, other_flag, second, returned);

    descriptor = open(file, O_RDONLY | O_CLOEXEC);
    flag = dup2(descriptor, 100) == 100 && (fcntl(100, F_GETFD) & FD_CLOEXEC) == 0;
    other_flag = dup3(descriptor, 101, O_CLOEXEC) == 101 && (fcntl(101, F_GETFD) & FD_CLOEXEC) != 0;
    int duplicated = fcntl(descriptor, F_DUPFD_CLOEXEC, 200);
    int duplicated_ok = duplicated >= 200 && (fcntl(duplicated, F_GETFD) & FD_CLOEXEC) != 0;
    first = outcome(dup3(descriptor, descriptor, 0));
    second = outcome(fcntl(descriptor, F_SETFL, O_NONBLOCK));
    int nonblocking = (fcntl(descriptor, F_GETFL) & O_NONBLOCK) != 0;
    third = outcome(close(100));
    fourth = outcome(close(100));
    emit("fs dup2=%d dup3=%d dupfd=%d dup3-same=%s setfl=%s nonblock=%d close=%s reclose=%s\n", flag,
        other_flag, duplicated_ok, first, second, nonblocking, third, fourth);
    close(101);
    close(duplicated);
    close(descriptor);
    close(directory_descriptor);

    flag = unlink(file) == 0 && unlink(renamed) == 0 && unlink(symbolic) == 0 && rmdir(directory) == 0;
    first = outcome(stat(directory, &status));
    emit("fs cleanup=%d gone=%s\n", flag, first);
}

static int wait_status(pid_t child, int options, int *status)
{
    pid_t result;

    do {
        result = waitpid(child, status, options);
    } while (result < 0 && errno == EINTR);
    return result == child;
}

static void process_exec_child(void)
{
    struct sigaction action;
    sigset_t mask;
    int result = 0;

    /* Caught dispositions reset to default across exec; ignored ones and the
     * blocked mask are inherited. */
    if (sigaction(SIGUSR1, NULL, &action) != 0 || action.sa_handler != SIG_DFL)
        result |= 1;
    if (sigaction(SIGUSR2, NULL, &action) != 0 || action.sa_handler != SIG_IGN)
        result |= 2;
    if (sigprocmask(SIG_BLOCK, NULL, &mask) != 0 || !sigismember(&mask, SIGHUP))
        result |= 4;
    if (getenv("CRABC_EXEC_CHILD") == NULL || strcmp(getenv("CRABC_EXEC_CHILD"), "1") != 0)
        result |= 8;
    _exit(40 + result);
}

static void exec_handler(int signal_number)
{
    (void)signal_number;
}

static void process(void)
{
    struct rlimit limit;
    struct rusage usage;
    struct tms times_buffer;
    int status = 0, exit_code, killed, stopped, continued, terminated, grouped, session, emfile;
    const char *first, *second, *third;
    pid_t child;

    emit("proc ids=%d\n", getpid() > 0 && getppid() > 0 && getpid() != getppid());

    child = fork();
    if (child == 0)
        _exit(42);
    exit_code = wait_status(child, 0, &status) && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    child = fork();
    if (child == 0) {
        for (;;)
            pause();
    }
    kill(child, SIGKILL);
    killed = wait_status(child, 0, &status) && WIFSIGNALED(status) ? WTERMSIG(status) : -1;
    child = fork();
    if (child == 0) {
        for (;;)
            pause();
    }
    kill(child, SIGSTOP);
    stopped = wait_status(child, WUNTRACED, &status) && WIFSTOPPED(status) ? WSTOPSIG(status) : -1;
    kill(child, SIGCONT);
    continued = wait_status(child, WCONTINUED, &status) && WIFCONTINUED(status);
    kill(child, SIGTERM);
    terminated = wait_status(child, 0, &status) && WIFSIGNALED(status) ? WTERMSIG(status) : -1;
    first = outcome(waitpid(-1, &status, WNOHANG));
    emit("proc exit=%d killed=%d stopped=%d continued=%d terminated=%d nochild=%s\n", exit_code, killed,
        stopped, continued, terminated, first);

    child = fork();
    if (child == 0)
        _exit(setpgid(0, 0) == 0 && getpgid(0) == getpid() && getpgrp() == getpid() ? 0 : 1);
    grouped = wait_status(child, 0, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    child = fork();
    if (child == 0)
        _exit(setsid() == getpid() && getsid(0) == getpid() ? 0 : 1);
    session = wait_status(child, 0, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    child = fork();
    if (child == 0) {
        struct rlimit lowered;
        int opened = 0;

        if (getrlimit(RLIMIT_NOFILE, &lowered) != 0)
            _exit(2);
        lowered.rlim_cur = 16;
        if (setrlimit(RLIMIT_NOFILE, &lowered) != 0)
            _exit(3);
        while (opened < 64 && open("/dev/null", O_RDONLY) >= 0)
            ++opened;
        _exit(errno == EMFILE && opened < 16 ? 0 : 4);
    }
    emfile = wait_status(child, 0, &status) && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    first = outcome(getrlimit(RLIMIT_NOFILE, &limit));
    emit("proc pgid=%d session=%d getrlimit=%s emfile=%d\n", grouped, session, first, emfile);

    child = fork();
    if (child == 0) {
        char *const child_argv[] = { "system-exec", "--exec-child", NULL };
        char *const child_envp[] = { "CRABC_EXEC_CHILD=1", NULL };
        sigset_t mask;

        signal(SIGUSR1, exec_handler);
        signal(SIGUSR2, SIG_IGN);
        sigemptyset(&mask);
        sigaddset(&mask, SIGHUP);
        sigprocmask(SIG_BLOCK, &mask, NULL);
        execve("/proc/self/exe", child_argv, child_envp);
        _exit(3);
    }
    exit_code = wait_status(child, 0, &status) && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    first = outcome(getrusage(RUSAGE_SELF, &usage));
    second = outcome(getrusage(RUSAGE_CHILDREN, &usage));
    third = times(&times_buffer) != (clock_t)-1 ? "ok" : error_name(errno);
    emit("proc exec=%d rusage=%s children=%s times=%s\n", exit_code, first, second, third);
}

static volatile sig_atomic_t deliveries;
static volatile sig_atomic_t last_code;
static volatile sig_atomic_t last_value;
static volatile sig_atomic_t last_sender_matches;
static volatile sig_atomic_t mask_has_self;
static volatile sig_atomic_t mask_has_extra;
static volatile sig_atomic_t on_alternate_stack;
static volatile sig_atomic_t queued_values[4];
static char *alternate_base;
static size_t alternate_size;

static void information_handler(int signal_number, siginfo_t *information, void *context)
{
    sigset_t current;
    stack_t stack;
    char local;

    (void)context;
    if (deliveries < 4)
        queued_values[deliveries] = information->si_value.sival_int;
    ++deliveries;
    last_code = information->si_code;
    last_value = information->si_value.sival_int;
    last_sender_matches = information->si_pid == getpid() && information->si_uid == getuid();
    sigprocmask(SIG_BLOCK, NULL, &current);
    mask_has_self = sigismember(&current, signal_number);
    mask_has_extra = sigismember(&current, SIGWINCH);
    on_alternate_stack = alternate_base != NULL && &local >= alternate_base &&
        &local < alternate_base + alternate_size &&
        sigaltstack(NULL, &stack) == 0 && (stack.ss_flags & SS_ONSTACK) != 0;
}

static void install(int signal_number, int flags)
{
    struct sigaction action;

    memset(&action, 0, sizeof action);
    action.sa_sigaction = information_handler;
    action.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGWINCH);
    if (sigaction(signal_number, &action, NULL) != 0)
        _exit(94);
}

static const char *code_name(int code)
{
    switch (code) {
    case SI_USER: return "SI_USER";
    case SI_QUEUE: return "SI_QUEUE";
    case SI_TIMER: return "SI_TIMER";
    case SI_TKILL: return "SI_TKILL";
    default: return "other";
    }
}

static void block(int how, int signal_number)
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, signal_number);
    if (sigprocmask(how, &set, NULL) != 0)
        _exit(95);
}

static void signals(void)
{
    struct sigaction query;
    union sigval value;
    sigset_t pending, set;
    siginfo_t information;
    struct timespec zero = { 0, 0 }, second_timeout = { 1, 0 };
    stack_t stack;
    const char *first, *second, *third, *fourth;
    int flag, count, waited;

    emit("sig range rtmin=%d rtmax=%d\n", SIGRTMIN, SIGRTMAX);
    install(SIGUSR1, 0);
    deliveries = 0;
    first = outcome(raise(SIGUSR1));
    emit("sig raise=%s count=%d code=%s self-masked=%d extra-masked=%d\n", first, deliveries,
        code_name(last_code), mask_has_self, mask_has_extra);
    deliveries = 0;
    first = outcome(kill(getpid(), SIGUSR1));
    emit("sig kill=%s count=%d code=%s sender=%d\n", first, deliveries, code_name(last_code),
        last_sender_matches);

    install(SIGRTMIN + 1, 0);
    deliveries = 0;
    value.sival_int = 77;
    first = outcome(sigqueue(getpid(), SIGRTMIN + 1, value));
    emit("sig sigqueue=%s count=%d code=%s value=%d sender=%d\n", first, deliveries,
        code_name(last_code), last_value, last_sender_matches);

    install(SIGUSR2, 0);
    block(SIG_BLOCK, SIGUSR2);
    deliveries = 0;
    raise(SIGUSR2);
    raise(SIGUSR2);
    sigpending(&pending);
    flag = sigismember(&pending, SIGUSR2);
    count = deliveries;
    block(SIG_UNBLOCK, SIGUSR2);
    emit("sig blocked pending=%d count=%d coalesced=%d\n", flag, count, deliveries);

    install(SIGRTMIN + 2, 0);
    block(SIG_BLOCK, SIGRTMIN + 2);
    deliveries = 0;
    for (int index = 1; index <= 3; ++index) {
        value.sival_int = index;
        sigqueue(getpid(), SIGRTMIN + 2, value);
    }
    block(SIG_UNBLOCK, SIGRTMIN + 2);
    emit("sig realtime queued=%d order=%d%d%d\n", deliveries, queued_values[0], queued_values[1],
        queued_values[2]);

    install(SIGUSR1, SA_NODEFER);
    deliveries = 0;
    raise(SIGUSR1);
    count = deliveries;
    flag = mask_has_self;
    install(SIGUSR1, SA_RESETHAND);
    raise(SIGUSR1);
    int reset = sigaction(SIGUSR1, NULL, &query) == 0 && query.sa_handler == SIG_DFL;
    emit("sig nodefer count=%d self-masked=%d resethand=%d\n", count, flag, reset);

    alternate_size = 4 * SIGSTKSZ;
    alternate_base = malloc(alternate_size);
    stack.ss_sp = alternate_base;
    stack.ss_size = alternate_size;
    stack.ss_flags = 0;
    first = outcome(sigaltstack(&stack, NULL));
    install(SIGUSR1, SA_ONSTACK);
    on_alternate_stack = 0;
    raise(SIGUSR1);
    flag = on_alternate_stack;
    stack.ss_flags = SS_DISABLE;
    second = outcome(sigaltstack(&stack, NULL));
    emit("sig sigaltstack=%s onstack=%d disable=%s\n", first, flag, second);
    free(alternate_base);
    alternate_base = NULL;

    install(SIGUSR1, 0);
    block(SIG_BLOCK, SIGUSR1);
    deliveries = 0;
    raise(SIGUSR1);
    sigemptyset(&set);
    first = outcome(sigsuspend(&set));
    count = deliveries;
    block(SIG_UNBLOCK, SIGUSR1);
    block(SIG_BLOCK, SIGUSR2);
    raise(SIGUSR2);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    memset(&information, 0, sizeof information);
    waited = sigtimedwait(&set, &information, &second_timeout);
    second = code_name(information.si_code);
    third = outcome(sigtimedwait(&set, &information, &zero));
    block(SIG_UNBLOCK, SIGUSR2);
    emit("sig sigsuspend=%s count=%d sigtimedwait=%d code=%s empty=%s\n", first, count,
        waited == SIGUSR2, second, third);

    signal(SIGUSR2, SIG_IGN);
    raise(SIGUSR2);
    sigpending(&pending);
    flag = sigismember(&pending, SIGUSR2);
    first = outcome(sigprocmask(12345, &set, NULL));
    second = outcome(sigaction(SIGKILL, &query, NULL));
    third = outcome(kill(INT_MAX, 0));
    fourth = outcome(kill(getpid(), 0));
    emit("sig ignored pending=%d badhow=%s sigkill=%s esrch=%s probe=%s\n", flag, first, second, third,
        fourth);
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
    signal(SIGRTMIN + 1, SIG_DFL);
    signal(SIGRTMIN + 2, SIG_DFL);
}

static void clocks(void)
{
    static const struct {
        clockid_t clock;
        const char *name;
    } selected[] = {
        { CLOCK_REALTIME, "realtime" }, { CLOCK_MONOTONIC, "monotonic" },
        { CLOCK_PROCESS_CPUTIME_ID, "process" }, { CLOCK_THREAD_CPUTIME_ID, "thread" },
        { CLOCK_MONOTONIC_RAW, "raw" }, { CLOCK_REALTIME_COARSE, "realtime-coarse" },
        { CLOCK_MONOTONIC_COARSE, "monotonic-coarse" }, { CLOCK_BOOTTIME, "boottime" },
    };
    struct timespec now, before, after, resolution;
    struct timeval wall;
    const char *first, *second, *third;
    int flag, other_flag, monotonic = 1;

    for (size_t index = 0; index < sizeof selected / sizeof selected[0]; ++index) {
        first = outcome(clock_gettime(selected[index].clock, &now));
        emit("time clock %s=%s normalized=%d\n", selected[index].name, first,
            now.tv_nsec >= 0 && now.tv_nsec < 1000000000L);
    }
    first = outcome(clock_getres(CLOCK_MONOTONIC, &resolution));
    flag = resolution.tv_sec == 0 && resolution.tv_nsec > 0;
    second = outcome(clock_gettime((clockid_t)0x7fff, &now));
    clock_gettime(CLOCK_MONOTONIC, &before);
    for (int index = 0; index < 1000; ++index) {
        clock_gettime(CLOCK_MONOTONIC, &after);
        monotonic &= elapsed_nanoseconds(before, after) >= 0;
        before = after;
    }
    clock_gettime(CLOCK_REALTIME, &now);
    time_t seconds = time(NULL);
    /* Allow a descheduled contended host several seconds between reads;
     * only ordering and unit normalization are asserted. */
    int wall_ok = gettimeofday(&wall, NULL) == 0 && wall.tv_usec >= 0 && wall.tv_usec < 1000000 &&
        wall.tv_sec - now.tv_sec >= 0 && wall.tv_sec - now.tv_sec <= 5;
    emit("time getres=%s positive=%d invalid=%s monotonic=%d time=%d gettimeofday=%d\n", first, flag,
        second, monotonic, seconds - now.tv_sec >= 0 && seconds - now.tv_sec <= 5, wall_ok);

    struct timespec request = { 0, 20 * 1000 * 1000 }, invalid = { 0, 1000000000L }, deadline;
    clock_gettime(CLOCK_MONOTONIC, &before);
    first = outcome(nanosleep(&request, NULL));
    clock_gettime(CLOCK_MONOTONIC, &after);
    flag = elapsed_nanoseconds(before, after) >= request.tv_nsec;
    second = outcome(nanosleep(&invalid, NULL));
    clock_gettime(CLOCK_MONOTONIC, &before);
    deadline = before;
    deadline.tv_nsec += 10 * 1000 * 1000;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_nsec -= 1000000000L;
        ++deadline.tv_sec;
    }
    int absolute = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    clock_gettime(CLOCK_MONOTONIC, &after);
    other_flag = elapsed_nanoseconds(deadline, after) >= 0;
    errno = EDOM;
    third = error_name(clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, &request, NULL));
    int errno_unchanged = errno == EDOM;
    emit("time nanosleep=%s elapsed=%d invalid=%s absolute=%d reached=%d thread-clock=%s errno=%s\n",
        first, flag, second, absolute, other_flag, third, errno_unchanged ? "unchanged" : "changed");

    int signal_number = SIGRTMIN + 3;
    struct sigevent event;
    struct itimerspec schedule = { { 0, 0 }, { 0, 10 * 1000 * 1000 } }, remaining;
    siginfo_t information;
    sigset_t set;
    timer_t timer;

    sigemptyset(&set);
    sigaddset(&set, signal_number);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigdelset(&set, SIGALRM);
    memset(&event, 0, sizeof event);
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = signal_number;
    event.sigev_value.sival_int = 99;
    memset(&information, 0, sizeof information);
    first = outcome(timer_create(CLOCK_MONOTONIC, &event, &timer));
    second = outcome(timer_settime(timer, 0, &schedule, NULL));
    flag = sigwaitinfo(&set, &information) == signal_number;
    other_flag = timer_gettime(timer, &remaining) == 0 && remaining.it_value.tv_sec == 0 &&
        remaining.it_value.tv_nsec == 0;
    int overrun = timer_getoverrun(timer);
    third = outcome(timer_delete(timer));
    emit("time timer_create=%s settime=%s wait=%d code=%s value=%d gettime=%d overrun=%d delete=%s\n",
        first, second, flag, code_name(information.si_code), information.si_value.sival_int, other_flag,
        overrun, third);

    struct itimerval interval = { { 0, 0 }, { 0, 10000 } }, current;
    int received = 0;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    first = outcome(setitimer(ITIMER_REAL, &interval, NULL));
    flag = sigwait(&set, &received) == 0 && received == SIGALRM;
    other_flag = getitimer(ITIMER_REAL, &current) == 0 && current.it_value.tv_sec == 0 &&
        current.it_value.tv_usec == 0;
    unsigned previous_alarm = alarm(0);
    emit("time setitimer=%s sigwait=%d getitimer=%d alarm=%u\n", first, flag, other_flag, previous_alarm);
    sigaddset(&set, signal_number);
    sigprocmask(SIG_UNBLOCK, &set, NULL);

    struct timespec cpu;
    do {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
    } while (cpu.tv_sec == 0 && cpu.tv_nsec < 1000000L);
    emit("time cpu-advanced=1\n");
}

static void calendar(void)
{
    static const time_t moments[] = { 1720000000, 1700000000 };
    struct tm broken, round;
    char text[128];
    time_t moment = 0;

    gmtime_r(&moment, &broken);
    strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%S %a yday=%j", &broken);
    emit("cal epoch=%s\n", text);
    memset(&broken, 0, sizeof broken);
    broken.tm_year = 100;
    broken.tm_mon = 1;
    broken.tm_mday = 29;
    broken.tm_hour = 12;
    broken.tm_min = 34;
    broken.tm_sec = 56;
    moment = timegm(&broken);
    gmtime_r(&moment, &round);
    emit("cal timegm=%lld wday=%d roundtrip=%d\n", (long long)moment, broken.tm_wday,
        round.tm_year == 100 && round.tm_mon == 1 && round.tm_mday == 29 && round.tm_sec == 56);

    setenv("TZ", "EST5EDT,M3.2.0,M11.1.0", 1);
    tzset();
    for (size_t index = 0; index < sizeof moments / sizeof moments[0]; ++index) {
        moment = moments[index];
        localtime_r(&moment, &broken);
        strftime(text, sizeof text, "%Y-%m-%d %H:%M:%S %Z %z", &broken);
        int dst = broken.tm_isdst;
        long offset = broken.tm_gmtoff;
        broken.tm_isdst = -1;
        int round_trip = mktime(&broken) == moment;
        emit("cal local=%s dst=%d gmtoff=%ld mktime=%d\n", text, dst, offset, round_trip);
    }
    emit("cal tzname=%s,%s\n", tzname[0], tzname[1]);
    unsetenv("TZ");
    tzset();
}

static void sockets(const char *base)
{
    int datagram[2], stream_pair[2], transfer[2];
    char byte = 'x', received_byte = 0, buffer[32];
    union {
        struct cmsghdr header;
        char space[CMSG_SPACE(sizeof(int))];
    } control;
    struct iovec vector = { &byte, 1 };
    struct msghdr message;
    struct cmsghdr *header;
    struct ucred credentials;
    socklen_t length;
    const char *first, *second, *third, *fourth;
    int flag, type = 0, received = -1;
    ssize_t sent, got, passed;

    first = outcome(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, datagram));
    length = sizeof type;
    flag = getsockopt(datagram[0], SOL_SOCKET, SO_TYPE, &type, &length) == 0 && type == SOCK_DGRAM;
    second = outcome(pipe2(transfer, O_CLOEXEC));
    memset(&message, 0, sizeof message);
    memset(&control, 0, sizeof control);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.space;
    message.msg_controllen = sizeof control.space;
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &transfer[0], sizeof(int));
    sent = sendmsg(datagram[0], &message, 0);
    vector.iov_base = &received_byte;
    memset(&control, 0, sizeof control);
    message.msg_controllen = sizeof control.space;
    got = recvmsg(datagram[1], &message, MSG_CMSG_CLOEXEC);
    header = CMSG_FIRSTHDR(&message);
    if (header != NULL && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS)
        memcpy(&received, CMSG_DATA(header), sizeof(int));
    int rights = received >= 0 && received != transfer[0] && (fcntl(received, F_GETFD) & FD_CLOEXEC) != 0;
    write(transfer[1], "via", 3);
    memset(buffer, 0, sizeof buffer);
    passed = read(received, buffer, sizeof buffer - 1);
    emit("sock socketpair=%s type=%d pipe=%s sendmsg=%zd recvmsg=%zd byte=%c rights=%d passed=%zd text=%s\n",
        first, flag, second, sent, got, received_byte, rights, passed, buffer);
    close(received);
    close(transfer[0]);
    close(transfer[1]);
    close(datagram[0]);
    close(datagram[1]);

    first = outcome(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, stream_pair));
    length = sizeof credentials;
    flag = getsockopt(stream_pair[0], SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0 &&
        credentials.pid == getpid() && credentials.uid == getuid() && credentials.gid == getgid();
    second = outcome(shutdown(stream_pair[0], SHUT_WR));
    got = read(stream_pair[1], buffer, sizeof buffer);
    emit("sock stream=%s peercred=%d shutdown=%s eof=%zd\n", first, flag, second, got);
    close(stream_pair[0]);
    close(stream_pair[1]);

    struct sockaddr_un address, peer;
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int home = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    /* sun_path holds at most 108 bytes; bind a relative name from inside the
     * private directory so the caller's path length cannot matter. */
    if (home < 0 || chdir(base) != 0)
        _exit(96);
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, "socket", sizeof "socket");
    first = outcome(bind(listener, (struct sockaddr *)&address, sizeof address));
    second = outcome(listen(listener, 1));
    third = outcome(connect(client, (struct sockaddr *)&address, sizeof address));
    int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    fourth = outcome(accepted);
    flag = (fcntl(accepted, F_GETFD) & FD_CLOEXEC) != 0;
    sent = send(client, "unix", 4, 0);
    memset(buffer, 0, sizeof buffer);
    got = recv(accepted, buffer, sizeof buffer - 1, 0);
    length = sizeof peer;
    int peer_ok = getpeername(client, (struct sockaddr *)&peer, &length) == 0 &&
        strcmp(peer.sun_path, address.sun_path) == 0;
    close(accepted);
    close(client);
    close(listener);
    const char *removed = outcome(unlink(address.sun_path));
    if (fchdir(home) != 0)
        _exit(97);
    close(home);
    emit("sock bind=%s listen=%s connect=%s accept4=%s cloexec=%d send=%zd recv=%zd text=%s peer=%d unlink=%s\n",
        first, second, third, fourth, flag, sent, got, buffer, peer_ok, removed);

    struct sockaddr_in receiver, sender, source;
    int inbound = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int outbound = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    memset(&receiver, 0, sizeof receiver);
    receiver.sin_family = AF_INET;
    receiver.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    first = outcome(bind(inbound, (struct sockaddr *)&receiver, sizeof receiver));
    length = sizeof receiver;
    flag = getsockname(inbound, (struct sockaddr *)&receiver, &length) == 0 && receiver.sin_port != 0;
    memset(&sender, 0, sizeof sender);
    sender.sin_family = AF_INET;
    sender.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(outbound, (struct sockaddr *)&sender, sizeof sender);
    length = sizeof sender;
    getsockname(outbound, (struct sockaddr *)&sender, &length);
    sent = sendto(outbound, "udp", 3, 0, (struct sockaddr *)&receiver, sizeof receiver);
    memset(buffer, 0, sizeof buffer);
    length = sizeof source;
    got = recvfrom(inbound, buffer, sizeof buffer - 1, 0, (struct sockaddr *)&source, &length);
    int source_ok = length == sizeof source && source.sin_port == sender.sin_port &&
        source.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    close(inbound);
    close(outbound);
    emit("sock udp bind=%s name=%d sendto=%zd recvfrom=%zd text=%s source=%d\n", first, flag, sent, got,
        buffer, source_ok);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--exec-child") == 0)
        process_exec_child();
    if (argc != 2)
        return 120;
    filesystem(argv[1]);
    process();
    signals();
    clocks();
    calendar();
    sockets(argv[1]);
    emit("owned-static-system-ok\n");
    return 0;
}
