/* Static crabc-libc x86-64 selected header/layout baseline fixture.
 *
 * This is one deliberately narrow composition artifact: the same C body and
 * freestanding C++17 companion first run with pinned musl 1.2.6 and then in a
 * dependency-free static candidate linked only through the already selected
 * crabc archive.  It joins existing header/layout gates to existing archive
 * leaves; it adds no C export, header, or runtime capability.  In particular,
 * it is not installed-header closure, a general C ABI, libc.so, CRT, loader,
 * sysroot, pthread lifecycle, or public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CRABC_TYPE_IS(expression, type) \
    __builtin_types_compatible_p(__typeof__(expression), type)

enum {
    CRABC_PAGE_SIZE = 4096,
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
    "x86 stat layout");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8 &&
    __builtin_offsetof(struct timespec, tv_sec) == 0 &&
    __builtin_offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec layout");
_Static_assert(sizeof(struct pollfd) == 8 && _Alignof(struct pollfd) == 4 &&
    __builtin_offsetof(struct pollfd, fd) == 0 &&
    __builtin_offsetof(struct pollfd, events) == 4 &&
    __builtin_offsetof(struct pollfd, revents) == 6,
    "x86 pollfd layout");
_Static_assert(FD_SETSIZE == 1024 && sizeof(fd_set) == 128 &&
    _Alignof(fd_set) == 8 && sizeof(struct timeval) == 16,
    "x86 select records");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 signal mask layout");
_Static_assert(sizeof(struct rlimit) == 16 && _Alignof(struct rlimit) == 8 &&
    __builtin_offsetof(struct rlimit, rlim_cur) == 0 &&
    __builtin_offsetof(struct rlimit, rlim_max) == 8,
    "x86 resource-limit layout");
_Static_assert(sizeof(struct sockaddr) == 16 && _Alignof(struct sockaddr) == 2 &&
    sizeof(struct sockaddr_in) == 16 && _Alignof(struct sockaddr_in) == 4 &&
    sizeof(struct sockaddr_storage) == 128 &&
    _Alignof(struct sockaddr_storage) == 8,
    "x86 socket layouts");
_Static_assert(sizeof(struct utsname) == 390 && _Alignof(struct utsname) == 1 &&
    sizeof(struct sysinfo) == 368 && _Alignof(struct sysinfo) == 8,
    "x86 system-observation layouts");
_Static_assert(NCCS == 32 && sizeof(struct termios) == 60 &&
    _Alignof(struct termios) == 4 &&
    __builtin_offsetof(struct termios, c_cc) == 17,
    "x86 termios layout");
_Static_assert(O_CLOEXEC == 02000000 && F_GETFD == 1 && POLLIN == 0x0001 &&
    CLOCK_MONOTONIC == 1 && RLIMIT_NOFILE == 7 && AF_UNIX == 1 &&
    SOCK_STREAM == 1 && PROT_READ == 1 && PROT_WRITE == 2 &&
    MAP_PRIVATE == 2 && MAP_ANONYMOUS == 0x20,
    "selected x86 header constants");
/* Pinned musl marks __errno_location itself const while the staged project
 * declaration intentionally remains an ordinary callable accessor.  Exercise
 * the selected C symbol below, but do not turn this aggregate into an
 * attribute-parity claim or edit the installed header. */
_Static_assert(CRABC_TYPE_IS(&fstat, int (*)(int, struct stat *)),
    "fstat declaration");
_Static_assert(CRABC_TYPE_IS(&clock_gettime,
    int (*)(clockid_t, struct timespec *)), "clock_gettime declaration");
_Static_assert(CRABC_TYPE_IS(&mmap,
    void *(*)(void *, size_t, int, int, int, off_t)), "mmap declaration");
_Static_assert(CRABC_TYPE_IS(&munmap, int (*)(void *, size_t)),
    "munmap declaration");
_Static_assert(CRABC_TYPE_IS(&mprotect, int (*)(void *, size_t, int)),
    "mprotect declaration");
_Static_assert(CRABC_TYPE_IS(&madvise, int (*)(void *, size_t, int)),
    "madvise declaration");
_Static_assert(CRABC_TYPE_IS(&posix_madvise, int (*)(void *, size_t, int)),
    "posix_madvise declaration");
_Static_assert(CRABC_TYPE_IS(&mincore, int (*)(void *, size_t, unsigned char *)),
    "mincore declaration");
_Static_assert(CRABC_TYPE_IS(&getrlimit, int (*)(int, struct rlimit *)),
    "getrlimit declaration");
_Static_assert(CRABC_TYPE_IS(&poll, int (*)(struct pollfd *, nfds_t, int)),
    "poll declaration");
_Static_assert(CRABC_TYPE_IS(&select,
    int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *)),
    "select declaration");
_Static_assert(CRABC_TYPE_IS(&socketpair, int (*)(int, int, int, int *)),
    "socketpair declaration");
_Static_assert(CRABC_TYPE_IS(&close, int (*)(int)), "close declaration");
_Static_assert(CRABC_TYPE_IS(&sigemptyset, int (*)(sigset_t *)),
    "sigemptyset declaration");
_Static_assert(CRABC_TYPE_IS(&cfmakeraw, void (*)(struct termios *)),
    "cfmakeraw declaration");
_Static_assert(CRABC_TYPE_IS(&uname, int (*)(struct utsname *)),
    "uname declaration");
_Static_assert(CRABC_TYPE_IS(&sysinfo, int (*)(struct sysinfo *)),
    "sysinfo declaration");
_Static_assert(CRABC_TYPE_IS(&getpagesize, int (*)(void)),
    "getpagesize declaration");

/* The C++17 companion is separately compiled and linked with the C fixture.
 * C therefore observes its unmangled entry exactly as an ordinary C ABI
 * symbol; it is not a C++ runtime/constructor admission. */
int crabc_x86_64_header_layouts_baseline_cxx_probe(void);

static int check_observation_records(void)
{
    struct timespec clock_value;
    struct rlimit limit;
    struct utsname name;
    struct sysinfo info;
    const int stale_errno = ERANGE;

    errno = stale_errno;
    if (getpagesize() != CRABC_PAGE_SIZE || errno != stale_errno)
        return 1;
    if (clock_gettime(CLOCK_MONOTONIC, &clock_value) != 0 ||
        clock_value.tv_nsec < 0 || clock_value.tv_nsec >= 1000000000L ||
        errno != stale_errno)
        return 2;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 ||
        limit.rlim_cur > limit.rlim_max || errno != stale_errno)
        return 3;
    if (uname(&name) != 0 || name.sysname[0] != 'L' ||
        name.sysname[1] != 'i' || name.sysname[2] != 'n' ||
        name.sysname[3] != 'u' || name.sysname[4] != 'x' ||
        name.sysname[5] != '\0' || errno != stale_errno)
        return 4;
    if (sysinfo(&info) != 0 || info.procs == 0 || info.mem_unit == 0 ||
        errno != stale_errno)
        return 5;
    return 0;
}

static int check_mapping_records(void)
{
    volatile unsigned char *bytes;
    unsigned char residency = 0;
    void *mapping;

    mapping = mmap(0, CRABC_PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 1;
    bytes = mapping;
    bytes[0] = 0x5a;
    if (mprotect(mapping, CRABC_PAGE_SIZE, PROT_READ) != 0 ||
        mprotect(mapping, CRABC_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0 ||
        madvise(mapping, CRABC_PAGE_SIZE, MADV_NORMAL) != 0 ||
        posix_madvise(mapping, CRABC_PAGE_SIZE, POSIX_MADV_NORMAL) != 0 ||
        mincore(mapping, CRABC_PAGE_SIZE, &residency) != 0 ||
        (residency & 1) == 0 || munmap(mapping, CRABC_PAGE_SIZE) != 0)
        return 2;
    return 0;
}

static int check_descriptor_records(void)
{
    struct stat status;
    struct pollfd descriptor;
    struct timeval timeout = { 0, 0 };
    fd_set readable;
    int pair[2] = { -1, -1 };
    int result = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        return 1;
    if (fstat(pair[0], &status) != 0 || !S_ISSOCK(status.st_mode)) {
        result = 2;
        goto finish;
    }
    descriptor.fd = pair[0];
    descriptor.events = POLLIN;
    descriptor.revents = (short)0x7fff;
    if (poll(&descriptor, 1, 0) != 0 || descriptor.revents != 0) {
        result = 3;
        goto finish;
    }
    FD_ZERO(&readable);
    FD_SET(pair[0], &readable);
    if (select(pair[0] + 1, &readable, 0, 0, &timeout) != 0 ||
        FD_ISSET(pair[0], &readable)) {
        result = 4;
        goto finish;
    }

finish:
    if (pair[1] >= 0 && close(pair[1]) != 0 && result == 0)
        result = 5;
    if (pair[0] >= 0 && close(pair[0]) != 0 && result == 0)
        result = 6;
    return result;
}

static int check_signal_and_termios_records(void)
{
    sigset_t empty;
    struct termios terminal;
    unsigned long *words = (unsigned long *)&empty;
    unsigned long index;

    for (index = 0; index < sizeof(empty) / sizeof(*words); ++index)
        words[index] = ~0UL;
    if (sigemptyset(&empty) != 0 || words[0] != 0)
        return 1;
    /* Musl and the selected archive clear Linux's one 64-bit signal word;
     * the public sigset_t tail remains caller-resident. */
    for (index = 1; index < sizeof(empty) / sizeof(*words); ++index)
        if (words[index] != ~0UL)
            return 2;

    terminal.c_iflag = IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR |
        ICRNL | IXON;
    terminal.c_oflag = OPOST;
    terminal.c_cflag = CS7 | PARENB;
    terminal.c_lflag = ECHO | ECHONL | ICANON | ISIG | IEXTEN;
    terminal.c_cc[VMIN] = 0;
    terminal.c_cc[VTIME] = 9;
    cfmakeraw(&terminal);
    if (terminal.c_iflag != 0 || terminal.c_oflag != 0 ||
        terminal.c_lflag != 0 || terminal.c_cflag != CS8 ||
        terminal.c_cc[VMIN] != 1 || terminal.c_cc[VTIME] != 0)
        return 3;
    return 0;
}

int crabc_x86_64_header_layouts_baseline_probe(void)
{
    int status = check_observation_records();

    if (status != 0)
        return 10 + status;
    status = check_mapping_records();
    if (status != 0)
        return 20 + status;
    status = check_descriptor_records();
    if (status != 0)
        return 30 + status;
    status = check_signal_and_termios_records();
    if (status != 0)
        return 40 + status;
    status = crabc_x86_64_header_layouts_baseline_cxx_probe();
    return status == 0 ? 0 : 50 + status;
}

#ifndef CRABC_HEADER_LAYOUTS_BASELINE_FREESTANDING
int main(void)
{
    return crabc_x86_64_header_layouts_baseline_probe();
}
#endif
