/* Freestanding C++17 companion for libc_header_layouts_baseline_probe.c.
 *
 * It intentionally uses no C++ standard header, exception, RTTI, constructor,
 * local-static, allocation, or pthread facility.  The exported entry is C
 * linkage and C calls it from the same static candidate, so this is a concrete
 * C++ header/layout and unmangled-reference check rather than a C++ runtime
 * admission.
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

using fstat_function = int (*)(int, struct stat *);
using clock_gettime_function = int (*)(clockid_t, struct timespec *);
using mmap_function = void *(*)(void *, size_t, int, int, int, off_t);
using munmap_function = int (*)(void *, size_t);
using mprotect_function = int (*)(void *, size_t, int);
using madvise_function = int (*)(void *, size_t, int);
using posix_madvise_function = int (*)(void *, size_t, int);
using mincore_function = int (*)(void *, size_t, unsigned char *);
using getrlimit_function = int (*)(int, struct rlimit *);
using poll_function = int (*)(struct pollfd *, nfds_t, int);
using select_function = int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
using socketpair_function = int (*)(int, int, int, int *);
using close_function = int (*)(int);
using sigemptyset_function = int (*)(sigset_t *);
using cfmakeraw_function = void (*)(struct termios *);
using uname_function = int (*)(struct utsname *);
using sysinfo_function = int (*)(struct sysinfo *);
using getpagesize_function = int (*)(void);

static_assert(sizeof(long) == 8 && sizeof(void *) == 8, "x86 LP64 scalars");
static_assert(sizeof(struct stat) == 144 && alignof(struct stat) == 8,
    "C++ stat layout");
static_assert(sizeof(struct timespec) == 16 && alignof(struct timespec) == 8,
    "C++ timespec layout");
static_assert(sizeof(struct pollfd) == 8 && alignof(struct pollfd) == 4 &&
    sizeof(fd_set) == 128 && alignof(fd_set) == 8,
    "C++ readiness layouts");
static_assert(sizeof(sigset_t) == 128 && alignof(sigset_t) == 8,
    "C++ signal layout");
static_assert(sizeof(struct rlimit) == 16 && alignof(struct rlimit) == 8,
    "C++ resource layout");
static_assert(sizeof(struct sockaddr) == 16 && sizeof(struct sockaddr_in) == 16 &&
    sizeof(struct sockaddr_storage) == 128,
    "C++ socket layouts");
static_assert(sizeof(struct utsname) == 390 && sizeof(struct sysinfo) == 368,
    "C++ system layouts");
static_assert(NCCS == 32 && sizeof(struct termios) == 60,
    "C++ termios layout");
static_assert(O_CLOEXEC == 02000000 && F_GETFD == 1 && POLLIN == 0x0001 &&
    CLOCK_MONOTONIC == 1 && RLIMIT_NOFILE == 7 && AF_UNIX == 1 &&
    SOCK_STREAM == 1 && PROT_READ == 1 && PROT_WRITE == 2 &&
    MAP_PRIVATE == 2 && MAP_ANONYMOUS == 0x20,
    "C++ selected x86 constants");
/* Pinned musl gives __errno_location a const function attribute; the staged
 * header intentionally does not claim that optimizer property.  The runtime
 * C-linkage proof below still calls the existing selected accessor. */
static_assert(__is_same(decltype(&fstat), fstat_function), "C++ fstat declaration");
static_assert(__is_same(decltype(&clock_gettime), clock_gettime_function),
    "C++ clock_gettime declaration");
static_assert(__is_same(decltype(&mmap), mmap_function), "C++ mmap declaration");
static_assert(__is_same(decltype(&munmap), munmap_function), "C++ munmap declaration");
static_assert(__is_same(decltype(&mprotect), mprotect_function),
    "C++ mprotect declaration");
static_assert(__is_same(decltype(&madvise), madvise_function),
    "C++ madvise declaration");
static_assert(__is_same(decltype(&posix_madvise), posix_madvise_function),
    "C++ posix_madvise declaration");
static_assert(__is_same(decltype(&mincore), mincore_function),
    "C++ mincore declaration");
static_assert(__is_same(decltype(&getrlimit), getrlimit_function),
    "C++ getrlimit declaration");
static_assert(__is_same(decltype(&poll), poll_function), "C++ poll declaration");
static_assert(__is_same(decltype(&select), select_function), "C++ select declaration");
static_assert(__is_same(decltype(&socketpair), socketpair_function),
    "C++ socketpair declaration");
static_assert(__is_same(decltype(&close), close_function), "C++ close declaration");
static_assert(__is_same(decltype(&sigemptyset), sigemptyset_function),
    "C++ sigemptyset declaration");
static_assert(__is_same(decltype(&cfmakeraw), cfmakeraw_function),
    "C++ cfmakeraw declaration");
static_assert(__is_same(decltype(&uname), uname_function), "C++ uname declaration");
static_assert(__is_same(decltype(&sysinfo), sysinfo_function),
    "C++ sysinfo declaration");
static_assert(__is_same(decltype(&getpagesize), getpagesize_function),
    "C++ getpagesize declaration");

static int check_cpp_observation(void)
{
    struct timespec clock_value;
    struct rlimit limit;
    struct utsname name;
    struct sysinfo info;
    int *errno_slot = __errno_location();

    if (errno_slot == nullptr)
        return 1;
    *errno_slot = ERANGE;
    if (getpagesize() != 4096 || *errno_slot != ERANGE ||
        clock_gettime(CLOCK_MONOTONIC, &clock_value) != 0 ||
        clock_value.tv_nsec < 0 || clock_value.tv_nsec >= 1000000000L ||
        getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur > limit.rlim_max ||
        uname(&name) != 0 || name.sysname[0] != 'L' ||
        sysinfo(&info) != 0 || info.procs == 0 || info.mem_unit == 0)
        return 2;
    return 0;
}

static int check_cpp_mapping(void)
{
    volatile unsigned char *bytes;
    unsigned char residency;
    void *mapping = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mapping == MAP_FAILED)
        return 1;
    bytes = static_cast<volatile unsigned char *>(mapping);
    bytes[0] = 0x5a;
    if (mprotect(mapping, 4096, PROT_READ) != 0 ||
        mprotect(mapping, 4096, PROT_READ | PROT_WRITE) != 0 ||
        madvise(mapping, 4096, MADV_NORMAL) != 0 ||
        posix_madvise(mapping, 4096, POSIX_MADV_NORMAL) != 0 ||
        mincore(mapping, 4096, &residency) != 0 || (residency & 1) == 0 ||
        munmap(mapping, 4096) != 0)
        return 2;
    return 0;
}

static int check_cpp_descriptor_and_signal(void)
{
    struct stat status;
    struct pollfd descriptor;
    struct timeval timeout;
    fd_set readable;
    sigset_t empty;
    struct termios terminal;
    unsigned long *mask_words = reinterpret_cast<unsigned long *>(&empty);
    int pair[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        return 1;
    if (fstat(pair[0], &status) != 0 || !S_ISSOCK(status.st_mode))
        return 2;
    descriptor.fd = pair[0];
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    if (poll(&descriptor, 1, 0) != 0)
        return 3;
    for (unsigned long index = 0;
         index < sizeof(readable.fds_bits) / sizeof(readable.fds_bits[0]); ++index)
        readable.fds_bits[index] = 0;
    FD_SET(pair[0], &readable);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    if (select(pair[0] + 1, &readable, nullptr, nullptr, &timeout) != 0 ||
        FD_ISSET(pair[0], &readable))
        return 4;
    for (unsigned long index = 0; index < sizeof(empty) / sizeof(*mask_words); ++index)
        mask_words[index] = ~0UL;
    if (sigemptyset(&empty) != 0 || mask_words[0] != 0)
        return 5;
    for (unsigned long index = 1; index < sizeof(empty) / sizeof(*mask_words); ++index)
        if (mask_words[index] != ~0UL)
            return 6;
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
        return 7;
    if (close(pair[1]) != 0 || close(pair[0]) != 0)
        return 8;
    return 0;
}

extern "C" int crabc_x86_64_header_layouts_baseline_cxx_probe(void)
{
    int status = check_cpp_observation();

    if (status != 0)
        return 10 + status;
    status = check_cpp_mapping();
    if (status != 0)
        return 20 + status;
    status = check_cpp_descriptor_and_signal();
    return status == 0 ? 0 : 30 + status;
}
