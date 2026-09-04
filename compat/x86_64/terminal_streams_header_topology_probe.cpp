// Pinned-musl x86 C++ direct-header topology companion.  The C fixture owns
// macro/layout assertions; this fixture makes the public function linkage and
// exact function-pointer forms explicit for each direct include path.

#if defined(CRABC_TERMINAL_STREAMS_STROPTS)

#include <stropts.h>

#ifdef TCGETS
#error "<stropts.h> must not acquire <sys/ioctl.h> request macros"
#endif
#ifdef _IOC
#error "<stropts.h> must not acquire ioctl request-composition macros"
#endif
extern "C" int isastream(int);
extern "C" int ioctl(int, int, ...);
static_assert(__is_same(decltype(&isastream), int (*)(int)));
static_assert(__is_same(decltype(&ioctl), int (*)(int, int, ...)));
static_assert(sizeof(struct strbuf) == 16 && sizeof(struct strpeek) == 40 &&
    sizeof(struct strfdinsert) == 48 && sizeof(struct strioctl) == 24);

#elif defined(CRABC_TERMINAL_STREAMS_SYS_STROPTS)

#include <sys/stropts.h>

#ifdef _CRABC_SYS_STROPTS_H
#error "<sys/stropts.h> must be musl's unguarded forwarding include"
#endif
#ifdef TCGETS
#error "<sys/stropts.h> must not acquire <sys/ioctl.h> request macros"
#endif
extern "C" int ioctl(int, int, ...);
static_assert(__is_same(decltype(&ioctl), int (*)(int, int, ...)));

#elif defined(CRABC_TERMINAL_STREAMS_TTYDEFAULTS_DIRECT)

#include <sys/ttydefaults.h>

#ifdef BRKINT
#error "<sys/ttydefaults.h> must not directly include <termios.h>"
#endif
#ifdef TCGETS
#error "<sys/ttydefaults.h> must not acquire ioctl request macros"
#endif
#ifndef TTYDEF_IFLAG
#error "<sys/ttydefaults.h> must declare its default macros"
#endif

#elif defined(CRABC_TERMINAL_STREAMS_TTYDEFAULTS_WITH_TERMIOS)

#include <termios.h>
#include <sys/ttydefaults.h>

static_assert(TTYDEF_IFLAG == (BRKINT | ISTRIP | ICRNL | IMAXBEL | IXON | IXANY));
static_assert(TTYDEF_CFLAG == (CREAD | CS7 | PARENB | HUPCL) &&
    TTYDEF_SPEED == B9600 && CTRL('d') == 4 && CEOF == CTRL('d'));
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
static_assert(TTYDEF_OFLAG == (OPOST | ONLCR | XTABS));
static_assert(TTYDEF_LFLAG == (ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL));
#endif

#elif defined(CRABC_TERMINAL_STREAMS_PTY)

#include <pty.h>

#ifndef TCGETS
#error "<pty.h> must retain its direct <sys/ioctl.h> dependency"
#endif
extern "C" int openpty(int *, int *, char *, const struct termios *, const struct winsize *);
extern "C" int forkpty(int *, char *, const struct termios *, const struct winsize *);
static_assert(__is_same(decltype(&openpty),
    int (*)(int *, int *, char *, const struct termios *, const struct winsize *)));
static_assert(__is_same(decltype(&forkpty),
    int (*)(int *, char *, const struct termios *, const struct winsize *)));
static_assert(sizeof(struct winsize) == 8 && alignof(struct winsize) == 2);

#elif defined(CRABC_TERMINAL_STREAMS_TERMIOS) || defined(CRABC_TERMINAL_STREAMS_SYS_TERMIOS)

#if defined(CRABC_TERMINAL_STREAMS_TERMIOS)
#include <termios.h>
#else
#include <sys/termios.h>
#endif

extern "C" speed_t cfgetispeed(const struct termios *);
extern "C" speed_t cfgetospeed(const struct termios *);
extern "C" int cfsetispeed(struct termios *, speed_t);
extern "C" int cfsetospeed(struct termios *, speed_t);
static_assert(__is_same(decltype(&cfgetispeed), speed_t (*)(const struct termios *)));
static_assert(__is_same(decltype(&cfgetospeed), speed_t (*)(const struct termios *)));
static_assert(__is_same(decltype(&cfsetispeed), int (*)(struct termios *, speed_t)));
static_assert(__is_same(decltype(&cfsetospeed), int (*)(struct termios *, speed_t)));
static_assert(VSWTC == 7 && VEOL2 == 16 && IMAXBEL == 0020000 && IUTF8 == 0040000);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
extern "C" int cfsetspeed(struct termios *, speed_t);
extern "C" void cfmakeraw(struct termios *);
static_assert(__is_same(decltype(&cfsetspeed), int (*)(struct termios *, speed_t)));
static_assert(__is_same(decltype(&cfmakeraw), void (*)(struct termios *)));
static_assert(CMSPAR == 010000000000 && CRTSCTS == 020000000000 && XTABS == 0014000);
#else
#ifdef CMSPAR
#error "strict POSIX/XSI termios profile must hide CMSPAR"
#endif
#endif

#else
#error "select exactly one terminal/STREAMS direct-header topology variant"
#endif

int crabc_x86_terminal_streams_header_topology_probe_cpp()
{
    return 0;
}
