/*
 * Pinned-musl x86 direct-header topology assertions for STREAMS and terminal
 * headers.  Each translation unit selects one direct include path so a
 * transitive include cannot disguise a leaked declaration or macro surface.
 */

#if defined(CRABC_TERMINAL_STREAMS_STROPTS)

#include <stropts.h>

#ifdef TCGETS
#error "<stropts.h> must not acquire <sys/ioctl.h> request macros"
#endif
#ifdef TIOCGWINSZ
#error "<stropts.h> must not acquire terminal ioctl request macros"
#endif
#ifdef _IOC
#error "<stropts.h> must not acquire ioctl request-composition macros"
#endif
#ifdef N_TTY
#error "<stropts.h> must not acquire line-discipline macros"
#endif

_Static_assert(__SID == ('S' << 8) && I_NREAD == (__SID | 1) &&
    I_CANPUT == (__SID | 34), "STREAMS command vocabulary");
_Static_assert(FMNAMESZ == 8 && FLUSHRW == 0x03 && S_WRNORM == S_OUTPUT &&
    RPROTMASK == 0x001C && MUXID_ALL == -1, "STREAMS scalar vocabulary");
_Static_assert(sizeof(struct bandinfo) == 8 && _Alignof(struct bandinfo) == 4,
    "bandinfo layout");
_Static_assert(sizeof(struct strbuf) == 16 && _Alignof(struct strbuf) == 8,
    "strbuf layout");
_Static_assert(sizeof(struct strpeek) == 40 && sizeof(struct strfdinsert) == 48,
    "STREAMS aggregate layouts");
_Static_assert(sizeof(struct strioctl) == 24 && sizeof(struct strrecvfd) == 20 &&
    sizeof(struct str_mlist) == 9 && sizeof(struct str_list) == 16,
    "STREAMS remaining layouts");
_Static_assert(__builtin_types_compatible_p(__typeof__(&isastream), int (*)(int)),
    "isastream declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ioctl), int (*)(int, int, ...)),
    "stropts ioctl declaration");

#elif defined(CRABC_TERMINAL_STREAMS_SYS_STROPTS)

#include <sys/stropts.h>

#ifdef _CRABC_SYS_STROPTS_H
#error "<sys/stropts.h> must be musl's unguarded forwarding include"
#endif
#ifdef TCGETS
#error "<sys/stropts.h> must not acquire <sys/ioctl.h> request macros"
#endif
#ifdef _IOC
#error "<sys/stropts.h> must not acquire ioctl request-composition macros"
#endif
_Static_assert(I_PUSH == (__SID | 2) && I_RECVFD == (__SID | 14),
    "sys/stropts forwarding vocabulary");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ioctl), int (*)(int, int, ...)),
    "sys/stropts ioctl declaration");

#elif defined(CRABC_TERMINAL_STREAMS_TTYDEFAULTS_DIRECT)

#include <sys/ttydefaults.h>

#ifdef BRKINT
#error "<sys/ttydefaults.h> must not directly include <termios.h>"
#endif
#ifdef B9600
#error "<sys/ttydefaults.h> must not directly include terminal speed macros"
#endif
#ifdef TCGETS
#error "<sys/ttydefaults.h> must not acquire ioctl request macros"
#endif
#ifndef TTYDEF_IFLAG
#error "<sys/ttydefaults.h> must declare its default macros"
#endif
#ifndef TTYDEF_SPEED
#error "<sys/ttydefaults.h> must declare its default speed macro"
#endif
#ifndef CTRL
#error "<sys/ttydefaults.h> must declare CTRL"
#endif
#ifndef CFLUSH
#error "<sys/ttydefaults.h> must declare legacy aliases"
#endif

#elif defined(CRABC_TERMINAL_STREAMS_TTYDEFAULTS_WITH_TERMIOS)

#include <termios.h>
#include <sys/ttydefaults.h>

_Static_assert(TTYDEF_IFLAG == (BRKINT | ISTRIP | ICRNL | IMAXBEL | IXON | IXANY),
    "terminal default input flags");
_Static_assert(TTYDEF_CFLAG == (CREAD | CS7 | PARENB | HUPCL) &&
    TTYDEF_SPEED == B9600 && CTRL('d') == 4 && CEOF == CTRL('d') &&
    CEOT == CEOF && CBRK == CEOL && CRPRNT == CREPRINT && CFLUSH == CDISCARD,
    "terminal default scalar vocabulary");
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
_Static_assert(TTYDEF_OFLAG == (OPOST | ONLCR | XTABS) &&
    TTYDEF_LFLAG == (ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL),
    "feature-selected terminal defaults");
#endif

#elif defined(CRABC_TERMINAL_STREAMS_PTY)

#include <pty.h>

#ifndef TCGETS
#error "<pty.h> must retain its direct <sys/ioctl.h> dependency"
#endif
#ifndef VSWTC
#error "<pty.h> must retain its direct <termios.h> dependency"
#endif
_Static_assert(sizeof(struct winsize) == 8 && _Alignof(struct winsize) == 2,
    "winsize layout from pty direct dependencies");
_Static_assert(__builtin_types_compatible_p(__typeof__(&openpty),
    int (*)(int *, int *, char *, const struct termios *, const struct winsize *)),
    "openpty declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&forkpty),
    int (*)(int *, char *, const struct termios *, const struct winsize *)),
    "forkpty declaration");

#elif defined(CRABC_TERMINAL_STREAMS_TERMIOS) || defined(CRABC_TERMINAL_STREAMS_SYS_TERMIOS)

#if defined(CRABC_TERMINAL_STREAMS_TERMIOS)
#include <termios.h>
#else
#include <sys/termios.h>
#endif

_Static_assert(sizeof(struct termios) == 60 && _Alignof(struct termios) == 4 &&
    __builtin_offsetof(struct termios, c_cc) == 17 &&
    __builtin_offsetof(struct termios, __c_ispeed) == 52 &&
    __builtin_offsetof(struct termios, __c_ospeed) == 56,
    "termios x86 record layout");
_Static_assert(VSWTC == 7 && VREPRINT == 12 && VDISCARD == 13 &&
    VWERASE == 14 && VLNEXT == 15 && VEOL2 == 16,
    "extended terminal control-code indices");
_Static_assert(IUCLC == 0001000 && IMAXBEL == 0020000 && IUTF8 == 0040000 &&
    OLCUC == 0000002 && VTDLY == 0040000 && VT0 == 0 && VT1 == 0040000,
    "unconditionally visible Linux terminal masks");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfgetispeed),
    speed_t (*)(const struct termios *)), "cfgetispeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfgetospeed),
    speed_t (*)(const struct termios *)), "cfgetospeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetispeed),
    int (*)(struct termios *, speed_t)), "cfsetispeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetospeed),
    int (*)(struct termios *, speed_t)), "cfsetospeed declaration");
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#ifndef CMSPAR
#error "GNU/BSD termios profile must expose CMSPAR"
#endif
#ifndef XTABS
#error "GNU/BSD termios profile must expose XTABS"
#endif
_Static_assert(CMSPAR == 010000000000 && CRTSCTS == 020000000000 &&
    XCASE == 0000004 && ECHOCTL == 0001000 && ECHOPRT == 0002000 &&
    ECHOKE == 0004000 && FLUSHO == 0010000 && PENDIN == 0040000 &&
    EXTPROC == 0200000 && XTABS == 0014000,
    "GNU/BSD terminal extension masks");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetspeed),
    int (*)(struct termios *, speed_t)), "cfsetspeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfmakeraw),
    void (*)(struct termios *)), "cfmakeraw declaration");
#else
#ifdef CMSPAR
#error "strict POSIX/XSI termios profile must hide CMSPAR"
#endif
#ifdef XTABS
#error "strict POSIX/XSI termios profile must hide XTABS"
#endif
#endif

#else
#error "select exactly one terminal/STREAMS direct-header topology variant"
#endif

int crabc_x86_terminal_streams_header_topology_probe(void)
{
    return 0;
}
