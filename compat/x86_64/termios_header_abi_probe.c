/*
 * Pinned-musl Linux/x86-64 GNU <termios.h> ABI assertions.
 *
 * This source checks the public C record and the deliberately bounded
 * termios-control declarations only. It does not link or select a C runtime.
 * The record member spellings are part of this source-level layout contract,
 * so the project and pinned-musl passes intentionally use the same names.
 */

#define _GNU_SOURCE 1

#include <stddef.h>
#include <termios.h>

_Static_assert(sizeof(cc_t) == 1, "x86 cc_t width");
_Static_assert(sizeof(speed_t) == 4 && sizeof(tcflag_t) == 4,
    "x86 termios scalar widths");
_Static_assert(NCCS == 32, "x86 public termios NCCS");
_Static_assert(sizeof(struct termios) == 60 && _Alignof(struct termios) == 4,
    "x86 public termios layout");
_Static_assert(offsetof(struct termios, c_iflag) == 0,
    "x86 termios input flags");
_Static_assert(offsetof(struct termios, c_oflag) == 4,
    "x86 termios output flags");
_Static_assert(offsetof(struct termios, c_cflag) == 8,
    "x86 termios control flags");
_Static_assert(offsetof(struct termios, c_lflag) == 12,
    "x86 termios local flags");
_Static_assert(offsetof(struct termios, c_line) == 16,
    "x86 termios line discipline");
_Static_assert(offsetof(struct termios, c_cc) == 17,
    "x86 termios control codes");
_Static_assert(offsetof(struct termios, __c_ispeed) == 52,
    "x86 termios input-speed tail");
_Static_assert(offsetof(struct termios, __c_ospeed) == 56,
    "x86 termios output-speed tail");

_Static_assert(sizeof(struct winsize) == 8 && _Alignof(struct winsize) == 2,
    "x86 winsize layout");
_Static_assert(offsetof(struct winsize, ws_row) == 0,
    "x86 winsize row");
_Static_assert(offsetof(struct winsize, ws_col) == 2,
    "x86 winsize column");
_Static_assert(offsetof(struct winsize, ws_xpixel) == 4,
    "x86 winsize horizontal pixels");
_Static_assert(offsetof(struct winsize, ws_ypixel) == 6,
    "x86 winsize vertical pixels");

_Static_assert(CBAUD == 0x100f && CBAUDEX == 0x1000 &&
    CIBAUD == 0x100f0000, "x86 GNU baud masks");
_Static_assert(B0 == 0 && B9600 == 13 && B38400 == 15 &&
    B57600 == 0010001 && B4000000 == 0010017,
    "x86 standard and extended baud selectors");
_Static_assert(IGNBRK == 0000001 && BRKINT == 0000002 &&
    PARMRK == 0000010 && ISTRIP == 0000040 && INLCR == 0000100 &&
    IGNCR == 0000200 && ICRNL == 0000400 && IXON == 0002000,
    "x86 raw input masks");
_Static_assert(OPOST == 0000001 && ECHO == 0000010 && ECHONL == 0000100 &&
    ICANON == 0000002 && ISIG == 0000001 && IEXTEN == 0100000,
    "x86 raw output and local masks");
_Static_assert(CSIZE == 0000060 && CS8 == 0000060 && PARENB == 0000400 &&
    VMIN == 6 && VTIME == 5, "x86 raw control masks and indices");
_Static_assert(TCSANOW == 0 && TCSADRAIN == 1 && TCSAFLUSH == 2,
    "x86 termios actions");
_Static_assert(TCIFLUSH == 0 && TCOFLUSH == 1 && TCIOFLUSH == 2 &&
    TCOOFF == 0 && TCOON == 1 && TCIOFF == 2 && TCION == 3,
    "x86 termios queue actions");

_Static_assert(__builtin_types_compatible_p(__typeof__(&cfgetispeed),
    speed_t (*)(const struct termios *)), "cfgetispeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfgetospeed),
    speed_t (*)(const struct termios *)), "cfgetospeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetispeed),
    int (*)(struct termios *, speed_t)), "cfsetispeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetospeed),
    int (*)(struct termios *, speed_t)), "cfsetospeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetspeed),
    int (*)(struct termios *, speed_t)), "cfsetspeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfmakeraw),
    void (*)(struct termios *)), "cfmakeraw declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcgetattr),
    int (*)(int, struct termios *)), "tcgetattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsetattr),
    int (*)(int, int, const struct termios *)), "tcsetattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcflush),
    int (*)(int, int)), "tcflush declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcflow),
    int (*)(int, int)), "tcflow declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsendbreak),
    int (*)(int, int)), "tcsendbreak declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcgetwinsize),
    int (*)(int, struct winsize *)), "tcgetwinsize declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsetwinsize),
    int (*)(int, const struct winsize *)), "tcsetwinsize declaration");

int crabc_x86_64_termios_header_abi_probe(void)
{
    return B4000000 == CBAUD ? 1 : 0;
}
