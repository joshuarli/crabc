/* C++ companion for the bounded Linux/x86-64 GNU <termios.h> header slice. */

#define _GNU_SOURCE 1

#include <termios.h>

extern "C" {
speed_t cfgetispeed(const struct termios *);
speed_t cfgetospeed(const struct termios *);
int cfsetispeed(struct termios *, speed_t);
int cfsetospeed(struct termios *, speed_t);
int cfsetspeed(struct termios *, speed_t);
void cfmakeraw(struct termios *);
int tcgetattr(int, struct termios *);
int tcsetattr(int, int, const struct termios *);
int tcflush(int, int);
int tcflow(int, int);
int tcsendbreak(int, int);
int tcgetwinsize(int, struct winsize *);
int tcsetwinsize(int, const struct winsize *);
}

using termios_get_speed_type = speed_t (*)(const struct termios *);
using termios_set_speed_type = int (*)(struct termios *, speed_t);
using termios_set_attributes_type = int (*)(int, int, const struct termios *);

static_assert(sizeof(cc_t) == 1 && sizeof(speed_t) == 4 &&
    sizeof(tcflag_t) == 4, "C++ termios scalar widths");
static_assert(NCCS == 32 && sizeof(struct termios) == 60 &&
    alignof(struct termios) == 4, "C++ public termios layout");
static_assert(__builtin_offsetof(struct termios, c_iflag) == 0 &&
    __builtin_offsetof(struct termios, c_cc) == 17 &&
    __builtin_offsetof(struct termios, __c_ispeed) == 52 &&
    __builtin_offsetof(struct termios, __c_ospeed) == 56,
    "C++ termios field offsets");
static_assert(sizeof(struct winsize) == 8 && alignof(struct winsize) == 2 &&
    __builtin_offsetof(struct winsize, ws_ypixel) == 6, "C++ winsize layout");
static_assert(CBAUD == 0x100f && CIBAUD == 0x100f0000 &&
    B4000000 == 0010017, "C++ GNU baud vocabulary");
static_assert(__is_same(decltype(&cfgetispeed), termios_get_speed_type) &&
    __is_same(decltype(&cfgetospeed), termios_get_speed_type),
    "C++ getter declarations");
static_assert(__is_same(decltype(&cfsetispeed), termios_set_speed_type) &&
    __is_same(decltype(&cfsetospeed), termios_set_speed_type) &&
    __is_same(decltype(&cfsetspeed), termios_set_speed_type),
    "C++ speed setter declarations");
static_assert(__is_same(decltype(&cfmakeraw), void (*)(struct termios *)),
    "C++ cfmakeraw declaration");
static_assert(__is_same(decltype(&tcgetattr), int (*)(int, struct termios *)) &&
    __is_same(decltype(&tcsetattr), termios_set_attributes_type) &&
    __is_same(decltype(&tcflush), int (*)(int, int)) &&
    __is_same(decltype(&tcflow), int (*)(int, int)) &&
    __is_same(decltype(&tcsendbreak), int (*)(int, int)),
    "C++ terminal control declarations");
static_assert(__is_same(decltype(&tcgetwinsize),
    int (*)(int, struct winsize *)) && __is_same(decltype(&tcsetwinsize),
    int (*)(int, const struct winsize *)), "C++ winsize declarations");

int crabc_x86_64_termios_header_abi_probe_cpp()
{
    return B57600 == 0 ? 1 : 0;
}
