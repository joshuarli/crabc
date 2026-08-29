/* C++17 companion for the Linux/x86-64 <sys/ioctl.h> ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/ioctl.h>

struct crabc_ioctl_word {
    unsigned int value;
};

static_assert(sizeof(int) == 4 && sizeof(unsigned long) == 8,
              "x86 ioctl scalar ABI");
static_assert(sizeof(struct winsize) == 8 && alignof(struct winsize) == 2,
              "Linux ioctl winsize record");
static_assert(_IOC_NONE == 0U && _IOC_WRITE == 1U && _IOC_READ == 2U,
              "Linux ioctl directions");
static_assert(_IO('q', 0x12) == 0x00007112U,
              "no-argument ioctl composition");
static_assert(_IOR('q', 0x12, struct crabc_ioctl_word) == 0x80047112U,
              "read ioctl composition");
static_assert(_IOW('q', 0x12, struct crabc_ioctl_word) == 0x40047112U,
              "write ioctl composition");
static_assert(_IOWR('q', 0x12, struct crabc_ioctl_word) == 0xc0047112U,
              "read/write ioctl composition");
static_assert(FIONREAD == 0x541b && FIONBIO == 0x5421 && FIOCLEX == 0x5451 &&
                  FIONCLEX == 0x5450,
              "generic descriptor ioctl requests");
static_assert(TIOCSCTTY == 0x540e && TIOCNOTTY == 0x5422,
              "controlling-terminal ioctl requests");
static_assert(SIOCGIFNAME == 0x8910 && SIOCGIFCONF == 0x8912 &&
                  SIOCGIFINDEX == 0x8933 && SIOGIFINDEX == SIOCGIFINDEX,
              "network-interface ioctl requests");

using ioctl_signature = int (*)(int, int, ...);
static_assert(__is_same(decltype(&ioctl), ioctl_signature),
              "musl ioctl C++ declaration");

extern "C" int ioctl(int, int, ...);
