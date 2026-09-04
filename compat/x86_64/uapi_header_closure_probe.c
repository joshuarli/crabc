/* Direct x86-64 Linux UAPI header closure and request-encoding probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>

#if defined(CRABC_UAPI_IOCTL_ONLY)
#include <sys/ioctl.h>
#elif defined(CRABC_UAPI_MOUNT_ONLY)
#include <sys/mount.h>
#elif defined(CRABC_UAPI_PTY_ONLY)
#include <pty.h>
#elif defined(CRABC_UAPI_MTIO_ONLY)
#include <sys/mtio.h>
#elif defined(CRABC_UAPI_MOUNT_IOCTL)
#include <sys/mount.h>
#include <sys/ioctl.h>
#elif defined(CRABC_UAPI_PTY_IOCTL)
#include <pty.h>
#include <sys/ioctl.h>
#elif defined(CRABC_UAPI_MTIO_IOCTL)
#include <sys/mtio.h>
#include <sys/ioctl.h>
#else
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <pty.h>
#include <sys/mtio.h>
#endif

/* The public ioctl vocabulary is unconditional once any target header imports
 * sys/ioctl.h. Mount and legacy tape records remain header-local contracts. */
_Static_assert(_IOC_NONE == 0U && _IOC_WRITE == 1U && _IOC_READ == 2U,
               "ioctl direction vocabulary");
_Static_assert(_IO('q', 0x12) == 0x00007112U &&
                   _IOR('q', 0x12, unsigned int) == 0x80047112U &&
                   _IOW('q', 0x12, unsigned int) == 0x40047112U &&
                   _IOWR('q', 0x12, unsigned int) == 0xc0047112U,
               "x86 ioctl encoding");
#if !defined(CRABC_UAPI_MOUNT_ONLY) && !defined(CRABC_UAPI_MOUNT_IOCTL)
_Static_assert(TCGETS == 0x5401 && TCSETS == 0x5402 &&
                   TCSBRK == 0x5409 && TIOCSCTTY == 0x540e &&
                   TIOCGWINSZ == 0x5413 && TIOCSWINSZ == 0x5414 &&
                   TIOCGPTN == 0x80045430U &&
                   TIOCSPTLCK == 0x40045431U && TIOCGPTPEER == 0x5441U,
               "terminal ioctl vocabulary");
#endif
_Static_assert(FIONREAD == 0x541b && FIONBIO == 0x5421 &&
                   FIONCLEX == 0x5450 && FIOCLEX == 0x5451 &&
                   FIOASYNC == 0x5452 && FIOQSIZE == 0x5460,
               "descriptor ioctl vocabulary");
_Static_assert(SIOCGIFNAME == 0x8910 && SIOCGIFCONF == 0x8912 &&
                   SIOCGIFINDEX == 0x8933 && SIOGIFINDEX == SIOCGIFINDEX &&
                   SIOCATMARK == 0x8905,
               "socket ioctl vocabulary");
_Static_assert(N_TTY == 0 && N_NULL == 27 && TIOCPKT_IOCTL == 64,
               "line discipline vocabulary");
_Static_assert(sizeof(struct winsize) == 8 && _Alignof(struct winsize) == 2 &&
                   offsetof(struct winsize, ws_row) == 0 &&
                   offsetof(struct winsize, ws_ypixel) == 6,
               "winsize layout");
#if defined(CRABC_UAPI_MOUNT_ONLY) || defined(CRABC_UAPI_MOUNT_IOCTL) || \
    !defined(CRABC_UAPI_IOCTL_ONLY) && !defined(CRABC_UAPI_PTY_ONLY) && \
    !defined(CRABC_UAPI_MTIO_ONLY) && !defined(CRABC_UAPI_PTY_IOCTL) && \
    !defined(CRABC_UAPI_MTIO_IOCTL)
_Static_assert(BLKROSET == _IO(0x12, 93) &&
                   BLKROGET == _IO(0x12, 94) &&
                   BLKRRPART == _IO(0x12, 95) &&
                   BLKGETSIZE == _IO(0x12, 96) &&
                   BLKBSZGET == _IOR(0x12, 112, size_t) &&
                   BLKBSZSET == _IOW(0x12, 113, size_t) &&
                   BLKGETSIZE64 == _IOR(0x12, 114, size_t),
               "block-device mount ioctl vocabulary");
_Static_assert(MS_RDONLY == 1 && MS_NOSUID == 2 && MS_NODEV == 4 &&
                   MS_BIND == 4096 && MS_NOUSER == (1U << 31) &&
                   MNT_FORCE == 1 && UMOUNT_NOFOLLOW == 8,
               "mount flags");
#endif
#if defined(CRABC_UAPI_MTIO_ONLY) || defined(CRABC_UAPI_MTIO_IOCTL) || \
    (!defined(CRABC_UAPI_IOCTL_ONLY) && !defined(CRABC_UAPI_MOUNT_ONLY) && \
     !defined(CRABC_UAPI_PTY_ONLY) && !defined(CRABC_UAPI_MOUNT_IOCTL) && \
     !defined(CRABC_UAPI_PTY_IOCTL))
_Static_assert(MTIOCTOP == _IOW('m', 1, struct mtop) &&
                   MTIOCGET == _IOR('m', 2, struct mtget) &&
                   MTIOCPOS == _IOR('m', 3, struct mtpos),
               "legacy tape ioctl vocabulary");
#endif

static int (*const crabc_ioctl_type)(int, int, ...) = ioctl;
#if defined(CRABC_UAPI_MOUNT_ONLY) || defined(CRABC_UAPI_MOUNT_IOCTL) || \
    (!defined(CRABC_UAPI_IOCTL_ONLY) && !defined(CRABC_UAPI_PTY_ONLY) && \
     !defined(CRABC_UAPI_MTIO_ONLY) && !defined(CRABC_UAPI_PTY_IOCTL) && \
     !defined(CRABC_UAPI_MTIO_IOCTL))
static int (*const crabc_mount_type)(const char *, const char *, const char *,
                                     unsigned long, const void *) = mount;
static int (*const crabc_umount_type)(const char *) = umount;
#endif
#if defined(CRABC_UAPI_PTY_ONLY) || defined(CRABC_UAPI_PTY_IOCTL) || \
    (!defined(CRABC_UAPI_IOCTL_ONLY) && !defined(CRABC_UAPI_MOUNT_ONLY) && \
     !defined(CRABC_UAPI_MTIO_ONLY) && !defined(CRABC_UAPI_MOUNT_IOCTL) && \
     !defined(CRABC_UAPI_MTIO_IOCTL))
static int (*const crabc_openpty_type)(int *, int *, char *,
                                       const struct termios *,
                                       const struct winsize *) = openpty;
#endif

int main(void)
{
    int invalid = crabc_ioctl_type == 0;
#if defined(CRABC_UAPI_MOUNT_ONLY) || defined(CRABC_UAPI_MOUNT_IOCTL) || \
    (!defined(CRABC_UAPI_IOCTL_ONLY) && !defined(CRABC_UAPI_PTY_ONLY) && \
     !defined(CRABC_UAPI_MTIO_ONLY) && !defined(CRABC_UAPI_PTY_IOCTL) && \
     !defined(CRABC_UAPI_MTIO_IOCTL))
    invalid = invalid || crabc_mount_type == 0 || crabc_umount_type == 0;
#endif
#if defined(CRABC_UAPI_PTY_ONLY) || defined(CRABC_UAPI_PTY_IOCTL) || \
    (!defined(CRABC_UAPI_IOCTL_ONLY) && !defined(CRABC_UAPI_MOUNT_ONLY) && \
     !defined(CRABC_UAPI_MTIO_ONLY) && !defined(CRABC_UAPI_MOUNT_IOCTL) && \
     !defined(CRABC_UAPI_MTIO_IOCTL))
    invalid = invalid || crabc_openpty_type == 0;
#endif
    return invalid;
}
