#include <alloca.h>
#include <ar.h>
#include <byteswap.h>
#include <elf.h>
#include <endian.h>
#include <features.h>
#include <lastlog.h>
#include <malloc.h>
#include <memory.h>
#include <paths.h>
#include <pthread.h>
#include <sched.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdc-predef.h>
#include <stddef.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdnoreturn.h>
#include <sysexits.h>
#include <utime.h>
#include <values.h>
#include <wait.h>

#include <sys/auxv.h>
#include <sys/cachectl.h>
#include <sys/dir.h>
#include <sys/epoll.h>
#include <sys/errno.h>
#include <sys/eventfd.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/io.h>
#include <sys/kd.h>
#include <sys/membarrier.h>
#include <sys/mtio.h>
#include <sys/param.h>
#include <sys/personality.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/signal.h>
#include <sys/signalfd.h>
#include <sys/soundcard.h>
#include <sys/statfs.h>
#include <sys/stropts.h>
#include <sys/syscall.h>
#include <sys/syslog.h>
#include <sys/sysmacros.h>
#include <sys/termios.h>
#include <sys/timerfd.h>
#include <sys/ttydefaults.h>
#include <sys/vfs.h>
#include <sys/vt.h>

_Static_assert(sizeof(struct ar_hdr) == 60, "ar.h public archive record");
_Static_assert(EI_NIDENT == 16, "elf.h identification width");
_Static_assert(EM_AARCH64 == 183, "elf.h AArch64 machine id");
_Static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "AArch64 byte order");
_Static_assert(__NR_read == 63 && SYS_read == 63, "AArch64 syscall numbering");
_Static_assert(HWCAP_AES == (1UL << 3), "AArch64 HWCAP surface");
_Static_assert(EPOLLMSG == 0x400, "epoll event constants");
_Static_assert(EPIOCSPARAMS == _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params),
               "epoll parameter ioctl");
_Static_assert(EFD_CLOEXEC == O_CLOEXEC, "eventfd flags");
_Static_assert(IN_ALL_EVENTS == 0x00000fff, "inotify event mask");
_Static_assert(L_SET == 0 && L_INCR == 1 && L_XTND == 2, "file lock origins");
_Static_assert(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ == 128,
               "membarrier RSEQ command");
_Static_assert(MTFSFM == 11 && MTIOCTOP == _IOW('m', 1, struct mtop),
               "tape ioctl surface");
_Static_assert(PR_SET_TAGGED_ADDR_CTRL == 55, "prctl AArch64 controls");
_Static_assert(TFD_TIMER_ABSTIME == 1, "timerfd flags");
_Static_assert(KDGETMODE == 0x4b3b && VT_OPENQRY == 0x5600,
               "Linux console UAPI forwarding");
_Static_assert(SNDCTL_DSP_SYNC == _IO('P', 1), "OSS UAPI forwarding");
_Static_assert(sizeof(struct signalfd_siginfo) == 128, "signalfd record width");
_Static_assert(sizeof(struct epoll_event) == 16, "epoll event ABI");

alignas(16) static unsigned char aligned_storage[16];

static void va_probe(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    va_end(ap);
}

int main(void)
{
    void *stack_storage = alloca(16);
    va_probe("header surface");
    printf("%zu %d %d %lu %lu %u %u %zu %zu %u\n",
           sizeof(struct ar_hdr), EM_AARCH64, __NR_read,
           (unsigned long)HWCAP_AES, (unsigned long)HWCAP2_MTE,
           (unsigned)EPIOCSPARAMS, (unsigned)MTIOCTOP,
           sizeof(struct epoll_event), sizeof(struct signalfd_siginfo),
           (unsigned)PR_SET_TAGGED_ADDR_CTRL);
    return stack_storage == NULL || aligned_storage[0] != 0;
}
