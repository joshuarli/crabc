#ifndef _CRABC_SYS_SIGNALFD_H
#define _CRABC_SYS_SIGNALFD_H

#include <stdint.h>
#include <fcntl.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SFD_CLOEXEC O_CLOEXEC
#define SFD_NONBLOCK O_NONBLOCK
int signalfd(int, const sigset_t *, int);
struct signalfd_siginfo {
    uint32_t ssi_signo; int32_t ssi_errno; int32_t ssi_code;
    uint32_t ssi_pid, ssi_uid; int32_t ssi_fd; uint32_t ssi_tid, ssi_band, ssi_overrun, ssi_trapno;
    int32_t ssi_status, ssi_int; uint64_t ssi_ptr, ssi_utime, ssi_stime, ssi_addr;
    uint16_t ssi_addr_lsb, __pad2; int32_t ssi_syscall; uint64_t ssi_call_addr;
    uint32_t ssi_arch; uint8_t __pad[128-14*4-5*8-2*2];
};

#ifdef __cplusplus
}
#endif

#endif
