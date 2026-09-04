#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H

/* Match musl's direct-header record dependency: a consumer that includes
 * only <sys/ioctl.h> may name the Linux `struct winsize` request record. */
#define __NEED_struct_winsize
#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Musl's public Linux ABI takes a signed 32-bit request word. Linux consumes
 * its low 32 bits after the platform C ABI widens it into an argument word. */
int ioctl(int, int, ...);

#include <bits/ioctl.h>

#ifdef __cplusplus
}
#endif

#endif
