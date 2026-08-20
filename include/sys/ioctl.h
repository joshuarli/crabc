#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int ioctl(int, unsigned long, ...);

/* Linux generic file-descriptor requests. */
#define FIONREAD 0x541b
#define FIONBIO 0x5421
#define FIOCLEX 0x5451
#define FIONCLEX 0x5450

/* Linux network-interface requests. */
#define SIOCGIFNAME  0x8910
#define SIOCGIFCONF  0x8912
#define SIOCGIFINDEX 0x8933
#define SIOGIFINDEX  SIOCGIFINDEX

#ifdef __cplusplus
}
#endif

#endif
