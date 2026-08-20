#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int ioctl(int, unsigned long, ...);

/* Linux's generic ioctl request encoding, used by public device headers. */
#define _IOC_NRBITS 8
#define _IOC_TYPEBITS 8
#define _IOC_SIZEBITS 14
#define _IOC_DIRBITS 2
#define _IOC_NRMASK ((1 << _IOC_NRBITS) - 1)
#define _IOC_TYPEMASK ((1 << _IOC_TYPEBITS) - 1)
#define _IOC_SIZEMASK ((1 << _IOC_SIZEBITS) - 1)
#define _IOC_DIRMASK ((1 << _IOC_DIRBITS) - 1)
#define _IOC_NRSHIFT 0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT (_IOC_SIZESHIFT + _IOC_SIZEBITS)
#define _IOC(dir, type, nr, size) (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
#define _IOC_TYPECHECK(type) (sizeof(type))
#define _IO(type, nr) _IOC(0, (type), (nr), 0)
#define _IOR(type, nr, size) _IOC(2, (type), (nr), _IOC_TYPECHECK(size))
#define _IOW(type, nr, size) _IOC(1, (type), (nr), _IOC_TYPECHECK(size))
#define _IOWR(type, nr, size) _IOC(3, (type), (nr), _IOC_TYPECHECK(size))

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
