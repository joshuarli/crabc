#ifndef _CRABC_SYS_IO_H
#define _CRABC_SYS_IO_H

#include <features.h>

/* AArch64's public musl surface retains these declarations even though the
 * architecture's bits/io.h contributes no extra port-I/O definitions. */
#ifdef __cplusplus
extern "C" {
#endif

int iopl(int);
int ioperm(unsigned long, unsigned long, int);

#ifdef __cplusplus
}
#endif

#endif
