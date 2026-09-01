#ifndef _CRABC_SYS_IO_H
#define _CRABC_SYS_IO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

/* Pinned musl 1.2.6's x86_64 `include/sys/io.h` makes port-I/O helpers
 * header-local rather than archive callables.  Keep them target-private: the
 * AArch64 surface retains only iopl/ioperm and does not gain x86 instructions.
 */
#if defined(__x86_64__)
#include <bits/io.h>
#endif

int iopl(int);
int ioperm(unsigned long, unsigned long, int);

#ifdef __cplusplus
}
#endif

#endif
