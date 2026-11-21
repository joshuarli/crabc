#ifndef _SYS_IO_H
#define _SYS_IO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#if defined(__x86_64__) || defined(__aarch64__)
#include <bits/io.h>
#endif

int iopl(int);
int ioperm(unsigned long, unsigned long, int);

#ifdef __cplusplus
}
#endif

#endif
