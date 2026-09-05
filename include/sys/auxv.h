#if defined(__x86_64__)
#ifndef _SYS_AUXV_H
#define _SYS_AUXV_H
#ifdef __cplusplus
extern "C" {
#endif
#include <elf.h>
#include <bits/hwcap.h>
unsigned long getauxval(unsigned long);
#ifdef __cplusplus
}
#endif
#endif
#else
#ifndef _CRABC_SYS_AUXV_H
#define _CRABC_SYS_AUXV_H

#include <elf.h>
#include <bits/hwcap.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned long getauxval(unsigned long);

#ifdef __cplusplus
}
#endif

#endif
#endif
