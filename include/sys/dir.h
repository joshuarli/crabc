#ifndef _CRABC_SYS_DIR_H
#define _CRABC_SYS_DIR_H

#if defined(__x86_64__)
/* Keep the historical AArch64 guard isolated from musl's x86 public form. */
#undef _CRABC_SYS_DIR_H
#include <dirent.h>
#define direct dirent
#else
#include <dirent.h>
#define direct dirent
#endif

#endif
