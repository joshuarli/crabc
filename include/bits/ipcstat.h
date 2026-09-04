#ifndef _BITS_IPCSTAT_H
#define _BITS_IPCSTAT_H

/* Linux/x86-64 System V IPC control command from pinned musl. */
#if !defined(__x86_64__) || !defined(__LP64__)
#error "crabc x86-64 bits/ipcstat.h requires LP64 x86-64"
#endif

#define IPC_STAT 2

#endif
