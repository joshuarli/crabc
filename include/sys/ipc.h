#ifndef _SYS_IPC_H
#define _SYS_IPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

/* Musl keeps the ABI backing spellings private outside its GNU/BSD
 * namespace, then maps the public compatibility spellings back under those
 * feature selectors. Declare the record through the backing names so a
 * strict consumer cannot accidentally rely on a GNU/BSD member name. */
#define __ipc_perm_key __key
#define __ipc_perm_seq __seq
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __key key
#define __seq seq
#endif

#define __NEED_uid_t
#define __NEED_gid_t
#define __NEED_mode_t
#define __NEED_key_t

#include <bits/alltypes.h>
#include <bits/ipc.h>
#include <bits/ipcstat.h>


#define IPC_CREAT  01000
#define IPC_EXCL   02000
#define IPC_NOWAIT 04000

#define IPC_RMID 0
#define IPC_SET  1
#define IPC_INFO 3

#define IPC_PRIVATE ((key_t) 0)

key_t ftok(const char *, int);

#ifdef __cplusplus
}
#endif
#endif
