#ifndef _SYS_IPC_H
#define _SYS_IPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <sys/types.h>

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

struct ipc_perm {
	key_t __ipc_perm_key;
	uid_t uid;
	gid_t gid;
	uid_t cuid;
	gid_t cgid;
	mode_t mode;
	int __ipc_perm_seq;
	long __pad1;
	long __pad2;
};

#define IPC_CREAT  01000
#define IPC_EXCL   02000
#define IPC_NOWAIT 04000

#define IPC_RMID 0
#define IPC_SET  1
#define IPC_STAT 2
#define IPC_INFO 3

#define IPC_PRIVATE ((key_t) 0)

key_t ftok(const char *, int);

#ifdef __cplusplus
}
#endif
#endif
