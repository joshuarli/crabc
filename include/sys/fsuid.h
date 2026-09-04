#ifndef _SYS_FSUID_H
#define _SYS_FSUID_H

#if defined(__x86_64__)
/* This header needs only its two Linux identity words.  Requesting them
 * directly keeps the GNU/BSD sys/types.h callable tail owned by its umbrella
 * header, as in the pinned musl x86 source. */
#define __NEED_uid_t
#define __NEED_gid_t
#include <bits/alltypes.h>
#else
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Linux returns the previous filesystem identity from these calls.  Passing
 * (uid_t)-1 or (gid_t)-1 queries the current value without changing it.
 */
int setfsuid(uid_t);
int setfsgid(gid_t);

#ifdef __cplusplus
}
#endif

#endif
