#ifndef _SYS_FSUID_H
#define _SYS_FSUID_H

#include <sys/types.h>

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
