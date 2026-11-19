#ifndef _CRABC_SYS_SENDFILE_H
#define _CRABC_SYS_SENDFILE_H


/* Keep the historical AArch64 guard isolated from musl's x86 public name. */
#undef _CRABC_SYS_SENDFILE_H

#ifndef _SYS_SENDFILE_H
#define _SYS_SENDFILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <unistd.h>

ssize_t sendfile(int, int, off_t *, size_t);

#if defined(_LARGEFILE64_SOURCE)
#define sendfile64 sendfile
#define off64_t off_t
#endif

#ifdef __cplusplus
}
#endif

#endif

#endif
