#ifndef _CRABC_DAEMON_H
#define _CRABC_DAEMON_H

/* The canonical declaration remains feature-gated in <unistd.h>.  This
 * project extension is intentionally unconditional, but must retain C ABI
 * linkage when a C++ consumer includes this standalone spelling directly. */
#ifdef __cplusplus
extern "C" {
#endif

int daemon(int, int);

#ifdef __cplusplus
}
#endif

#endif
