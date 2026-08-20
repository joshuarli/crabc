#ifndef _SYS_FANOTIFY_H
#define _SYS_FANOTIFY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FAN_CLOEXEC          0x00000001
#define FAN_NONBLOCK         0x00000002
#define FAN_CLASS_NOTIF      0x00000000
#define FAN_CLASS_CONTENT    0x00000004
#define FAN_CLASS_PRE_CONTENT 0x00000008
#define FAN_UNLIMITED_QUEUE  0x00000010
#define FAN_UNLIMITED_MARKS  0x00000020

#define FAN_MARK_ADD         0x00000001
#define FAN_MARK_REMOVE      0x00000002
#define FAN_MARK_DONT_FOLLOW 0x00000004
#define FAN_MARK_ONLYDIR     0x00000008
#define FAN_MARK_MOUNT       0x00000010
#define FAN_MARK_IGNORED_MASK 0x00000020
#define FAN_MARK_FLUSH       0x00000080
#define FAN_MARK_FILESYSTEM  0x00000100

#define FAN_ACCESS           0x00000001ULL
#define FAN_MODIFY           0x00000002ULL
#define FAN_OPEN             0x00000020ULL
#define FAN_CLOSE_WRITE      0x00000008ULL
#define FAN_CLOSE_NOWRITE    0x00000010ULL

int fanotify_init(unsigned int, unsigned int);
int fanotify_mark(int, unsigned int, uint64_t, int, const char *);

#ifdef __cplusplus
}
#endif

#endif
