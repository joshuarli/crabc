#ifndef _SYS_KLOG_H
#define _SYS_KLOG_H

#ifdef __cplusplus
extern "C" {
#endif

#define KLOG_CLOSE         0
#define KLOG_OPEN          1
#define KLOG_READ          2
#define KLOG_READ_ALL      3
#define KLOG_READ_CLEAR    4
#define KLOG_CLEAR         5
#define KLOG_CONSOLE_OFF   6
#define KLOG_CONSOLE_ON    7
#define KLOG_CONSOLE_LEVEL 8
#define KLOG_SIZE_UNREAD   9
#define KLOG_SIZE_BUFFER   10

int klogctl(int, char *, int);

#ifdef __cplusplus
}
#endif

#endif
