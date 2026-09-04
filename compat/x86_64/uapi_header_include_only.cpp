/* C++ include-order-only half of the x86 public UAPI closure matrix. */
#if defined(CRABC_UAPI_IOCTL_ONLY)
#include <sys/ioctl.h>
#elif defined(CRABC_UAPI_MOUNT_ONLY)
#include <sys/mount.h>
#elif defined(CRABC_UAPI_PTY_ONLY)
#include <pty.h>
#elif defined(CRABC_UAPI_MTIO_ONLY)
#include <sys/mtio.h>
#elif defined(CRABC_UAPI_MOUNT_IOCTL)
#include <sys/mount.h>
#include <sys/ioctl.h>
#elif defined(CRABC_UAPI_PTY_IOCTL)
#include <pty.h>
#include <sys/ioctl.h>
#elif defined(CRABC_UAPI_MTIO_IOCTL)
#include <sys/mtio.h>
#include <sys/ioctl.h>
#else
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <pty.h>
#include <sys/mtio.h>
#endif
int main() { return 0; }
