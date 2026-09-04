/* Source-only Linux/x86-64 C++ <mqueue.h> mq_setattr declaration probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <mqueue.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

#ifdef MQ_PRIO_MAX
#error "MQ_PRIO_MAX belongs to <limits.h>, not <mqueue.h>"
#endif

static_assert(sizeof(mqd_t) == sizeof(int), "x86 mq_setattr mqd_t width");
static_assert(sizeof(mq_attr) == 64 && alignof(mq_attr) == 8,
    "x86 mq_setattr mq_attr layout");
static_assert(offsetof(mq_attr, mq_flags) == 0 &&
    offsetof(mq_attr, mq_maxmsg) == 8 &&
    offsetof(mq_attr, mq_msgsize) == 16 &&
    offsetof(mq_attr, mq_curmsgs) == 24 &&
    offsetof(mq_attr, __unused) == 32,
    "x86 mq_setattr mq_attr field offsets");
static_assert(SYS_mq_getsetattr == 245, "x86 mq_setattr syscall number");

using mq_setattr_function = int (*)(mqd_t, const mq_attr *, mq_attr *);
static_assert(__is_same(decltype(&mq_setattr), mq_setattr_function),
    "x86 mq_setattr declaration");

int crabc_x86_64_mq_setattr_header_abi_probe()
{
    return SYS_mq_getsetattr;
}
