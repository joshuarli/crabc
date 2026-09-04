/* Source-only Linux/x86-64 <mqueue.h> mq_setattr declaration probe. */

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

_Static_assert(sizeof(mqd_t) == sizeof(int), "x86 mq_setattr mqd_t width");
_Static_assert(sizeof(struct mq_attr) == 64 && _Alignof(struct mq_attr) == 8,
    "x86 mq_setattr mq_attr layout");
_Static_assert(offsetof(struct mq_attr, mq_flags) == 0 &&
    offsetof(struct mq_attr, mq_maxmsg) == 8 &&
    offsetof(struct mq_attr, mq_msgsize) == 16 &&
    offsetof(struct mq_attr, mq_curmsgs) == 24 &&
    offsetof(struct mq_attr, __unused) == 32,
    "x86 mq_setattr mq_attr field offsets");
_Static_assert(SYS_mq_getsetattr == 245,
    "x86 mq_setattr syscall number");

static int (*mq_setattr_signature)(mqd_t, const struct mq_attr *,
    struct mq_attr *) = mq_setattr;

int crabc_x86_64_mq_setattr_header_abi_probe(void)
{
    (void)mq_setattr_signature;
    return SYS_mq_getsetattr;
}
