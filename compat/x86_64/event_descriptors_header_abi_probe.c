/* Selected Linux/x86-64 <sys/eventfd.h>/<sys/inotify.h> ABI facts. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>

typedef int (*crabc_eventfd_signature)(unsigned int, int);
typedef int (*crabc_eventfd_read_signature)(int, eventfd_t *);
typedef int (*crabc_eventfd_write_signature)(int, eventfd_t);
typedef int (*crabc_inotify_init_signature)(void);
typedef int (*crabc_inotify_init1_signature)(int);
typedef int (*crabc_inotify_add_watch_signature)(int, const char *, uint32_t);
typedef int (*crabc_inotify_rm_watch_signature)(int, int);

_Static_assert(sizeof(eventfd_t) == 8 && _Alignof(eventfd_t) == 8 &&
                   __builtin_types_compatible_p(eventfd_t, uint64_t),
               "x86 eventfd_t ABI");
_Static_assert(EFD_SEMAPHORE == 1 && EFD_CLOEXEC == O_CLOEXEC &&
                   EFD_NONBLOCK == O_NONBLOCK,
               "eventfd flag values");

_Static_assert(sizeof(struct inotify_event) == 16 &&
                   _Alignof(struct inotify_event) == 4,
               "x86 inotify record header ABI");
_Static_assert(offsetof(struct inotify_event, wd) == 0 &&
                   offsetof(struct inotify_event, mask) == 4 &&
                   offsetof(struct inotify_event, cookie) == 8 &&
                   offsetof(struct inotify_event, len) == 12 &&
                   offsetof(struct inotify_event, name) == 16,
               "x86 inotify record offsets");
_Static_assert(IN_CLOEXEC == O_CLOEXEC && IN_NONBLOCK == O_NONBLOCK &&
                   IN_ACCESS == 0x00000001 && IN_MODIFY == 0x00000002 &&
                   IN_CREATE == 0x00000100 && IN_DELETE == 0x00000200 &&
                   IN_IGNORED == 0x00008000 && IN_ONLYDIR == 0x01000000 &&
                   IN_DONT_FOLLOW == 0x02000000 && IN_EXCL_UNLINK == 0x04000000 &&
                   IN_MASK_CREATE == 0x10000000 && IN_MASK_ADD == 0x20000000 &&
                   IN_ISDIR == 0x40000000 && IN_ONESHOT == 0x80000000,
               "selected inotify constants");

_Static_assert(__builtin_types_compatible_p(__typeof__(&eventfd),
                                             crabc_eventfd_signature),
               "eventfd declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&eventfd_read),
                                             crabc_eventfd_read_signature),
               "eventfd_read declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&eventfd_write),
                                             crabc_eventfd_write_signature),
               "eventfd_write declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inotify_init),
                                             crabc_inotify_init_signature),
               "inotify_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inotify_init1),
                                             crabc_inotify_init1_signature),
               "inotify_init1 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inotify_add_watch),
                                             crabc_inotify_add_watch_signature),
               "inotify_add_watch declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inotify_rm_watch),
                                             crabc_inotify_rm_watch_signature),
               "inotify_rm_watch declaration");

int crabc_x86_64_event_descriptors_header_abi_probe(void)
{
    return EFD_SEMAPHORE + IN_IGNORED;
}
