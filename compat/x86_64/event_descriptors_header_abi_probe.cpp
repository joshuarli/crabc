/* C++17 companion for selected Linux/x86-64 event-descriptor headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>

using eventfd_signature = int (*)(unsigned int, int);
using eventfd_read_signature = int (*)(int, eventfd_t *);
using eventfd_write_signature = int (*)(int, eventfd_t);
using inotify_init_signature = int (*)(void);
using inotify_init1_signature = int (*)(int);
using inotify_add_watch_signature = int (*)(int, const char *, uint32_t);
using inotify_rm_watch_signature = int (*)(int, int);

static_assert(sizeof(eventfd_t) == 8 && alignof(eventfd_t) == 8 &&
                  __is_same(eventfd_t, uint64_t),
              "C++ x86 eventfd_t ABI");
static_assert(EFD_SEMAPHORE == 1 && EFD_CLOEXEC == O_CLOEXEC &&
                  EFD_NONBLOCK == O_NONBLOCK,
              "C++ eventfd flag values");
static_assert(sizeof(struct inotify_event) == 16 &&
                  alignof(struct inotify_event) == 4,
              "C++ x86 inotify record header ABI");
static_assert(__builtin_offsetof(struct inotify_event, wd) == 0 &&
                  __builtin_offsetof(struct inotify_event, mask) == 4 &&
                  __builtin_offsetof(struct inotify_event, cookie) == 8 &&
                  __builtin_offsetof(struct inotify_event, len) == 12 &&
                  __builtin_offsetof(struct inotify_event, name) == 16,
              "C++ x86 inotify record offsets");
static_assert(IN_CLOEXEC == O_CLOEXEC && IN_NONBLOCK == O_NONBLOCK &&
                  IN_ACCESS == 0x00000001 && IN_MODIFY == 0x00000002 &&
                  IN_CREATE == 0x00000100 && IN_DELETE == 0x00000200 &&
                  IN_IGNORED == 0x00008000 && IN_ONLYDIR == 0x01000000 &&
                  IN_DONT_FOLLOW == 0x02000000 && IN_EXCL_UNLINK == 0x04000000 &&
                  IN_MASK_CREATE == 0x10000000 && IN_MASK_ADD == 0x20000000 &&
                  IN_ISDIR == 0x40000000 && IN_ONESHOT == 0x80000000,
              "C++ selected inotify constants");

static_assert(__is_same(decltype(&eventfd), eventfd_signature),
              "C++ eventfd declaration");
static_assert(__is_same(decltype(&eventfd_read), eventfd_read_signature),
              "C++ eventfd_read declaration");
static_assert(__is_same(decltype(&eventfd_write), eventfd_write_signature),
              "C++ eventfd_write declaration");
static_assert(__is_same(decltype(&inotify_init), inotify_init_signature),
              "C++ inotify_init declaration");
static_assert(__is_same(decltype(&inotify_init1), inotify_init1_signature),
              "C++ inotify_init1 declaration");
static_assert(__is_same(decltype(&inotify_add_watch), inotify_add_watch_signature),
              "C++ inotify_add_watch declaration");
static_assert(__is_same(decltype(&inotify_rm_watch), inotify_rm_watch_signature),
              "C++ inotify_rm_watch declaration");

extern "C" int eventfd(unsigned int, int);
extern "C" int eventfd_read(int, eventfd_t *);
extern "C" int eventfd_write(int, eventfd_t);
extern "C" int inotify_init(void);
extern "C" int inotify_init1(int);
extern "C" int inotify_add_watch(int, const char *, uint32_t);
extern "C" int inotify_rm_watch(int, int);

int crabc_x86_64_event_descriptors_header_abi_probe_cpp()
{
    return EFD_SEMAPHORE + IN_IGNORED;
}
