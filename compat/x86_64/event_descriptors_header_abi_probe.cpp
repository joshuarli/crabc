/*
 * C++17 companion for selected Linux/x86-64 event-descriptor headers.
 *
 * The direct event-descriptor declarations are unconditional in musl 1.2.6.
 * The opt-in AT_EMPTY_PATH checks retain the one immediate <fcntl.h>
 * GNU/BSD-versus-strict visibility boundary without expanding this into a
 * general fcntl header assertion.
 */

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
                  IN_ATTRIB == 0x00000004 && IN_CLOSE_WRITE == 0x00000008 &&
                  IN_CLOSE_NOWRITE == 0x00000010 && IN_CLOSE == 0x00000018 &&
                  IN_OPEN == 0x00000020 && IN_MOVED_FROM == 0x00000040 &&
                  IN_MOVED_TO == 0x00000080 && IN_MOVE == 0x000000c0 &&
                  IN_CREATE == 0x00000100 && IN_DELETE == 0x00000200 &&
                  IN_DELETE_SELF == 0x00000400 && IN_MOVE_SELF == 0x00000800 &&
                  IN_ALL_EVENTS == 0x00000fff && IN_UNMOUNT == 0x00002000 &&
                  IN_Q_OVERFLOW == 0x00004000 && IN_IGNORED == 0x00008000 &&
                  IN_ONLYDIR == 0x01000000 && IN_DONT_FOLLOW == 0x02000000 &&
                  IN_EXCL_UNLINK == 0x04000000 && IN_MASK_CREATE == 0x10000000 &&
                  IN_MASK_ADD == 0x20000000 && IN_ISDIR == 0x40000000 &&
                  IN_ONESHOT == 0x80000000,
              "C++ inotify constants");

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

#if defined(CRABC_EVENT_DESCRIPTOR_REQUIRE_AT_EMPTY_PATH)
#ifndef AT_EMPTY_PATH
#error "GNU/BSD event-descriptor profile must expose AT_EMPTY_PATH through fcntl.h"
#endif
static_assert(AT_EMPTY_PATH == 0x1000,
              "C++ GNU/BSD event-descriptor profile AT_EMPTY_PATH value");
#endif

#if defined(CRABC_EVENT_DESCRIPTOR_REQUIRE_AT_EMPTY_PATH_HIDDEN)
#ifdef AT_EMPTY_PATH
#error "C++ strict/POSIX/XOPEN event-descriptor profile must hide AT_EMPTY_PATH"
#endif
#endif

/* `used` keeps the header-requested external spellings observable to nm. */
__attribute__((used)) static eventfd_signature eventfd_cxx_eventfd = eventfd;
__attribute__((used)) static eventfd_read_signature eventfd_cxx_eventfd_read = eventfd_read;
__attribute__((used)) static eventfd_write_signature eventfd_cxx_eventfd_write = eventfd_write;
__attribute__((used)) static inotify_init_signature inotify_cxx_init = inotify_init;
__attribute__((used)) static inotify_init1_signature inotify_cxx_init1 = inotify_init1;
__attribute__((used)) static inotify_add_watch_signature inotify_cxx_add_watch =
    inotify_add_watch;
__attribute__((used)) static inotify_rm_watch_signature inotify_cxx_rm_watch =
    inotify_rm_watch;

int crabc_x86_64_event_descriptors_header_abi_probe_cpp()
{
    return EFD_SEMAPHORE + IN_IGNORED;
}
