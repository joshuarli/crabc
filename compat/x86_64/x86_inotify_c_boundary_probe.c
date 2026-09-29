/* Selected x86 C inotify boundary against pinned musl and owned static libc.
 * The fixture uses direct Linux syscalls for filesystem setup and event reads;
 * only the inotify calls under test cross the selected C ABI.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/inotify.h>
#include <sys/syscall.h>

static long kernel_call(long number, long a, long b, long c, long d)
{
    register long fourth __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c), "r"(fourth)
                     : "rcx", "r11", "memory");
    return result;
}

#define KC1(n, a) kernel_call((n), (long)(a), 0, 0, 0)
#define KC3(n, a, b, c) kernel_call((n), (long)(a), (long)(b), (long)(c), 0)
#define KC4(n, a, b, c, d) kernel_call((n), (long)(a), (long)(b), (long)(c), (long)(d))

static const char source_name[] = "source\xff";
static const char moved_name[] = "moved\xfe";

static int expected_error(int result, int expected)
{
    return result == -1 && errno == expected;
}

static int read_events(int fd, uint32_t *storage, unsigned capacity)
{
    long length = KC3(SYS_read, fd, storage, capacity);
    return length > 0 && length <= (long)capacity ? (int)length : -1;
}

/* Each event is consumed as a complete, aligned Linux record. The name
 * length includes NUL and padding; compare the byte name before its NUL.
 */
static int find_event(const uint32_t *storage, int length, int watch,
                      uint32_t mask, const char *name, uint32_t *cookie)
{
    const unsigned char *bytes = (const unsigned char *)storage;
    int offset = 0;
    while (offset + 16 <= length) {
        const struct inotify_event *event =
            (const struct inotify_event *)(bytes + offset);
        unsigned i = 0;
        if (event->len > (unsigned)(length - offset - 16) ||
            (event->len & 3) != 0) return 0;
        if (event->wd == watch && (event->mask & mask) == mask) {
            if (name == 0 && event->len == 0) {
                if (cookie) *cookie = event->cookie;
                return 1;
            }
            if (name != 0 && event->len != 0) {
                while (i < event->len && name[i] &&
                       event->name[i] == name[i]) i++;
                if (i < event->len && name[i] == 0 &&
                    event->name[i] == 0) {
                    if (cookie) *cookie = event->cookie;
                    return 1;
                }
            }
        }
        offset += 16 + (int)event->len;
    }
    return 0;
}

int crabc_x86_64_event_descriptors_probe(void)
{
    uint32_t events[1024];
    uint32_t from_cookie = 0, to_cookie = 0;
    int fd, held, dir, watch, file_watch, file, length;

    if (KC3(SYS_mkdirat, AT_FDCWD, "watched", 0700) != 0) return 10;
    dir = (int)KC4(SYS_openat, AT_FDCWD, "watched",
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dir < 0) return 11;
    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return 12;
    if (!expected_error(inotify_init1(IN_CLOEXEC | 1), EINVAL)) return 13;
    watch = inotify_add_watch(fd, "watched", IN_CREATE);
    if (watch < 0) return 14;
    if (!expected_error(inotify_add_watch(fd, "watched",
                                          IN_MASK_CREATE | IN_CREATE), EEXIST)) return 15;
    if (inotify_add_watch(fd, "watched", IN_MASK_ADD | IN_MOVED_FROM |
                          IN_MOVED_TO | IN_DELETE) != watch) return 16;
    if (!expected_error(inotify_add_watch(-1, (const char *)0, IN_CREATE), EBADF))
        return 17;
    if (!expected_error(inotify_add_watch(fd, (const char *)0, IN_CREATE), EFAULT))
        return 18;
    if (!expected_error(inotify_rm_watch(-1, watch), EBADF)) return 19;

    file = (int)KC4(SYS_openat, dir, source_name,
                    O_CREAT | O_EXCL | O_RDONLY | O_CLOEXEC, 0600);
    if (file < 0) return 20;
    if (KC1(SYS_close, file) != 0) return 21;
    length = read_events(fd, events, sizeof(events));
    if (length < 0 || !find_event(events, length, watch, IN_CREATE,
                                  source_name, 0)) return 22;

    if (KC4(SYS_renameat, dir, source_name, dir, moved_name) != 0) return 23;
    length = read_events(fd, events, sizeof(events));
    if (length < 0 || !find_event(events, length, watch, IN_MOVED_FROM,
                                  source_name, &from_cookie) ||
        !find_event(events, length, watch, IN_MOVED_TO,
                    moved_name, &to_cookie) ||
        from_cookie == 0 || from_cookie != to_cookie) return 24;

    if (inotify_add_watch(fd, "watched", IN_DELETE | IN_DELETE_SELF) != watch)
        return 25;
    file = (int)KC4(SYS_openat, dir, "unwatched", O_CREAT | O_EXCL | O_RDONLY, 0600);
    if (file < 0 || KC1(SYS_close, file) != 0) return 26;
    if (KC3(SYS_read, fd, events, sizeof(events)) != -EAGAIN) return 27;
    if (KC3(SYS_unlinkat, dir, "unwatched", 0) != 0) return 28;
    length = read_events(fd, events, sizeof(events));
    if (length < 0 || !find_event(events, length, watch, IN_DELETE,
                                  "unwatched", 0)) return 29;

    file_watch = inotify_add_watch(fd, "watched/moved\xfe", IN_DELETE_SELF);
    if (file_watch < 0 || file_watch == watch) return 30;
    if (KC4(SYS_renameat, AT_FDCWD, "watched", AT_FDCWD, "renamed") != 0)
        return 31;
    file = (int)KC4(SYS_openat, dir, "after-rename", O_CREAT | O_EXCL | O_RDONLY, 0600);
    if (file < 0 || KC1(SYS_close, file) != 0) return 32;
    if (KC3(SYS_unlinkat, dir, moved_name, 0) != 0) return 33;
    length = read_events(fd, events, sizeof(events));
    if (length < 0 || !find_event(events, length, watch, IN_DELETE,
                                  moved_name, 0) ||
        !find_event(events, length, file_watch, IN_DELETE_SELF, 0, 0) ||
        !find_event(events, length, file_watch, IN_IGNORED, 0, 0)) return 34;
    if (!expected_error(inotify_rm_watch(fd, file_watch), EINVAL)) return 35;

    held = (int)KC1(SYS_dup, fd);
    if (held < 0 || KC1(SYS_close, fd) != 0) return 36;
    if (KC3(SYS_unlinkat, dir, "after-rename", 0) != 0) return 37;
    length = read_events(held, events, sizeof(events));
    if (length < 0 || !find_event(events, length, watch, IN_DELETE,
                                  "after-rename", 0)) return 38;
    if (KC1(SYS_close, dir) != 0) return 39;
    if (KC3(SYS_unlinkat, AT_FDCWD, "renamed", AT_REMOVEDIR) != 0) return 40;
    length = read_events(held, events, sizeof(events));
    if (length < 0 || !find_event(events, length, watch, IN_DELETE_SELF, 0, 0) ||
        !find_event(events, length, watch, IN_IGNORED, 0, 0))
        return 41;
    if (!expected_error(inotify_rm_watch(held, watch), EINVAL)) return 42;
    if (KC1(SYS_close, held) != 0) return 43;
    fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) return 44;
    if (!expected_error(inotify_rm_watch(fd, watch), EINVAL)) return 45;
    if (KC1(SYS_close, fd) != 0) return 46;
    return 0;
}

#ifndef CRABC_EVENT_DESCRIPTORS_FREESTANDING
int main(void)
{
    return crabc_x86_64_event_descriptors_probe();
}
#endif
