#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

typedef uint64_t eventfd_t;

struct epoll_event {
    uint32_t events;
    uint64_t data;
}
;

extern int ppoll(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);
extern int epoll_create(int);
extern int epoll_create1(int);
extern int epoll_ctl(int, int, int, const struct epoll_event *);
extern int epoll_wait(int, struct epoll_event *, int, int);
extern int epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);
extern int eventfd(unsigned int, int);
extern int eventfd_read(int, eventfd_t *);
extern int eventfd_write(int, eventfd_t);
extern int inotify_init(void);
extern int inotify_init1(int);
extern int inotify_add_watch(int, const char *, uint32_t);
extern int inotify_rm_watch(int, int);

struct inotify_event {
    int wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
};

#define EPOLL_CTL_ADD 1
#define EPOLLIN 0x001
#define EFD_NONBLOCK 0x800
#define IN_NONBLOCK 0x800
#define IN_CLOEXEC 0x80000
#define IN_CREATE 0x00000100
#define IN_DELETE 0x00000200

static int check_poll_and_ppoll(void) {
    int p[2];
    struct pollfd fd;
    struct timespec zero = {0, 0};
    char byte = 'p';

    if (pipe(p) != 0) return 1;
    fd.fd = p[0];
    fd.events = POLLIN;
    fd.revents = 0;
    if (poll(&fd, 1, 0) != 0 || fd.revents != 0) return 2;
    if (write(p[1], &byte, 1) != 1) return 3;
    fd.revents = 0;
    if (poll(&fd, 1, 0) != 1 || !(fd.revents & POLLIN)) return 4;
    if (ppoll(&fd, 1, &zero, NULL) != 1 || !(fd.revents & POLLIN)) return 5;
    if (read(p[0], &byte, 1) != 1) return 6;
    close(p[0]);
    close(p[1]);
    return 0;
}

static int check_epoll(void) {
    int p[2];
    int epfd;
    struct epoll_event add;
    struct epoll_event got;
    char byte = 'e';

    errno = 0;
    if (epoll_create1(0x40000000) != -1 || errno != EINVAL) return 10;
    epfd = epoll_create(1);
    if (epfd < 0) return 11;
    close(epfd);
    if (pipe(p) != 0) return 12;
    epfd = epoll_create1(0);
    if (epfd < 0) return 13;
    memset(&add, 0, sizeof add);
    add.events = EPOLLIN;
    add.data = UINT64_C(0x123456789abcdef0);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &add) != 0) return 14;
    if (write(p[1], &byte, 1) != 1) return 15;
    memset(&got, 0, sizeof got);
    if (epoll_wait(epfd, &got, 1, 0) != 1) return 16;
    if (!(got.events & EPOLLIN) || got.data != UINT64_C(0x123456789abcdef0)) return 17;
    if (read(p[0], &byte, 1) != 1) return 18;
    if (epoll_pwait(epfd, &got, 1, 0, NULL) != 0) return 19;
    close(epfd);
    close(p[0]);
    close(p[1]);
    return 0;
}

static int check_eventfd(void) {
    int fd;
    struct pollfd p;
    eventfd_t value = 0;

    fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) return 20;
    p.fd = fd;
    p.events = POLLIN;
    p.revents = 0;
    if (poll(&p, 1, 0) != 0) return 21;
    if (eventfd_write(fd, 5) != 0) return 22;
    if (poll(&p, 1, 0) != 1 || !(p.revents & POLLIN)) return 23;
    if (eventfd_read(fd, &value) != 0 || value != 5) return 24;
    errno = 0;
    if (eventfd_read(fd, &value) != -1 || errno != EAGAIN) return 25;
    close(fd);
    return 0;
}

static int check_inotify(void) {
    const char *path = "/tmp/crabc-c-abi-inotify-file";
    char buffer[512];
    struct pollfd p;
    struct inotify_event *event;
    int fd, wd, file, result;

    unlink(path);
    errno = 0;
    if (inotify_init1(0x40000000) != -1 || errno != EINVAL) return 30;
    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return 31;
    wd = inotify_add_watch(fd, "/tmp", IN_CREATE | IN_DELETE);
    if (wd < 0) return 32;
    file = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (file < 0) return 33;
    close(file);
    p.fd = fd;
    p.events = POLLIN;
    p.revents = 0;
    if (poll(&p, 1, 1000) != 1 || !(p.revents & POLLIN)) return 34;
    result = (int)read(fd, buffer, sizeof buffer);
    if (result < (int)sizeof(struct inotify_event)) return 35;
    event = (struct inotify_event *)buffer;
    if (event->wd != wd || !(event->mask & IN_CREATE)) return 36;
    if (inotify_rm_watch(fd, wd) != 0) return 37;
    close(fd);
    unlink(path);
    return 0;
}

int main(void) {
    int result;
    result = check_poll_and_ppoll();
    if (result) return result;
    result = check_epoll();
    if (result) return result;
    result = check_eventfd();
    if (result) return result;
    result = check_inotify();
    if (result) return result;
    puts("poll events ok");
    return 0;
}
