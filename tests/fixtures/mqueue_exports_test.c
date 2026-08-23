#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what)
{
    fprintf(stderr, "mqueue failure: %s (errno=%d)\n", what, errno);
    return 1;
}

int main(void)
{
    char name[64];
    const char message[] = "crabc mqueue";
    char received[64];
    unsigned priority = 0;
    struct mq_attr create_attr;
    struct mq_attr attr;
    struct mq_attr old_attr;
    struct sigevent notification;
    struct timespec expired = { 0, 0 };
    mqd_t queue = (mqd_t)-1;
    ssize_t length;
    int result = 1;

    snprintf(name, sizeof name, "/crabc-c-abi-mq-%ld", (long)getpid());
    errno = 0;
    if (mq_unlink(name) == -1 && errno != ENOENT)
        return fail("initial mq_unlink error");
    errno = 0;
    if (mq_unlink("not-a-posix-mqueue-name") != -1 || errno != EINVAL)
        return fail("mq_unlink name validation");

    memset(&create_attr, 0, sizeof create_attr);
    create_attr.mq_maxmsg = 4;
    create_attr.mq_msgsize = 64;
    queue = mq_open(name, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0600,
                    &create_attr);
    if (queue == (mqd_t)-1)
        return fail("mq_open");

    memset(&attr, 0, sizeof attr);
    if (mq_getattr(queue, &attr) != 0)
        goto cleanup;
    if (attr.mq_flags != O_NONBLOCK || attr.mq_maxmsg != 4 ||
        attr.mq_msgsize != 64 || attr.mq_curmsgs != 0)
        goto cleanup;

    /* mq_setattr changes only mq_flags and returns the previous attributes. */
    memset(&old_attr, 0, sizeof old_attr);
    attr.mq_flags = 0;
    if (mq_setattr(queue, &attr, &old_attr) != 0 ||
        old_attr.mq_flags != O_NONBLOCK)
        goto cleanup;
    if (mq_getattr(queue, &old_attr) != 0 || old_attr.mq_flags != 0)
        goto cleanup;

    attr.mq_flags = O_NONBLOCK;
    if (mq_setattr(queue, &attr, NULL) != 0)
        goto cleanup;

    if (mq_send(queue, message, sizeof message - 1, 7) != 0)
        goto cleanup;
    memset(received, 0, sizeof received);
    length = mq_receive(queue, received, sizeof received, &priority);
    if (length != (ssize_t)(sizeof message - 1) || priority != 7 ||
        memcmp(received, message, sizeof message - 1) != 0)
        goto cleanup;

    /* The non-blocking queue makes an empty timed receive deterministic. */
    errno = 0;
    if (mq_timedreceive(queue, received, sizeof received, &priority,
                        &expired) != -1 || errno != EAGAIN)
        goto cleanup;
    if (mq_timedsend(queue, message, sizeof message - 1, 3, &expired) != 0)
        goto cleanup;
    memset(&notification, 0, sizeof notification);
    if (sizeof notification != 64)
        goto cleanup;
    notification.sigev_notify = SIGEV_NONE;
    if (mq_notify(queue, &notification) != 0 || mq_notify(queue, NULL) != 0)
        goto cleanup;

    errno = 0;
    if (mq_close(-1) != -1 || errno != EBADF)
        goto cleanup;
    errno = 0;
    if (mq_receive(-1, received, sizeof received, &priority) != -1 ||
        errno != EBADF)
        goto cleanup;

    /* Unlink removes the name while the open descriptor remains usable. */
    if (mq_unlink(name) != 0)
        goto cleanup;
    if (mq_close(queue) != 0)
        return fail("mq_close");
    queue = (mqd_t)-1;
    errno = 0;
    if (mq_open(name, O_RDONLY | O_NONBLOCK) != (mqd_t)-1 ||
        errno != ENOENT)
        goto cleanup;

    result = 0;

cleanup:
    if (queue != (mqd_t)-1) {
        mq_close(queue);
        mq_unlink(name);
    }
    if (result == 0)
        puts("c-abi mqueue exports ok");
    return result;
}
