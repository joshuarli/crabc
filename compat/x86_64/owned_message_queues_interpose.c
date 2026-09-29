/* Public calls made by the pinned mq_getattr, mq_send, and mq_receive objects. */
#include <errno.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "message-queues-interpose:%d: %s errno=%d\n", __LINE__, #x, errno); \
    _Exit(95); \
} } while (0)

static int attributes_calls, send_calls, receive_calls;

int mq_setattr(mqd_t queue, const struct mq_attr *new_attributes,
               struct mq_attr *old_attributes) {
    CHECK(queue == -1 && new_attributes == NULL && old_attributes != NULL);
    attributes_calls++;
    old_attributes->mq_maxmsg = 17;
    return 0;
}

int mq_timedsend(mqd_t queue, const char *message, size_t length,
                 unsigned priority, const struct timespec *deadline) {
    CHECK(queue == -1 && length == 2 && !memcmp(message, "xy", 2));
    CHECK(priority == 9 && deadline == NULL);
    send_calls++;
    return 0;
}

ssize_t mq_timedreceive(mqd_t queue, char *message, size_t length,
                        unsigned *priority, const struct timespec *deadline) {
    CHECK(queue == -1 && length == 8 && priority != NULL && deadline == NULL);
    receive_calls++;
    memcpy(message, "abc", 3);
    *priority = 11;
    return 3;
}

int main(int argc, char **argv) {
    struct mq_attr attributes = {0};
    char message[8] = {0};
    unsigned priority = 0;
    if (argc == 2 && !strcmp(argv[1], "--shared-local")) {
        errno = 0;
        CHECK(mq_getattr(-1, &attributes) == -1 && errno == EBADF);
        errno = 0;
        CHECK(mq_send(-1, "xy", 2, 9) == -1 && errno == EBADF);
        errno = 0;
        CHECK(mq_receive(-1, message, sizeof message, &priority) == -1 && errno == EBADF);
        CHECK(attributes_calls == 0 && send_calls == 0 && receive_calls == 0);
        puts("owned-message-queues-local-ok");
        return 0;
    }
    CHECK(argc == 1);
    errno = 91;
    CHECK(mq_getattr(-1, &attributes) == 0 && attributes.mq_maxmsg == 17);
    CHECK(mq_send(-1, "xy", 2, 9) == 0);
    CHECK(mq_receive(-1, message, sizeof message, &priority) == 3);
    CHECK(!memcmp(message, "abc", 3) && priority == 11 && errno == 91);
    CHECK(attributes_calls == 1 && send_calls == 1 && receive_calls == 1);
    puts("owned-message-queues-interpose-ok");
}
