#define _GNU_SOURCE 1

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition, code) \
    do { \
        if (!(condition)) { \
            unlink(path); \
            return (code); \
        } \
    } while (0)

static pthread_mutex_t callback_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t callback_cond = PTHREAD_COND_INITIALIZER;

static void aio_callback(union sigval value)
{
    pthread_mutex_lock(&callback_mutex);
    ++*(int *)value.sival_ptr;
    pthread_cond_signal(&callback_cond);
    pthread_mutex_unlock(&callback_mutex);
}

int main(void)
{
    char path[128];
    int fd;
    char read_back[5] = { 0 };
    char verify[5] = { 0 };
    char write_data[] = "AIO!";
    struct aiocb read_cb = { 0 };
    struct aiocb write_cb = { 0 };
    struct aiocb sync_cb = { 0 };
    struct aiocb error_cb = { 0 };
    struct aiocb list_write = { 0 };
    struct aiocb list_read = { 0 };
    struct aiocb nowait_read = { 0 };
    struct aiocb list_error = { 0 };
    struct sigevent async_event = { 0 };
    int callback_seen = 0;
    const struct aiocb *wait_list[2];
    struct aiocb *list[2];
    struct timespec no_wait = { 0, 0 };

    if (snprintf(path, sizeof path, "/tmp/crabc-c-abi-aio-%ld", (long)getpid()) <= 0)
        return 1;
    fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0)
        return 2;
    if (write(fd, "seed", 4) != 4)
        return 3;

    read_cb.aio_fildes = fd;
    read_cb.aio_offset = 0;
    read_cb.aio_buf = read_back;
    read_cb.aio_nbytes = 4;
    read_cb.aio_lio_opcode = LIO_READ;
    CHECK(aio_read(&read_cb) == 0, 4);
    CHECK(aio_error(&read_cb) == 0, 5);
    CHECK(aio_return(&read_cb) == 4 && memcmp(read_back, "seed", 4) == 0, 6);
    wait_list[0] = &read_cb;
    wait_list[1] = NULL;
    CHECK(aio_suspend(wait_list, 2, &no_wait) == 0, 7);

    write_cb.aio_fildes = fd;
    write_cb.aio_offset = 0;
    write_cb.aio_buf = write_data;
    write_cb.aio_nbytes = 4;
    write_cb.aio_lio_opcode = LIO_WRITE;
    async_event.sigev_notify = SIGEV_THREAD;
    async_event.sigev_notify_function = aio_callback;
    async_event.sigev_value.sival_ptr = &callback_seen;
    write_cb.aio_sigevent = async_event;
    pthread_mutex_lock(&callback_mutex);
    int submit_result = aio_write(&write_cb);
    pthread_mutex_unlock(&callback_mutex);
    CHECK(submit_result == 0, 31);
    pthread_mutex_lock(&callback_mutex);
    while (callback_seen == 0)
        pthread_cond_wait(&callback_cond, &callback_mutex);
    int callback_result = callback_seen;
    pthread_mutex_unlock(&callback_mutex);
    CHECK(callback_result == 1, 32);
    CHECK(aio_error(&write_cb) == 0 && aio_return(&write_cb) == 4, 9);
    CHECK(pread(fd, verify, 4, 0) == 4 && memcmp(verify, "AIO!", 4) == 0, 10);
    CHECK(aio_cancel(fd, &write_cb) == AIO_ALLDONE, 11);
    CHECK(aio_return(&write_cb) == 4, 12);
    CHECK(aio_cancel(fd, NULL) == AIO_ALLDONE, 13);

    sync_cb.aio_fildes = fd;
    CHECK(aio_fsync(O_SYNC, &sync_cb) == 0, 14);
    CHECK(aio_error(&sync_cb) == 0 && aio_return(&sync_cb) == 0, 15);

    /* A valid submission can complete with an operation error. */
    error_cb.aio_fildes = open(path, O_RDONLY);
    CHECK(error_cb.aio_fildes >= 0, 16);
    error_cb.aio_buf = write_data;
    error_cb.aio_nbytes = 4;
    error_cb.aio_offset = 0;
    CHECK(aio_write(&error_cb) == 0, 17);
    CHECK(aio_error(&error_cb) == EBADF && aio_return(&error_cb) == -1, 18);
    list_write.aio_fildes = fd;
    list_write.aio_lio_opcode = LIO_WRITE;
    list_write.aio_offset = 0;
    list_write.aio_buf = "list";
    list_write.aio_nbytes = 4;
    list_read.aio_fildes = fd;
    list_read.aio_lio_opcode = LIO_READ;
    list_read.aio_offset = 0;
    list_read.aio_buf = verify;
    list_read.aio_nbytes = 4;
    list[0] = &list_write;
    list[1] = &list_read;
    CHECK(lio_listio(LIO_WAIT, list, 2, NULL) == 0, 20);
    CHECK(aio_error(&list_write) == 0 && aio_return(&list_write) == 4, 21);
    CHECK(aio_error(&list_read) == 0 && aio_return(&list_read) == 4 &&
              memcmp(verify, "list", 4) == 0, 22);

    nowait_read.aio_fildes = fd;
    nowait_read.aio_lio_opcode = LIO_READ;
    nowait_read.aio_offset = 0;
    nowait_read.aio_buf = read_back;
    nowait_read.aio_nbytes = 4;
    list[0] = &nowait_read;
    CHECK(lio_listio(LIO_NOWAIT, list, 1, NULL) == 0, 23);
    wait_list[0] = &nowait_read;
    CHECK(aio_suspend(wait_list, 1, &no_wait) == 0 &&
              aio_return(&nowait_read) == 4, 24);

    list_error.aio_fildes = error_cb.aio_fildes;
    list_error.aio_lio_opcode = LIO_WRITE;
    list_error.aio_buf = write_data;
    list_error.aio_nbytes = 4;
    list_error.aio_offset = 0;
    list[0] = &list_error;
    errno = 0;
    CHECK(lio_listio(LIO_WAIT, list, 1, NULL) == -1 && errno == EIO &&
              aio_error(&list_error) == EBADF && aio_return(&list_error) == -1, 25);

    errno = 0;
    CHECK(aio_cancel(fd + 1, &write_cb) == -1 && errno == EINVAL, 26);
    errno = 0;
    CHECK(aio_suspend(NULL, 0, &no_wait) == -1 && errno == EAGAIN, 30);
    CHECK(close(error_cb.aio_fildes) == 0, 27);
    CHECK(close(fd) == 0, 28);
    CHECK(unlink(path) == 0, 29);
    puts("c-abi posix aio ok");
    return 0;
}
