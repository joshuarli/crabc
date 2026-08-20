#ifndef _AIO_H
#define _AIO_H

#include <sys/types.h>
#include <time.h>
#include <signal.h>

struct aiocb {
    int aio_fildes;
    off_t aio_offset;
    volatile void *aio_buf;
    size_t aio_nbytes;
    int aio_reqprio;
    struct sigevent aio_sigevent;
    int aio_lio_opcode;
    int __reserved[8];
};

#define AIO_ALLDONE 2
#define AIO_CANCELED 0
#define AIO_NOTCANCELED 1
#define LIO_READ 0
#define LIO_WRITE 1
#define LIO_NOP 2
#define LIO_NOWAIT 0
#define LIO_WAIT 1

int aio_cancel(int, struct aiocb *);
int aio_error(const struct aiocb *);
int aio_fsync(int, struct aiocb *);
int aio_read(struct aiocb *);
ssize_t aio_return(struct aiocb *);
int aio_suspend(const struct aiocb *const [], int, const struct timespec *);
int aio_write(struct aiocb *);
int lio_listio(int, struct aiocb *restrict const [restrict], int, struct sigevent *restrict);

#endif
