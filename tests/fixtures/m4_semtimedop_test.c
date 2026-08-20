#include <errno.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <time.h>

static void remove_set(int id)
{
    if (id >= 0)
        semctl(id, 0, IPC_RMID);
}

int main(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    struct sembuf wait_for_zero = { 0, 0, 0 };
    struct sembuf decrement = { 0, -1, IPC_NOWAIT };
    struct timespec no_wait = { 0, 0 };

    if (id < 0)
        return 1;
    if (semtimedop(id, &wait_for_zero, 1, &no_wait) != 0) {
        remove_set(id);
        return 2;
    }

    errno = 0;
    if (semtimedop(id, &decrement, 1, &no_wait) != -1 || errno != EAGAIN) {
        remove_set(id);
        return 3;
    }
    if (semctl(id, 0, IPC_RMID) != 0)
        return 4;

    errno = 0;
    if (semtimedop(-1, &wait_for_zero, 1, &no_wait) != -1 || errno != EINVAL)
        return 5;

    puts("m4 semtimedop ok");
    return 0;
}
