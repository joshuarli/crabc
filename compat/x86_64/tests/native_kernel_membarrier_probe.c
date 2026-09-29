#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/membarrier.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Read kernel registration state without calling libc's membarrier wrapper. */
struct observation {
    int command;
    long result;
    int errno_before;
    int errno_after;
};

struct stage {
    struct observation query;
    struct observation expedited;
};

struct child_result {
    struct stage before_register;
    struct observation register_private;
    struct stage after_register;
};

static struct stage preinit_state;
static int preinit_seen;

static long raw_membarrier(int command)
{
    long result;

    __asm__ volatile ("syscall" : "=a"(result)
        : "a"((long)SYS_membarrier), "D"((long)command), "S"(0L), "d"(0L)
        : "rcx", "r11", "memory");
    return result;
}

static struct observation observe(int command)
{
    struct observation record;

    record.command = command;
    errno = E2BIG;
    record.errno_before = errno;
    record.result = raw_membarrier(command);
    record.errno_after = errno;
    return record;
}

static struct stage observe_stage(void)
{
    struct stage record;

    record.query = observe(MEMBARRIER_CMD_QUERY);
    record.expedited = observe(MEMBARRIER_CMD_PRIVATE_EXPEDITED);
    return record;
}

/* This is the earliest C hook in the executable, before its constructors. */
static void observe_preinit(void)
{
    preinit_seen = 1;
    preinit_state = observe_stage();
}

__attribute__((used, section(".preinit_array")))
static void (*const preinit_hook)(void) = observe_preinit;

static int write_full(int fd, const void *data, size_t size)
{
    const unsigned char *bytes = data;

    while (size) {
        ssize_t written = write(fd, bytes, size);
        if (written <= 0) return -1;
        bytes += (size_t)written;
        size -= (size_t)written;
    }
    return 0;
}

static int read_full(int fd, void *data, size_t size)
{
    unsigned char *bytes = data;

    while (size) {
        ssize_t received = read(fd, bytes, size);
        if (received <= 0) return -1;
        bytes += (size_t)received;
        size -= (size_t)received;
    }
    return 0;
}

static void print_observation(const char *stage, struct observation value)
{
    printf("stage=%s command=%d raw=%ld errno_before=%d errno_after=%d\n",
        stage, value.command, value.result, value.errno_before, value.errno_after);
}

static void print_stage(const char *stage, struct stage value)
{
    print_observation(stage, value.query);
    print_observation(stage, value.expedited);
}

int main(void)
{
    struct stage before_allocation = observe_stage();
    void *allocation;
    int allocation_errno;
    struct stage after_allocation;
    struct child_result child_state;
    int channel[2];
    pid_t child;
    int status;

    errno = E2BIG;
    allocation = malloc(17);
    allocation_errno = errno;
    if (!allocation) return 10;
    ((volatile unsigned char *)allocation)[0] = 0x5a;
    after_allocation = observe_stage();
    if (pipe(channel) != 0) return 11;
    child = fork();
    if (child < 0) return 12;
    if (child == 0) {
        close(channel[0]);
        child_state.before_register = observe_stage();
        child_state.register_private = observe(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED);
        child_state.after_register = observe_stage();
        _exit(write_full(channel[1], &child_state, sizeof child_state) == 0 ? 0 : 13);
    }
    close(channel[1]);
    if (read_full(channel[0], &child_state, sizeof child_state) != 0) return 14;
    close(channel[0]);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 15;
    free(allocation);

    printf("preinit_seen=%d\n", preinit_seen);
    if (preinit_seen) print_stage("preinit", preinit_state);
    print_stage("main-before-malloc", before_allocation);
    printf("malloc_status=1 malloc_errno_after=%d\n", allocation_errno);
    print_stage("main-after-malloc", after_allocation);
    print_stage("child-before-register", child_state.before_register);
    print_observation("child-register", child_state.register_private);
    print_stage("child-after-register", child_state.after_register);
    printf("child_exit=%d\n", WEXITSTATUS(status));
    return 0;
}
