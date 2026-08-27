#include <stdint.h>
#include <stddef.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef CRABC_CLONE_ORACLE
#include <sched.h>
#else
#include <signal.h>
#endif

#ifndef CRABC_CLONE_ORACLE
extern long crabc_clone_raw_probe_entry(int (*)(void *), unsigned char *, int, void *);
#endif

struct context {
    unsigned char *lo;
    unsigned char *hi;
    int code;
};

static int child(void *arg)
{
    const struct context *context = arg;
    unsigned char marker;

    const uintptr_t marker_address = (uintptr_t)&marker;
    return (marker_address >= (uintptr_t)context->lo
            && marker_address < (uintptr_t)context->hi) ? context->code : 99;
}

static long invoke_clone(
    int (*callback)(void *),
    unsigned char *stack,
    int flags,
    void *argument
)
{
#ifdef CRABC_CLONE_ORACLE
    return clone(callback, stack, flags, argument);
#else
    return crabc_clone_raw_probe_entry(callback, stack, flags, argument);
#endif
}

int main(void)
{
    static union {
        max_align_t alignment;
        unsigned char bytes[16 * 1024];
    } child_stack;
    struct context context = {
        .lo = child_stack.bytes,
        .hi = child_stack.bytes + sizeof(child_stack.bytes),
        .code = 42,
    };
    int status;
    long pid = invoke_clone(child, context.hi, SIGCHLD, &context);

    if (pid <= 0 || waitpid((pid_t)pid, &status, 0) != pid || !WIFEXITED(status)
        || WEXITSTATUS(status) != context.code) {
        return 3;
    }
    return 0;
}
