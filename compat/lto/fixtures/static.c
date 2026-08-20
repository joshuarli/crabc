/* Controlled C workload for the explicit musl/crabc static lane. */
#include <unistd.h>

int main(void) {
    /* Keep the static lane focused on startup, one libc call, and a syscall.
     * In particular, do not make allocator ABI compatibility a prerequisite
     * for measuring explicit archive selection. */
    pid_t pid = getpid();
    const char output[] = "lto-static-c:ok\n";
    if (write(STDOUT_FILENO, output, sizeof(output) - 1) != (ssize_t)(sizeof(output) - 1)) {
        return 2;
    }
    return pid > 0 ? 0 : 3;
}
