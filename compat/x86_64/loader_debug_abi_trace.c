#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t child;
static void fail(const char *message)
{
    perror(message);
    if (child > 0) { kill(child, SIGKILL); waitpid(child, 0, 0); }
    exit(100);
}
static long peek(uintptr_t address)
{
    errno = 0;
    long value = ptrace(PTRACE_PEEKDATA, child, (void *)address, 0);
    if (errno) fail("debugger peek");
    return value;
}
static void memory(uintptr_t address, void *output, size_t bytes)
{
    if (bytes % sizeof(long)) fail("debugger memory alignment");
    for (size_t offset = 0; offset < bytes; offset += sizeof(long)) {
        long value = peek(address + offset);
        memcpy((char *)output + offset, &value, sizeof value);
    }
}
static void poke(uintptr_t address, long value)
{
    if (ptrace(PTRACE_POKETEXT, child, (void *)address, (void *)value)) fail("debugger poke");
}
static int wait_child(void)
{
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) fail("debugger wait");
    return status;
}
static uintptr_t provider_base(const struct stat *provider)
{
    char path[80], line[8192], permissions[8];
    snprintf(path, sizeof path, "/proc/%ld/maps", (long)child);
    FILE *maps = fopen(path, "r");
    if (!maps) fail("debugger maps");
    uintptr_t result = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long start, end, offset, inode;
        unsigned device_major, device_minor;
        if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu", &start, &end,
                   permissions, &offset, &device_major, &device_minor, &inode) != 7)
            fail("debugger maps row");
        if (offset == 0 && inode == provider->st_ino
            && device_major == major(provider->st_dev) && device_minor == minor(provider->st_dev)) {
            if (result) fail("debugger ambiguous provider");
            result = start;
        }
    }
    fclose(maps);
    if (!result) fail("debugger missing provider");
    return result;
}

/* Infrastructure only: observe the actual loader breakpoint, without
 * replacing _dl_debug_state or calling application code under its lock.
 * ELF offsets come from the reader's inspected immutable loader/provider. */
int main(int argc, char **argv)
{
    if (argc != 8) return 2;
    const char *root = argv[1], *interpreter = argv[2], *consumer = argv[3];
    uintptr_t entry = strtoull(argv[4], 0, 0), hook = strtoull(argv[5], 0, 0);
    uintptr_t pointer_offset = strtoull(argv[7], 0, 0);
    struct stat provider;
    if (stat(argv[6], &provider)) fail("debugger provider stat");
    child = fork();
    if (child < 0) fail("debugger fork");
    if (!child) {
        if (chroot(root) || chdir("/")) _exit(101);
        if (setenv("CRABC_DEBUGGER_TRACE", "1", 1)) _exit(105);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(102);
        raise(SIGSTOP);
        if (strcmp(interpreter, "kernel")) execl(interpreter, interpreter, consumer, "trace", (char *)0);
        else execl(consumer, consumer, "trace", (char *)0);
        _exit(103);
    }
    int status = wait_child();
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) fail("debugger initial stop");
    if (ptrace(PTRACE_SETOPTIONS, child, 0, (void *)(PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL))
        || ptrace(PTRACE_CONT, child, 0, 0)) fail("debugger continue to exec");
    status = wait_child();
    if (!WIFSTOPPED(status) || (unsigned)status >> 16 != PTRACE_EVENT_EXEC) fail("debugger exec stop");
    struct user_regs_struct registers;
    if (ptrace(PTRACE_GETREGS, child, 0, &registers)) fail("debugger entry registers");
    uintptr_t loader_base = registers.rip - entry;
    uintptr_t breakpoint = loader_base + hook;
    long original = peek(breakpoint);
    poke(breakpoint, (original & ~255L) | 0xcc);
    if (ptrace(PTRACE_CONT, child, 0, 0)) fail("debugger start");
    unsigned events = 0, initial_count = 0, maximum_delta = 0;
    uintptr_t debug_address = 0;
    for (;;) {
        status = wait_child();
        if (WIFEXITED(status)) {
            child = 0;
            if (WEXITSTATUS(status) || events < 5 || !(events & 1) || maximum_delta != 1) return 104;
            return 0;
        }
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) fail("debugger unexpected child stop");
        if (ptrace(PTRACE_GETREGS, child, 0, &registers) || registers.rip != breakpoint + 1)
            fail("debugger breakpoint registers");
        uintptr_t actual = (uintptr_t)peek(provider_base(&provider) + pointer_offset);
        if (!actual || (debug_address && debug_address != actual)) fail("debugger pointer ownership");
        debug_address = actual;
        struct r_debug debug;
        memory(debug_address, &debug, sizeof debug);
        int expected = !events || !(events & 1) ? RT_CONSISTENT : RT_ADD;
        if (debug.r_version != 1 || debug.r_state != expected
            || debug.r_brk != breakpoint || debug.r_ldbase != loader_base)
            fail("debugger rendezvous");
        unsigned count = 0;
        uintptr_t map = (uintptr_t)debug.r_map, previous = 0;
        while (map) {
            struct link_map value;
            memory(map, &value, sizeof value);
            if (++count > 256 || (uintptr_t)value.l_prev != previous || !value.l_name || !value.l_ld)
                fail("debugger link map");
            previous = map;
            map = (uintptr_t)value.l_next;
        }
        if (!events) initial_count = count;
        if (count < initial_count || count - initial_count > 1) fail("debugger retained graph");
        unsigned delta = count - initial_count;
        if (delta < maximum_delta) fail("debugger graph regressed");
        if (delta > maximum_delta) maximum_delta = delta;
        fprintf(stderr, "debug-event=%d,maps-added=%u\n", debug.r_state, delta);
        if (++events > 255) fail("debugger event bound");
        poke(breakpoint, original);
        --registers.rip;
        if (ptrace(PTRACE_SETREGS, child, 0, &registers) || ptrace(PTRACE_SINGLESTEP, child, 0, 0))
            fail("debugger single step");
        status = wait_child();
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) fail("debugger step stop");
        poke(breakpoint, (original & ~255L) | 0xcc);
        if (ptrace(PTRACE_CONT, child, 0, 0)) fail("debugger continue");
    }
}
