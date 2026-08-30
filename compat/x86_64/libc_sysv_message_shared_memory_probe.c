/* Native Linux/x86-64 static SysV message/shared-memory C ABI fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through the selected freestanding crabc archive. It specifies a bounded
 * queue lifecycle, a bounded shared-memory lifecycle, and ftok's stat-derived
 * key formula. It deliberately excludes POSIX IPC, cross-process policy,
 * cancellation, general namespace permissions, CRT, loader, sysroot, and
 * public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

struct crabc_message {
    long mtype;
    char mtext[8];
};

/* Keep this test-only classic-BPF contract private. Linux seccomp_data stores
 * the syscall number at byte zero and arguments at byte 16 plus eight bytes
 * per word. The filters below prove msgsnd's fourth word reaches r10 and
 * msgrcv's fourth/fifth words reach r10/r8; a wrong ordinary-C rcx path is
 * rejected deterministically with EBADE before Linux can consume it. */
struct crabc_bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t immediate;
};

struct crabc_bpf_program {
    uint16_t length;
    struct crabc_bpf_instruction *instructions;
};

enum {
    CRABC_BPF_LD = 0x00,
    CRABC_BPF_W = 0x00,
    CRABC_BPF_ABS = 0x20,
    CRABC_BPF_JMP = 0x05,
    CRABC_BPF_JEQ = 0x10,
    CRABC_BPF_K = 0x00,
    CRABC_BPF_RET = 0x06,
    CRABC_SECCOMP_SET_MODE_FILTER = 1,
    CRABC_SECCOMP_RET_ALLOW = 0x7fff0000U,
    CRABC_SECCOMP_RET_ERRNO = 0x00050000U,
    CRABC_SECCOMP_BAD_ARGUMENT_ERRNO = EBADE,
    CRABC_SECCOMP_ARGUMENT_THREE_LOW = 40,
    CRABC_SECCOMP_ARGUMENT_THREE_HIGH = 44,
    CRABC_SECCOMP_ARGUMENT_FOUR_LOW = 48,
    CRABC_SECCOMP_ARGUMENT_FOUR_HIGH = 52,
};

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct crabc_message) == 16 &&
    __builtin_offsetof(struct crabc_message, mtext) == 8,
    "System V message record ABI");
_Static_assert(sizeof(struct msqid_ds) == 120 &&
    sizeof(struct shmid_ds) == 112 && sizeof(struct stat) == 144,
    "selected project-header record ABI");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ftok), key_t (*)(const char *, int)) &&
    CRABC_TYPE_IS(__typeof__(&msgctl), int (*)(int, int, struct msqid_ds *)) &&
    CRABC_TYPE_IS(__typeof__(&msgget), int (*)(key_t, int)) &&
    CRABC_TYPE_IS(__typeof__(&msgrcv), ssize_t (*)(int, void *, size_t, long, int)) &&
    CRABC_TYPE_IS(__typeof__(&msgsnd), int (*)(int, const void *, size_t, int)) &&
    CRABC_TYPE_IS(__typeof__(&shmat), void *(*)(int, const void *, int)) &&
    CRABC_TYPE_IS(__typeof__(&shmctl), int (*)(int, int, struct shmid_ds *)) &&
    CRABC_TYPE_IS(__typeof__(&shmdt), int (*)(const void *)) &&
    CRABC_TYPE_IS(__typeof__(&shmget), int (*)(key_t, size_t, int)),
    "selected SysV IPC declarations");
_Static_assert(SYS_msgget == 68 && SYS_msgsnd == 69 && SYS_msgrcv == 70 &&
    SYS_msgctl == 71 && SYS_shmget == 29 && SYS_shmat == 30 &&
    SYS_shmdt == 67 && SYS_shmctl == 31,
    "Linux x86-64 SysV message/shared-memory syscall numbers");

static int message_queue_id = -1;
static int shared_memory_id = -1;
static void *shared_memory_address = (void *)-1;

static long crabc_x86_64_raw_syscall3(long number, long argument_one,
    long argument_two, long argument_three)
{
    long result;
    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three)
        : "rcx", "r11", "memory");
    return result;
}

static long crabc_x86_64_raw_syscall5(long number, long argument_one,
    long argument_two, long argument_three, long argument_four,
    long argument_five)
{
    long result;
    register long linux_argument_four __asm__("r10") = argument_four;
    register long linux_argument_five __asm__("r8") = argument_five;

    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(linux_argument_four),
          "r"(linux_argument_five)
        : "rcx", "r11", "memory");
    return result;
}

static int install_message_send_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_msgsnd, 0, 6),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_THREE_LOW),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            IPC_NOWAIT, 0, 3),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_THREE_HIGH),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 0, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | CRABC_SECCOMP_BAD_ARGUMENT_ERRNO),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
    };
    struct crabc_bpf_program program = {
        .length = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
        .instructions = filter,
    };

    if (crabc_x86_64_raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0,
            0) != 0)
        return -1;
    if (crabc_x86_64_raw_syscall3(SYS_seccomp,
            CRABC_SECCOMP_SET_MODE_FILTER, 0, (long)(uintptr_t)&program) != 0)
        return -1;
    return 0;
}

static int install_message_receive_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_msgrcv, 0, 10),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_THREE_LOW),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 5, 0, 7),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_THREE_HIGH),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 0, 0, 5),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_FOUR_LOW),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            IPC_NOWAIT, 0, 3),
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS,
            CRABC_SECCOMP_ARGUMENT_FOUR_HIGH),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K, 0, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | CRABC_SECCOMP_BAD_ARGUMENT_ERRNO),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
    };
    struct crabc_bpf_program program = {
        .length = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
        .instructions = filter,
    };

    if (crabc_x86_64_raw_syscall3(SYS_seccomp,
            CRABC_SECCOMP_SET_MODE_FILTER, 0, (long)(uintptr_t)&program) != 0)
        return -1;
    return 0;
}

static void cleanup_resources(void)
{
    if (shared_memory_address != (void *)-1) {
        (void)shmdt(shared_memory_address);
        shared_memory_address = (void *)-1;
    }
    if (shared_memory_id >= 0) {
        (void)shmctl(shared_memory_id, IPC_RMID, 0);
        shared_memory_id = -1;
    }
    if (message_queue_id >= 0) {
        (void)msgctl(message_queue_id, IPC_RMID, 0);
        message_queue_id = -1;
    }
}

static int fail_after_cleanup(int status)
{
    cleanup_resources();
    return status;
}

int crabc_x86_64_sysv_message_shared_memory_probe(void)
{
    static const char executable_path[] = "/proc/self/exe";
    static const char absent_path[] = "/crabc-x86-64-ftok-absent";
    struct stat executable_stat;
    struct crabc_message outgoing = { .mtype = 5, .mtext = "hello" };
    struct crabc_message incoming = { 0 };
    struct msqid_ds message_status = { 0 };
    struct shmid_ds shared_status = { 0 };
    key_t expected_key;
    int removed_shared_memory_id;
    size_t above_ptrdiff_max = (size_t)1 << ((sizeof(size_t) * 8) - 1);

    if (stat(executable_path, &executable_stat) != 0)
        return 10;
    expected_key = (key_t)((executable_stat.st_ino & 0xffff) |
        ((executable_stat.st_dev & 0xff) << 16) | (0xffu << 24));
    errno = E2BIG;
    if (ftok(executable_path, 0xff) != expected_key || errno != E2BIG)
        return 11;
    errno = 0;
    if (ftok(absent_path, 0x42) != (key_t)-1 || errno != ENOENT)
        return 12;

    errno = E2BIG;
    message_queue_id = msgget(IPC_PRIVATE, 0600);
    if (message_queue_id < 0 || errno != E2BIG)
        return fail_after_cleanup(13);
    if (install_message_send_filter() != 0)
        return fail_after_cleanup(14);
    errno = E2BIG;
    if (msgsnd(message_queue_id, &outgoing, 5, IPC_NOWAIT) != 0 ||
        errno != E2BIG)
        return fail_after_cleanup(15);
    if (install_message_receive_filter() != 0)
        return fail_after_cleanup(16);
    errno = E2BIG;
    if (msgrcv(message_queue_id, &incoming, sizeof(incoming.mtext), 5,
            IPC_NOWAIT) != 5 || incoming.mtype != 5 ||
        incoming.mtext[0] != 'h' || incoming.mtext[4] != 'o' || errno != E2BIG)
        return fail_after_cleanup(17);
    errno = E2BIG;
    if (msgctl(message_queue_id, IPC_STAT, &message_status) != 0 ||
        message_status.msg_qnum != 0 || message_status.msg_qbytes == 0 ||
        errno != E2BIG)
        return fail_after_cleanup(18);
    errno = E2BIG;
    if (msgctl(message_queue_id, IPC_RMID, 0) != 0 || errno != E2BIG)
        return fail_after_cleanup(19);
    message_queue_id = -1;

    errno = E2BIG;
    shared_memory_id = shmget(IPC_PRIVATE, 4096, 0600);
    if (shared_memory_id < 0 || errno != E2BIG)
        return fail_after_cleanup(20);
    errno = E2BIG;
    shared_memory_address = shmat(shared_memory_id, 0, 0);
    if (shared_memory_address == (void *)-1 || errno != E2BIG)
        return fail_after_cleanup(21);
    *(volatile uint64_t *)shared_memory_address = UINT64_C(0x9156a3c4d20e7b8f);
    if (*(volatile uint64_t *)shared_memory_address !=
        UINT64_C(0x9156a3c4d20e7b8f))
        return fail_after_cleanup(22);
    errno = E2BIG;
    if (shmctl(shared_memory_id, IPC_STAT, &shared_status) != 0 ||
        shared_status.shm_segsz != 4096 || errno != E2BIG)
        return fail_after_cleanup(23);
    errno = E2BIG;
    if (shmdt(shared_memory_address) != 0 || errno != E2BIG)
        return fail_after_cleanup(24);
    shared_memory_address = (void *)-1;
    removed_shared_memory_id = shared_memory_id;
    errno = E2BIG;
    if (shmctl(removed_shared_memory_id, IPC_RMID, 0) != 0 || errno != E2BIG)
        return fail_after_cleanup(25);
    shared_memory_id = -1;
    errno = 0;
    if (shmat(removed_shared_memory_id, 0, 0) != (void *)-1 || errno != EINVAL)
        return 26;

    /* Musl rewrites this just-over-PTRDIFF_MAX request to SIZE_MAX before the
     * kernel sees it. The eventual kernel EINVAL is expected; EBADE would
     * identify an unrewritten second syscall word in the companion filter. */
    {
        struct crabc_bpf_instruction filter[] = {
            CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
            CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
                SYS_shmget, 0, 6),
            CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 24),
            CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
                UINT32_MAX, 0, 3),
            CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 28),
            CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
                UINT32_MAX, 0, 1),
            CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
                CRABC_SECCOMP_RET_ALLOW),
            CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
                CRABC_SECCOMP_RET_ERRNO | CRABC_SECCOMP_BAD_ARGUMENT_ERRNO),
            CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
                CRABC_SECCOMP_RET_ALLOW),
        };
        struct crabc_bpf_program program = {
            .length = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
            .instructions = filter,
        };

        if (crabc_x86_64_raw_syscall3(SYS_seccomp,
                CRABC_SECCOMP_SET_MODE_FILTER, 0,
                (long)(uintptr_t)&program) != 0)
            return 27;
    }
    errno = 0;
    if (shmget(IPC_PRIVATE, above_ptrdiff_max, 0600) != -1 || errno != EINVAL)
        return 28;
    return 0;
}

#ifndef CRABC_SYSV_MESSAGE_SHARED_MEMORY_FREESTANDING
int main(void)
{
    return crabc_x86_64_sysv_message_shared_memory_probe();
}
#endif
