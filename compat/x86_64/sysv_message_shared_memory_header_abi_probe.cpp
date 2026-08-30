/* C++17 companion for the native Linux/x86-64 SysV message/shared-memory ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

using ftok_signature = key_t (*)(const char *, int);
using msgctl_signature = int (*)(int, int, struct msqid_ds *);
using msgget_signature = int (*)(key_t, int);
using msgrcv_signature = ssize_t (*)(int, void *, size_t, long, int);
using msgsnd_signature = int (*)(int, const void *, size_t, int);
using shmat_signature = void *(*)(int, const void *, int);
using shmctl_signature = int (*)(int, int, struct shmid_ds *);
using shmdt_signature = int (*)(const void *);
using shmget_signature = int (*)(key_t, size_t, int);

static_assert(sizeof(key_t) == 4 && alignof(key_t) == 4 && __is_same(key_t, int),
    "C++ x86 key_t ABI");
static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8 &&
    __is_same(size_t, unsigned long), "C++ x86 size_t ABI");
static_assert(sizeof(ssize_t) == 8 && alignof(ssize_t) == 8 &&
    __is_same(ssize_t, long), "C++ x86 ssize_t ABI");
static_assert(sizeof(time_t) == 8 && alignof(time_t) == 8 &&
    __is_same(time_t, long), "C++ x86 time_t ABI");

static_assert(sizeof(struct ipc_perm) == 48 && alignof(struct ipc_perm) == 8,
    "C++ x86 ipc_perm size/alignment");
static_assert(offsetof(struct ipc_perm, uid) == 4 &&
    offsetof(struct ipc_perm, mode) == 20 &&
    offsetof(struct ipc_perm, __pad2) == 40, "C++ x86 ipc_perm offsets");
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
static_assert(offsetof(struct ipc_perm, key) == 0 &&
    offsetof(struct ipc_perm, seq) == 24, "C++ GNU/BSD ipc_perm spellings");
#else
static_assert(offsetof(struct ipc_perm, __key) == 0 &&
    offsetof(struct ipc_perm, __seq) == 24, "C++ strict ipc_perm spellings");
#endif

static_assert(sizeof(struct msqid_ds) == 120 && alignof(struct msqid_ds) == 8 &&
    offsetof(struct msqid_ds, msg_perm) == 0 &&
    offsetof(struct msqid_ds, msg_cbytes) == 72 &&
    offsetof(struct msqid_ds, __unused) == 104, "C++ x86 msqid_ds ABI");
static_assert(sizeof(struct msginfo) == 32 && alignof(struct msginfo) == 4 &&
    offsetof(struct msginfo, msgseg) == 28, "C++ x86 msginfo ABI");
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
static_assert(sizeof(struct msgbuf) == 16 && alignof(struct msgbuf) == 8 &&
    offsetof(struct msgbuf, mtext) == 8, "C++ GNU/BSD msgbuf ABI");
#endif

static_assert(sizeof(struct shmid_ds) == 112 && alignof(struct shmid_ds) == 8 &&
    offsetof(struct shmid_ds, shm_segsz) == 48 &&
    offsetof(struct shmid_ds, __pad2) == 104, "C++ x86 shmid_ds ABI");
static_assert(sizeof(struct shminfo) == 72 && alignof(struct shminfo) == 8 &&
    offsetof(struct shminfo, shmall) == 32, "C++ x86 shminfo ABI");
static_assert(sizeof(struct shm_info) == 48 && alignof(struct shm_info) == 8 &&
    offsetof(struct shm_info, shm_swp) == 24, "C++ x86 shm_info ABI");
#ifdef _GNU_SOURCE
static_assert(offsetof(struct shm_info, used_ids) == 0 &&
    offsetof(struct shm_info, swap_attempts) == 32 &&
    offsetof(struct shm_info, swap_successes) == 40,
    "C++ GNU shm_info spellings");
#else
static_assert(offsetof(struct shm_info, __used_ids) == 0 &&
    offsetof(struct shm_info, __swap_attempts) == 32 &&
    offsetof(struct shm_info, __swap_successes) == 40,
    "C++ strict shm_info spellings");
#endif

static_assert(IPC_CREAT == 01000 && IPC_EXCL == 02000 && IPC_NOWAIT == 04000 &&
    IPC_RMID == 0 && IPC_SET == 1 && IPC_STAT == 2 && IPC_INFO == 3,
    "C++ x86 IPC values");
static_assert(MSG_NOERROR == 010000 && MSG_EXCEPT == 020000 &&
    MSG_STAT == 11 && MSG_INFO == 12 && MSG_STAT_ANY == 13,
    "C++ x86 message values");
static_assert(SHMLBA == 4096 && SHM_LOCK == 11 && SHM_UNLOCK == 12 &&
    SHM_STAT == 13 && SHM_INFO == 14 && SHM_STAT_ANY == 15,
    "C++ x86 shared-memory values");

static_assert(__is_same(decltype(&ftok), ftok_signature), "C++ ftok declaration");
static_assert(__is_same(decltype(&msgctl), msgctl_signature), "C++ msgctl declaration");
static_assert(__is_same(decltype(&msgget), msgget_signature), "C++ msgget declaration");
static_assert(__is_same(decltype(&msgrcv), msgrcv_signature), "C++ msgrcv declaration");
static_assert(__is_same(decltype(&msgsnd), msgsnd_signature), "C++ msgsnd declaration");
static_assert(__is_same(decltype(&shmat), shmat_signature), "C++ shmat declaration");
static_assert(__is_same(decltype(&shmctl), shmctl_signature), "C++ shmctl declaration");
static_assert(__is_same(decltype(&shmdt), shmdt_signature), "C++ shmdt declaration");
static_assert(__is_same(decltype(&shmget), shmget_signature), "C++ shmget declaration");

__attribute__((used)) static ftok_signature crabc_sysv_ftok = ftok;
__attribute__((used)) static msgctl_signature crabc_sysv_msgctl = msgctl;
__attribute__((used)) static msgget_signature crabc_sysv_msgget = msgget;
__attribute__((used)) static msgrcv_signature crabc_sysv_msgrcv = msgrcv;
__attribute__((used)) static msgsnd_signature crabc_sysv_msgsnd = msgsnd;
__attribute__((used)) static shmat_signature crabc_sysv_shmat = shmat;
__attribute__((used)) static shmctl_signature crabc_sysv_shmctl = shmctl;
__attribute__((used)) static shmdt_signature crabc_sysv_shmdt = shmdt;
__attribute__((used)) static shmget_signature crabc_sysv_shmget = shmget;

int crabc_x86_64_sysv_message_shared_memory_header_abi_probe_cpp()
{
    return MSG_STAT_ANY + SHM_STAT_ANY + IPC_INFO;
}
