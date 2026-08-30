/* Native Linux/x86-64 System V message/shared-memory header ABI probe.
 *
 * Pinned musl 1.2.6 owns these source-level declaration, record-layout,
 * feature-namespace, and value facts. The companion runner compiles this
 * fixture through its installed headers and the project tree under isolated
 * C11/C++17 feature profiles. It proves no runtime linkage or C-family
 * completion by itself.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

typedef key_t (*crabc_ftok_signature)(const char *, int);
typedef int (*crabc_msgctl_signature)(int, int, struct msqid_ds *);
typedef int (*crabc_msgget_signature)(key_t, int);
typedef ssize_t (*crabc_msgrcv_signature)(int, void *, size_t, long, int);
typedef int (*crabc_msgsnd_signature)(int, const void *, size_t, int);
typedef void *(*crabc_shmat_signature)(int, const void *, int);
typedef int (*crabc_shmctl_signature)(int, int, struct shmid_ds *);
typedef int (*crabc_shmdt_signature)(const void *);
typedef int (*crabc_shmget_signature)(key_t, size_t, int);

_Static_assert(sizeof(key_t) == 4 && _Alignof(key_t) == 4 &&
    __builtin_types_compatible_p(key_t, int), "x86 SysV key_t ABI");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8 &&
    __builtin_types_compatible_p(size_t, unsigned long), "x86 size_t ABI");
_Static_assert(sizeof(ssize_t) == 8 && _Alignof(ssize_t) == 8 &&
    __builtin_types_compatible_p(ssize_t, long), "x86 ssize_t ABI");
_Static_assert(sizeof(time_t) == 8 && _Alignof(time_t) == 8 &&
    __builtin_types_compatible_p(time_t, long), "x86 time_t ABI");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4 &&
    __builtin_types_compatible_p(pid_t, int), "x86 pid_t ABI");

_Static_assert(sizeof(struct ipc_perm) == 48 && _Alignof(struct ipc_perm) == 8,
    "x86 ipc_perm size/alignment");
_Static_assert(offsetof(struct ipc_perm, uid) == 4 &&
    offsetof(struct ipc_perm, gid) == 8 &&
    offsetof(struct ipc_perm, cuid) == 12 &&
    offsetof(struct ipc_perm, cgid) == 16 &&
    offsetof(struct ipc_perm, mode) == 20 &&
    offsetof(struct ipc_perm, __pad1) == 32 &&
    offsetof(struct ipc_perm, __pad2) == 40,
    "x86 ipc_perm stable offsets");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct ipc_perm *)0)->mode), mode_t),
    "x86 ipc_perm mode type");

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
_Static_assert(offsetof(struct ipc_perm, key) == 0 &&
    offsetof(struct ipc_perm, seq) == 24,
    "GNU/BSD ipc_perm member spellings");
#else
_Static_assert(offsetof(struct ipc_perm, __key) == 0 &&
    offsetof(struct ipc_perm, __seq) == 24,
    "strict ipc_perm member spellings");
#endif

_Static_assert(sizeof(struct msqid_ds) == 120 &&
    _Alignof(struct msqid_ds) == 8, "x86 msqid_ds size/alignment");
_Static_assert(offsetof(struct msqid_ds, msg_perm) == 0 &&
    offsetof(struct msqid_ds, msg_stime) == 48 &&
    offsetof(struct msqid_ds, msg_rtime) == 56 &&
    offsetof(struct msqid_ds, msg_ctime) == 64 &&
    offsetof(struct msqid_ds, msg_cbytes) == 72 &&
    offsetof(struct msqid_ds, msg_qnum) == 80 &&
    offsetof(struct msqid_ds, msg_qbytes) == 88 &&
    offsetof(struct msqid_ds, msg_lspid) == 96 &&
    offsetof(struct msqid_ds, msg_lrpid) == 100 &&
    offsetof(struct msqid_ds, __unused) == 104,
    "x86 msqid_ds offsets");
_Static_assert(__builtin_types_compatible_p(msgqnum_t, unsigned long) &&
    __builtin_types_compatible_p(msglen_t, unsigned long),
    "x86 message count/length types");

_Static_assert(sizeof(struct msginfo) == 32 && _Alignof(struct msginfo) == 4 &&
    offsetof(struct msginfo, msgpool) == 0 &&
    offsetof(struct msginfo, msgseg) == 28 &&
    __builtin_types_compatible_p(__typeof__(((struct msginfo *)0)->msgseg),
        unsigned short), "x86 msginfo ABI");

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
_Static_assert(sizeof(struct msgbuf) == 16 && _Alignof(struct msgbuf) == 8 &&
    offsetof(struct msgbuf, mtype) == 0 && offsetof(struct msgbuf, mtext) == 8,
    "GNU/BSD msgbuf ABI");
#endif

_Static_assert(sizeof(struct shmid_ds) == 112 &&
    _Alignof(struct shmid_ds) == 8, "x86 shmid_ds size/alignment");
_Static_assert(offsetof(struct shmid_ds, shm_perm) == 0 &&
    offsetof(struct shmid_ds, shm_segsz) == 48 &&
    offsetof(struct shmid_ds, shm_atime) == 56 &&
    offsetof(struct shmid_ds, shm_dtime) == 64 &&
    offsetof(struct shmid_ds, shm_ctime) == 72 &&
    offsetof(struct shmid_ds, shm_cpid) == 80 &&
    offsetof(struct shmid_ds, shm_lpid) == 84 &&
    offsetof(struct shmid_ds, shm_nattch) == 88 &&
    offsetof(struct shmid_ds, __pad1) == 96 &&
    offsetof(struct shmid_ds, __pad2) == 104,
    "x86 shmid_ds offsets");
_Static_assert(__builtin_types_compatible_p(shmatt_t, unsigned long),
    "x86 shmatt_t spelling");

_Static_assert(sizeof(struct shminfo) == 72 && _Alignof(struct shminfo) == 8 &&
    offsetof(struct shminfo, shmmax) == 0 &&
    offsetof(struct shminfo, shmall) == 32 &&
    offsetof(struct shminfo, __unused) == 40,
    "x86 shminfo ABI");
_Static_assert(sizeof(struct shm_info) == 48 && _Alignof(struct shm_info) == 8 &&
    offsetof(struct shm_info, shm_tot) == 8 &&
    offsetof(struct shm_info, shm_rss) == 16 &&
    offsetof(struct shm_info, shm_swp) == 24,
    "x86 shm_info stable ABI");

#ifdef _GNU_SOURCE
_Static_assert(offsetof(struct shm_info, used_ids) == 0 &&
    offsetof(struct shm_info, swap_attempts) == 32 &&
    offsetof(struct shm_info, swap_successes) == 40,
    "GNU shm_info member spellings");
#else
_Static_assert(offsetof(struct shm_info, __used_ids) == 0 &&
    offsetof(struct shm_info, __swap_attempts) == 32 &&
    offsetof(struct shm_info, __swap_successes) == 40,
    "strict shm_info member spellings");
#endif

_Static_assert(IPC_CREAT == 01000 && IPC_EXCL == 02000 && IPC_NOWAIT == 04000 &&
    IPC_RMID == 0 && IPC_SET == 1 && IPC_STAT == 2 && IPC_INFO == 3 &&
    IPC_PRIVATE == (key_t)0, "x86 SysV IPC values");
_Static_assert(MSG_NOERROR == 010000 && MSG_EXCEPT == 020000 &&
    MSG_STAT == 11 && MSG_INFO == 12 && MSG_STAT_ANY == 13,
    "x86 SysV message values");
_Static_assert(SHMLBA == 4096 && SHM_R == 0400 && SHM_W == 0200 &&
    SHM_RDONLY == 010000 && SHM_RND == 020000 && SHM_REMAP == 040000 &&
    SHM_EXEC == 0100000 && SHM_LOCK == 11 && SHM_UNLOCK == 12 &&
    SHM_STAT == 13 && SHM_INFO == 14 && SHM_STAT_ANY == 15,
    "x86 SysV shared-memory values");

_Static_assert(__builtin_types_compatible_p(__typeof__(&ftok),
    crabc_ftok_signature), "ftok declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msgctl),
    crabc_msgctl_signature), "msgctl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msgget),
    crabc_msgget_signature), "msgget declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msgrcv),
    crabc_msgrcv_signature), "msgrcv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msgsnd),
    crabc_msgsnd_signature), "msgsnd declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&shmat),
    crabc_shmat_signature), "shmat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&shmctl),
    crabc_shmctl_signature), "shmctl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&shmdt),
    crabc_shmdt_signature), "shmdt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&shmget),
    crabc_shmget_signature), "shmget declaration");

#if defined(CRABC_SYSV_MESSAGE_SHM_REQUIRE_COMPAT_IPC)
typedef __typeof__(((struct ipc_perm *)0)->key) crabc_compat_ipc_key;
typedef __typeof__(((struct ipc_perm *)0)->seq) crabc_compat_ipc_seq;
#endif

#if defined(CRABC_SYSV_MESSAGE_SHM_REQUIRE_STRICT_IPC)
typedef __typeof__(((struct ipc_perm *)0)->__key) crabc_strict_ipc_key;
typedef __typeof__(((struct ipc_perm *)0)->__seq) crabc_strict_ipc_seq;
#endif

#if defined(CRABC_SYSV_MESSAGE_SHM_REQUIRE_MSGBUF)
_Static_assert(sizeof(struct msgbuf) == 16, "msgbuf must be selected");
#endif

#if defined(CRABC_SYSV_MESSAGE_SHM_REQUIRE_GNU_SHM)
typedef __typeof__(((struct shm_info *)0)->used_ids) crabc_gnu_shm_used_ids;
typedef __typeof__(((struct shm_info *)0)->swap_attempts)
    crabc_gnu_shm_swap_attempts;
#endif

#if defined(CRABC_SYSV_MESSAGE_SHM_REQUIRE_STRICT_SHM)
typedef __typeof__(((struct shm_info *)0)->__used_ids) crabc_strict_shm_used_ids;
typedef __typeof__(((struct shm_info *)0)->__swap_attempts)
    crabc_strict_shm_swap_attempts;
#endif

int crabc_x86_64_sysv_message_shared_memory_header_abi_probe(void)
{
    return MSG_STAT_ANY + SHM_STAT_ANY + IPC_INFO;
}
