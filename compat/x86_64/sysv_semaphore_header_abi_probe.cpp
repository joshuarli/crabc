/* C++17 companion for the native Linux/x86-64 SysV semaphore ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/sem.h>

using semctl_signature = int (*)(int, int, int, ...);
using semget_signature = int (*)(key_t, int, int);
using semop_signature = int (*)(int, struct sembuf *, size_t);
using semtimedop_signature = int (*)(
    int, struct sembuf *, size_t, const struct timespec *);

static_assert(sizeof(key_t) == 4 && alignof(key_t) == 4 &&
    __is_same(key_t, int), "C++ x86 SysV key_t ABI");
static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8 &&
    __is_same(size_t, unsigned long), "C++ x86 SysV size_t ABI");
static_assert(sizeof(time_t) == 8 && alignof(time_t) == 8 &&
    __is_same(time_t, long), "C++ x86 SysV time_t ABI");

static_assert(sizeof(struct ipc_perm) == 48 && alignof(struct ipc_perm) == 8,
    "C++ x86 ipc_perm size/alignment");
static_assert(offsetof(struct ipc_perm, uid) == 4 &&
    offsetof(struct ipc_perm, gid) == 8 &&
    offsetof(struct ipc_perm, cuid) == 12 &&
    offsetof(struct ipc_perm, cgid) == 16 &&
    offsetof(struct ipc_perm, mode) == 20 &&
    offsetof(struct ipc_perm, __pad1) == 32 &&
    offsetof(struct ipc_perm, __pad2) == 40,
    "C++ x86 ipc_perm selected offsets");
static_assert(__is_same(decltype(((struct ipc_perm *)0)->mode), mode_t),
    "C++ x86 ipc_perm mode type");

static_assert(sizeof(struct semid_ds) == 104 && alignof(struct semid_ds) == 8,
    "C++ x86 semid_ds size/alignment");
static_assert(offsetof(struct semid_ds, sem_perm) == 0 &&
    offsetof(struct semid_ds, sem_otime) == 48 &&
    offsetof(struct semid_ds, sem_ctime) == 64 &&
    offsetof(struct semid_ds, sem_nsems) == 80 &&
    offsetof(struct semid_ds, __unused3) == 88 &&
    offsetof(struct semid_ds, __unused4) == 96,
    "C++ x86 semid_ds selected offsets");
static_assert(__is_same(decltype(((struct semid_ds *)0)->sem_nsems),
    unsigned short), "C++ x86 semid_ds semaphore-count type");

static_assert(sizeof(struct seminfo) == 40 && alignof(struct seminfo) == 4,
    "C++ x86 seminfo size/alignment");
static_assert(offsetof(struct seminfo, semmap) == 0 &&
    offsetof(struct seminfo, semopm) == 20 &&
    offsetof(struct seminfo, semaem) == 36,
    "C++ x86 seminfo selected offsets");

static_assert(sizeof(struct sembuf) == 6 && alignof(struct sembuf) == 2,
    "C++ x86 sembuf size/alignment");
static_assert(offsetof(struct sembuf, sem_num) == 0 &&
    offsetof(struct sembuf, sem_op) == 2 &&
    offsetof(struct sembuf, sem_flg) == 4,
    "C++ x86 sembuf offsets");
static_assert(__is_same(decltype(((struct sembuf *)0)->sem_num), unsigned short) &&
    __is_same(decltype(((struct sembuf *)0)->sem_op), short) &&
    __is_same(decltype(((struct sembuf *)0)->sem_flg), short),
    "C++ x86 sembuf member types");

static_assert(IPC_CREAT == 01000 && IPC_EXCL == 02000 && IPC_NOWAIT == 04000,
    "C++ x86 SysV IPC creation flags");
static_assert(IPC_RMID == 0 && IPC_SET == 1 && IPC_STAT == 2 && IPC_INFO == 3,
    "C++ x86 SysV IPC control commands");
static_assert(IPC_PRIVATE == static_cast<key_t>(0) &&
    __is_same(decltype(IPC_PRIVATE), key_t),
    "C++ x86 SysV private-key value/type");
static_assert(SEM_UNDO == 0x1000 && GETPID == 11 && GETVAL == 12 &&
    GETALL == 13 && GETNCNT == 14 && GETZCNT == 15 && SETVAL == 16 &&
    SETALL == 17, "C++ x86 SysV semaphore operation commands");
static_assert(_SEM_SEMUN_UNDEFINED == 1 && SEM_STAT == 18 && SEM_INFO == 19 &&
    SEM_STAT_ANY == 20, "C++ x86 SysV semaphore extension commands");

static_assert(__is_same(decltype(&semctl), semctl_signature),
    "C++ semctl variadic declaration");
static_assert(__is_same(decltype(&semget), semget_signature),
    "C++ semget declaration");
static_assert(__is_same(decltype(&semop), semop_signature),
    "C++ semop declaration");

__attribute__((used)) static semctl_signature crabc_sysv_semctl = semctl;
__attribute__((used)) static semget_signature crabc_sysv_semget = semget;
__attribute__((used)) static semop_signature crabc_sysv_semop = semop;

#if defined(CRABC_SYSV_SEMAPHORE_REQUIRE_GNU) || \
    defined(CRABC_SYSV_SEMAPHORE_REQUIRE_GNU_HIDDEN)
static_assert(__is_same(decltype(&semtimedop), semtimedop_signature),
    "C++ semtimedop GNU declaration");
__attribute__((used)) static semtimedop_signature crabc_sysv_semtimedop =
    semtimedop;
#endif

/* This opt-in reference must fail outside GNU feature selection. */
#if defined(CRABC_SYSV_SEMAPHORE_REQUIRE_GNU_HIDDEN)
__attribute__((used)) static semtimedop_signature
    crabc_sysv_semaphore_semtimedop_must_be_hidden = semtimedop;
#endif

int crabc_x86_64_sysv_semaphore_header_abi_probe_cpp()
{
    return SEM_STAT_ANY + SETALL + IPC_INFO;
}
