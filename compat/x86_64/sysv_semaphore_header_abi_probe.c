/*
 * Native Linux/x86-64 SysV semaphore header ABI probe.
 *
 * Pinned musl 1.2.6 owns these selected source-level facts.  The companion
 * runner compiles this C fixture through both its installed headers and the
 * project header tree under isolated feature profiles.  This is declaration
 * and layout evidence only: it neither links nor selects a crabc C runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/sem.h>

typedef int (*crabc_semctl_signature)(int, int, int, ...);
typedef int (*crabc_semget_signature)(key_t, int, int);
typedef int (*crabc_semop_signature)(int, struct sembuf *, size_t);
typedef int (*crabc_semtimedop_signature)(
    int, struct sembuf *, size_t, const struct timespec *);

_Static_assert(sizeof(key_t) == 4 && _Alignof(key_t) == 4,
    "x86 SysV key_t ABI");
_Static_assert(__builtin_types_compatible_p(key_t, int),
    "x86 SysV key_t spelling");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8,
    "x86 SysV size_t ABI");
_Static_assert(__builtin_types_compatible_p(size_t, unsigned long),
    "x86 SysV size_t spelling");
_Static_assert(sizeof(time_t) == 8 && _Alignof(time_t) == 8,
    "x86 SysV time_t ABI");
_Static_assert(__builtin_types_compatible_p(time_t, long),
    "x86 SysV time_t spelling");

_Static_assert(sizeof(struct ipc_perm) == 48 && _Alignof(struct ipc_perm) == 8,
    "x86 ipc_perm size/alignment");
_Static_assert(offsetof(struct ipc_perm, uid) == 4 &&
    offsetof(struct ipc_perm, gid) == 8 &&
    offsetof(struct ipc_perm, cuid) == 12 &&
    offsetof(struct ipc_perm, cgid) == 16 &&
    offsetof(struct ipc_perm, mode) == 20 &&
    offsetof(struct ipc_perm, __pad1) == 32 &&
    offsetof(struct ipc_perm, __pad2) == 40,
    "x86 ipc_perm selected offsets");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct ipc_perm *)0)->mode), mode_t),
    "x86 ipc_perm mode type");

_Static_assert(sizeof(struct semid_ds) == 104 &&
    _Alignof(struct semid_ds) == 8, "x86 semid_ds size/alignment");
_Static_assert(offsetof(struct semid_ds, sem_perm) == 0 &&
    offsetof(struct semid_ds, sem_otime) == 48 &&
    offsetof(struct semid_ds, sem_ctime) == 64 &&
    offsetof(struct semid_ds, sem_nsems) == 80 &&
    offsetof(struct semid_ds, __unused3) == 88 &&
    offsetof(struct semid_ds, __unused4) == 96,
    "x86 semid_ds selected offsets");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct semid_ds *)0)->sem_nsems), unsigned short),
    "x86 semid_ds semaphore-count type");

_Static_assert(sizeof(struct seminfo) == 40 && _Alignof(struct seminfo) == 4,
    "x86 seminfo size/alignment");
_Static_assert(offsetof(struct seminfo, semmap) == 0 &&
    offsetof(struct seminfo, semopm) == 20 &&
    offsetof(struct seminfo, semaem) == 36,
    "x86 seminfo selected offsets");

_Static_assert(sizeof(struct sembuf) == 6 && _Alignof(struct sembuf) == 2,
    "x86 sembuf size/alignment");
_Static_assert(offsetof(struct sembuf, sem_num) == 0 &&
    offsetof(struct sembuf, sem_op) == 2 &&
    offsetof(struct sembuf, sem_flg) == 4,
    "x86 sembuf offsets");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct sembuf *)0)->sem_num), unsigned short) &&
    __builtin_types_compatible_p(__typeof__(((struct sembuf *)0)->sem_op), short) &&
    __builtin_types_compatible_p(__typeof__(((struct sembuf *)0)->sem_flg), short),
    "x86 sembuf member types");

_Static_assert(IPC_CREAT == 01000 && IPC_EXCL == 02000 && IPC_NOWAIT == 04000,
    "x86 SysV IPC creation flags");
_Static_assert(IPC_RMID == 0 && IPC_SET == 1 && IPC_STAT == 2 && IPC_INFO == 3,
    "x86 SysV IPC control commands");
_Static_assert(IPC_PRIVATE == (key_t)0 &&
    __builtin_types_compatible_p(__typeof__(IPC_PRIVATE), key_t),
    "x86 SysV private-key value/type");
_Static_assert(SEM_UNDO == 0x1000 && GETPID == 11 && GETVAL == 12 &&
    GETALL == 13 && GETNCNT == 14 && GETZCNT == 15 && SETVAL == 16 &&
    SETALL == 17, "x86 SysV semaphore operation commands");
_Static_assert(_SEM_SEMUN_UNDEFINED == 1 && SEM_STAT == 18 && SEM_INFO == 19 &&
    SEM_STAT_ANY == 20, "x86 SysV semaphore extension commands");

_Static_assert(__builtin_types_compatible_p(__typeof__(&semctl),
    crabc_semctl_signature), "semctl variadic declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&semget),
    crabc_semget_signature), "semget declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&semop),
    crabc_semop_signature), "semop declaration");

#if defined(CRABC_SYSV_SEMAPHORE_REQUIRE_GNU) || \
    defined(CRABC_SYSV_SEMAPHORE_REQUIRE_GNU_HIDDEN)
_Static_assert(__builtin_types_compatible_p(__typeof__(&semtimedop),
    crabc_semtimedop_signature), "semtimedop GNU declaration");
#endif

/* This opt-in reference must fail outside GNU feature selection. */
#if defined(CRABC_SYSV_SEMAPHORE_REQUIRE_GNU_HIDDEN)
__attribute__((used)) static crabc_semtimedop_signature
    crabc_sysv_semaphore_semtimedop_must_be_hidden = semtimedop;
#endif

int crabc_x86_64_sysv_semaphore_header_abi_probe(void)
{
    return SEM_STAT_ANY + SETALL + IPC_INFO;
}
