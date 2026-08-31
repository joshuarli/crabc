/* Native Linux/x86-64 C <semaphore.h> declaration and record contract. */

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <time.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

typedef int (*sem_close_signature)(sem_t *);
typedef int (*sem_destroy_signature)(sem_t *);
typedef int (*sem_getvalue_signature)(sem_t *__restrict, int *__restrict);
typedef int (*sem_init_signature)(sem_t *, int, unsigned);
typedef sem_t *(*sem_open_signature)(const char *, int, ...);
typedef int (*sem_post_signature)(sem_t *);
typedef int (*sem_timedwait_signature)(sem_t *__restrict,
    const struct timespec *__restrict);
typedef int (*sem_trywait_signature)(sem_t *);
typedef int (*sem_unlink_signature)(const char *);
typedef int (*sem_wait_signature)(sem_t *);

_Static_assert(sizeof(sem_t) == 32 && _Alignof(sem_t) == 4,
    "x86 sem_t storage");
_Static_assert(sizeof(((sem_t *)0)->__val) == 32,
    "x86 sem_t word array");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((sem_t *)0)->__val[0]), volatile int),
    "sem_t words remain volatile int");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec for sem_timedwait");
_Static_assert(SEM_FAILED == (sem_t *)0, "SEM_FAILED sentinel");
_Static_assert(O_CREAT == 64 && O_EXCL == 128,
    "semaphore creation flags arrive from fcntl.h");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_close),
    sem_close_signature), "sem_close declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_destroy),
    sem_destroy_signature), "sem_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_getvalue),
    sem_getvalue_signature), "sem_getvalue declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_init),
    sem_init_signature), "sem_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_open),
    sem_open_signature), "sem_open declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_post),
    sem_post_signature), "sem_post declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_timedwait),
    sem_timedwait_signature), "sem_timedwait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_trywait),
    sem_trywait_signature), "sem_trywait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_unlink),
    sem_unlink_signature), "sem_unlink declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_wait),
    sem_wait_signature), "sem_wait declaration");

int crabc_x86_64_posix_semaphore_header_abi_probe(void)
{
    return sizeof(sem_t) == 32 ? 0 : 1;
}
