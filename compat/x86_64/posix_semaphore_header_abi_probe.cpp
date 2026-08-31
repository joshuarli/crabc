/* Native Linux/x86-64 C++ <semaphore.h> declaration and C-linkage contract. */

#include <fcntl.h>
#include <semaphore.h>
#include <time.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

using sem_close_signature = int (*)(sem_t *);
using sem_destroy_signature = int (*)(sem_t *);
using sem_getvalue_signature = int (*)(sem_t *__restrict, int *__restrict);
using sem_init_signature = int (*)(sem_t *, int, unsigned);
using sem_open_signature = sem_t *(*)(const char *, int, ...);
using sem_post_signature = int (*)(sem_t *);
using sem_timedwait_signature = int (*)(sem_t *__restrict,
    const struct timespec *__restrict);
using sem_trywait_signature = int (*)(sem_t *);
using sem_unlink_signature = int (*)(const char *);
using sem_wait_signature = int (*)(sem_t *);

static_assert(sizeof(sem_t) == 32 && alignof(sem_t) == 4,
    "C++ x86 sem_t storage");
static_assert(sizeof(((sem_t *)nullptr)->__val) == 32,
    "C++ x86 sem_t word array");
static_assert(__is_same(decltype(((sem_t *)nullptr)->__val[0]), volatile int &),
    "C++ sem_t words remain volatile int");
static_assert(sizeof(struct timespec) == 16 && alignof(struct timespec) == 8,
    "C++ x86 timespec for sem_timedwait");
static_assert(SEM_FAILED == (sem_t *)0, "C++ SEM_FAILED sentinel");
static_assert(O_CREAT == 64 && O_EXCL == 128,
    "C++ semaphore creation flags arrive from fcntl.h");
static_assert(__is_same(decltype(&sem_close), sem_close_signature),
    "C++ sem_close declaration");
static_assert(__is_same(decltype(&sem_destroy), sem_destroy_signature),
    "C++ sem_destroy declaration");
static_assert(__is_same(decltype(&sem_getvalue), sem_getvalue_signature),
    "C++ sem_getvalue declaration");
static_assert(__is_same(decltype(&sem_init), sem_init_signature),
    "C++ sem_init declaration");
static_assert(__is_same(decltype(&sem_open), sem_open_signature),
    "C++ sem_open declaration");
static_assert(__is_same(decltype(&sem_post), sem_post_signature),
    "C++ sem_post declaration");
static_assert(__is_same(decltype(&sem_timedwait), sem_timedwait_signature),
    "C++ sem_timedwait declaration");
static_assert(__is_same(decltype(&sem_trywait), sem_trywait_signature),
    "C++ sem_trywait declaration");
static_assert(__is_same(decltype(&sem_unlink), sem_unlink_signature),
    "C++ sem_unlink declaration");
static_assert(__is_same(decltype(&sem_wait), sem_wait_signature),
    "C++ sem_wait declaration");

static sem_close_signature sem_close_reference __attribute__((used)) = sem_close;
static sem_destroy_signature sem_destroy_reference __attribute__((used)) = sem_destroy;
static sem_getvalue_signature sem_getvalue_reference __attribute__((used)) = sem_getvalue;
static sem_init_signature sem_init_reference __attribute__((used)) = sem_init;
static sem_open_signature sem_open_reference __attribute__((used)) = sem_open;
static sem_post_signature sem_post_reference __attribute__((used)) = sem_post;
static sem_timedwait_signature sem_timedwait_reference __attribute__((used)) = sem_timedwait;
static sem_trywait_signature sem_trywait_reference __attribute__((used)) = sem_trywait;
static sem_unlink_signature sem_unlink_reference __attribute__((used)) = sem_unlink;
static sem_wait_signature sem_wait_reference __attribute__((used)) = sem_wait;

extern "C" int crabc_x86_64_posix_semaphore_header_abi_probe_cpp()
{
    return sizeof(sem_t) == 32 ? 0 : 1;
}
