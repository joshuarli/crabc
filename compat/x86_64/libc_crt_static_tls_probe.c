/* Real x86-64 rcrt1 -> libc Static Initial TLS v1 composition fixture.
 *
 * The same body first runs with pinned musl, then through real crabc rcrt1.o,
 * crti.o, crtn.o, and the selected static libc archive. Its lifecycle arrays
 * require TLS before preinit; main mutates the live main image and a selected
 * pthread worker must instead receive the linked PT_TLS initializers. This is
 * a private composition artifact, not a general x86 startup or pthread ABI.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

enum {
    primary_initial_value = 0x13579bdf,
    peer_initial_value = 0x2468ace0,
    preinit_value = 0x31415926,
    init_value = 0x27182818,
    main_value = 0x5555aaaa,
    worker_value = 0x11223344,
    tls_alignment = 4096,
};

__thread int crabc_crt_primary_initial = primary_initial_value;
__thread int crabc_crt_primary_tbss;
__thread unsigned char crabc_crt_primary_alignment __attribute__((aligned(tls_alignment))) = 0x5a;

extern __thread int crabc_crt_peer_initial;
extern __thread int crabc_crt_peer_tbss;
extern __thread unsigned char crabc_crt_peer_alignment;
extern uintptr_t crabc_crt_peer_alignment_address(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_create),
    int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict,
        void *(*)(void *), void *__restrict)),
    "pthread_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_join),
    int (*)(pthread_t, void **)), "pthread_join declaration");

static void emit(char value)
{
    register long result __asm__("rax") = 1;
    register long descriptor __asm__("rdi") = 1;
    register const char *bytes __asm__("rsi") = &value;
    register long count __asm__("rdx") = 1;

    __asm__ volatile("syscall"
        : "+a"(result)
        : "D"(descriptor), "S"(bytes), "d"(count)
        : "rcx", "r11", "memory");
}

static void reject(unsigned long status) __attribute__((noreturn));

static void reject(unsigned long status)
{
    register unsigned long number __asm__("rax") = 231;
    register unsigned long code __asm__("rdi") = status;

    __asm__ volatile("syscall" : "+a"(number) : "D"(code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static uintptr_t installed_thread_pointer(void)
{
    uintptr_t base = 0;
    register long result __asm__("rax") = 158;
    register long operation __asm__("rdi") = 0x1003;
    register uintptr_t *destination __asm__("rsi") = &base;

    __asm__ volatile("syscall"
        : "+a"(result)
        : "D"(operation), "S"(destination)
        : "rcx", "r11", "memory");
    return result == 0 ? base : 0;
}

static uintptr_t fs_self(void)
{
    uintptr_t value;

    __asm__ volatile("mov %%fs:0, %0" : "=r"(value));
    return value;
}

static int initial_values_hold(void)
{
    return errno == 0 && crabc_crt_primary_initial == primary_initial_value &&
        crabc_crt_primary_tbss == 0 && crabc_crt_peer_initial == peer_initial_value &&
        crabc_crt_peer_tbss == 0 && crabc_crt_primary_alignment == 0x5a &&
        crabc_crt_peer_alignment == 0x6b &&
        ((uintptr_t)&crabc_crt_primary_alignment & (tls_alignment - 1)) == 0 &&
        (crabc_crt_peer_alignment_address() & (tls_alignment - 1)) == 0;
}

static void set_all_tls(int value)
{
    crabc_crt_primary_initial = value;
    crabc_crt_primary_tbss = value;
    crabc_crt_peer_initial = value;
    crabc_crt_peer_tbss = value;
}

struct worker_observation {
    int initial_errno;
    int initial_primary;
    int initial_primary_tbss;
    int initial_peer;
    int initial_peer_tbss;
    uintptr_t errno_location;
    uintptr_t primary_alignment_address;
    uintptr_t peer_alignment_address;
};

static void *observe_worker(void *opaque)
{
    struct worker_observation *observation = opaque;

    observation->initial_errno = errno;
    observation->initial_primary = crabc_crt_primary_initial;
    observation->initial_primary_tbss = crabc_crt_primary_tbss;
    observation->initial_peer = crabc_crt_peer_initial;
    observation->initial_peer_tbss = crabc_crt_peer_tbss;
    observation->errno_location = (uintptr_t)__errno_location();
    observation->primary_alignment_address = (uintptr_t)&crabc_crt_primary_alignment;
    observation->peer_alignment_address = crabc_crt_peer_alignment_address();
    errno = E2BIG;
    set_all_tls(worker_value);
    return (void *)(uintptr_t)worker_value;
}

static void preinit(void)
{
    if (installed_thread_pointer() == 0 || installed_thread_pointer() != fs_self() ||
        !initial_values_hold())
        reject(81);
    set_all_tls(preinit_value);
    emit('P');
}

static void init(void)
{
    if (crabc_crt_primary_initial != preinit_value || crabc_crt_primary_tbss != preinit_value ||
        crabc_crt_peer_initial != preinit_value || crabc_crt_peer_tbss != preinit_value)
        reject(82);
    set_all_tls(init_value);
    emit('I');
}

static unsigned int callbacks_completed;
static unsigned int quiet_callbacks_completed;
static unsigned char cxa_argument;

static int main_values_hold(void)
{
    return errno == EACCES && crabc_crt_primary_initial == main_value &&
        crabc_crt_primary_tbss == main_value && crabc_crt_peer_initial == main_value &&
        crabc_crt_peer_tbss == main_value;
}

static void first_exit_handler(void)
{
    if (!main_values_hold() || callbacks_completed != 6)
        reject(89);
    callbacks_completed = 7;
    emit('A');
}

static void second_exit_handler(void)
{
    if (!main_values_hold() || callbacks_completed != 0 ||
        quiet_callbacks_completed != 28)
        reject(90);
    callbacks_completed = 2;
    emit('B');
}

static void cxa_exit_handler(void *argument)
{
    if (!main_values_hold() || argument != &cxa_argument || callbacks_completed != 2)
        reject(93);
    callbacks_completed = 6;
    emit('C');
}

static void quiet_exit_handler(void)
{
    ++quiet_callbacks_completed;
}

static void fini(void)
{
    if (errno != EACCES || crabc_crt_primary_initial != main_value ||
        crabc_crt_primary_tbss != main_value || crabc_crt_peer_initial != main_value ||
        crabc_crt_peer_tbss != main_value || callbacks_completed != 7 ||
        quiet_callbacks_completed != 28)
        reject(84);
    emit('F');
}

#if !defined(CRABC_CRT_STATIC_TLS_MUSL_REFERENCE)
__attribute__((used, section(".preinit_array")))
static void (*const preinit_entry)(void) = preinit;

__attribute__((used, section(".init_array")))
static void (*const init_entry)(void) = init;

__attribute__((used, section(".fini_array")))
static void (*const fini_entry)(void) = fini;
#endif

int main(int argc, char **argv, char **envp)
{
    pthread_t worker;
    void *worker_result = 0;
    struct worker_observation observation = {
        .initial_errno = -1,
        .initial_primary = -1,
        .initial_primary_tbss = -1,
        .initial_peer = -1,
        .initial_peer_tbss = -1,
        .errno_location = 0,
        .primary_alignment_address = 0,
        .peer_alignment_address = 0,
    };
    int *main_errno_location = __errno_location();

    extern int __cxa_atexit(void (*)(void *), void *, void *);
    extern void __cxa_finalize(void *);

#if defined(CRABC_CRT_STATIC_TLS_MUSL_REFERENCE)
    /* Musl's ordinary route does not call .preinit_array. Keep its TLS and
     * pthread behavior as the oracle while the fixture explicitly supplies
     * the lifecycle sequence that real rcrt1 owns in the candidate. */
    preinit();
    init();
    /* Ordinary musl exit owns the LIFO callback walk. Its normal CRT does
     * not dispatch this fixture's fini array, so establish the candidate's
     * pre-application fini registration explicitly before app handlers. */
    if (atexit(fini) != 0)
        return 91;
#endif

    if (argc <= 0 || argv == 0 || argv[0] == 0 || envp == 0 ||
        crabc_crt_primary_initial != init_value || crabc_crt_primary_tbss != init_value ||
        crabc_crt_peer_initial != init_value || crabc_crt_peer_tbss != init_value)
        return 85;
    errno = EACCES;
    set_all_tls(main_value);
    if (pthread_create(&worker, 0, observe_worker, &observation) != 0)
        return 86;
    if (pthread_join(worker, &worker_result) != 0)
        return 87;
    if (worker_result != (void *)(uintptr_t)worker_value ||
        observation.initial_errno != 0 || observation.initial_primary != primary_initial_value ||
        observation.initial_primary_tbss != 0 || observation.initial_peer != peer_initial_value ||
        observation.initial_peer_tbss != 0 || observation.errno_location == 0 ||
        observation.errno_location == (uintptr_t)main_errno_location ||
        (observation.primary_alignment_address & (tls_alignment - 1)) != 0 ||
        (observation.peer_alignment_address & (tls_alignment - 1)) != 0 ||
        errno != EACCES || crabc_crt_primary_initial != main_value ||
        crabc_crt_primary_tbss != main_value || crabc_crt_peer_initial != main_value ||
        crabc_crt_peer_tbss != main_value)
        return 88;
    if (atexit(first_exit_handler) != 0 ||
        __cxa_atexit(cxa_exit_handler, &cxa_argument, 0) != 0 ||
        atexit(second_exit_handler) != 0)
        return 92;
    /* Musl leaves ordinary registrations for the process-exit walk; the
     * selected archive intentionally preserves that no-op compatibility
     * boundary instead of claiming DSO-specific destruction. */
    __cxa_finalize(0);
    for (unsigned int index = 0; index < 28; ++index) {
        if (atexit(quiet_exit_handler) != 0)
            return 94;
    }
#if defined(CRABC_CRT_STATIC_TLS_CANDIDATE)
    if (atexit(quiet_exit_handler) != -1)
        return 95;
#endif
    emit('M');
    return 0;
}
