/* Initial dependency of the owned dynamic cross-DSO composition witness.
 *
 * The consumer links this object as an ordinary DT_NEEDED dependency. Its
 * thread-local variables use the initial-exec model, so the object carries
 * DF_STATIC_TLS and must be placed in the initial static TLS block; the
 * executable reaches the same variables through its own IE GOT entries. The
 * object also owns the process-wide pieces other modules share: an allocation
 * producer and consumer, an errno-setting failure, a stdout writer, a
 * pthread key whose destructor runs for threads that never called into it,
 * a SA_SIGINFO handler, and a destructor that writes buffered stdout after
 * every atexit handler. Everything observable is a deterministic fact so
 * pinned musl and the installed product must print identical bytes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__thread int cross_ie_value __attribute__((tls_model("initial-exec"))) = 29;
__thread unsigned char cross_ie_zero[97] __attribute__((tls_model("initial-exec"), aligned(128)));

static pthread_key_t key;
static atomic_int destructed;
static atomic_int handled_signal;
static atomic_int handled_code;
static atomic_int handled_value;

int *cross_ie_address(void) { return &cross_ie_value; }

int cross_ie_template(void)
{
    for (size_t index = 0; index < sizeof cross_ie_zero; ++index)
        if (cross_ie_zero[index]) return 0;
    return cross_ie_value == 29 && ((unsigned long)cross_ie_zero & 127) == 0;
}

int *cross_errno_address(void) { return &errno; }
FILE *cross_stdout(void) { return stdout; }

void *cross_allocate(size_t size, int fill)
{
    unsigned char *block = malloc(size);
    if (block) memset(block, fill, size);
    return block;
}

void cross_release(void *block) { free(block); }

/* Fails through an ordinary libc call; the caller observes the errno. */
int cross_fail_errno(void) { return close(-1); }

void cross_emit(const char *text) { fputs(text, stdout); }

static void destroy(void *value)
{
    /* The value was allocated by another module and is freed here. */
    unsigned char *block = value;
    if (block[0] == 0x5c && block[63] == 0x5c) atomic_fetch_add(&destructed, 1);
    free(block);
}

int cross_key_create(void) { return pthread_key_create(&key, destroy); }
pthread_key_t cross_key(void) { return key; }
int cross_key_destructed(void) { return atomic_load(&destructed); }

static void handler(int signal, siginfo_t *information, void *context)
{
    (void)context;
    int saved = errno;
    /* A handler that fails a call must not leak its errno to the interrupted code. */
    (void)close(-1);
    atomic_store(&handled_signal, signal);
    atomic_store(&handled_code, information->si_code);
    atomic_store(&handled_value, cross_ie_value);
    errno = saved;
}

int cross_install_handler(int signal)
{
    struct sigaction action = {0};
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    return sigaction(signal, &action, 0);
}

int cross_handled_signal(void) { return atomic_load(&handled_signal); }
int cross_handled_code(void) { return atomic_load(&handled_code); }
int cross_handled_value(void) { return atomic_load(&handled_value); }

__attribute__((constructor)) static void construct(void) { fputs("initial constructor\n", stdout); }
__attribute__((destructor)) static void finalize(void) { fputs("initial destructor\n", stdout); }
