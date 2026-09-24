/* Owned dynamic product cross-DSO composition witness.
 *
 * The installed main links one initial dependency whose TLS uses the
 * initial-exec model and loads one plugin at run time. One ordinary C program
 * then proves the behavior a real application relies on across module
 * boundaries: initial IE TLS shared by the executable and the dependency,
 * reopening that already-initial IE object through dlopen, a runtime plugin's
 * GD TLS in both an existing worker and new workers, allocation ownership
 * moving between modules, one errno and one stdout per thread/process, a
 * pthread key whose destructor lives in a different module from the value's
 * setter, a signal raised in one module and handled in another, retained
 * dlclose/reopen of the plugin, and exit-time atexit/destructor/stdio order.
 *
 * Each line is a deterministic fact; pinned musl and every installed product
 * mode must print identical bytes. A failed check exits with its line number.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern __thread int cross_ie_value;
extern __thread unsigned char cross_ie_zero[97];
extern int *cross_ie_address(void);
extern int cross_ie_template(void);
extern int *cross_errno_address(void);
extern FILE *cross_stdout(void);
extern void *cross_allocate(size_t size, int fill);
extern void cross_release(void *block);
extern int cross_fail_errno(void);
extern void cross_emit(const char *text);
extern int cross_key_create(void);
extern int cross_key_destructed(void);
extern int cross_install_handler(int signal);
extern int cross_handled_signal(void);
extern int cross_handled_code(void);
extern int cross_handled_value(void);

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "cross-dso check failed: line %d: %s; %s\n", __LINE__, #condition, dlerror()); \
    _Exit(100); } } while (0)

enum { WORKERS = 4 };

static int (*plugin_views)(void);
static int (*plugin_gd_template)(void);
static void (*plugin_gd_set)(int);
static int (*plugin_gd_get)(void);
static int (*plugin_consume)(void *, int);
static void *(*plugin_aligned)(void);
static int (*plugin_set_specific)(void);
static int (*plugin_raise)(int);
static int (*plugin_errno_set)(int);
static int (*plugin_register_exit)(void);

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t loaded_changed = PTHREAD_COND_INITIALIZER;
static int plugin_loaded;

static void *resolve(void *handle, const char *name)
{
    void *symbol = dlsym(handle, name);
    CHECK(symbol);
    return symbol;
}

/* Worker TLS starts from the linked templates, never from the main thread's
   live values, and errno is per thread in every module. */
static int fresh_thread_state(void)
{
    return cross_ie_template() && &cross_ie_value == cross_ie_address()
        && cross_ie_zero[0] == 0 && cross_ie_zero[96] == 0 && errno == 0
        && &errno == cross_errno_address();
}

static int plugin_thread_state(void)
{
    if (!plugin_gd_template() || !plugin_views()) return 0;
    plugin_gd_set(88);
    if (plugin_gd_get() != 88) return 0;
    if (plugin_errno_set(ERANGE) != ERANGE || errno != ERANGE) return 0;
    return plugin_set_specific() == 0;
}

static void *early_worker(void *argument)
{
    (void)argument;
    if (!fresh_thread_state()) return (void *)1;
    cross_ie_value = 5;
    pthread_mutex_lock(&lock);
    while (!plugin_loaded) pthread_cond_wait(&loaded_changed, &lock);
    pthread_mutex_unlock(&lock);
    /* The plugin's TLS module appeared after this thread was created. */
    if (!plugin_thread_state() || cross_ie_value != 5) return (void *)2;
    return 0;
}

static void *late_worker(void *argument)
{
    (void)argument;
    if (!fresh_thread_state() || !plugin_thread_state()) return (void *)3;
    /* This thread allocates; the initial thread frees after join. */
    return cross_allocate(80, 0x6d);
}

static void main_at_exit(void) { fputs("main atexit\n", stdout); }

__attribute__((constructor)) static void construct(void) { fputs("main constructor\n", stdout); }
__attribute__((destructor)) static void finalize(void) { fputs("main destructor\n", stdout); }

int main(void)
{
    /* Initial IE TLS: the executable's IE access and the dependency's own
       access name one initialized, zero-filled, over-aligned block. */
    CHECK(&cross_ie_value == cross_ie_address() && cross_ie_template());
    cross_ie_value = 101;
    CHECK(*cross_ie_address() == 101);
    puts("initial IE: executable and dependency share the static block");

    pthread_t early;
    CHECK(pthread_create(&early, 0, early_worker, 0) == 0);

    /* Reopening the already-initial IE object is not a new static-TLS load. */
    void *initial = dlopen("libcross-initial.so", RTLD_NOW | RTLD_NOLOAD);
    CHECK(initial);
    void *again = dlopen("libcross-initial.so", RTLD_LAZY | RTLD_GLOBAL);
    CHECK(again == initial);
    CHECK(dlsym(initial, "cross_ie_value") == (void *)&cross_ie_value);
    CHECK(dlclose(again) == 0 && dlclose(initial) == 0);
    CHECK(cross_ie_value == 101 && *cross_ie_address() == 101);
    puts("initial IE reopen: same handle and TLS address");

    errno = 0;
    CHECK(cross_fail_errno() == -1 && errno == EBADF && &errno == cross_errno_address());
    puts("errno: dependency failure visible to caller");

    void *plugin = dlopen("libcross-plugin.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(plugin);
    plugin_views = (int (*)(void))resolve(plugin, "plugin_views");
    plugin_gd_template = (int (*)(void))resolve(plugin, "plugin_gd_template");
    plugin_gd_set = (void (*)(int))resolve(plugin, "plugin_gd_set");
    plugin_gd_get = (int (*)(void))resolve(plugin, "plugin_gd_get");
    plugin_consume = (int (*)(void *, int))resolve(plugin, "plugin_consume");
    plugin_aligned = (void *(*)(void))resolve(plugin, "plugin_aligned");
    plugin_set_specific = (int (*)(void))resolve(plugin, "plugin_set_specific");
    plugin_raise = (int (*)(int))resolve(plugin, "plugin_raise");
    plugin_errno_set = (int (*)(int))resolve(plugin, "plugin_errno_set");
    plugin_register_exit = (int (*)(void))resolve(plugin, "plugin_register_exit");
    CHECK(plugin_views() && plugin_gd_template());
    puts("plugin: GD access names the initial IE block, errno and stdout");

    CHECK(plugin_consume(cross_allocate(48, 0x3a), 0x3a));
    void *aligned = plugin_aligned();
    CHECK(aligned && ((uintptr_t)aligned & 255) == 0);
    memset(aligned, 0x11, 512);
    cross_release(aligned);
    unsigned char *grown = realloc(cross_allocate(24, 0x42), 8192);
    CHECK(grown && grown[0] == 0x42 && grown[23] == 0x42);
    free(grown);
    puts("allocation: blocks cross module ownership");

    CHECK(cross_key_create() == 0);
    pthread_mutex_lock(&lock);
    plugin_loaded = 1;
    pthread_cond_broadcast(&loaded_changed);
    pthread_mutex_unlock(&lock);
    void *result = (void *)1;
    CHECK(pthread_join(early, &result) == 0 && result == 0);
    errno = EDOM;
    pthread_t late[WORKERS];
    for (int index = 0; index < WORKERS; ++index)
        CHECK(pthread_create(&late[index], 0, late_worker, 0) == 0);
    for (int index = 0; index < WORKERS; ++index) {
        unsigned char *block = 0;
        CHECK(pthread_join(late[index], (void **)&block) == 0);
        CHECK((uintptr_t)block > 16 && block[0] == 0x6d && block[79] == 0x6d);
        free(block);
    }
    CHECK(cross_key_destructed() == WORKERS + 1);
    CHECK(errno == EDOM && cross_ie_value == 101 && plugin_gd_template());
    puts("threads: existing and new workers see fresh IE and GD TLS");
    puts("TSD: dependency destructor frees plugin values at thread exit");

    CHECK(cross_install_handler(SIGUSR1) == 0);
    errno = E2BIG;
    CHECK(plugin_raise(SIGUSR1) == 0);
    CHECK(errno == E2BIG && cross_handled_signal() == SIGUSR1);
    CHECK(cross_handled_code() == SI_TKILL && cross_handled_value() == 101);
    puts("signal: plugin raise, dependency handler, errno preserved");

    cross_emit("stdio: dependency writes the shared buffered stdout\n");
    CHECK(cross_stdout() == stdout);

    /* Successful dlclose retains the mapping; reopening does not reconstruct
       the plugin and its thread-local state survives. */
    plugin_gd_set(77);
    int (*get)(void) = plugin_gd_get;
    CHECK(dlclose(plugin) == 0);
    void *reopened = dlopen("libcross-plugin.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(reopened);
    CHECK(dlsym(reopened, "plugin_gd_get") == (void *)get && get() == 77);
    puts("retained close: reopen keeps mapping and TLS without reconstruction");

    CHECK(plugin_register_exit() == 0 && atexit(main_at_exit) == 0);
    puts("exit: returning from main");
    return 0;
}
