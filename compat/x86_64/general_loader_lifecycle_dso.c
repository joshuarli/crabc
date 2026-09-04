/* One source creates every node; topology and identity belong to the loader. */
extern void lifecycle_emit(char);
extern void lifecycle_reenter(void);
#ifdef USE_TLS
static __thread int tls_value = 7;
#endif
#ifdef HAS_DEPENDENCY
extern int dependency_anchor(void);
#endif

void legacy_init(void) {
#ifdef USE_TLS
    if (tls_value != 7) lifecycle_emit('?');
#endif
    lifecycle_emit(TAG_BASE);
}
static void init_first(void) { lifecycle_emit(TAG_BASE + 1); }
static void init_second(void) { lifecycle_emit(TAG_BASE + 2); }
static void fini_first(void) { lifecycle_emit(TAG_BASE + 3); }
static void fini_second(void) {
    lifecycle_emit(TAG_BASE + 4);
    lifecycle_reenter();
}
#ifdef BAD_LEGACY_FINI
int legacy_fini;
#else
void legacy_fini(void) {
#ifdef USE_TLS
    if (tls_value != 7) lifecycle_emit('?');
#endif
    lifecycle_emit(TAG_BASE + 5);
}
#endif
__attribute__((section(".init_array"), used))
static void (*const initializers[])(void) = { init_first, init_second };
#ifdef BAD_FINI_ZERO
#define LAST_FINALIZER 0
#elif defined(BAD_FINI_DATA)
static int nonexecutable;
#define LAST_FINALIZER ((void (*)(void)) &nonexecutable)
#else
#define LAST_FINALIZER fini_second
#endif
__attribute__((section(".fini_array"), used))
static void (*const finalizers[])(void) = { fini_first, LAST_FINALIZER };

int ANCHOR(void) {
#ifdef HAS_DEPENDENCY
    return dependency_anchor();
#else
#ifdef USE_TLS
    return tls_value;
#else
    return 7;
#endif
#endif
}
