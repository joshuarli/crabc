extern void lifecycle_emit(char);
extern void lifecycle_runtime_check(void);
extern volatile int lifecycle_stage;
extern int *__errno_location(void);
extern void _Exit(int) __attribute__((noreturn));
#ifdef HAS_DEPENDENCY
extern int dependency_anchor(void);
#endif
static __thread int dependency_tls = 7;
static void init(void) {
    lifecycle_runtime_check();
    /* Pinned musl does not dispatch DT_PREINIT_ARRAY; owned CRT does. */
    if ((lifecycle_stage != 0 && lifecycle_stage != 1)
        || *__errno_location() || dependency_tls != 7) _Exit(81);
    lifecycle_emit(INIT_MARKER);
}
static void fini(void) {
    lifecycle_runtime_check();
    if (lifecycle_stage != 5 || *__errno_location() != 37 || dependency_tls != 7) _Exit(82);
    lifecycle_emit(FINI_MARKER);
}
__attribute__((section(".init_array"), used)) static void (*const init_entry)(void) = init;
__attribute__((section(".fini_array"), used)) static void (*const fini_entry)(void) = fini;
int ANCHOR(void) {
#ifdef HAS_DEPENDENCY
    return dependency_anchor();
#else
    return dependency_tls;
#endif
}
