/* One ordinary application; all lifecycle work belongs to CRT/libc/ldso. */
extern char *getenv(const char *);
extern unsigned long getauxval(unsigned long);
extern int issetugid(void);
extern int *__errno_location(void);
extern int atexit(void (*)(void));
extern void exit(int) __attribute__((noreturn));
extern void _Exit(int) __attribute__((noreturn));
extern int left_anchor(void);
extern int right_anchor(void);
extern char **environ;
volatile int lifecycle_stage;
static __thread int application_tls = 17;

void lifecycle_emit(char value) {
    __asm__ volatile("syscall" : : "a"(1L), "D"(1L), "S"(&value), "d"(1L)
                     : "rcx", "r11", "memory");
}
void lifecycle_runtime_check(void) {
    char *value = getenv("CRABC_LIFECYCLE_VALUE");
    unsigned long guard;
    __asm__ volatile("mov %%fs:40, %0" : "=r"(guard));
    if (!environ || !value || value[0] != 'y' || value[1] != 'e'
        || value[2] != 's' || value[3] || getauxval(6) != 4096
        || issetugid() != !!(getauxval(23) || getauxval(11) != getauxval(12)
                            || getauxval(13) != getauxval(14))
        || !guard || (guard & 0xff00) || application_tls != 17)
        _Exit(71);
}
static void preinit(void) {
    lifecycle_runtime_check();
    if (lifecycle_stage || *__errno_location()) _Exit(72);
    lifecycle_stage = 1;
    lifecycle_emit('P');
}
static void init(void) {
    lifecycle_runtime_check();
#ifdef MUSL_ORACLE
    const int expected_stage = 0; /* musl 1.2.6 ignores DT_PREINIT_ARRAY. */
#else
    const int expected_stage = 1;
#endif
    if (lifecycle_stage != expected_stage || left_anchor() != 7 || right_anchor() != 7) _Exit(73);
    lifecycle_stage = 2;
    lifecycle_emit('I');
}
static void fini(void) {
    lifecycle_runtime_check();
    if (lifecycle_stage != 4 || *__errno_location() != 37) _Exit(74);
    lifecycle_stage = 5;
    lifecycle_emit('F');
}
static void handler_first(void) { lifecycle_stage = 4; lifecycle_emit('a'); }
static void handler_second(void) { lifecycle_emit('b'); }
__attribute__((section(".preinit_array"), used)) static void (*const preinit_entry)(void) = preinit;
__attribute__((section(".init_array"), used)) static void (*const init_entry)(void) = init;
__attribute__((section(".fini_array"), used)) static void (*const fini_entry)(void) = fini;

int main(int argc, char **argv, char **envp) {
    lifecycle_runtime_check();
    if (argc < 1 || !argv || !argv[0] || envp != environ || lifecycle_stage != 2
        || atexit(handler_first) || atexit(handler_second)) _Exit(75);
    *__errno_location() = 37;
    lifecycle_stage = 3;
    lifecycle_emit('M');
#ifdef EXPLICIT_EXIT
    exit(23);
#elif defined(IMMEDIATE_EXIT)
    _Exit(29);
#else
    return 19;
#endif
}
