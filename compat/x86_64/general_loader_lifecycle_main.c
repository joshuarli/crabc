typedef void (*finalizer)(void);
static finalizer process_finalizer;
extern int left_anchor(void);
extern int right_anchor(void);

void lifecycle_emit(char value) {
    __asm__ volatile("syscall" : : "a"(1L), "D"(1L), "S"(&value), "d"(1L)
                     : "rcx", "r11", "memory");
}
void lifecycle_reenter(void) {
    if (process_finalizer) process_finalizer();
}
#ifdef CANDIDATE
int lifecycle_main(finalizer finish) {
    if (!finish) return 91;
    process_finalizer = finish;
#else
int main(void) {
#endif
    if (left_anchor() != 7 || right_anchor() != 7) return 92;
    lifecycle_emit('!');
#ifdef CANDIDATE
    process_finalizer();
    process_finalizer();
#endif
    return 0;
}
