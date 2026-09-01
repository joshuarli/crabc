#ifndef CRABC_LDSO_GENERAL_INITIAL_GRAPH_CYCLE_MARKER_H
#define CRABC_LDSO_GENERAL_INITIAL_GRAPH_CYCLE_MARKER_H

#if defined(CRABC_GENERAL_CYCLE_CALLBACK_MARKER)
/*
 * The cycle-negative graph must fail while its full constructor plan is still
 * being preflighted. Keep this marker independent of libc so the fixtures
 * retain their `-nostdlib` profile: any erroneous dependency callback makes
 * a visible line on stderr before the loader can report `ctorplan`.
 */
static void general_initial_graph_cycle_callback_marker(void) {
    static const char message[] = "cycle-constructor-ran\n";
    register long syscall_number __asm__("rax") = 1; /* Linux SYS_write. */
    register long output_fd __asm__("rdi") = 2;
    register const char *output_message __asm__("rsi") = message;
    register long output_length __asm__("rdx") = sizeof(message) - 1;

    __asm__ volatile(
        "syscall"
        : "+a"(syscall_number)
        : "D"(output_fd), "S"(output_message), "d"(output_length)
        : "rcx", "r11", "memory");
}
#endif

#endif
