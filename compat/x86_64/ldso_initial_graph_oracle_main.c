extern int mid_value(void);
extern int mid_leaf_relro_write_signal(void);

/* The pinned-musl baseline uses a fixture CRT that enters `main` directly,
 * so it intentionally proves mapping/relocation only; musl's ordinary
 * init-array handoff belongs to its libc startup path, not this CRT. */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (mid_value() != 42) return 42;
    return mid_leaf_relro_write_signal() == 11 ? 0 : 43;
}
