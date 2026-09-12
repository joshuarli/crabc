extern void _init(void);
extern void _fini(void);
int loader_crt_events;
__attribute__((weak)) int loader_crt_expected;

int loader_crt_archive_probe(void)
{
    _init();
    _fini();
    return loader_crt_events == loader_crt_expected * 3 ? 0 : 51;
}

/* This isolated archive consumer intentionally contributes no CRT hooks.
 * The same PIC object exercises each selected archive through ordinary
 * extraction; none of the initialized runtime/TLS machinery is called. */
__asm__(".text\n.global _start\n.type _start,@function\n_start:\n"
        "and $-16,%rsp\ncall loader_crt_archive_probe\n"
        "mov %eax,%edi\nmov $60,%eax\nsyscall\nud2\n");
