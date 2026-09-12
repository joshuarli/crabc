#include <stdlib.h>
#include <unistd.h>

static int phase;

__attribute__((used, noinline)) static void legacy_init(void)
{
    if (phase != 0) _Exit(41);
    phase = 1;
}
__attribute__((constructor)) static void constructor(void)
{
    if (phase != 1) _Exit(42);
    phase = 2;
}
static void registered_exit(void)
{
    if (phase != 3) _Exit(44);
    phase = 4;
}
__attribute__((destructor)) static void destructor(void)
{
    if (phase != 4) _Exit(45);
    phase = 5;
}
__attribute__((used, noinline)) static void legacy_fini(void)
{
    if (phase != 5) _Exit(46);
    phase = 6;
    static const char message[] = "loader-crt-lifecycle-ok\n";
    if (write(1, message, sizeof message - 1) != sizeof message - 1) _Exit(47);
}
__asm__(".pushsection .init,\"ax\",@progbits\ncall legacy_init\n.popsection\n"
        ".pushsection .fini,\"ax\",@progbits\ncall legacy_fini\n.popsection\n");

int main(void)
{
    if (phase != 2 || atexit(registered_exit)) return 43;
    phase = 3;
    return 0;
}
