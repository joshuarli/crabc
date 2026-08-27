#define _GNU_SOURCE 1
#include <signal.h>
#include <stdint.h>
#include <stddef.h>

static void actual_handler(int signal) { (void)signal; }
static void reference_restorer(void) { __builtin_trap(); }
struct kernel_action { uintptr_t handler; uint64_t flags; uintptr_t restorer; uint64_t mask; };
#ifdef CRABC_SIGNAL_REFERENCE
static void crabc_x86_64_signal_action_pack(const void *input, void *output)
{
    const struct sigaction *in = input;
    struct kernel_action *out = output;
    out->handler = (uintptr_t)in->sa_handler;
    out->flags = (unsigned long)in->sa_flags;
    out->flags |= SA_RESTORER;
    out->restorer = (uintptr_t)reference_restorer;
    out->mask = in->sa_mask.__bits[0];
}
#else
extern void crabc_x86_64_signal_action_pack(const void *, void *);
#endif
static int check(void (*handler)(int), int flags, uint64_t mask)
{
    struct sigaction in = {0};
    struct kernel_action out = {0};
    in.sa_handler = handler;
    in.sa_flags = flags;
    in.sa_mask.__bits[0] = mask;
    in.sa_restorer = (void (*)(void))0x1234;
    crabc_x86_64_signal_action_pack(&in, &out);
    if (out.handler != (uintptr_t)handler || out.mask != mask) return 1;
    if (out.flags != ((unsigned long)flags | SA_RESTORER)) return 2;
    if (out.restorer == 0x1234) return 3;
    return 0;
}
int main(void)
{
    _Static_assert(sizeof(struct sigaction) == 152, "public x86 action");
    _Static_assert(sizeof(struct kernel_action) == 32, "kernel action");
    if (check(SIG_DFL, SA_RESTART, 0x55)) return 10;
    if (check(SIG_IGN, SA_RESTART, 0x66)) return 11;
    if (check(actual_handler, SA_SIGINFO, 0xaa)) return 12;
    if (check(SIG_DFL, INT32_MIN, 0xff)) return 13;
    return 0;
}
