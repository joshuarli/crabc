/* Owned compiler-helper consumer for the private installed static sysroot.
 *
 * Volatile 128-bit operands force the final link to resolve __udivti3 from
 * the installed Rust-only libcrabc-builtins.a.  This constructor is silent so
 * the adjacent CRT/libc/TLS lifecycle fixture retains its existing trace.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

typedef unsigned __int128 crabc_uint128;

static volatile crabc_uint128 numerator = (crabc_uint128)10 << 64;
static volatile crabc_uint128 denominator = 5;

static void reject(void) __attribute__((noreturn));

static void reject(void)
{
    register unsigned long number __asm__("rax") = 231;
    register unsigned long status __asm__("rdi") = 97;

    __asm__ volatile("syscall" : "+a"(number) : "D"(status) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static void require_owned_udivti3(void)
{
    crabc_uint128 quotient = numerator / denominator;

    if (quotient != (crabc_uint128)2 << 64)
        reject();
}

__attribute__((used, section(".init_array")))
static void (*const owned_builtins_initializer)(void) = require_owned_udivti3;
