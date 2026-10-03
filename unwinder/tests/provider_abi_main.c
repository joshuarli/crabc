/* Link with explicit startup inputs: crt1 for ET_EXEC, rcrt1 for static PIE,
 * or the dynamic interpreter's startup route. A PIE without an interpreter
 * needs its own relocation startup before it can call the unwind provider. */
extern int crabc_provider_abi_walk(void);

__attribute__((noinline)) static int call_provider(void)
{
    volatile int result = crabc_provider_abi_walk();
    return result;
}

int main(void)
{
    return call_provider();
}
