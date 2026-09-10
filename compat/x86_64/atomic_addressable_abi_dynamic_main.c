/* The two existing probes exercise C and C++ address-taken calls.  Keep the
 * installed dynamic executable's entry point separate so neither fixture
 * becomes an implicit CRT or language-runtime test. */
extern int crabc_x86_64_atomic_addressable_probe(void);

int main(void)
{
    return crabc_x86_64_atomic_addressable_probe();
}
