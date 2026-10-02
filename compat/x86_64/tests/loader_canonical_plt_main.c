#include <dlfcn.h>

extern int loader_canonical_plt_function(void);
extern void *loader_canonical_plt_provider_address(void);

/* Compile without PIE: taking this imported function's address publishes
 * its canonical PLT entry in the executable's undefined dynamic symbol. */
int main(void)
{
    void *canonical = (void *)loader_canonical_plt_function;
    return loader_canonical_plt_function() != 73
        || canonical != loader_canonical_plt_provider_address()
        || canonical != dlsym(RTLD_DEFAULT, "loader_canonical_plt_function");
}
