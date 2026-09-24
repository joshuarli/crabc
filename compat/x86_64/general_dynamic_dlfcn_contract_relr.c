/* Musl differential for DT_RELR in a runtime-loaded object: every packed
 * relative pointer, including a bitmap boundary and a separated cluster,
 * must equal its target after dlopen. Output is the comparison surface. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

#include "general_dynamic_dlfcn_contract.h"

int main(void)
{
    void *handle = dlopen("librelr.so", RTLD_NOW);
    printf("relr open: %s\n", result(handle));
    show_error("relr open");
    int (*matches)(void) = handle ? (int (*)(void))dlsym(handle, "relr_matches") : 0;
    char ****environ_slot = handle ? dlsym(handle, "relr_environ") : 0;
    extern char **environ;
    printf("relr matches=%d of 71\n", matches ? matches() : -1);
    printf("relr symbolic import intact=%d\n", environ_slot && *environ_slot == &environ);
    puts("relr contract: complete");
    return 0;
}
