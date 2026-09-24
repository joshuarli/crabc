/* Musl differential for dlfcn reentry from runtime constructors.
 *
 * dlopen(libre_root.so, RTLD_LOCAL) queues libre_dep.so then the root. The
 * dependency's constructor sees both published images and reopens the
 * unconstructed root with RTLD_NOLOAD, which runs the root's constructor
 * nested inside its own (pinned musl 1.2.6 ldso/dynlink.c::do_init_fini
 * skips only objects this thread is already visiting). The root constructor
 * consumes the caller's pending dlerror, reopens and closes itself, finds
 * itself through its handle but not RTLD_DEFAULT, loads a new object with
 * its own constructor, and leaves a failed open pending: a successful outer
 * dlopen does not clear it. Output is the comparison surface. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>

#include "general_dynamic_dlfcn_contract.h"

int main(void)
{
    dlsym(RTLD_DEFAULT, "re_pending_before_open");
    void *root = dlopen("libre_root.so", RTLD_NOW | RTLD_LOCAL);
    printf("root open: %s\n", result(root));
    show_error("after root open");
    show_error("consumed");
    if (!root) return 2;
    int *value = dlsym(root, "re_root_symbol");
    printf("root handle re_root_symbol=%d\n", value ? *value : -1);
    printf("default re_root_symbol: %s\n", dlsym(RTLD_DEFAULT, "re_root_symbol") ? "found" : "null");
    show_error("default re_root_symbol");
    printf("reopen root: %d\n", dlopen("libre_root.so", RTLD_NOW) == root);
    printf("plain retained: %s\n", result(dlopen("libre_plain.so", RTLD_NOW | RTLD_NOLOAD)));
    printf("dep retained: %s\n", result(dlopen("libre_dep.so", RTLD_NOW | RTLD_NOLOAD)));
    puts("reentrant contract: complete");
    return 0;
}
