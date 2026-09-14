#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

static int constructor_completed;

static void require(int condition)
{
    if (!condition) _Exit(91);
}

static void public_dlfcn_transaction(void)
{
    typedef int (*value_function)(void);
    void *handle;
    value_function value;

    dlerror();
    require(dlsym(RTLD_DEFAULT, "loader_structural_owner_missing") == NULL);
    require(dlerror() != NULL);
    require(dlerror() == NULL);
    handle = dlopen("libloader-structural-owner-plugin.so", RTLD_NOW | RTLD_LOCAL);
    require(handle != NULL);
    value = (value_function)dlsym(handle, "loader_structural_owner_plugin_value");
    require(value != NULL && dlerror() == NULL && value() == 47);
    require(dlclose(handle) == 0);
}

__attribute__((constructor)) static void selected_constructor_consumer(void)
{
    public_dlfcn_transaction();
    constructor_completed = 1;
}

int main(void)
{
    require(constructor_completed == 1);
    public_dlfcn_transaction();
    puts("loader-structural-startup-public-dlfcn-ok");
    return 0;
}
