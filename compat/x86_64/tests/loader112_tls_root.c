#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>

extern int *loader112_dependency_cell(void);
extern int loader112_dependency_ready(void);
static _Thread_local int value = 101;
static unsigned constructed, destroyed, constructor_worker;
static int *(*nested_cell)(void);
static unsigned char *(*nested_zero)(void);
static int (*nested_ready)(void);

#define CHECK(c) do { if (!(c)) _Exit(81); } while (0)

static void *fresh_constructor_worker(void *argument)
{
    (void)argument;
    CHECK(value == 101 && *loader112_dependency_cell() == 201);
    CHECK(nested_ready() && *nested_cell() == 301);
    CHECK(nested_zero()[0] == 0 && nested_zero()[256] == 0);
    value = 141;
    *loader112_dependency_cell() = 241;
    *nested_cell() = 341;
    constructor_worker = 1;
    return 0;
}

__attribute__((constructor)) static void initialize(void)
{
    CHECK(value == 101 && loader112_dependency_ready());
    CHECK(*loader112_dependency_cell() == 201);
    void *nested = dlopen("libloader112-module-00.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(nested);
    nested_cell = (int *(*)(void))dlsym(nested, "loader112_cell");
    nested_zero = (unsigned char *(*)(void))dlsym(nested, "loader112_zero");
    nested_ready = (int (*)(void))dlsym(nested, "loader112_ready");
    CHECK(nested_cell && nested_zero && nested_ready && nested_ready());
    CHECK(*nested_cell() == 301);
    value = 111;
    *loader112_dependency_cell() = 211;
    *nested_cell() = 311;
    pthread_t worker;
    CHECK(pthread_create(&worker, 0, fresh_constructor_worker, 0) == 0);
    CHECK(pthread_join(worker, 0) == 0);
    CHECK(constructor_worker && value == 111);
    CHECK(*loader112_dependency_cell() == 211 && *nested_cell() == 311);
    CHECK(dlclose(nested) == 0);
    ++constructed;
}

__attribute__((destructor)) static void finalize(void) { ++destroyed; }

int *loader112_root_cell(void) { return &value; }
int loader112_root_ready(void)
{
    return constructed == 1 && destroyed == 0 && constructor_worker == 1;
}
