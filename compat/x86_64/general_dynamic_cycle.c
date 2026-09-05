#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { if (!(condition)) _Exit(91); } while (0)

#if defined(CYCLE_SEED)
int cycle_a_leaf(void) { return 5; }
#elif defined(CYCLE_A)
static _Thread_local int value = 5;
static int initialized;
extern int cycle_b_leaf(void);
int cycle_a_leaf(void) { return value; }
void cycle_a_set(int next) { value = next; }
int cycle_a_count(void) { return initialized; }
__attribute__((constructor)) static void initialize(void)
{
    CHECK(!initialized && value == 5 && cycle_b_leaf() == 7);
    initialized = 1;
    puts("A init");
}
__attribute__((destructor)) static void finalize(void)
{
    CHECK(initialized == 1 && value == 31);
    initialized = 2;
    puts("A fini");
}
#elif defined(CYCLE_B)
static _Thread_local int value = 7;
static int initialized;
extern int cycle_a_leaf(void);
int cycle_b_leaf(void) { return value; }
void cycle_b_set(int next) { value = next; }
int cycle_b_count(void) { return initialized; }
__attribute__((constructor)) static void initialize(void)
{
    CHECK(!initialized && value == 7 && cycle_a_leaf() == 5);
    initialized = 1;
    puts("B init");
}
__attribute__((destructor)) static void finalize(void)
{
    CHECK(initialized == 1 && value == 43);
    initialized = 2;
    puts("B fini");
}
#else
extern int cycle_a_leaf(void), cycle_b_leaf(void), cycle_a_count(void), cycle_b_count(void);
extern void cycle_a_set(int), cycle_b_set(int);
__attribute__((constructor)) static void initialize(void) { puts("main init"); }
__attribute__((destructor)) static void finalize(void) { puts("main fini"); }
static void *worker(void *unused)
{
    (void)unused;
    CHECK(cycle_a_leaf() == 5 && cycle_b_leaf() == 7);
    CHECK(cycle_a_count() == 1 && cycle_b_count() == 1);
    cycle_a_set(67);
    cycle_b_set(79);
    return 0;
}
int main(void)
{
    CHECK(cycle_a_leaf() == 5 && cycle_b_leaf() == 7);
    CHECK(cycle_a_count() == 1 && cycle_b_count() == 1);
    void *a = dlopen("libcycle_a.so", RTLD_NOW);
    void *b = dlopen("libcycle_b.so", RTLD_NOW);
    CHECK(a && b && !dlclose(a) && !dlclose(b));
    CHECK(cycle_a_count() == 1 && cycle_b_count() == 1);
    cycle_a_set(31);
    cycle_b_set(43);
    pthread_t thread;
    CHECK(!pthread_create(&thread, 0, worker, 0) && !pthread_join(thread, 0));
    CHECK(cycle_a_leaf() == 31 && cycle_b_leaf() == 43);
    puts("cycle main");
    return 0;
}
#endif
