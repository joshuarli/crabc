#define _GNU_SOURCE
#include <errno.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "static phdr check failed at %d: %s\n", __LINE__, #c); abort(); } } while (0)
static _Thread_local unsigned long initialized_tls = 0x31415926UL;
static _Thread_local unsigned long zero_tls;
extern const ElfW(Dyn) _DYNAMIC[] __attribute__((weak, visibility("hidden")));
struct observation { unsigned calls; int result; uintptr_t tls_base; };

static int observe(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct observation *seen = opaque;
    CHECK(errno == EDOM);
    CHECK(size == sizeof(*info) && ++seen->calls == 1);
    CHECK(strcmp(info->dlpi_name, "/proc/self/exe") == 0);
    CHECK((uintptr_t)info->dlpi_phdr == getauxval(AT_PHDR));
    CHECK(info->dlpi_phnum == getauxval(AT_PHNUM));
    CHECK(info->dlpi_adds == 0 && info->dlpi_subs == 0);
    uintptr_t base = 0;
    const ElfW(Phdr) *tls = 0;
    int contains_callback = 0;
    for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type == PT_PHDR) base = (uintptr_t)info->dlpi_phdr - p->p_vaddr;
        if (p->p_type == PT_DYNAMIC && _DYNAMIC) base = (uintptr_t)_DYNAMIC - p->p_vaddr;
        if (p->p_type == PT_TLS) tls = p;
        if (p->p_type == PT_LOAD && (uintptr_t)observe >= info->dlpi_addr + p->p_vaddr &&
            (uintptr_t)observe < info->dlpi_addr + p->p_vaddr + p->p_memsz) contains_callback = 1;
    }
    CHECK(info->dlpi_addr == base && contains_callback);
#ifdef EXPECT_STATIC_PIE
    CHECK(base != 0);
#else
    CHECK(base == 0);
#endif
    CHECK(tls != 0 && info->dlpi_tls_modid == 1 && info->dlpi_tls_data != 0);
    seen->tls_base = (uintptr_t)info->dlpi_tls_data;
    CHECK((uintptr_t)&initialized_tls >= seen->tls_base);
    CHECK((uintptr_t)&initialized_tls + sizeof(initialized_tls) <= seen->tls_base + tls->p_memsz);
    CHECK((uintptr_t)&zero_tls >= seen->tls_base);
    CHECK((uintptr_t)&zero_tls + sizeof(zero_tls) <= seen->tls_base + tls->p_memsz);
    CHECK(initialized_tls == 0x31415926UL && zero_tls == 0);
    errno = ERANGE;
    return seen->result;
}

static void *worker(void *opaque)
{
    struct observation *seen = opaque;
    errno = EDOM;
    CHECK(dl_iterate_phdr(observe, seen) == seen->result);
    CHECK(seen->calls == 1 && errno == ERANGE);
    initialized_tls = 99;
    zero_tls = 101;
    return opaque;
}

int main(void)
{
    struct observation main_zero = {0, 0, 0}, main_stop = {0, 73, 0}, thread_stop = {0, -29, 0};
    worker(&main_zero);
    initialized_tls = 0x31415926UL;
    zero_tls = 0;
    worker(&main_stop);
    initialized_tls = 0x31415926UL;
    zero_tls = 0;
    CHECK(main_zero.tls_base == main_stop.tls_base);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, worker, &thread_stop) == 0);
    void *result = 0;
    CHECK(pthread_join(thread, &result) == 0 && result == &thread_stop);
    CHECK(thread_stop.tls_base != main_zero.tls_base);
    CHECK(initialized_tls == 0x31415926UL && zero_tls == 0);
    puts("static dl_iterate_phdr: main metadata, callback results, errno, main/worker TLS passed");
    return 0;
}
