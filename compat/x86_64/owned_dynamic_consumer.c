#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int dynamic_dependency_value(void);
extern int dynamic_dependency_worker(void);
extern char **environ;
static _Thread_local int local_value = 31;
static int *main_errno;

/* dladdr reports the first mapped page, including the kernel-owned executable.
   Its mapping is not owned by the loader's rollback/unmap registry. */
static int main_mapping_base(struct dl_phdr_info *object, size_t size, void *data)
{
    (void)size;
    Dl_info *info = data;
    uintptr_t address = (uintptr_t)main_mapping_base;
    uintptr_t first = UINTPTR_MAX;
    int contains_address = 0;
    for (size_t index = 0; index < object->dlpi_phnum; ++index) {
        const ElfW(Phdr) *header = &object->dlpi_phdr[index];
        uintptr_t start = object->dlpi_addr + header->p_vaddr;
        if (header->p_type != PT_LOAD) continue;
        if (header->p_vaddr < first) first = header->p_vaddr;
        if (address >= start && address - start < header->p_memsz)
            contains_address = 1;
    }
    if (!contains_address) return 0;
    uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    return (uintptr_t)info->dli_fbase == object->dlpi_addr
        + first - first % page_size ? 1 : 2;
}

static void *worker(void *argument)
{
    if (__errno_location() == main_errno || errno != 0 || local_value != 31)
        return (void *)1;
    errno = EDOM;
    local_value = 97;
    char *allocation = malloc(129);
    if (!allocation) return (void *)2;
    memset(allocation, 73, 129);
    int result = allocation[128] == 73 && dynamic_dependency_worker() == 0;
    free(allocation);
    return result ? argument : (void *)3;
}

static void normal_exit(void)
{
    /* This remains buffered: the shared process owner must flush after fini. */
    fputs("ordinary exit\n", stdout);
}

int main(void)
{
    Dl_info info = {0};
    if (!dladdr((void *)main_mapping_base, &info)
        || dl_iterate_phdr(main_mapping_base, &info) != 1) return 73;
    main_errno = __errno_location();
    /* Constructors have already run and may call errno-setting functions.
       Worker TLS below must still begin with its independent zero template. */
    if (local_value != 31) return 71;
    if (dynamic_dependency_value() != 17) return 72;
    if (!environ || setenv("CRABC_DYNAMIC_TEST", "owned", 1)
        || !getenv("CRABC_DYNAMIC_TEST") || strcmp(getenv("CRABC_DYNAMIC_TEST"), "owned")) return 70;
    errno = ERANGE;
    for (unsigned index = 0; index < 24; ++index) {
        pthread_t thread;
        void *result = 0;
        if (pthread_create(&thread, 0, worker, (void *)42)) return 62;
        if (pthread_join(thread, &result) || result != (void *)42) return 63;
        if (errno != ERANGE || local_value != 31 || dynamic_dependency_value() != 17) return 64;
    }
    FILE *file = tmpfile();
    if (!file || fprintf(file, "%s:%d", "dynamic", 42) != 10 || fseek(file, 0, SEEK_SET)) return 65;
    char buffer[16] = {0};
    if (fread(buffer, 1, 10, file) != 10 || strcmp(buffer, "dynamic:42") || fclose(file)) return 66;
    char *memory = calloc(64, 4);
    if (!memory || memory[255]) return 67;
    memory = realloc(memory, 1024);
    if (!memory) return 68;
    free(memory);
    if (atexit(normal_exit)) return 69;
    printf("installed dynamic: allocation errno stdio threads\n");
    return 0;
}
