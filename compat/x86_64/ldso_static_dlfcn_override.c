/* Archive override boundary of the static dlfcn surface. Pinned musl 1.2.6
 * libc.a publishes dlopen, dladdr and dl_iterate_phdr as weak aliases of its
 * stubs, so these application definitions win while the dlsym reference
 * still links libc's global stub. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>

void *dlopen(const char *file, int mode) { (void)file; return (void *)(long)(mode + 1); }
int dladdr(const void *address, Dl_info *info) { (void)address; (void)info; return 55; }
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)
{
    (void)callback; (void)data;
    return 66;
}

int main(void)
{
    Dl_info info;
    printf("override dlopen=%ld dladdr=%d dl_iterate_phdr=%d\n", (long)dlopen("x", 2),
        dladdr((void *)main, &info), dl_iterate_phdr(0, 0));
    void *symbol = dlsym(RTLD_DEFAULT, "main");
    const char *error = dlerror();
    printf("libc dlsym: %s; %s\n", symbol ? "found" : "null", error ? error : "(none)");
    return 0;
}
