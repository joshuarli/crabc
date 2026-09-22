#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>

/* A strong application definition must override musl's weak archive entry. */
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)
{
    (void)callback;
    return data ? 113 : -1;
}

int main(void)
{
    int witness = 0;
    if (dl_iterate_phdr(0, &witness) != 113) return 1;
    return puts("static dl_iterate_phdr: strong application override passed") < 0;
}
