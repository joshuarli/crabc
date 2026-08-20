#define _GNU_SOURCE 1

#include <net/if.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct if_nameindex *interfaces = if_nameindex();
    char roundtrip[IF_NAMESIZE];
    unsigned int count = 0;
    int result = 1;

    if (!interfaces)
        return result;

    /* A Linux network namespace always has at least the loopback link. */
    if (interfaces[0].if_index == 0 || !interfaces[0].if_name)
        goto cleanup;

    for (;;) {
        struct if_nameindex *entry = &interfaces[count];
        if (entry->if_index == 0) {
            if (entry->if_name != NULL)
                goto cleanup;
            break;
        }
        if (!entry->if_name || if_nametoindex(entry->if_name) != entry->if_index)
            goto cleanup;
        if (!if_indextoname(entry->if_index, roundtrip) ||
            strcmp(roundtrip, entry->if_name) != 0)
            goto cleanup;
        if (count == 255)
            goto cleanup;
        ++count;
    }

    if (if_nametoindex("crabc-interface-that-does-not-exist") != 0)
        goto cleanup;
    if (if_indextoname(0, roundtrip) != NULL)
        goto cleanup;

    result = 0;

cleanup:
    if_freenameindex(interfaces);
    if (result == 0)
        puts("m4 interface nameindex ok");
    return result;
}
