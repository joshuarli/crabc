#include <link.h>
#include <stdio.h>
#include <string.h>

/* These are musl's loader/debugger ABI spellings.  `_dlstart` receives the
 * process's raw entry stack and is inspected here only by taking its address. */
extern struct r_debug *_dl_debug_addr;
extern void _dl_debug_state(void) __attribute__((weak));
extern void _dlstart(void);

static int check_link_map(struct r_debug *debug)
{
    struct link_map *map = debug->r_map;
    size_t count = 0;
    int saw_libc = 0;

    while (map != NULL && count < 64) {
        if (map->l_name == NULL || map->l_ld == NULL)
            return 1;
        if (strstr(map->l_name, "libc.so") != NULL)
            saw_libc = 1;
        map = map->l_next;
        count++;
    }
    if (map != NULL || count < 2 || !saw_libc)
        return 2;
    return 0;
}

int main(void)
{
    struct r_debug *debug = _dl_debug_addr;

    if (debug == NULL)
        return 1;
    if (debug->r_version != 1 || debug->r_state != RT_CONSISTENT)
        return 2;
    if (debug->r_brk == 0 || debug->r_ldbase == 0)
        return 3;
    if (_dl_debug_state == NULL)
        return 4;

    /* This ordinary weak hook is safe to call; it is not the raw-entry hook. */
    _dl_debug_state();
    if (debug->r_state != RT_CONSISTENT)
        return 5;
    if (check_link_map(debug) != 0)
        return 6;

    /* `_dlstart` must be publicly discoverable, but calling it would restart
     * the loader with ordinary C arguments instead of the kernel entry stack. */
    if (_dlstart == NULL)
        return 7;

    puts("m4 loader debug exports ok");
    return 0;
}
