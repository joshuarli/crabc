/*
 * Deterministic LLD-only proof of musl's libc shared-link dynamic-list scope.
 *
 * The provider and caller compile as separate PIC objects. The runner links
 * them with the pinned LLD first without a dynamic list (the retained RED),
 * then with the checked musl-shaped list. Nothing executes: `malloc` is only
 * an ELF relocation subject, so this cannot introduce allocator side effects.
 */
#include <stddef.h>

#if defined(CRABC_SHARED_DYNAMIC_LIST_PROVIDER)
int optind = 17;

void *malloc(size_t size)
{
    (void)size;
    return 0;
}

int ordinary_local_call(void)
{
    return 23;
}
#else
extern int optind;
extern void *malloc(size_t);
extern int ordinary_local_call(void);

int call_ordinary_local(void)
{
    return ordinary_local_call();
}

void *call_listed_malloc(size_t size)
{
    return malloc(size);
}

int read_listed_optind(void)
{
    return optind;
}
#endif
