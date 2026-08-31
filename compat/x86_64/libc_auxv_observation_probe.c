/* Bounded static getauxval/__getauxval evidence.
 *
 * The same body runs through pinned musl's normal static startup and through
 * the selected crabc static-startup handoff. It deliberately observes only
 * kernel-owned initial auxiliary-vector values: no loader, secure_getenv, or
 * general environment policy is selected here.
 */

#include <elf.h>
#include <errno.h>
#include <sys/auxv.h>

extern unsigned long __getauxval(unsigned long);

static int constructor_status;

static int check_auxv_values(void)
{
    unsigned long value;

    errno = E2BIG;
    value = getauxval(AT_PAGESZ);
    if (value != 4096 || errno != E2BIG)
        return 1;

    errno = E2BIG;
    value = getauxval(AT_PHENT);
    if (value != sizeof(Elf64_Phdr) || errno != E2BIG)
        return 2;

    errno = E2BIG;
    value = getauxval(AT_PHNUM);
    if (value == 0 || errno != E2BIG)
        return 3;

    errno = E2BIG;
    value = getauxval(AT_SECURE);
    if (value > 1 || errno != E2BIG)
        return 4;

    errno = 0;
    if (getauxval(AT_NULL) != 0 || errno != ENOENT)
        return 5;
    errno = 0;
    if (__getauxval(AT_NULL) != 0 || errno != ENOENT)
        return 6;
    return 0;
}

/* The freestanding startup shim passes this exact callback to the bounded
 * __libc_start_main. Its result proves auxv publication precedes application
 * constructors, matching the ordinary pinned-musl static startup. */
__attribute__((constructor))
void crabc_x86_64_auxv_observation_init(void)
{
    constructor_status = check_auxv_values();
}

int main(void)
{
    int result;

    if (getauxval != __getauxval)
        return 10;
    if (constructor_status != 0)
        return 20 + constructor_status;
    result = check_auxv_values();
    if (result != 0)
        return 40 + result;
    return 0;
}
