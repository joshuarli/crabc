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
static unsigned long constructor_random_address;
static unsigned char constructor_random_bytes[16];

static int check_found(unsigned long item, unsigned long expected)
{
    errno = E2BIG;
    if (getauxval(item) != expected || errno != E2BIG)
        return 1;
    errno = E2BIG;
    if (__getauxval(item) != expected || errno != E2BIG)
        return 2;
    return 0;
}

static int check_missing(unsigned long item)
{
    errno = E2BIG;
    if (getauxval(item) != 0 || errno != ENOENT)
        return 1;
    errno = E2BIG;
    if (__getauxval(item) != 0 || errno != ENOENT)
        return 2;
    return 0;
}

static int check_auxv_values(void)
{
    unsigned long value;

    value = getauxval(AT_PAGESZ);
    if (value != 4096 || check_found(AT_PAGESZ, 4096))
        return 1;

    value = getauxval(AT_PHENT);
    if (value != sizeof(Elf64_Phdr) || check_found(AT_PHENT, sizeof(Elf64_Phdr)))
        return 2;

    value = getauxval(AT_PHNUM);
    if (value == 0 || check_found(AT_PHNUM, value))
        return 3;

    value = getauxval(AT_SECURE);
    if (value != 0 || check_found(AT_SECURE, 0))
        return 4;

    if (check_missing(AT_NULL))
        return 5;
    if (check_missing(~0UL))
        return 6;
    return 0;
}

/* The kernel's initial envp terminator is immediately followed by auxv.
 * Compare every present tag with the raw vector, including zero-valued
 * records, while keeping the lookup independent of libc's auxv storage. */
static int check_initial_vector(char **envp)
{
    const unsigned long *auxv;
    unsigned long env_count, index, first, prior;
    int saw_zero = 0, saw_nonzero = 0, saw_random = 0;

    if (!envp)
        return 1;
    for (env_count = 0; env_count < (1UL << 20); ++env_count)
        if (!envp[env_count])
            break;
    if (env_count == (1UL << 20))
        return 2;
    auxv = (const unsigned long *)(envp + env_count + 1);
    for (index = 0; index < 4096; ++index) {
        unsigned long item = auxv[index * 2];
        unsigned long value = auxv[index * 2 + 1];

        if (item == AT_NULL)
            break;
        if (item == ~0UL)
            return 3;
        first = value;
        for (prior = 0; prior < index; ++prior)
            if (auxv[prior * 2] == item) {
                first = auxv[prior * 2 + 1];
                break;
            }
        if (check_found(item, first))
            return 4;
        saw_zero |= first == 0;
        saw_nonzero |= first != 0;
        if (item == AT_RANDOM) {
            const unsigned char *random = (const unsigned char *)value;
            unsigned long byte;

            if (!random || value != constructor_random_address)
                return 5;
            for (byte = 0; byte < sizeof constructor_random_bytes; ++byte)
                if (random[byte] != constructor_random_bytes[byte])
                    return 6;
            saw_random = 1;
        }
    }
    if (index == 4096 || !saw_zero || !saw_nonzero || !saw_random)
        return 7;
    if (check_missing(~0UL) || check_missing(AT_NULL))
        return 8;
    return 0;
}

/* The freestanding startup shim passes this exact callback to the bounded
 * __libc_start_main. Its result proves auxv publication precedes application
 * constructors, matching the ordinary pinned-musl static startup. */
__attribute__((constructor))
void crabc_x86_64_auxv_observation_init(void)
{
    const unsigned char *random;
    unsigned long byte;

    constructor_status = check_auxv_values();
    if (constructor_status)
        return;
    constructor_random_address = getauxval(AT_RANDOM);
    if (!constructor_random_address) {
        constructor_status = 7;
        return;
    }
    random = (const unsigned char *)constructor_random_address;
    for (byte = 0; byte < sizeof constructor_random_bytes; ++byte)
        constructor_random_bytes[byte] = random[byte];
}

int main(int argc, char **argv, char **envp)
{
    int result;

    (void)argc;
    (void)argv;
    if (getauxval != __getauxval)
        return 10;
    if (constructor_status != 0)
        return 20 + constructor_status;
    result = check_auxv_values();
    if (result != 0)
        return 40 + result;
    result = check_initial_vector(envp);
    if (result != 0)
        return 60 + result;
    return 0;
}
