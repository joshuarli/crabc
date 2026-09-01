/* Static Linux/x86-64 sethostent/setnetent C ABI and behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and
 * then through an opt-in `-nostdlib -static` crabc archive. It proves only
 * musl's stateless legacy netdb setter pair: both `int` arguments are ignored,
 * direct and function-pointer calls are no-ops, and weak setnetent initially
 * has the same address as strong sethostent. The optional freestanding
 * override build proves a caller's strong setnetent replaces the archive weak
 * alias while sethostent still extracts the selected object. It selects no
 * host/network enumeration, resolver, database, filesystem, errno, TLS, or
 * runtime policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <limits.h>
#include <netdb.h>

typedef void (*sethostent_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sethostent),
                                             sethostent_signature),
               "sethostent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setnetent),
                                             sethostent_signature),
               "setnetent declaration");

#ifdef CRABC_SETHOSTENT_OVERRIDE
static int override_calls;
static int override_value;

/* A caller-owned strong definition must supersede the archive weak alias. */
void setnetent(int stayopen)
{
    ++override_calls;
    override_value = stayopen;
}
#endif

static int check_noop_pair(int stayopen)
{
    const sethostent_signature host_function = sethostent;
    const sethostent_signature net_function = setnetent;

    if (host_function != net_function)
        return 1;
    sethostent(stayopen);
    setnetent(stayopen);
    host_function(stayopen);
    net_function(stayopen);
    return 0;
}

#ifdef CRABC_SETHOSTENT_OVERRIDE
static int check_strong_setnetent_override(void)
{
    const sethostent_signature host_function = sethostent;
    const sethostent_signature net_function = setnetent;

    if (host_function == net_function)
        return 1;
    host_function(INT_MIN);
    net_function(INT_MAX);
    if (override_calls != 1)
        return 2;
    return override_value == INT_MAX ? 0 : 3;
}
#endif

int crabc_x86_64_sethostent_probe(void)
{
#ifdef CRABC_SETHOSTENT_OVERRIDE
    return check_strong_setnetent_override();
#else
    static const int inputs[] = { 0, 1, INT_MIN, INT_MAX };
    unsigned int index;

    for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); ++index) {
        int result = check_noop_pair(inputs[index]);

        if (result != 0)
            return (int)index * 10 + result;
    }
    return 0;
#endif
}

#ifndef CRABC_SETHOSTENT_FREESTANDING
int main(void)
{
    return crabc_x86_64_sethostent_probe();
}
#endif
