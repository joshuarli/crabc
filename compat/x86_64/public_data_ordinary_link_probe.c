/* Exact ordinary-link probe for the 32 selected static/shared public objects.
 *
 * Object names and aliases come from native-abi-selection.toml. Installed
 * declarations are used where available. The explicit declarations below are
 * only for typed declaration_kind = abi-only objects; h_errno is an installed
 * accessor macro whose selected backing object requires an ABI-only reference.
 * source_mutable describes the object storage, independently of pointer const
 * in an installed declaration such as FILE *const stdin.
 */
#define _GNU_SOURCE
#include <arpa/nameser.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

extern char **__environ, **_environ, **___environ;
extern char *__progname, *__progname_full;
extern int __optpos, __optreset, __daylight, __signgam;
extern long __timezone;
extern char *__tzname[2];
extern uintptr_t __stack_chk_guard;
#undef h_errno
extern int h_errno;

enum object_index {
    object____environ,
    object___daylight,
    object___environ,
    object___optpos,
    object___optreset,
    object___progname,
    object___progname_full,
    object___signgam,
    object___stack_chk_guard,
    object___timezone,
    object___tzname,
    object__environ,
    object__ns_flagdata,
    object_daylight,
    object_environ,
    object_getdate_err,
    object_h_errno,
    object_in6addr_any,
    object_in6addr_loopback,
    object_optarg,
    object_opterr,
    object_optind,
    object_optopt,
    object_optreset,
    object_program_invocation_name,
    object_program_invocation_short_name,
    object_signgam,
    object_stderr,
    object_stdin,
    object_stdout,
    object_timezone,
    object_tzname,
    object_count
};

static const volatile uintptr_t addresses[object_count] = {
    (uintptr_t)&___environ,
    (uintptr_t)&__daylight,
    (uintptr_t)&__environ,
    (uintptr_t)&__optpos,
    (uintptr_t)&__optreset,
    (uintptr_t)&__progname,
    (uintptr_t)&__progname_full,
    (uintptr_t)&__signgam,
    (uintptr_t)&__stack_chk_guard,
    (uintptr_t)&__timezone,
    (uintptr_t)&__tzname,
    (uintptr_t)&_environ,
    (uintptr_t)&_ns_flagdata,
    (uintptr_t)&daylight,
    (uintptr_t)&environ,
    (uintptr_t)&getdate_err,
    (uintptr_t)&h_errno,
    (uintptr_t)&in6addr_any,
    (uintptr_t)&in6addr_loopback,
    (uintptr_t)&optarg,
    (uintptr_t)&opterr,
    (uintptr_t)&optind,
    (uintptr_t)&optopt,
    (uintptr_t)&optreset,
    (uintptr_t)&program_invocation_name,
    (uintptr_t)&program_invocation_short_name,
    (uintptr_t)&signgam,
    (uintptr_t)&stderr,
    (uintptr_t)&stdin,
    (uintptr_t)&stdout,
    (uintptr_t)&timezone,
    (uintptr_t)&tzname,
};

static const unsigned alignments[object_count] = {
    8, 4, 8, 4, 4, 8, 8, 4, 8, 8, 8, 8, 4, 4, 8, 4,
    4, 4, 4, 8, 4, 4, 4, 4, 8, 8, 4, 8, 8, 8, 8, 8,
};

int main(void)
{
    unsigned index;
    for (index = 0; index < object_count; ++index) {
        if (addresses[index] == 0 || addresses[index] % alignments[index] != 0)
            return 1 + (int)index;
    }
    if (addresses[object____environ] != addresses[object___environ]) return 65;
    if (addresses[object__environ] != addresses[object___environ]) return 66;
    if (addresses[object_daylight] != addresses[object___daylight]) return 67;
    if (addresses[object_environ] != addresses[object___environ]) return 68;
    if (addresses[object_optreset] != addresses[object___optreset]) return 69;
    if (addresses[object_program_invocation_name] != addresses[object___progname_full]) return 70;
    if (addresses[object_program_invocation_short_name] != addresses[object___progname]) return 71;
    if (addresses[object_signgam] != addresses[object___signgam]) return 72;
    if (addresses[object_timezone] != addresses[object___timezone]) return 73;
    if (addresses[object_tzname] != addresses[object___tzname]) return 74;
    return write(1, "public-data-ordinary-link-ok\n", 29) == 29 ? 0 : 100;
}
