/* Static C hasmntopt differential over caller-owned option bytes. */
#include <mntent.h>
#include <stddef.h>

typedef char *(*hasmntopt_signature)(const struct mntent *, const char *);

_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer width");
_Static_assert(sizeof(struct mntent) == 40 && _Alignof(struct mntent) == 8,
               "x86 struct mntent layout");
_Static_assert(offsetof(struct mntent, mnt_opts) == 24,
               "x86 mnt_opts offset");
_Static_assert(offsetof(struct mntent, mnt_freq) == 32,
               "x86 mnt_freq offset");
_Static_assert(offsetof(struct mntent, mnt_passno) == 36,
               "x86 mnt_passno offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&hasmntopt),
                                             hasmntopt_signature),
               "hasmntopt declaration");

static char option_bytes[] = "rw,relatime,noexec=1,nodev";
static char original_option_bytes[] = "rw,relatime,noexec=1,nodev";
static char empty_option_bytes[] = "";
static char leading_empty_option_bytes[] = ",rw";
static struct mntent entry;

static int same_bytes(const char *left, const char *right)
{
    for (;;) {
        if (*left != *right)
            return 0;
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
}

static int expects(const char *option, char *expected)
{
    return hasmntopt(&entry, option) == expected;
}

int crabc_x86_64_hasmntopt_probe(void)
{
    entry.mnt_opts = option_bytes;
    if (!expects("rw", option_bytes))
        return 10;
    if (!expects("relatime", option_bytes + 3))
        return 11;
    if (!expects("noexec", option_bytes + 12))
        return 12;
    if (!expects("noexec=1", option_bytes + 12))
        return 13;
    if (!expects("nodev", option_bytes + 21))
        return 14;
    if (!expects("no", 0) || !expects("r", 0) || !expects("noexec=2", 0))
        return 15;
    if (!expects("missing", 0) || !expects("nodev-extra", 0))
        return 16;
    if (!same_bytes(option_bytes, original_option_bytes))
        return 17;

    /* Musl treats an empty requested option as a whole first list element. */
    entry.mnt_opts = empty_option_bytes;
    if (!expects("", empty_option_bytes) || !expects("rw", 0))
        return 20;
    entry.mnt_opts = leading_empty_option_bytes;
    if (!expects("", leading_empty_option_bytes))
        return 21;
    if (!expects("rw", leading_empty_option_bytes + 1))
        return 22;
    if (!same_bytes(option_bytes, original_option_bytes))
        return 23;

    return 0;
}

#ifndef CRABC_HASMNTOPT_FREESTANDING
int main(void)
{
    return crabc_x86_64_hasmntopt_probe();
}
#endif
