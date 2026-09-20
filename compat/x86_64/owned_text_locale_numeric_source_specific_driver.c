/* Ordered candidate-only frames for existing source-specific locale branches.
 *
 * The three callees retain macros whose assertions intentionally describe the
 * selected candidate profile rather than Musl behavior.  This driver never
 * turns those results into parity credit.  It only gives the runner an
 * unambiguous stream for six-mode candidate consistency checks.
 */

#include <stdio.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this driver requires native Linux/x86-64 LP64"
#endif

int crabc_x86_64_locale_object_wide_probe(void);
int crabc_x86_64_locale_wide_iconv_probe(void);
int crabc_x86_64_locale_multibyte_probe(void);

static int write_frame(const char *role, const char *state)
{
    static const char prefix[] = "text-locale-numeric-source-specific/";
    const char *part;

    for (part = prefix; *part != '\0'; ++part)
        if (write(STDOUT_FILENO, part, 1) != 1)
            return 1;
    for (part = role; *part != '\0'; ++part)
        if (write(STDOUT_FILENO, part, 1) != 1)
            return 1;
    if (write(STDOUT_FILENO, ":", 1) != 1)
        return 1;
    for (part = state; *part != '\0'; ++part)
        if (write(STDOUT_FILENO, part, 1) != 1)
            return 1;
    return write(STDOUT_FILENO, "\n", 1) == 1 ? 0 : 1;
}

static int run_role(const char *role, int (*probe)(void))
{
    int status;

    if (fflush(stdout) != 0 || write_frame(role, "begin") != 0)
        return 120;
    status = probe();
    if (fflush(stdout) != 0)
        return 121;
    if (status != 0)
        return status;
    return write_frame(role, "ok") == 0 ? 0 : 122;
}

int main(void)
{
    int status;

    status = run_role("locale-object-wide-profile", crabc_x86_64_locale_object_wide_probe);
    if (status != 0)
        return status;
    status = run_role("locale-wide-iconv-profile", crabc_x86_64_locale_wide_iconv_probe);
    if (status != 0)
        return status;
    return run_role("locale-multibyte-profile", crabc_x86_64_locale_multibyte_probe);
}
