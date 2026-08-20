#define _GNU_SOURCE 1

#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int __optpos;
extern int __optreset;
extern int optreset;
extern char *__progname;
extern char *__progname_full;
extern char *program_invocation_name;
extern char *program_invocation_short_name;
extern int __posix_getopt(int, char *const [], const char *);

static int check_parse(void)
{
    char a0[] = "tool";
    char a1[] = "-abvalue";
    char a2[] = "tail";
    char *argv[] = { a0, a1, a2, NULL };

    optind = 0;
    opterr = 0;
    if (getopt(3, argv, "ab:") != 'a')
        return 1;
    if (getopt(3, argv, "ab:") != 'b' || strcmp(optarg, "value"))
        return 2;
    if (getopt(3, argv, "ab:") != -1 || optind != 2)
        return 3;

    optind = 0;
    if (__posix_getopt(3, argv, "ab:") != 'a')
        return 4;

    optreset = 1;
    if (getopt(3, argv, "ab:") != 'a' || optreset != 0 || __optreset != 0)
        return 5;
    return 0;
}

static int check_errors(void)
{
    char a0[] = "tool";
    char a1[] = "-z";
    char *unknown[] = { a0, a1, NULL };
    char a2[] = "-b";
    char *missing[] = { a0, a2, NULL };

    optind = 0;
    opterr = 0;
    if (getopt(2, unknown, "ab:") != '?' || optopt != 'z')
        return 1;
    optind = 0;
    if (getopt(2, missing, ":ab:") != ':' || optopt != 'b')
        return 2;
    return 0;
}

int main(int argc, char **argv)
{
    int result = check_parse();
    if (result)
        return result;
    result = check_errors();
    if (result)
        return 10 + result;
    if (!__progname || !__progname_full || !program_invocation_name ||
        !program_invocation_short_name || __progname_full != argv[0] ||
        program_invocation_name != argv[0] || strchr(__progname, '/') ||
        strcmp(program_invocation_short_name, __progname))
        return 2;
    puts("m4 getopt exports ok");
    return 0;
}
