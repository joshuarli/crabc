#define _GNU_SOURCE 1

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int check_long_arguments(void)
{
    int flag = 0;
    int idx = -1;
    struct option options[] = {
        { "alpha", no_argument, NULL, 'a' },
        { "beta", required_argument, NULL, 'b' },
        { "color", optional_argument, NULL, 'c' },
        { "flag", no_argument, &flag, 42 },
        { "alpine", no_argument, NULL, 'p' },
        { "verbose", no_argument, NULL, 'v' },
        { NULL, 0, NULL, 0 }
    };

    {
        char a0[] = "tool";
        char a1[] = "--beta=path";
        char *argv[] = { a0, a1, NULL };
        optind = 0;
        opterr = 0;
        if (getopt_long(2, argv, "abc:", options, &idx) != 'b' ||
            idx != 1 || !optarg || strcmp(optarg, "path") || optind != 2)
            return 1;
    }

    {
        char a0[] = "tool";
        char a1[] = "--beta";
        char a2[] = "separate";
        char *argv[] = { a0, a1, a2, NULL };
        optind = 0;
        if (getopt_long(3, argv, "abc:", options, &idx) != 'b' ||
            idx != 1 || !optarg || strcmp(optarg, "separate") || optind != 3)
            return 2;
    }

    {
        char a0[] = "tool";
        char a1[] = "--color";
        char *argv[] = { a0, a1, NULL };
        optind = 0;
        optarg = (char *)"stale";
        if (getopt_long(2, argv, "abc:", options, &idx) != 'c' ||
            idx != 2 || optarg != NULL || optind != 2)
            return 3;
    }

    {
        char a0[] = "tool";
        char a1[] = "--color=blue";
        char *argv[] = { a0, a1, NULL };
        optind = 0;
        if (getopt_long(2, argv, "abc:", options, &idx) != 'c' ||
            idx != 2 || !optarg || strcmp(optarg, "blue"))
            return 4;
    }

    {
        char a0[] = "tool";
        char a1[] = "--flag";
        char *argv[] = { a0, a1, NULL };
        flag = 0;
        optind = 0;
        if (getopt_long(2, argv, "abc:", options, &idx) != 0 ||
            idx != 3 || flag != 42)
            return 5;
    }
    return 0;
}

static int check_permutation_and_errors(void)
{
    struct option options[] = {
        { "alpha", no_argument, NULL, 'a' },
        { "alpine", no_argument, NULL, 'p' },
        { "beta", required_argument, NULL, 'b' },
        { NULL, 0, NULL, 0 }
    };
    int idx = -1;

    {
        char a0[] = "tool";
        char a1[] = "tail";
        char a2[] = "--alpha";
        char *argv[] = { a0, a1, a2, NULL };
        optind = 0;
        opterr = 0;
        if (getopt_long(3, argv, "ab:", options, &idx) != 'a' ||
            idx != 0 || optind != 2 || argv[1] != a2 || argv[2] != a1)
            return 1;
    }

    {
        char a0[] = "tool";
        char a1[] = "--al";
        char *argv[] = { a0, a1, NULL };
        optind = 0;
        idx = -1;
        if (getopt_long(2, argv, "ab:", options, &idx) != '?' ||
            optopt != 0 || idx != -1 || optind != 2)
            return 2;
    }

    {
        char a0[] = "tool";
        char a1[] = "--beta";
        char *argv[] = { a0, a1, NULL };
        optind = 0;
        if (getopt_long(2, argv, ":ab:", options, &idx) != ':' ||
            optopt != 'b' || optind != 2)
            return 3;
    }
    return 0;
}

static int check_long_only(void)
{
    struct option options[] = {
        { "verbose", no_argument, NULL, 'V' },
        { "value", required_argument, NULL, 'q' },
        { "v", no_argument, NULL, 'L' },
        { NULL, 0, NULL, 0 }
    };
    int idx = -1;

    {
        char a0[] = "tool";
        char a1[] = "-verbose";
        char *argv[] = { a0, a1, NULL };
        optind = 0;
        if (getopt_long_only(2, argv, "v", options, &idx) != 'V' ||
            idx != 0 || optind != 2)
            return 1;
    }

    {
        char a0[] = "tool";
        char a1[] = "-v";
        char *argv[] = { a0, a1, NULL };
        optind = 0;
        idx = -1;
        if (getopt_long_only(2, argv, "v", options, &idx) != 'v' ||
            idx != -1 || optind != 2)
            return 2;
    }

    {
        char a0[] = "tool";
        char a1[] = "-value";
        char a2[] = "payload";
        char *argv[] = { a0, a1, a2, NULL };
        optind = 0;
        if (getopt_long_only(3, argv, "v", options, &idx) != 'q' ||
            idx != 1 || !optarg || strcmp(optarg, "payload"))
            return 3;
    }
    return 0;
}

int main(void)
{
    int result = check_long_arguments();
    if (result)
        return result;
    result = check_permutation_and_errors();
    if (result)
        return 10 + result;
    result = check_long_only();
    if (result)
        return 20 + result;
    puts("m4 getopt long exports ok");
    return 0;
}
