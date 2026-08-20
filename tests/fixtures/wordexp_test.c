#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>

static int check_words(wordexp_t *we, size_t count, const char *first)
{
    return we->we_wordc == count &&
        (!count || !strcmp(we->we_wordv[we->we_offs], first));
}

int main(void)
{
    wordexp_t we;

    if (wordexp("one two", &we, 0) || !check_words(&we, 2, "one")) return 1;
    wordfree(&we);

    if (wordexp("$1", &we, 0) || !check_words(&we, 0, "")) return 2;
    wordfree(&we);

    if (wordexp("$FOO", &we, 0) || !check_words(&we, 2, "bar")) return 3;
    wordfree(&we);

    /* A command substitution hidden in shell-specific quoting is rejected. */
    if (wordexp("$'\\''$(echo bad)\\'", &we, WRDE_NOCMD) != WRDE_CMDSUB) return 4;

    we.we_offs = 1;
    if (wordexp("a", &we, WRDE_DOOFFS) || !check_words(&we, 1, "a") || we.we_wordv[0]) return 5;
    if (wordexp("b", &we, WRDE_DOOFFS | WRDE_APPEND) ||
        we.we_wordc != 2 || strcmp(we.we_wordv[1], "a") || strcmp(we.we_wordv[2], "b")) return 6;
    wordfree(&we);

    if (wordexp("$UNSET", &we, WRDE_UNDEF) != WRDE_BADVAL) return 7;

    puts("wordexp ok");
    return 0;
}
