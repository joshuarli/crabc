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

    unsetenv("X");

    if (wordexp("one two", &we, 0) || !check_words(&we, 2, "one")) return 1;
    wordfree(&we);

    if (wordexp("$1", &we, 0) || !check_words(&we, 0, "")) return 2;
    wordfree(&we);

    if (wordexp("$FOO", &we, 0) || !check_words(&we, 2, "bar")) return 3;
    wordfree(&we);

    if (wordexp("\"\"", &we, 0) || !check_words(&we, 1, "")) return 19;
    wordfree(&we);

    if (wordexp("${X=1} $((${X-'}))", &we, WRDE_NOCMD) != WRDE_SYNTAX) return 20;

    /* A command substitution hidden in shell-specific quoting is rejected. */
    if (wordexp("$'\\''$(echo bad)\\'", &we, WRDE_NOCMD) != WRDE_CMDSUB) return 4;

    /* Pinned musl accepts escaped grammar characters inside expansions. */
    if (wordexp("$'\\'$(echo bad)'\\'", &we, WRDE_NOCMD) ||
        !check_words(&we, 1, "'$(echo bad)'")) return 9;
    wordfree(&we);
    if (wordexp("${X-\\'}", &we, WRDE_NOCMD) || !check_words(&we, 1, "'")) return 10;
    wordfree(&we);
    if (wordexp("${X-\\\"}", &we, WRDE_NOCMD) || !check_words(&we, 1, "\"")) return 11;
    wordfree(&we);
    if (wordexp("${X-\\}}", &we, WRDE_NOCMD) || !check_words(&we, 1, "}")) return 12;
    wordfree(&we);
    if (wordexp("${X-{}", &we, WRDE_NOCMD) || !check_words(&we, 1, "{")) return 13;
    wordfree(&we);
    if (wordexp("${X-\\{}", &we, WRDE_NOCMD) || !check_words(&we, 1, "{")) return 14;
    wordfree(&we);
    if (wordexp("\"${X-{}\"", &we, WRDE_NOCMD) || !check_words(&we, 1, "{")) return 21;
    wordfree(&we);
    if (wordexp("\"${X-\\{}\"", &we, WRDE_NOCMD) || !check_words(&we, 1, "\\{")) return 22;
    wordfree(&we);
    if (wordexp("${X-\\$A}", &we, WRDE_NOCMD) || !check_words(&we, 1, "$A")) return 15;
    wordfree(&we);
    if (wordexp("${X-\\`}", &we, WRDE_NOCMD) || !check_words(&we, 1, "`")) return 16;
    wordfree(&we);
    if (wordexp("${X-'}'}", &we, WRDE_NOCMD) || !check_words(&we, 1, "}")) return 17;
    wordfree(&we);
    if (wordexp("${X-'\"'}", &we, WRDE_NOCMD) || !check_words(&we, 1, "\"")) return 18;
    wordfree(&we);
    { int rc = wordexp("${X-'$'A}", &we, WRDE_NOCMD); int ok = !rc && check_words(&we, 1, "$A"); if (!rc) wordfree(&we); if (rc || !ok) return 23; }
    if (wordexp("\"${X-'$'A}\"", &we, WRDE_NOCMD) != WRDE_SYNTAX) return 24;
    if (wordexp("${X=1} $((${X%'}))$(cmd)'}))", &we, WRDE_NOCMD) ||
        !check_words(&we, 2, "1")) return 25;
    wordfree(&we);
    if (wordexp("$(($((1+${X-$((1+1))}))+3))", &we, WRDE_NOCMD) ||
        !check_words(&we, 1, "6")) return 27;
    wordfree(&we);

    we.we_offs = 1;
    if (wordexp("a", &we, WRDE_DOOFFS) || !check_words(&we, 1, "a") || we.we_wordv[0]) return 5;
    if (wordexp("b", &we, WRDE_DOOFFS | WRDE_APPEND) ||
        we.we_wordc != 2 || strcmp(we.we_wordv[1], "a") || strcmp(we.we_wordv[2], "b")) return 6;
    wordfree(&we);

    if (wordexp("$UNSET", &we, WRDE_UNDEF) != WRDE_BADVAL) return 7;

    /* A syntax error must remain WRDE_SYNTAX even with WRDE_UNDEF. */
    if (wordexp("$UNSET )", &we, WRDE_UNDEF) != WRDE_SYNTAX) return 8;

    puts("wordexp ok");
    return 0;
}
