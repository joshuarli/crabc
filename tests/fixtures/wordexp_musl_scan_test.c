#include <wordexp.h>

int main(void)
{
    wordexp_t words = {0};
    if (wordexp("$(", &words, WRDE_NOCMD) != WRDE_CMDSUB) return 1;
    if (wordexp("a`b", &words, WRDE_NOCMD) != WRDE_CMDSUB) return 2;
    if (wordexp("${X}", &words, WRDE_NOCMD) != WRDE_BADCHAR) return 3;
    if (wordexp("'$('", &words, WRDE_NOCMD)) return 4;
    wordfree(&words);
    return 0;
}
