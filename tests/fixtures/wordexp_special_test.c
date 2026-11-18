#include <string.h>
#include <wordexp.h>

int main(void)
{
    wordexp_t words = {0};
    if (wordexp("$#", &words, 0)) return 1;
    if (words.we_wordc != 1 || strcmp(words.we_wordv[0], "0")) return 2;
    wordfree(&words);
    return 0;
}
