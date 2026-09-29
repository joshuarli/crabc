#define _XOPEN_SOURCE 700
#include <ftw.h>

static int visit(const char *path, const struct stat *record, int kind, struct FTW *state)
{
    (void)path;
    (void)record;
    (void)kind;
    (void)state;
    return 0;
}

int main(void)
{
    return nftw(".", visit, 4, FTW_CHDIR);
}
