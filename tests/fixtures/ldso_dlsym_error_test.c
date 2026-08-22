#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    const char *name = "crabc_lua_missing_symbol";
    const char *error;
    void *libc;

    libc = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL);
    if (libc == 0)
        return 1;

    if (dlsym(0, name) != 0)
        return 2;
    error = dlerror();
    if (error == 0 || strstr(error, name) == 0)
        return 3;
    if (dlerror() != 0)
        return 4;

    /*
     * musl leaves an unobserved dynamic-linker error pending across a later
     * successful lookup. Callers rely on this when they clear dlerror before
     * dlsym, then inspect it only after their lookup sequence is complete.
    */
    if (dlsym(0, name) != 0)
        return 5;
    if (dlsym(libc, "dlerror") == 0)
        return 6;
    error = dlerror();
    if (error == 0 || strstr(error, name) == 0)
        return 7;
    if (dlerror() != 0)
        return 8;

    /*
     * `dlsym` receives a live C string, not an immutable interned symbol
     * token. A handle-local fast path must therefore validate the current
     * bytes when the caller reuses and mutates the same character array.
     */
    {
        char mutable_name[] = "dlerror";
        void *dlerror_symbol = dlsym(libc, mutable_name);
        if (dlerror_symbol == 0)
            return 17;
        mutable_name[2] = 'c';
        mutable_name[3] = 'l';
        mutable_name[4] = 'o';
        mutable_name[5] = 's';
        mutable_name[6] = 'e';
        void *dlclose_symbol = dlsym(libc, mutable_name);
        if (dlclose_symbol == 0 || dlclose_symbol == dlerror_symbol)
            return 18;
        mutable_name[2] = 'e';
        mutable_name[3] = 'r';
        mutable_name[4] = 'r';
        mutable_name[5] = 'o';
        mutable_name[6] = 'r';
        if (dlsym(libc, mutable_name) != dlerror_symbol)
            return 19;
    }

    if (dlsym(0, name) != 0)
        return 9;
    {
        void *extra = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL);
        if (extra == 0)
            return 10;
        error = dlerror();
        if (error == 0 || strstr(error, name) == 0)
            return 11;
        if (dlerror() != 0)
            return 12;

        if (dlsym(0, name) != 0)
            return 13;
        if (dlclose(extra) != 0)
            return 14;
        error = dlerror();
        if (error == 0 || strstr(error, name) == 0)
            return 15;
        if (dlerror() != 0)
            return 16;
    }
    write(1, "dlsym error name ok\n", 20);
    return 0;
}
