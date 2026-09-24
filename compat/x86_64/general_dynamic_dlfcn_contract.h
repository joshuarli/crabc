/* Shared output helpers for the general dynamic dlfcn musl differentials.
 * Each consumer includes this once; output is the comparison surface. */
#ifndef GENERAL_DYNAMIC_DLFCN_CONTRACT_H
#define GENERAL_DYNAMIC_DLFCN_CONTRACT_H
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static const char *base_name(const char *path)
{
    if (!path) return "(null)";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* Print a diagnostic with every absolute path reduced to its final
 * component, so candidate and oracle roots compare byte for byte. */
static void print_reduced(const char *label, const char *error)
{
    char output[1024];
    size_t used = 0;
    for (size_t index = 0; error[index] && used + 3 < sizeof output;) {
        if (error[index] != '/') {
            output[used++] = error[index++];
            continue;
        }
        size_t end = index, last = index;
        while (error[end] && error[end] != ' ' && error[end] != ':' && error[end] != ')') {
            if (error[end] == '/') last = end;
            ++end;
        }
        output[used++] = '<';
        output[used++] = '>';
        for (size_t copy = last + 1; copy < end && used + 1 < sizeof output; ++copy)
            output[used++] = error[copy];
        index = end;
    }
    output[used] = 0;
    printf("%s: %s\n", label, output);
}

/* Consume and print this thread's pending diagnostic. */
static void show_error(const char *label)
{
    const char *error = dlerror();
    if (!error) printf("%s: (none)\n", label);
    else print_reduced(label, error);
}

static const char *result(const void *handle)
{
    return handle ? "handle" : "null";
}

#endif
