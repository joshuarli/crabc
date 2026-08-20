#include <unistd.h>

extern unsigned long getauxval(unsigned long);

static void putn(unsigned long value) {
    char buf[32];
    int pos = 0;
    if (value == 0) {
        write(1, "0", 1);
        return;
    }
    while (value != 0) {
        buf[pos++] = (char)('0' + value % 10);
        value /= 10;
    }
    while (pos > 0) {
        write(1, &buf[--pos], 1);
    }
}

int main(int argc, char **argv, char **envp) {
    unsigned long envc = 0;
    while (envp[envc] != 0) {
        envc++;
    }
    write(1, "argc=", 5);
    putn((unsigned long)argc);
    write(1, " envc=", 6);
    putn(envc);
    write(1, " execfn_nonnull=", sizeof(" execfn_nonnull=") - 1);
    putn(getauxval(31) != 0);
    write(1, " execfn_diff=", sizeof(" execfn_diff=") - 1);
    putn(getauxval(31) != (unsigned long)argv[0]);
    write(1, " platform=", 10);
    putn(getauxval(15) != 0);
    write(1, "\n", 1);
    return 0;
}
