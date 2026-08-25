/* Application fixture, not target-runtime implementation. */
#include <unistd.h>

int main(int argc, char **argv) {
    char release;

    if (argc != 2 || argv == 0 || argv[argc] != 0) {
        return 23;
    }
    return read(0, &release, 1) == 1 ? 0 : 24;
}
