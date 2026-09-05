// Small dynamic application used by the owned-loader short-stack regression.
//
// The companion launcher lowers RLIMIT_STACK immediately before exec. Keep
// this program free of application-side stack pressure so a failure isolates
// the interpreter/CRT startup path.
#include <unistd.h>

int main(void) {
    static const char message[] = "owned loader short stack\n";
    return write(STDOUT_FILENO, message, sizeof(message) - 1) ==
                   (ssize_t)(sizeof(message) - 1)
               ? 0
               : 1;
}
