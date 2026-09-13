#include <unistd.h>

extern int descriptor_dso_reference(void);

int main(void) {
    /* This byte is the application-main witness. A rejected DSO request must
     * leave stdout empty rather than merely making the call return an error. */
    if (write(1, "application-main\n", 17) != 17) return 3;
    return descriptor_dso_reference() ? 2 : 0;
}
