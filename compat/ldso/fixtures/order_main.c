#include <unistd.h>

__attribute__((constructor)) static void order_main_init(void)
{
    (void)write(1, "order-main-init\n", sizeof("order-main-init\n") - 1);
}

int main(void)
{
    (void)write(1, "order-main\n", sizeof("order-main\n") - 1);
    return 0;
}
