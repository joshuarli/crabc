#include <unistd.h>

__attribute__((constructor)) static void order_sibling_init(void)
{
    (void)write(1, "order-sibling\n", sizeof("order-sibling\n") - 1);
}

int order_sibling_value(void)
{
    return 7;
}
