#include <unistd.h>

__attribute__((constructor)) static void order_leaf_init(void)
{
    (void)write(1, "order-leaf\n", sizeof("order-leaf\n") - 1);
}

int order_leaf_value(void)
{
    return 5;
}
