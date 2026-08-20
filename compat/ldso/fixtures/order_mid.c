#include <unistd.h>

extern int order_leaf_value(void);

__attribute__((constructor)) static void order_mid_init(void)
{
    (void)write(1, "order-mid\n", sizeof("order-mid\n") - 1);
}

int order_mid_value(void)
{
    return order_leaf_value() + 1;
}
