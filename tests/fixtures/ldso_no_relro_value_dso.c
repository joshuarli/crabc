/* Deliberately keep this DSO outside GNU RELRO to exercise its independent
 * relocation-completion state. The initialized pointer requires a dynamic
 * base-relative relocation before `no_relro_value` can dereference it. */
static int value = 41;
// Keep the pointer externally visible so position-independent code must load
// it from the DSO data image rather than folding the initializer into a local
// address calculation. Its relocation is what a later `dlopen` must not
// replay.
int *no_relro_pointer = &value;

int no_relro_value(void)
{
    return *no_relro_pointer;
}
