/*
 * x86-64 companion for the frozen reloc_consumer.c fixture.
 *
 * The frozen consumer's initialized pointer deliberately names provider data,
 * which is an R_X86_64_64 import on this ABI.  Keep that source unchanged and
 * supply this separate local initialized pointer so the component proves the
 * required R_X86_64_RELATIVE form as an actual owned DSO relocation.
 */
__attribute__((visibility("hidden"))) int reloc_relative_x86_data = 73;
static int *volatile reloc_relative_x86_pointer = &reloc_relative_x86_data;

int reloc_relative_x86_value(void)
{
    return *reloc_relative_x86_pointer;
}
