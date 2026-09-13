#ifndef CRABC_HEADER_DECLARATION_INVENTORY_DEMO_H
#define CRABC_HEADER_DECLARATION_INVENTORY_DEMO_H

extern int header_inventory_public_value;
extern int header_inventory_public_function(int);
extern int header_inventory_public_function(int);
static int header_inventory_private_value = 7;
#define HEADER_INVENTORY_FIRST 1
#undef HEADER_INVENTORY_FIRST
#define HEADER_INVENTORY_FINAL(value) (value)

#ifdef __cplusplus
extern "C" {
extern int header_inventory_c_linkage_value;
}
namespace header_inventory_fixture {
const int header_inventory_cpp_internal_const = 9;
}
#endif

#endif
