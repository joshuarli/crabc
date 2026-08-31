/* This translation unit must fail outside the GNU feature profile. */

#include <search.h>

int crabc_x86_64_search_hash_table_hidden_probe(struct hsearch_data *table)
{
    return (int)sizeof(*table) + hcreate_r(8, table);
}
