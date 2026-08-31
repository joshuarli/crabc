/* Must fail outside GNU profiles: tdestroy and struct qelem are GNU-only. */

#include <search.h>

static struct qelem hidden_record;

int crabc_x86_64_search_tree_hidden_probe(void)
{
    tdestroy(0, 0);
    return hidden_record.q_forw != 0;
}
