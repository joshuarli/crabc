#include <stdio.h>

static int graph_leaf_initializations;
static int graph_leaf_finalizations;

__attribute__((constructor)) static void graph_leaf_initialize(void)
{
    ++graph_leaf_initializations;
    puts("scope graph: shared leaf initialized");
}

__attribute__((destructor)) static void graph_leaf_finalize(void)
{
    ++graph_leaf_finalizations;
}

int graph_leaf_lifecycle(void)
{
    return graph_leaf_initializations == 1 && graph_leaf_finalizations == 0;
}

int graph_leaf_marker(void)
{
    return graph_leaf_lifecycle() ? 3 : 0;
}
