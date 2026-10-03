#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

extern int graph_leaf_lifecycle(void);
extern int graph_node_lifecycle(void);
static int graph_root_initializations;
static int graph_root_finalizations;
static int graph_dependencies_ready;

__attribute__((constructor)) static void graph_root_initialize(void)
{
    ++graph_root_initializations;
    graph_dependencies_ready = graph_leaf_lifecycle() && graph_node_lifecycle();
    puts("scope graph: root initialized");
}

int graph_root_lifecycle(void)
{
    return graph_root_initializations == 1 && graph_root_finalizations == 0 && graph_dependencies_ready;
}

__attribute__((destructor)) static void graph_root_finalize(void)
{
    /* Retained parents finalize at exit while their shared dependencies are
       still initialized. Closing a handle must not consume this transition. */
    if (graph_root_initializations != 1 || graph_root_finalizations != 0 || !graph_dependencies_ready ||
        !graph_leaf_lifecycle() || !graph_node_lifecycle()) _Exit(31);
    ++graph_root_finalizations;
    puts("scope graph: retained root finalized");
}

int graph_marker(void)
{
    return 1;
}

/* RTLD_NEXT starts after this calling root in physical load order. Its first
   dependency provides the value even when another root is promoted first. */
int graph_next_value(void)
{
    int (*get)(void) = (int (*)(void))dlsym(RTLD_NEXT, "graph_value");
    return get ? get() : -1;
}
