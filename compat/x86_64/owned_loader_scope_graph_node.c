#if defined(GRAPH_LEFT)
#define GRAPH_BASE 11
#elif defined(GRAPH_RIGHT)
#define GRAPH_BASE 22
#else
#error A graph provider must be selected
#endif

static int graph_state;
static int graph_initializations;
static int graph_finalizations;
static int graph_dependency_ready;
extern int graph_leaf_marker(void);

__attribute__((constructor)) static void graph_initialize(void)
{
    ++graph_initializations;
    graph_dependency_ready = graph_leaf_marker() == 3;
    graph_state = GRAPH_BASE;
}

__attribute__((destructor)) static void graph_finalize(void)
{
    ++graph_finalizations;
}

int graph_node_lifecycle(void)
{
    return graph_initializations == 1 && graph_finalizations == 0 && graph_dependency_ready;
}

int graph_value(void)
{
    return graph_state;
}

void graph_advance(void)
{
    ++graph_state;
}
