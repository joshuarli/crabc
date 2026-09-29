#if defined(GRAPH_LEFT)
#define GRAPH_BASE 11
#elif defined(GRAPH_RIGHT)
#define GRAPH_BASE 22
#else
#error A graph provider must be selected
#endif

static int graph_state;

__attribute__((constructor)) static void graph_initialize(void)
{
    graph_state = GRAPH_BASE;
}

int graph_value(void)
{
    return graph_state;
}

void graph_advance(void)
{
    ++graph_state;
}
