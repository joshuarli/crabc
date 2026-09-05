/* Ordinary shared-object GD TLS and over-aligned initial TLS templates. */
static _Thread_local int initialized __attribute__((aligned(4096))) = 17;
static _Thread_local unsigned char zeroed[73] __attribute__((aligned(64)));

int dynamic_dependency_value(void) { return initialized; }

int dynamic_dependency_worker(void)
{
    if (initialized != 17 || zeroed[0] || zeroed[72]) return -1;
    initialized = 43;
    zeroed[0] = zeroed[72] = 11;
    return initialized == 43 && zeroed[0] == 11 && zeroed[72] == 11 ? 0 : -1;
}
