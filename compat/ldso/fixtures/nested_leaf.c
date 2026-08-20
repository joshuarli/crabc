/*
 * The leaf of the initial DT_NEEDED graph.  It has no libc dependency, so a
 * failure to start the main fixture isolates dynamic-linker graph traversal
 * and relocation from ordinary libc behavior.
 */
int nested_leaf_value(void)
{
    return 41;
}
