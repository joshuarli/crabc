extern int *dynamic_tls_dependency_child_slot(void);

__thread int dynamic_tls_dependency_parent = 47;

int dynamic_tls_dependency_access(int expected_parent, int expected_child,
    int next_parent, int next_child)
{
    int *const child = dynamic_tls_dependency_child_slot();

    if (child == 0 || dynamic_tls_dependency_parent != expected_parent
            || *child != expected_child)
        return -1;
    dynamic_tls_dependency_parent = next_parent;
    *child = next_child;
    return 0;
}
