__thread int dynamic_tls_dependency_child = 31;

int *dynamic_tls_dependency_child_slot(void)
{
    return &dynamic_tls_dependency_child;
}
