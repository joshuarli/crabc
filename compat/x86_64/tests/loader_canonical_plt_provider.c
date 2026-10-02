int loader_canonical_plt_function(void)
{
    return 73;
}

void *loader_canonical_plt_provider_address(void)
{
    return (void *)loader_canonical_plt_function;
}
