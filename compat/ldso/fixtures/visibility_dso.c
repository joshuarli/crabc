__attribute__((visibility("default"))) int visibility_public(void)
{
    return 23;
}

__attribute__((visibility("hidden"))) int visibility_hidden(void)
{
    return 41;
}
