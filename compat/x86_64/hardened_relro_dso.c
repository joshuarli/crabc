static int initialized;

__attribute__((constructor)) static void initialize(void)
{
    initialized = 7;
}

int hardened_fixture_initialized(void)
{
    return initialized;
}
