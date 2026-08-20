__thread char dynamic_tls[] __attribute__((aligned(4096))) = "dynamic";

char *load_dynamic_tls(void)
{
    return dynamic_tls;
}
