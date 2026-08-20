extern int reloc_data;
extern int reloc_function(void);

/* This initialized external pointer requires a dynamic data relocation. */
int *reloc_pointer = &reloc_data;

int reloc_sum(void)
{
    return reloc_data + *reloc_pointer + reloc_function();
}
