static _Thread_local int value = 201;
static unsigned constructed, destroyed;

__attribute__((constructor)) static void initialize(void)
{
    constructed += value == 201;
}

__attribute__((destructor)) static void finalize(void) { ++destroyed; }

int *loader112_dependency_cell(void) { return &value; }
int loader112_dependency_ready(void) { return constructed == 1 && destroyed == 0; }
