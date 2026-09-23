/* Enter the installed process-name probe with the Linux empty-argv case. */
#include <unistd.h>

int main(int argc, char **argv)
{
    char *empty_argv[] = { 0 };
    char *empty_env[] = { 0 };

    if (argc != 2) return 125;
    execve(argv[1], empty_argv, empty_env);
    return 126;
}
