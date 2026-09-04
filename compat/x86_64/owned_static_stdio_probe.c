#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

static FILE *shared;
static void *writer(void *argument)
{
    int byte = *(int *)argument;
    for (int i = 0; i < 100; ++i) {
        flockfile(shared);
        if (ftrylockfile(shared)) abort();
        if (fputc(byte, shared) != byte || fputc('\n', shared) != '\n') abort();
        funlockfile(shared);
        funlockfile(shared);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 1;
    FILE *a = fopen(argv[1], "w+e");
    FILE *b = fopen(argv[2], "w+");
    if (!a || !b || a == b) return 2;
    if (!(fcntl(fileno(a), F_GETFD) & FD_CLOEXEC)) return 3;
    char storage[37];
    if (setvbuf(a, storage, _IOFBF, sizeof storage)) return 4;
    if (fputs("first\nsecond\n", a) < 0 || fwrite("xyz", 1, 3, b) != 3) return 5;
    if (ftell(a) != 13 || fflush(NULL) || fseek(a, 0, SEEK_SET)) return 6;
    char line[32];
    if (!fgets(line, sizeof line, a) || strcmp(line, "first\n")) return 7;
    if (ftell(a) != 6 || ungetc('Q', a) != 'Q' || ftell(a) != 5) return 8;
    if (fgetc(a) != 'Q' || !fgets(line, sizeof line, a) || strcmp(line, "second\n")) return 9;
    if (fgetc(a) != EOF || !feof(a) || ferror(a)) return 10;
    clearerr(a);
    if (feof(a) || fclose(a)) return 11;
    a = fopen(argv[1], "a+");
    if (!a || fseek(a, 0, SEEK_SET) || fputs("tail", a) < 0 || ftell(a) != 17 || fclose(a)) return 12;
    int fd = open(argv[1], O_RDONLY);
    a = fdopen(fd, "r");
    if (!a || fgetc(a) != 'f' || fflush(a) || lseek(fd, 0, SEEK_CUR) != 1) return 13;
    if (fclose(a) || fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 14;
    shared = b;
    pthread_t threads[2];
    int bytes[2] = { 'A', 'B' };
    if (pthread_create(&threads[0], 0, writer, &bytes[0]) || pthread_create(&threads[1], 0, writer, &bytes[1])) return 15;
    if (pthread_join(threads[0], 0) || pthread_join(threads[1], 0) || fseek(b, 3, SEEK_SET)) return 16;
    int counts[2] = {0};
    for (int i = 0; i < 200; ++i) {
        int c = fgetc(b);
        if ((c != 'A' && c != 'B') || fgetc(b) != '\n') return 17;
        ++counts[c == 'B'];
    }
    if (counts[0] != 100 || counts[1] != 100 || fclose(b)) return 18;
    b = fopen(argv[2], "w+");
    if (!b || setvbuf(b, 0, _IOLBF, 0) || fputs("line\n", b) < 0) return 21;
    if (lseek(fileno(b), 0, SEEK_CUR) != 5 || fseek(b, 0, SEEK_SET)) return 22;
    if (fgets(line, 0, b) || fgets(line, -1, b) || fgetc(b) != 'l') return 23;
    if (fseek(b, 0, SEEK_SET) || fprintf(b, "%d %s", 42, "word") != 7 || fseek(b, 0, SEEK_SET)) return 24;
    int number = 0;
    if (fscanf(b, "%d %s", &number, line) != 2 || number != 42 || strcmp(line, "word")) return 25;
    if (fclose(b)) return 26;
    b = fopen(argv[2], "r");
    if (!b || setvbuf(b, 0, _IONBF, 0) || fgetc(b) != '4') return 27;
    if (fputc('X', b) != EOF || !ferror(b)) return 28;
    clearerr(b);
    if (ferror(b) || fclose(b)) return 29;
    b = fopen(argv[2], "w");
    if (!b || fputs("exit-flushed\n", b) < 0) return 19;
    /* Deliberately leave a dynamic stream and stdout buffered at ordinary exit. */
    if (fputs("owned-stdio-ok\n", stdout) < 0) return 20;
    return 0;
}
