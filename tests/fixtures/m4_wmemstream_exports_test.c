#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

int main(void)
{
    wchar_t *buffer = NULL;
    size_t length = 99;
    FILE *stream;

    errno = 0;
    if (open_wmemstream(NULL, &length) != NULL || errno != EINVAL)
        return 1;
    stream = open_wmemstream(&buffer, &length);
    if (!stream || fputws(L"hi", stream) != 0 || fputwc(0x03a9, stream) != 0x03a9)
        return 2;
    if (fflush(stream) != 0 || !buffer || length != 3 ||
        buffer[0] != L'h' || buffer[1] != L'i' || buffer[2] != 0x03a9 || buffer[3] != 0)
        return 3;
    if (fputwc(L'!', stream) != L'!' || fclose(stream) != 0 || length != 4 ||
        buffer[3] != L'!' || buffer[4] != 0)
        return 4;
    free(buffer);
    puts("m4 wmemstream exports ok");
    return 0;
}
