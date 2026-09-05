#define _GNU_SOURCE
#include <mntent.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

_Static_assert(sizeof(struct mntent) == 40, "LP64 mount record");
_Static_assert(_Alignof(struct mntent) == 8, "LP64 mount alignment");
static void require(int condition) { if (!condition) abort(); }
static FILE *input(const char *text) {
    FILE *f = tmpfile(); require(f != NULL);
    require(fputs(text, f) >= 0); rewind(f); return f;
}
static void bytes(const char *text) {
    for (; *text; ++text) printf("%02x", (unsigned char)*text);
}
static void record(struct mntent *m, int error, char *buffer, size_t size) {
    printf("result=%d errno=%d", m != NULL, error);
    if (m) {
        char *fields[] = {m->mnt_fsname, m->mnt_dir, m->mnt_type, m->mnt_opts};
        for (int i = 0; i < 4; ++i) {
            if (buffer) require((uintptr_t)fields[i] >= (uintptr_t)buffer &&
                (uintptr_t)fields[i] < (uintptr_t)buffer + size);
            putchar(' '); bytes(fields[i]);
        }
        printf(" %d %d", m->mnt_freq, m->mnt_passno);
    }
    putchar('\n');
}
int main(void) {
    setbuf(stdout, NULL);
    const char *lines[] = {
        "\n  # comment\n/dev/a / ext4 rw,noexec 1 2\n",
        "dev\\040one /a\\011b t ro,foo=bar 3 4 trailing\n",
        "a\\\\b\\000c\\777d\\12e\\9f / t rw -2 +3\n",
        "single\n", "first second\n", "first second third\n",
        "# x y z 7 8\nfirst second third fourth\n",
        "a\rb / t rw junk 9\n", "a / t rw 4 nope\n",
        "a / t rw 0 0", "#comment", "", " \t\n"
    };
    for (size_t i = 0; i < sizeof(lines)/sizeof(lines[0]); ++i) {
        FILE *f = input(lines[i]); struct mntent m; char buffer[256];
        memset(&m, 0x55, sizeof m); memset(buffer, 0x66, sizeof buffer);
        errno = 123; struct mntent *r = getmntent_r(f, &m, buffer, sizeof buffer);
        require(!r || r == &m); record(r, errno, buffer, sizeof buffer);
        errno = 123; r = getmntent_r(f, &m, buffer, sizeof buffer);
        record(r, errno, buffer, sizeof buffer); require(endmntent(f) == 1);
    }
    for (int size = 1; size <= 24; ++size) {
        FILE *f = input("longname / t rw 1 2\nnext / t ro 3 4\n");
        struct mntent m; unsigned char guarded[40]; memset(guarded, 0xa5, sizeof guarded);
        guarded[8] = 0;
        errno = 123; struct mntent *r = getmntent_r(f, &m, (char *)guarded+8, size);
        record(r, errno, (char *)guarded+8, size);
        for (int i=0; i<8; ++i) require(guarded[i] == 0xa5);
        for (int i=8+size; i<40; ++i) require(guarded[i] == 0xa5);
        char buffer[128]; errno = 123; r=getmntent_r(f,&m,buffer,sizeof buffer);
        record(r, errno, buffer, sizeof buffer); endmntent(f);
    }
    FILE *f = tmpfile(); require(f != NULL);
    for (int i=0; i<8192; ++i) require(fputc('x',f) == 'x');
    require(fputs(" / t rw 1 2\nnext / t ro 3 4\n", f)>=0); rewind(f);
    struct mntent *r=getmntent(f); require(r && strlen(r->mnt_fsname)==8192);
    struct mntent *first=r; r=getmntent(f); require(r==first && !strcmp(r->mnt_fsname,"next"));
    require(!getmntent(f)); endmntent(f); puts("shared-growth-ok");
    f=input("prefix\n"); struct mntent m={"dev name","/dir","type","rw",-1,2};
    errno=123; printf("append=%d ",addmntent(f,&m)); printf("errno=%d\n",errno);
    rewind(f); char output[128]; size_t n=fread(output,1,sizeof output-1,f); output[n]=0; bytes(output); putchar('\n');
    endmntent(f); errno=123; printf("null-close=%d ",endmntent(NULL)); printf("errno=%d\n",errno);
    errno=0; f=setmntent("/no-such-mount-table","r"); require(!f); printf("missing=%d\n",errno);
    f=setmntent("/tmp/mount-table-fixture", "w+"); require(f != NULL);
    require(addmntent(f, &m)==0); require(endmntent(f)==1);
    f=setmntent("/tmp/mount-table-fixture", "r"); require(f != NULL);
    char table_buffer[128]; struct mntent parsed;
    errno=123; r=getmntent_r(f,&parsed,table_buffer,sizeof table_buffer);
    record(r,errno,table_buffer,sizeof table_buffer);
    errno=0; int added=addmntent(f,&m); printf("readonly-append=%d errno=%d\n",added,errno);
    require(endmntent(f)==1); require(unlink("/tmp/mount-table-fixture")==0);
    f=tmpfile(); require(f != NULL); require(close(fileno(f))==0);
    errno=0; r=getmntent_r(f,&parsed,table_buffer,sizeof table_buffer);
    record(r,errno,table_buffer,sizeof table_buffer); require(ferror(f));
    errno=0; int ended=endmntent(f); printf("bad-close=%d errno=%d\n",ended,errno);
    int p[2]; require(pipe(p)==0); f=fdopen(p[1],"w"); require(f!=NULL); errno=0;
    printf("pipe-append=%d ",addmntent(f,&m)); printf("errno=%d\n",errno); endmntent(f); close(p[0]);
    m.mnt_opts="rw,noexec,foo=bar"; require(hasmntopt(&m,"foo")==m.mnt_opts+10); require(!hasmntopt(&m,"no"));
    puts("mount-table-ok"); return 0;
}
