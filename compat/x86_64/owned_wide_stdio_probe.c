#define _GNU_SOURCE
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"wide:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
struct cookie { const unsigned char *input; size_t length, position, observed_width; int fail; locale_t change_locale; };
static ssize_t cookie_read(void *data, char *bytes, size_t capacity) {
    struct cookie *c=data; c->observed_width=MB_CUR_MAX;
    if (c->change_locale) uselocale(c->change_locale);
    if (!capacity || c->position==c->length) return 0;
    *bytes=c->input[c->position++]; return 1;
}
static ssize_t cookie_write(void *data, const char *bytes, size_t count) {
    struct cookie *c=data; (void)bytes; c->observed_width=MB_CUR_MAX;
    if (c->change_locale) uselocale(c->change_locale);
    if (c->fail) { errno=EIO; return -1; }
    c->position+=count;
    return count;
}
static int worker_body(void) {
    locale_t utf8=newlocale(LC_CTYPE_MASK,"C.UTF-8",NULL), plain=newlocale(LC_CTYPE_MASK,"C",NULL);
    CHECK(utf8 && plain && uselocale(utf8));
    wchar_t *output; size_t size;
    FILE *f=open_wmemstream(&output,&size); CHECK(f && uselocale(plain));
    CHECK(MB_CUR_MAX==1 && fputws(L"thread\u20ac",f)>=0 && !fflush(f));
    CHECK(size==7 && output[6]==0x20ac && MB_CUR_MAX==1 && !fclose(f));
    free(output); CHECK(uselocale(LC_GLOBAL_LOCALE)); freelocale(utf8); freelocale(plain);
    return 0;
}
static void *worker(void *unused) { (void)unused; return (void *)(uintptr_t)worker_body(); }

static int malformed(const unsigned char *bytes, size_t length) {
    FILE *f=tmpfile(); CHECK(f);
    CHECK(fwrite(bytes,1,length,f)==length);
    CHECK(!fflush(f) && !fseek(f,0,SEEK_SET));
    /* Reopen resets byte orientation; a new descriptor stream sees the bytes. */
    int fd=dup(fileno(f)); CHECK(fd>=0 && !fclose(f));
    f=fdopen(fd,"r"); CHECK(f);
    errno=ENOSPC; wint_t wc=fgetwc(f);
    printf("decode %u %d %d %d %ld\n",wc,errno,!!ferror(f),!!feof(f),ftell(f));
    clearerr(f); wc=fgetwc(f);
    printf("resume %u %d %d\n",wc,!!ferror(f),!!feof(f));
    CHECK(!fclose(f)); return 0;
}
int main(int argc, char **argv) {
    CHECK(argc==2 && setlocale(LC_ALL,"C.UTF-8")); alarm(30);
    for (int operation=0;operation<4;operation++) {
        FILE *empty=tmpfile(); char byte=0; CHECK(empty && !fwide(empty,0));
        if (operation==0) CHECK(fread(&byte,0,1,empty)==0);
        if (operation==1) CHECK(fwrite(&byte,0,1,empty)==0);
        if (operation==2) CHECK(fgets(&byte,1,empty)==&byte);
        if (operation==3) CHECK(fprintf(empty,"%s","")==0);
        CHECK(fwide(empty,0)<0 && !fclose(empty));
    }
    FILE *f=fopen(argv[1],"w+"); CHECK(f && fwide(f,0)==0);
    CHECK(fwide(f,1)>0 && fwide(f,-1)>0);
    CHECK(setlocale(LC_CTYPE,"C")); /* orientation captures the conversion locale */
    CHECK(fputwc(0x20ac,f)==0x20ac && fputws(L"\U0001f642\n",f)>=0);
    CHECK(!fflush(f) && ftell(f)==8 && !fseek(f,0,SEEK_SET));
    CHECK(fgetwc(f)==0x20ac && ungetwc(0x20ac,f)==0x20ac && fgetwc(f)==0x20ac);
    wchar_t line[8]; CHECK(fgetws(line,8,f)==line && line[0]==0x1f642 && line[1]=='\n' && !line[2]);
    CHECK(fgetwc(f)==WEOF && feof(f) && !ferror(f));
    CHECK(ungetwc('X',f)=='X' && !feof(f) && fgetwc(f)=='X');
    CHECK(freopen(argv[1],"w+",f)==f && !fwide(f,0));
    CHECK(fwide(f,1)>0);
    errno=ENOSPC; CHECK(fputwc(0x20ac,f)==WEOF && errno==EILSEQ && ferror(f));
    clearerr(f); CHECK(fputwc(0xdf80,f)==0xdf80 && !fclose(f));
    CHECK(setlocale(LC_CTYPE,"C.UTF-8"));
    const unsigned char euro[]={0xe2,0x82,0xac};
    struct cookie cookie={euro,sizeof euro,0,0};
    cookie_io_functions_t io={cookie_read,cookie_write,NULL,NULL};
    f=fopencookie(&cookie,"r+",io); CHECK(f && !setvbuf(f,NULL,_IONBF,0) && fwide(f,1)>0);
    CHECK(setlocale(LC_CTYPE,"C"));
    CHECK(fgetwc(f)==0x20ac && cookie.observed_width==4 && MB_CUR_MAX==1);
    CHECK(fputwc(0x20ac,f)==0x20ac && cookie.observed_width==4 && MB_CUR_MAX==1);
    cookie.fail=1; errno=ENOSPC;
    CHECK(fputwc(0x20ac,f)==WEOF && ferror(f) && errno==EIO && cookie.observed_width==4 && MB_CUR_MAX==1);
    CHECK(!fclose(f) && setlocale(LC_CTYPE,"C.UTF-8"));
    locale_t plain=newlocale(LC_CTYPE_MASK,"C",NULL); CHECK(plain);
    cookie=(struct cookie){euro,sizeof euro,0,0,0,plain};
    f=fopencookie(&cookie,"r",io); CHECK(f && !setvbuf(f,NULL,_IONBF,0) && fwide(f,1)>0);
    CHECK(setlocale(LC_CTYPE,"C") && fgetwc(f)==0xdfe2 && cookie.observed_width==4);
    CHECK(uselocale(NULL)==LC_GLOBAL_LOCALE && MB_CUR_MAX==1 && !fclose(f));
    CHECK(setlocale(LC_CTYPE,"C.UTF-8"));
    cookie=(struct cookie){NULL,0,0,0,0,plain};
    f=fopencookie(&cookie,"w",io); CHECK(f && !setvbuf(f,NULL,_IONBF,0) && fwide(f,1)>0);
    wchar_t long_text[1102]; for (int i=0;i<1100;i++) long_text[i]='a'; long_text[1100]=0x20ac; long_text[1101]=0;
    CHECK(setlocale(LC_CTYPE,"C")); errno=ENOSPC;
    CHECK(fputws(long_text,f)==-1 && errno==EILSEQ && !ferror(f) && cookie.position==1024);
    CHECK(uselocale(NULL)==LC_GLOBAL_LOCALE && MB_CUR_MAX==1 && !fclose(f));
    freelocale(plain); CHECK(setlocale(LC_CTYPE,"C.UTF-8"));
    const unsigned char cases[][5]={{0xc2,'x'},{0xff,'y'},{0xe2,0x82},{0xc0,0x80},{0,0x41}};
    const size_t sizes[]={2,2,2,2,2};
    for (int i=0;i<5;i++) CHECK(!malformed(cases[i],sizes[i]));
    wchar_t *output=NULL; size_t count=777;
    f=open_wmemstream(&output,&count); CHECK(f && output && !count && fwide(f,0)>0);
    CHECK(fputws(L"alpha\u20ac",f)>=0 && !fflush(f) && count==6 && output[5]==0x20ac && !output[6]);
    CHECK(!fseek(f,9,SEEK_SET) && fputwc('Z',f)=='Z' && !fflush(f));
    CHECK(count==10 && !output[6] && !output[8] && output[9]=='Z' && !output[10]);
    fpos_t position; CHECK(!fgetpos(f,&position) && !fseek(f,1,SEEK_SET));
    CHECK(fputwc('!',f)=='!' && !fflush(f) && count==2 && output[2]=='p');
    CHECK(!fsetpos(f,&position) && ftell(f)==10 && !fclose(f)); free(output);
    f=open_wmemstream(&output,&count); CHECK(f);
    errno=ENOSPC;
    CHECK(fseek(f,-1,SEEK_SET)==-1 && errno==EINVAL && ftell(f)==0);
    CHECK(!fseek(f,INTPTR_MAX/4,SEEK_SET)); errno=ENOSPC;
    CHECK(fputwc('x',f)==WEOF && ferror(f) && errno==ENOSPC && count==0);
    CHECK(!fclose(f)); free(output);
    pthread_t thread; void *result;
    CHECK(!pthread_create(&thread,NULL,worker,NULL) && !pthread_join(thread,&result) && !result && MB_CUR_MAX==4);
    CHECK(!unlink(argv[1])); puts("owned-wide-stream-ok"); return 0;
}
