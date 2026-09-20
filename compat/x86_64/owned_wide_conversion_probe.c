#define _GNU_SOURCE
#include <errno.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <wchar.h>
#include <unistd.h>

_Static_assert(sizeof(wchar_t) == 4, "installed wchar_t");
_Static_assert(sizeof(mbstate_t) == 8, "installed mbstate_t");
static void require(int condition) { if (!condition) abort(); }
static void initial(mbstate_t *state) {
    unsigned words[2] = {0, 0x55667788};
    memcpy(state, words, sizeof words);
}
static void state_out(const mbstate_t *state) {
    unsigned words[2]; memcpy(words,state,sizeof words);
    printf(" state=%08x,%08x",words[0],words[1]);
}
/* A comparison checksum over all initialized output bytes also detects writes
 * beyond returned output. Surrounding canaries independently bound storage. */
static unsigned checksum(const void *memory,size_t size) {
    const unsigned char *p=memory; unsigned result=0;
    for(size_t i=0;i<size;i++) result=result*33+p[i];
    return result;
}
static void decode(const char *input,size_t bytes,size_t capacity,int count_only) {
    struct { uint64_t before; wchar_t output[320]; uint64_t after; } guarded;
    memset(&guarded,0x55,sizeof guarded); const char *source=input; mbstate_t state; initial(&state);
    errno=123;
    size_t result=mbsnrtowcs(count_only?NULL:guarded.output,&source,bytes,capacity,&state);
    int error=errno;
    require(guarded.before==UINT64_C(0x5555555555555555) && guarded.after==UINT64_C(0x5555555555555555));
    for(size_t i=count_only?0:capacity;i<320;i++) require(guarded.output[i]==0x55555555);
    printf("decode n=%zu cap=%zu count=%d result=%zd source=%td errno=%d checksum=%u",
        bytes,capacity,count_only,(ssize_t)result,source?source-input:-1,error,checksum(guarded.output,sizeof guarded.output));
    state_out(&state); putchar('\n');
}
static void encode(const wchar_t *input,size_t characters,size_t capacity,int count_only) {
    struct { uint64_t before; char output[64]; uint64_t after; } guarded;
    memset(&guarded,0x55,sizeof guarded); const wchar_t *source=input; mbstate_t state; initial(&state);
    errno=123;
    size_t result=wcsnrtombs(count_only?NULL:guarded.output,&source,characters,capacity,&state);
    int error=errno;
    require(guarded.before==UINT64_C(0x5555555555555555) && guarded.after==UINT64_C(0x5555555555555555));
    for(size_t i=count_only?0:capacity;i<64;i++) require(guarded.output[i]==0x55);
    printf("encode n=%zu cap=%zu count=%d result=%zd source=%td errno=%d checksum=%u",
        characters,capacity,count_only,(ssize_t)result,source?source-input:-1,error,checksum(guarded.output,sizeof guarded.output));
    state_out(&state); putchar('\n');
}
static void resume(int count_only,int null_state,int invalid) {
    const char prefix[]={ (char)0xe2, (char)0x82 }; const char suffix[]={ (char)0xac, '!', 0 };
    const char bad[]={ 'X', 0 }; const char *source=prefix; wchar_t output[8]; mbstate_t state; initial(&state);
    for(size_t i=0;i<8;i++) output[i]=0x55555555;
    errno=123;
    size_t first=mbsnrtowcs(count_only?NULL:output,&source,2,8,null_state?NULL:&state);
    printf("prefix count=%d null=%d bad=%d result=%zd source=%td errno=%d",count_only,null_state,invalid,(ssize_t)first,source?source-prefix:-1,errno);
    state_out(&state); putchar('\n');
    const char *next=invalid?bad:suffix; source=next; errno=123;
    size_t second=mbsnrtowcs(count_only?NULL:output,&source,invalid?sizeof bad:sizeof suffix,8,null_state?NULL:&state);
    printf("resume result=%zd source=%td errno=%d checksum=%u",(ssize_t)second,source?source-next:-1,errno,checksum(output,sizeof output));
    state_out(&state); putchar('\n');
}
/* Resume in the bulk path using one backing array, so musl's error cursor
 * immediately before the continuation still points within a live object. */
static void resume_bulk(size_t prefix_size,int invalid,int count_only) {
    char input[200]; memset(input,'x',sizeof input); input[0]=(char)0xe2;
    input[1]=(char)0x82; input[2]=(char)0xac; input[sizeof input-1]=0;
    if(invalid) input[2]='X';
    const char *source=input; wchar_t output[64]; mbstate_t state; initial(&state);
    for(size_t i=0;i<64;i++) output[i]=0x55555555;
    require(mbsnrtowcs(output,&source,prefix_size,64,&state)==0);
    require(source==input+prefix_size);
    errno=123;
    size_t result=mbsnrtowcs(count_only?NULL:output,&source,sizeof input-prefix_size,64,&state);
    printf("bulk-resume prefix=%zu bad=%d count=%d result=%zd source=%td errno=%d checksum=%u",
        prefix_size,invalid,count_only,(ssize_t)result,source?source-input:-1,errno,checksum(output,sizeof output));
    state_out(&state); putchar('\n');
}
static void guard_pages(void) {
    long page=sysconf(_SC_PAGESIZE); require(page>=4096);
    char *map=mmap(NULL,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    require(map!=MAP_FAILED); require(mprotect(map+page,(size_t)page,PROT_NONE)==0);
    for(size_t n=0;n<=4;n++) {
        char *input=map+page-n; for(size_t i=0;i<n;i++) input[i]='A';
        decode(input,n,0,0); decode(input,n,8,0); decode(input,n,8,1);
    }
    const size_t bulk_sizes[]={128,131,132,133,1024};
    for(size_t i=0;i<sizeof bulk_sizes/sizeof bulk_sizes[0];i++) {
        size_t n=bulk_sizes[i]; char *input=map+page-n; memset(input,'x',n);
        decode(input,n,16,0);decode(input,n,320,0);decode(input,n,0,1);
        input[n-2]=(char)0xe2;input[n-1]=(char)0x82;
        decode(input,n,320,0);decode(input,n,0,1);
    }
    for(size_t n=0;n<=4;n++) {
        wchar_t *input=(wchar_t *)(map+page)-n; for(size_t i=0;i<n;i++) input[i]=0x20ac;
        encode(input,n,0,0); encode(input,n,16,0); encode(input,n,0,1);
    }
    require(munmap(map,(size_t)page*2)==0); puts("guard-pages-ok");
}
static void independent_state(void) {
    const char prefix[]={(char)0xe2,(char)0x82};const char suffix[]={(char)0xac,0};
    const char *source=prefix;wchar_t output[4];
    require(mbsnrtowcs(output,&source,sizeof prefix,4,NULL)==0);
    wchar_t ascii=0;require(mbrtowc(&ascii,"A",1,NULL)==1 && ascii=='A');
    source=suffix;require(mbsnrtowcs(output,&source,sizeof suffix,4,NULL)==1);
    require(source==NULL && output[0]==0x20ac);puts("independent-null-state-ok");
    mbstate_t state,saved;initial(&state);source=prefix;
    require(mbsnrtowcs(output,&source,sizeof prefix,4,&state)==0);memcpy(&saved,&state,sizeof state);
    source=suffix;
    require(mbsnrtowcs(output,&source,0,4,&state)==0 && source==suffix);
    require(!memcmp(&state,&saved,sizeof state));
    require(mbsnrtowcs(output,&source,sizeof suffix,0,&state)==0 && source==suffix);
    require(!memcmp(&state,&saved,sizeof state));puts("pending-zero-limits-ok");
}
static void thread_locale(void) {
    require(setlocale(LC_ALL,"C")!=NULL);
    locale_t utf8=newlocale(LC_CTYPE_MASK,"C.UTF-8",(locale_t)0);require(utf8!=(locale_t)0);
    locale_t previous=uselocale(utf8);require(previous!=(locale_t)0);
    puts("thread-ctype-utf8");decode("\xc2\xa2",3,4,0);encode(L"\u00a2",2,4,0);
    require(uselocale(previous)==utf8);freelocale(utf8);
    require(setlocale(LC_ALL,"C.UTF-8")!=NULL);
    locale_t plain=newlocale(LC_CTYPE_MASK,"C",(locale_t)0);require(plain!=(locale_t)0);
    previous=uselocale(plain);require(previous!=(locale_t)0);
    puts("thread-ctype-c");decode("\xc2\xa2",3,4,0);encode(L"\u00a2",2,4,0);
    require(uselocale(previous)==plain);freelocale(plain);
}
static void duplication(void) {
    wchar_t original[]={L'a',0x20ac,0x1f642,0xd800,-1,0};
    errno=123; wchar_t *copy=wcsdup(original); int error=errno;
    require(copy && copy!=original && !memcmp(copy,original,sizeof original));
    original[0]=L'z';require(copy[0]==L'a');
    printf("duplicate errno=%d checksum=%u\n",error,checksum(copy,sizeof original)); free(copy);
    copy=wcsdup(L"");require(copy && copy[0]==0);free(copy);puts("duplicate-empty-ok");
}
int crabc_x86_64_owned_wide_conversion_probe(void) {
    const char *locales[]={"C","POSIX","C.UTF-8"};
    const char *strings[]={"", "abc", "a\xc2\xa2\xe2\x82\xac\xf0\x9f\x99\x82!", "a\xff!", "\xe2\x82", "\xed\xa0\x80", "\xf4\x90\x80\x80"};
    const wchar_t *wide[]={L"",L"abc",L"a\u00a2\u20ac\U0001f642!",(const wchar_t[]){'a',0xd800,0},(const wchar_t[]){-1,0},(const wchar_t[]){0xdf80,0xdfff,0}};
    for(size_t locale=0;locale<3;locale++) {
        require(setlocale(LC_ALL,locales[locale])!=NULL); printf("locale=%s\n",locales[locale]);
        for(size_t s=0;s<sizeof strings/sizeof strings[0];s++)
            for(size_t n=0;n<=strlen(strings[s])+1;n++)
                for(size_t capacity=0;capacity<=6;capacity++) decode(strings[s],n,capacity,0);
        for(size_t s=0;s<sizeof strings/sizeof strings[0];s++) decode(strings[s],strlen(strings[s])+1,0,1);
        for(size_t s=0;s<sizeof wide/sizeof wide[0];s++)
            for(size_t n=0;n<=wcslen(wide[s])+1;n++)
                for(size_t capacity=0;capacity<=17;capacity++) encode(wide[s],n,capacity,0);
        for(size_t s=0;s<sizeof wide/sizeof wide[0];s++) encode(wide[s],wcslen(wide[s])+1,0,1);
    }
    require(setlocale(LC_ALL,"C.UTF-8")!=NULL);
    for(int count=0;count<2;count++) for(int internal=0;internal<2;internal++) for(int invalid=0;invalid<2;invalid++) resume(count,internal,invalid);
    for(size_t prefix=1;prefix<=2;prefix++) for(int invalid=0;invalid<2;invalid++) for(int count=0;count<2;count++) resume_bulk(prefix,invalid,count);
    char bulk[1201]; memset(bulk,'x',sizeof bulk);bulk[1200]=0;
    decode(bulk,sizeof bulk,320,0);decode(bulk,sizeof bulk,0,1);
    bulk[133]=(char)0xff;decode(bulk,sizeof bulk,320,0);decode(bulk,sizeof bulk,0,1);
    const char *null_bytes=NULL;const wchar_t *null_wide=NULL;wchar_t wc;char byte;
    mbstate_t state;initial(&state);
    require(mbsnrtowcs(&wc,&null_bytes,0,1,&state)==0 && null_bytes==NULL);
    require(wcsnrtombs(&byte,&null_wide,1,1,&state)==0 && null_wide==NULL);
    guard_pages();independent_state();thread_locale();duplication();puts("wide-conversion-ok");return 0;
}

#ifndef CRABC_OWNED_WIDE_CONVERSION_COMPONENT_FREESTANDING
int main(void) {
    return crabc_x86_64_owned_wide_conversion_probe();
}
#endif
