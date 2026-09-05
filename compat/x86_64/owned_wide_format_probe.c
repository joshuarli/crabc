#define _GNU_SOURCE
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"wide-format:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
static void bytes(const void *data, size_t size) {
    const unsigned char *p=data; for (size_t i=0;i<size;i++) printf("%02x",p[i]); putchar('\n');
}
static int forwarded_output(wchar_t *out, size_t size, const wchar_t *format, ...) {
    va_list ap; va_start(ap,format); int r=vswprintf(out,size,format,ap); va_end(ap); return r;
}
static int forwarded_input(const wchar_t *input, const wchar_t *format, ...) {
    va_list ap; va_start(ap,format); int r=vswscanf(input,format,ap); va_end(ap); return r;
}
static int forwarded_file_output(FILE *f,const wchar_t *format, ...) {
    va_list ap; va_start(ap,format); int r=vfwprintf(f,format,ap); va_end(ap); return r;
}
static int forwarded_file_input(FILE *f,const wchar_t *format, ...) {
    va_list ap; va_start(ap,format); int r=vfwscanf(f,format,ap); va_end(ap); return r;
}
static int forwarded_standard_output(const wchar_t *format, ...) {
    va_list ap; va_start(ap,format); int r=vwprintf(format,ap); va_end(ap); return r;
}
static int forwarded_standard_input(const wchar_t *format, ...) {
    va_list ap; va_start(ap,format); int r=vwscanf(format,ap); va_end(ap); return r;
}
static int wide_formats(const char *path) {
    CHECK(setlocale(LC_CTYPE,"C.UTF-8"));
    wchar_t out[256]; int count;
    const wchar_t *formats[]={L"%d/%#x/%n",L"%+15.9d/%-12x/%n",L"%2$x/%1$d/%3$n"};
    for (size_t i=0;i<sizeof formats/sizeof *formats;i++) {
        memset(out,0x5a,sizeof out); count=-777; errno=ENOSPC;
        int result=forwarded_output(out,256,formats[i],-123,0xbeef,&count);
        printf("wint %d %d %d ",result,errno,count); bytes(out,160);
    }
    const wchar_t *text_formats[]={L"%s/%ls/%n",L"%10.2s/%-10.2ls/%n",L"%2$ls/%1$s/%3$n"};
    for (size_t i=0;i<sizeof text_formats/sizeof *text_formats;i++) {
        memset(out,0x5a,sizeof out); count=-777; errno=ENOSPC;
        int result=swprintf(out,256,text_formats[i],"\342\202\254x",L"\U0001f642z",&count);
        printf("wtext %d %d %d ",result,errno,count); bytes(out,128);
    }
    const long double values[]={0.0L,-0.0L,0.1L,LDBL_MIN,LDBL_MAX,INFINITY,NAN};
    const int rounds[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    for (size_t r=0;r<4;r++) for (size_t i=0;i<sizeof values/sizeof *values;i++) {
        CHECK(!fesetround(rounds[r])); feclearexcept(FE_ALL_EXCEPT);
        memset(out,0x5a,sizeof out); errno=ENOSPC;
        int result=swprintf(out,256,L"%+#20.7La/% .9Lg",values[i],values[i]);
        int exceptions=fetestexcept(FE_ALL_EXCEPT), error=errno;
        printf("wfloat %d %d %d ",result,error,exceptions); bytes(out,224);
    }
    CHECK(!fesetround(FE_TONEAREST));
    for (size_t size=0;size<12;size++) {
        memset(out,0x5a,sizeof out); errno=ENOSPC;
        int result=swprintf(out,size,L"a\u20ac/%d",12345);
        printf("wbound %d %d ",result,errno); bytes(out,48);
    }
    int number=0, used=-1; long double value=0; wchar_t *allocated=NULL;
    CHECK(forwarded_input(L"17 0x1.8p+2 \u20acword",L"%d %La %mls%n",&number,&value,&allocated,&used)==3);
    CHECK(number==17 && value==6 && allocated && !wcscmp(allocated,L"\u20acword"));
    printf("wscan-count %d\n",used); free(allocated);
    const wchar_t *inputs[]={L"123xyz",L" -0x2f rest",L"\u20acabc rest",L"",L"1e+tail"};
    for (size_t i=0;i<sizeof inputs/sizeof *inputs;i++) {
        wchar_t words[32]; memset(words,0x5a,sizeof words); used=-777; errno=ENOSPC;
        int result=swscanf(inputs[i],L"%5l[^ ]%n",words,&used);
        printf("wscan-set %d %d %d ",result,errno,used); bytes(words,48);
        char narrow[32]; memset(narrow,0x5a,sizeof narrow); used=-777; errno=ENOSPC;
        result=swscanf(inputs[i],L"%3s%n",narrow,&used);
        printf("wscan-byte %d %d %d ",result,errno,used); bytes(narrow,16);
    }
    FILE *f=fopen(path,"w+"); CHECK(f && fwide(f,0)==0);
    CHECK(forwarded_file_output(f,L"%d %ls %.2Lf\n",42,L"\u20ac",1.25L)>0 && !fflush(f));
    CHECK(fwide(f,0)>0 && !fseek(f,0,SEEK_SET));
    wchar_t word[16]; double decimal=0;
    CHECK(forwarded_file_input(f,L"%d %ls %lf",&number,word,&decimal)==3 && number==42 && word[0]==0x20ac && decimal==1.25);
    CHECK(!fclose(f) && !unlink(path));
    wchar_t large[901], recovered[901];
    for (size_t i=0;i<900;i++) large[i]=(i%3==0 ? 0x20ac : 'a'); large[900]=0;
    CHECK(swprintf(recovered,901,L"%ls",large)==900 && !wcscmp(large,recovered));
    allocated=NULL;
    CHECK(swscanf(large,L"%mls",&allocated)==1 && allocated && !wcscmp(large,allocated)); free(allocated);
    char narrow_large[1501];
    CHECK(snprintf(narrow_large,sizeof narrow_large,"%ls",large)==1500);
    allocated=NULL;
    CHECK(sscanf(narrow_large,"%mls",&allocated)==1 && allocated && !wcscmp(large,allocated)); free(allocated);
    f=tmpfile(); CHECK(f);
    errno=ENOSPC; CHECK(fwprintf(f,L"%lc",(wint_t)0x110000)==-1 && errno==EILSEQ && ferror(f));
    CHECK(fwprintf(f,L"ok")==2 && ferror(f) && !fclose(f));
    CHECK(!fflush(stdout)); int saved=dup(STDOUT_FILENO); CHECK(saved>=0);
    CHECK(freopen(path,"w",stdout)==stdout && wprintf(L"%ls %d",L"standard",9)==10);
    CHECK(forwarded_standard_output(L" %.1f\n",2.5)==5 && !fflush(stdout));
    char descriptor_path[80]; CHECK(snprintf(descriptor_path,sizeof descriptor_path,"/proc/self/fd/%d",saved)>0);
    CHECK(freopen(descriptor_path,"a",stdout)==stdout && !close(saved));
    CHECK(freopen(path,"r",stdin)==stdin && wscanf(L"%ls %d",word,&number)==2 && number==9 && !wcscmp(word,L"standard"));
    CHECK(forwarded_standard_input(L"%lf",&decimal)==1 && decimal==2.5 && !unlink(path));
    return 0;
}
int main(int argc, char **argv) {
    CHECK(argc==2);
    CHECK(setlocale(LC_ALL,"C.UTF-8"));
    char output[256];
    CHECK(snprintf(output,sizeof output,"%lc/%ls",0x20ac,L"\U0001f642")==8);
    const char *formats[]={"%ls","%12ls","%-12.4ls","%.0ls","%.1ls","%.2ls","%.3ls","%.4ls","%1$12.4ls"};
    const wchar_t private_unit[]={0xdf80,0};
    const wchar_t *strings[]={L"",L"ascii",L"\u20ac\U0001f642",L"a\u20acb",private_unit};
    for (int locale=0;locale<2;locale++) {
        CHECK(setlocale(LC_CTYPE,locale ? "C" : "C.UTF-8"));
        for (size_t i=0;i<sizeof formats/sizeof *formats;i++) for (size_t j=0;j<sizeof strings/sizeof *strings;j++) {
            memset(output,0x5a,sizeof output); errno=ENOSPC;
            int result=snprintf(output,sizeof output,formats[i],strings[j]);
            printf("out %d %d ",result,errno); bytes(output,20);
        }
        const unsigned characters[]={0,'x',0x20ac,0x1f642,0xdf80,0x110000};
        for (size_t i=0;i<sizeof characters/sizeof *characters;i++) {
            memset(output,0x5a,sizeof output); errno=ENOSPC;
            int result=snprintf(output,sizeof output,"[%5lc]",characters[i]);
            printf("char %d %d ",result,errno); bytes(output,16);
        }
        const char *inputs[]={"ascii word","\342\202\254x rest","\377x","\342\202",""};
        const char *scans[]={"%ls%n","%3ls%n","%2lc%n","%l[a-z]%n","%l[^x]%n"};
        for (size_t i=0;i<sizeof inputs/sizeof *inputs;i++) for (size_t j=0;j<sizeof scans/sizeof *scans;j++) {
            wchar_t wide[32]; memset(wide,0x5a,sizeof wide); int count=-777; errno=ENOSPC;
            int result=sscanf(inputs[i],scans[j],wide,&count);
            printf("in %d %d %d ",result,errno,count); bytes(wide,32);
        }
        wchar_t *allocated=NULL; errno=ENOSPC;
        int result=sscanf("alpha beta","%mls",&allocated);
        CHECK(result==1 && allocated && !wcscmp(allocated,L"alpha")); free(allocated);
    }
    CHECK(!wide_formats(argv[1]));
    puts("owned-wide-format-ok"); return 0;
}
