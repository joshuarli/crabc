#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { dprintf(2, "passwd line %d errno %d\n", __LINE__, errno); _exit(77); } } while (0)
static const char records[] = "malformed\nalpha:x:1001:2001:Alpha:/alpha:/bin/sh\nbad:x:-1:1:a:b:c\nbeta:*:1002:2002:Beta:/beta:/bin/bash\nalpha:z:9999:9999:Duplicate:/other:/other\nempty:::4294967296:E:/empty:/s\nwrap:x:4294967297:4294967298:W:/wrap:/s\ncrlf:x:7:8:C:/cr:/s\r\nextra:x:9:10:E:/extra:/s:tail\nraw\xff:x:11:12:R:/raw:/s\ntail:x:13:14:T:/tail:/shell";
static void write_records(const char *text, size_t length) {
    endpwent(); int fd=open("/etc/passwd", O_WRONLY|O_CREAT|O_TRUNC,0600); CHECK(fd>=0);
    CHECK(write(fd,text,length)==(ssize_t)length); CHECK(close(fd)==0);
}
static void setup(void) { write_records(records,sizeof records-1); }
static void in_buffer(struct passwd *p,char *b,size_t n) {
    char *fields[]={p->pw_name,p->pw_passwd,p->pw_gecos,p->pw_dir,p->pw_shell};
    for(unsigned i=0;i<5;i++) CHECK(fields[i]>=b && fields[i]<b+n && memchr(fields[i],0,b+n-fields[i]));
}
static void lookup(void) {
    setup(); struct passwd p,*r; char b[4096]; errno=EDOM;
    CHECK(getpwnam_r("alpha",&p,b,sizeof b,&r)==0 && r==&p && errno==EDOM);
    CHECK(p.pw_uid==1001 && p.pw_gid==2001 && !strcmp(p.pw_dir,"/alpha")); in_buffer(&p,b,sizeof b);
    CHECK(getpwuid_r(1002,&p,b,sizeof b,&r)==0 && r==&p && !strcmp(p.pw_name,"beta"));
    memset(b,0x5a,sizeof b); errno=EDOM; r=(void*)1;
    CHECK(getpwnam_r("absent",&p,b,sizeof b,&r)==0 && !r && errno==EDOM);
    for(unsigned i=0;i<sizeof b;i++) CHECK(b[i]==0x5a);
    CHECK(!getpwuid(12345));
    CHECK(getpwnam_r("empty",&p,b,sizeof b,&r)==0 && r && !p.pw_uid && !p.pw_gid);
    CHECK(getpwnam_r("wrap",&p,b,sizeof b,&r)==0 && r && p.pw_uid==1 && p.pw_gid==2);
    CHECK(getpwuid_r(7,&p,b,sizeof b,&r)==0 && r && !strcmp(p.pw_shell,"/s\r"));
    CHECK(getpwuid_r(9,&p,b,sizeof b,&r)==0 && r && !strcmp(p.pw_shell,"/s:tail"));
    CHECK(getpwuid_r(11,&p,b,sizeof b,&r)==0 && r && !strcmp(p.pw_name,"raw\xff"));
    CHECK(getpwuid_r(13,&p,b,sizeof b,&r)==0 && r && !strcmp(p.pw_shell,"/shel"));
}
static void ranges(void) {
    setup(); FILE *f=fopen("/etc/passwd","r"); CHECK(f); char *line=0; size_t capacity=0;
    CHECK(getline(&line,&capacity,f)>0); CHECK(getline(&line,&capacity,f)>0); CHECK(fclose(f)==0);
    struct passwd p,*r; char b[4096]; CHECK(capacity<sizeof b); memset(b,0x5a,sizeof b);
    CHECK(getpwnam_r("alpha",&p,b,capacity-1,&r)==ERANGE && !r && errno==ERANGE);
    for(unsigned i=0;i<sizeof b;i++) CHECK(b[i]==0x5a);
    CHECK(getpwnam_r("alpha",&p,b,capacity,&r)==0 && r==&p); in_buffer(&p,b,capacity); printf("matching allocation capacity %zu\n",capacity); free(line);
    char large[3000]; memset(large,'x',sizeof large); large[2500]='\n';
    const char last[]="last:x:21:22:L:/last:/s\n"; memcpy(large+2501,last,sizeof last-1);
    write_records(large,2501+sizeof last-1);
    CHECK(getpwnam_r("last",&p,b,128,&r)==ERANGE && !r);
    CHECK(getpwnam_r("last",&p,b,sizeof b,&r)==0 && r && p.pw_uid==21);
}
static void enumeration(void) {
    setup(); void (*volatile a)(void)=setpwent,(*volatile z)(void)=endpwent; CHECK(a==z);
    struct passwd *p=getpwent(); CHECK(p && !strcmp(p->pw_name,"alpha"));
    int count=0; for(int fd=3;fd<64;fd++) {int flags=fcntl(fd,F_GETFD); if(flags>=0) { CHECK(flags&FD_CLOEXEC); count++; }} CHECK(count==1);
    struct passwd *q=getpwnam("wrap"); CHECK(q==p && q->pw_uid==1);
    CHECK(getpwent()==p && !strcmp(p->pw_name,"beta"));
    FILE *f=fopen("/etc/passwd","r"); CHECK(f); q=fgetpwent(f); CHECK(q && q!=p && !strcmp(q->pw_name,"alpha"));
    CHECK(fgetpwent(f)==q && !strcmp(q->pw_name,"beta")); CHECK(fclose(f)==0);
    endpwent(); CHECK(getpwent()==p && !strcmp(p->pw_name,"alpha"));
    unsigned remaining=0; while(getpwent()) remaining++; CHECK(remaining==8); CHECK(!getpwent());
    setpwent(); CHECK(getpwent()==p && p->pw_uid==1001); endpwent();
}
static void stream(void) {
    char bytes[]="bad\none:x:1:2:G:/d:/s\ntwo:x:3:4:G:/d:/tail";
    FILE *f=fmemopen(bytes,sizeof bytes-1,"r"); CHECK(f); struct passwd *p=fgetpwent(f);
    CHECK(p && !strcmp(p->pw_name,"one")); CHECK(fgetpwent(f)==p && !strcmp(p->pw_shell,"/tai"));
    errno=EDOM; CHECK(!fgetpwent(f) && feof(f) && !ferror(f) && errno==EDOM); CHECK(fclose(f)==0);
    f=fopen("/etc/passwd","r"); CHECK(f && close(fileno(f))==0); errno=0; CHECK(!fgetpwent(f) && ferror(f) && errno==EBADF); CHECK(fclose(f)==-1);
}
static void output(void) {
    char b[512]={0}; FILE *f=fmemopen(b,sizeof b,"w+"); CHECK(f);
    struct passwd p={"n:x","*",4294967295U,42,"g\nx","/d","/s"};
    CHECK(putpwent(&p,f)==0 && fflush(f)==0);
    CHECK(!strcmp(b,"n:x:*:4294967295:42:g\nx:/d:/s\n")); CHECK(fclose(f)==0);
    f=fopen("/etc/passwd","w"); CHECK(f && setvbuf(f,0,_IONBF,0)==0 && close(fileno(f))==0); errno=0; CHECK(putpwent(&p,f)==-1 && errno==EBADF && ferror(f)); CHECK(fclose(f)==-1);
}
static void filter(int number,unsigned action) {
    struct instruction { unsigned short code; unsigned char yes,no; unsigned value; };
    struct program { unsigned short count; struct instruction *instructions; };
    struct instruction ins[]={{0x20,0,0,0},{0x15,0,1,(unsigned)number},{0x06,0,0,action},{0x06,0,0,0x7fff0000}};
    struct program p={4,ins}; CHECK(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0); CHECK(syscall(SYS_seccomp,1,0,&p)==0);
}
static void errors(const char *which) {
    setup(); int expected;
    if(!strcmp(which,"missing")) {CHECK(unlink("/etc/passwd")==0);expected=ENOENT;}
    else if(!strcmp(which,"directory")) {CHECK(unlink("/etc/passwd")==0); CHECK(mkdir("/etc/passwd",0700)==0);expected=EISDIR;}
    else if(!strcmp(which,"not-directory")) {CHECK(rename("/etc","/saved-etc")==0);int fd=open("/etc",O_WRONLY|O_CREAT,0600);CHECK(fd>=0 && !close(fd));expected=ENOTDIR;}
    else if(!strcmp(which,"read-error")) {filter(SYS_read,0x00050000|EIO);expected=EIO;}
    else {filter(SYS_open,0x00050000|EACCES);filter(SYS_openat,0x00050000|EACCES);expected=EACCES;}
    struct passwd p,*r=(void*)1; char b[4096]; memset(b,0x5a,sizeof b); errno=0;
    CHECK(getpwnam_r("alpha",&p,b,sizeof b,&r)==expected && !r && errno==expected);
    for(unsigned i=0;i<sizeof b;i++) CHECK(b[i]==0x5a);
    if(!strcmp(which,"directory")) CHECK(rmdir("/etc/passwd")==0);
    if(!strcmp(which,"not-directory")) CHECK(unlink("/etc")==0 && rename("/saved-etc","/etc")==0);
}
static void local_only(int oracle) {
    setup(); pid_t child=fork(); CHECK(child>=0);
    if(!child) {filter(SYS_socket,0x80000000); struct passwd p,*r;char b[256]; CHECK(getpwnam_r("absent",&p,b,sizeof b,&r)==0 && !r);_exit(0);}
    int status; CHECK(waitpid(child,&status,0)==child);
    if(oracle) CHECK(WIFSIGNALED(status) && WTERMSIG(status)==SIGSYS); else CHECK(WIFEXITED(status) && !WEXITSTATUS(status));
}
static void *thread_lookup(void *arg) {
    unsigned uid=(unsigned)(size_t)arg; struct passwd p,*r; char b[4096];
    for(unsigned i=0;i<100;i++) {CHECK(getpwuid_r(uid,&p,b,sizeof b,&r)==0 && r && p.pw_uid==uid); CHECK(!strcmp(p.pw_dir,uid==1001?"/alpha":"/beta")); in_buffer(&p,b,sizeof b);}
    return 0;
}
static void threads(void) {setup();pthread_t a,b;CHECK(!pthread_create(&a,0,thread_lookup,(void*)1001));CHECK(!pthread_create(&b,0,thread_lookup,(void*)1002));CHECK(!pthread_join(a,0)&&!pthread_join(b,0));}
static void fork_cursor(void) {
    setup();CHECK(getpwent()->pw_uid==1001);pid_t child=fork();CHECK(child>=0);
    if(!child) {CHECK(getpwent()->pw_uid==1002);setpwent();CHECK(getpwent()->pw_uid==1001);endpwent();_exit(0);}
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status)); CHECK(getpwent()->pw_uid==1002);endpwent();
}
static volatile int cancellation_returned;
static void *cancel_lookup(void *unused) {
    (void)unused; CHECK(pthread_cancel(pthread_self())==0); struct passwd p,*r;char b[4096];
    CHECK(getpwnam_r("alpha",&p,b,sizeof b,&r)==0 && r); CHECK(getpwuid(1002));
    CHECK(getpwent());endpwent(); cancellation_returned=1;pthread_testcancel();_exit(78);
}
static void cancellation(void) {setup();pthread_t t;void *r;CHECK(!pthread_create(&t,0,cancel_lookup,0));CHECK(!pthread_join(t,&r)&&r==PTHREAD_CANCELED&&cancellation_returned);}
static void allocation(void) {
    setup(); int fd=open("/etc/passwd",O_WRONLY|O_TRUNC); CHECK(fd>=0 && ftruncate(fd,256*1024*1024)==0 && !close(fd));
    struct rlimit old,limit; CHECK(!getrlimit(RLIMIT_AS,&old));limit=old;limit.rlim_cur=64*1024*1024; CHECK(!setrlimit(RLIMIT_AS,&limit));
    struct passwd p,*r;char b[64];memset(b,0x5a,sizeof b);errno=0;CHECK(getpwnam_r("absent",&p,b,sizeof b,&r)==ENOMEM && !r && errno==ENOMEM);
    for(unsigned i=0;i<sizeof b;i++) CHECK(b[i]==0x5a);
    for(int i=3;i<64;i++) CHECK(fcntl(i,F_GETFD)==-1 && errno==EBADF);
    CHECK(!setrlimit(RLIMIT_AS,&old));setup();char recovered[4096];CHECK(!getpwnam_r("alpha",&p,recovered,sizeof recovered,&r)&&r);
}
int main(int argc,char **argv) {
    CHECK(argc==3); const char *s=argv[1];
    if(!strcmp(s,"lookup"))lookup();else if(!strcmp(s,"ranges"))ranges();else if(!strcmp(s,"enumeration"))enumeration();else if(!strcmp(s,"stream")){setup();stream();}else if(!strcmp(s,"output")){setup();output();}
    else if(!strcmp(s,"local-only"))local_only(!strcmp(argv[2],"oracle"));else if(!strcmp(s,"threads"))threads();else if(!strcmp(s,"fork"))fork_cursor();else if(!strcmp(s,"cancellation"))cancellation();else if(!strcmp(s,"allocation"))allocation();else errors(s);
    puts("owned passwd scenario passed");return 0;
}
