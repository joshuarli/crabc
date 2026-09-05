#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "owned_cancellation_proc_witness.h"

#define CHECK(c) do { if (!(c)) { dprintf(2,"resolver cancellation line %d errno %d\n",__LINE__,errno); _exit(77); } } while (0)
static int baseline, cleanup_count, cleanup_fds, returned, state_after, result_errno, successful;
static atomic_int extra_fds;
static atomic_int worker_tid;
static const char *scenario, *api;
static int uses_server, tcp_case, initial_state, cancel_before_tcp, socket_failure, kernel_canceled;
static int normal_case, retry_case, reuse_case;
static int descriptor_count(void) {
    int count=0;
    for(int fd=0;fd<512;fd++) {
        if(fcntl(fd,F_GETFD)>=0) count++;
        else CHECK(errno==EBADF);
    }
    return count;
}
static void cleanup(void *unused) {
    (void)unused;
    cleanup_fds=descriptor_count()-baseline-atomic_load(&extra_fds);
    cleanup_count++;
}
static void query(void) {
    unsigned char answer[512];
    if(!strcmp(api,"query")) successful=res_query("cancel.example.test",1,1,answer,sizeof answer)>=12;
    else if(!strcmp(api,"send")) {
        unsigned char request[512];
        int n=res_mkquery(0,"cancel.example.test",1,1,0,0,0,request,sizeof request);
        CHECK(n>0);successful=res_send(request,n,answer,sizeof answer)>=12;
    } else if(!strcmp(api,"classic")) {
        struct hostent host,*result;char buffer[4096];int error;
        successful=!gethostbyname_r("cancel.example.test",&host,buffer,sizeof buffer,&result,&error) && result!=0;
    } else if(!strcmp(api,"modern")) {
        struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM},*result=0;
        successful=!getaddrinfo("cancel.example.test",0,&hints,&result) && result!=0;if(result) freeaddrinfo(result);
    } else if(!strcmp(api,"reverse")) {
        struct sockaddr_in address={.sin_family=AF_INET};char name[256];
        CHECK(inet_pton(AF_INET,"198.51.100.23",&address.sin_addr)==1);
        successful=!getnameinfo((void *)&address,sizeof address,name,sizeof name,0,0,NI_NAMEREQD)
                   && !strcmp(name,"resolved.example.test");
    } else CHECK(0);
}
static void syscall_error(int number,int error,int stream_only) {
    struct instruction { unsigned short code;unsigned char yes,no;unsigned value; };
    struct program { unsigned short count;struct instruction *instructions; };
    struct instruction instructions[]={
        {0x20,0,0,0}, {0x15,0,4,(unsigned)number},
        {0x20,0,0,24}, {0x54,0,0,15}, {0x15,0,1,1},
        {0x06,0,0,0x00050000u|(unsigned)error}, {0x06,0,0,0x7fff0000u},
    };
    if(!stream_only) { instructions[1].no=1;instructions[2]=instructions[5];instructions[3]=instructions[6]; }
    struct program program={(unsigned short)(stream_only?7:4),instructions};
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    CHECK(!prctl(PR_SET_SECCOMP,2,&program));
}
static void *worker(void *unused) {
    (void)unused;
    atomic_store(&worker_tid,(int)syscall(SYS_gettid));
    pthread_cleanup_push(cleanup,0);
    if(!uses_server && !kernel_canceled) {
        CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,0));
        CHECK(!pthread_cancel(pthread_self()));
    }
    CHECK(!pthread_setcancelstate(initial_state,0));
    if(socket_failure) syscall_error(SYS_socket,EMFILE,socket_failure==2);
    if(kernel_canceled) syscall_error(SYS_sendto,ECANCELED,0);
    if(reuse_case) { query();CHECK(successful);successful=0; }
    query();result_errno=errno;
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&state_after));
    returned=1;
    pthread_cleanup_pop(0);
    return (void *)42;
}
static int server(int type) {
    int fd=socket(AF_INET,type,0);CHECK(fd>=0);
    int one=1;CHECK(!setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one));
    struct timeval timeout={.tv_sec=3};
    CHECK(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout));
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(53),.sin_addr={htonl(INADDR_LOOPBACK)}};
    CHECK(!bind(fd,(void *)&address,sizeof address));
    if(type==SOCK_STREAM) CHECK(!listen(fd,1));
    return fd;
}
static void read_exact(int fd,unsigned char *p,size_t n) {
    while(n) { ssize_t r=read(fd,p,n);CHECK(r>0);p+=r;n-=(size_t)r; }
}
static size_t dns_answer(unsigned char *packet,size_t length) {
    CHECK(length>=12 && length+40<512);
    unsigned kind=((unsigned)packet[length-4]<<8)|packet[length-3];
    CHECK(kind==1 || kind==12);
    packet[2]=0x81;packet[3]=0x80;packet[6]=0;packet[7]=1;
    const unsigned char record[]={0xc0,0x0c,0,0,0,1,0,0,0,30,0,0};
    memcpy(packet+length,record,sizeof record);packet[length+3]=(unsigned char)kind;
    const unsigned char address[]={198,51,100,23};
    const unsigned char name[]={8,'r','e','s','o','l','v','e','d',7,'e','x','a','m','p','l','e',4,'t','e','s','t',0};
    size_t amount=kind==1?sizeof address:sizeof name;
    packet[length+11]=(unsigned char)amount;
    memcpy(packet+length+sizeof record,kind==1?address:name,amount);
    return length+sizeof record+amount;
}
static void witness_blocked_wait(void) {
    const struct timespec pause={0,1000000};
    for(int attempt=0;attempt<500;attempt++) {
        char path[96],record[256];
        snprintf(path,sizeof path,"/proc/self/task/%d/syscall",atomic_load(&worker_tid));
        int fd=owned_cancellation_open_proc(path);CHECK(fd>=0);
        ssize_t n=read(fd,record,sizeof record-1);CHECK(!close(fd));
        if(n>0) {
            record[n]=0;long number=-1;
            if(sscanf(record,"%ld",&number)==1 && (number==SYS_poll || number==SYS_ppoll)) return;
        }
        CHECK(!nanosleep(&pause,0));
    }
    CHECK(0);
}
int main(int argc,char **argv) {
    CHECK(argc==3);scenario=argv[1];api=argv[2];
    uses_server=strstr(scenario,"udp")!=0 || strstr(scenario,"tcp")!=0;
    tcp_case=strstr(scenario,"tcp")!=0;
    normal_case=!strncmp(scenario,"normal-",7) || !strcmp(scenario,"retry-udp");
    retry_case=!strncmp(scenario,"retry-",6);
    reuse_case=!strcmp(scenario,"reuse-cancel-udp");
    initial_state=!strncmp(scenario,"masked",6)?PTHREAD_CANCEL_MASKED:
                  !strncmp(scenario,"disabled",8)?PTHREAD_CANCEL_DISABLE:PTHREAD_CANCEL_ENABLE;
    cancel_before_tcp=!strcmp(scenario,"masked-udp-to-tcp") || !strcmp(scenario,"masked-tcp-socket-failure");
    socket_failure=!strcmp(scenario,"setup-pending")?1:!strcmp(scenario,"masked-tcp-socket-failure")?2:0;
    kernel_canceled=!strcmp(scenario,"kernel-canceled");
    if(kernel_canceled) initial_state=PTHREAD_CANCEL_MASKED;
    const struct rlimit descriptor_limit={512,512};
    CHECK(!setrlimit(RLIMIT_NOFILE,&descriptor_limit));
    int config=open("/etc/resolv.conf",O_WRONLY|O_CREAT|O_TRUNC,0600);CHECK(config>=0);
    char bytes[96];int config_size=snprintf(bytes,sizeof bytes,"nameserver 127.0.0.1\noptions timeout:1 attempts:%d\n",retry_case?2:1);
    CHECK(config_size>0 && config_size<(int)sizeof bytes);
    CHECK(write(config,bytes,(size_t)config_size)==config_size);CHECK(!close(config));
    int hosts=open("/etc/hosts",O_WRONLY|O_CREAT|O_TRUNC,0600);CHECK(hosts>=0);CHECK(!close(hosts));
    int udp=server(SOCK_DGRAM),tcp=server(SOCK_STREAM),accepted=-1;
    baseline=descriptor_count();CHECK(baseline>=6);
    pthread_t thread;CHECK(!pthread_create(&thread,0,worker,0));
    if(uses_server) {
        unsigned char packet[512];struct sockaddr_in peer;socklen_t size=sizeof peer;
        ssize_t n=recvfrom(udp,packet,sizeof packet,0,(void *)&peer,&size);CHECK(n>=12);
        if(reuse_case) {
            size_t length=dns_answer(packet,(size_t)n);
            CHECK(sendto(udp,packet,length,0,(void *)&peer,size)==(ssize_t)length);
        }
        if(retry_case || reuse_case) {
            size=sizeof peer;n=recvfrom(udp,packet,sizeof packet,0,(void *)&peer,&size);CHECK(n>=12);
        }
        if(cancel_before_tcp) { witness_blocked_wait();CHECK(!pthread_cancel(thread)); }
        if(tcp_case) {
            packet[2]|=0x82;packet[3]|=0x80;
            CHECK(sendto(udp,packet,(size_t)n,0,(void *)&peer,size)==n);
            if(!socket_failure) {
                accepted=accept(tcp,0,0);CHECK(accepted>=0);atomic_store(&extra_fds,1);
                unsigned char length[2];read_exact(accepted,length,2);
                unsigned amount=((unsigned)length[0]<<8)|length[1];CHECK(amount<=sizeof packet);
                read_exact(accepted,packet,amount);n=amount;
            }
        }
        if(normal_case) {
            size_t length=dns_answer(packet,(size_t)n);
            if(tcp_case) {
                unsigned char prefix[]={(unsigned char)(length>>8),(unsigned char)length};
                CHECK(write(accepted,prefix,2)==2);CHECK(write(accepted,packet,length)==(ssize_t)length);
            } else CHECK(sendto(udp,packet,length,0,(void *)&peer,size)==(ssize_t)length);
        } else if(!cancel_before_tcp) { witness_blocked_wait();CHECK(!pthread_cancel(thread)); }
    }
    void *joined=0;CHECK(!pthread_join(thread,&joined));
    int leaked=descriptor_count()-baseline-atomic_load(&extra_fds);
    unsigned char packet[512];ssize_t received=recv(udp,packet,sizeof packet,MSG_DONTWAIT);
    CHECK(received>=0 || errno==EAGAIN);int transmitted=received>=0;
    printf("canceled=%d returned=%d cleanup=%d cleanup_fds=%d leaked=%d state=%d transmitted=%d success=%d errno=%d\n",
           joined==PTHREAD_CANCELED,returned,cleanup_count,cleanup_fds,leaked,state_after,transmitted,successful,result_errno);
    if(accepted>=0) CHECK(!close(accepted));CHECK(!close(tcp));CHECK(!close(udp));
    if((uses_server && initial_state==PTHREAD_CANCEL_ENABLE && !normal_case) || !strcmp(scenario,"pending"))
        CHECK(joined==PTHREAD_CANCELED && !returned && cleanup_count==1 && !cleanup_fds && !leaked && !transmitted);
    else {
        int expected=kernel_canceled?PTHREAD_CANCEL_MASKED:socket_failure==1 || normal_case?PTHREAD_CANCEL_ENABLE:PTHREAD_CANCEL_DISABLE;
        CHECK(joined==(void *)42 && returned && !cleanup_count && !leaked && state_after==expected);
        CHECK(transmitted==(!uses_server && initial_state==PTHREAD_CANCEL_DISABLE));
        if(initial_state==PTHREAD_CANCEL_MASKED && !kernel_canceled) CHECK(result_errno==ECANCELED);
        if(socket_failure==1) CHECK(result_errno==EMFILE);
        CHECK(successful==normal_case);
    }
    return 0;
}
