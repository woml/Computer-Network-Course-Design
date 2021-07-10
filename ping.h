#include 	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/ip6.h>
#include	<sys/types.h>	/* basic system data types */
#include	<sys/socket.h>	/* basic socket definitions */
#include	<sys/time.h>	/* timeval{} for select() */
#include	<time.h>		/* timespec{} for pselect() */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<arpa/inet.h>	/* inet(3) functions */
#include	<netdb.h>
#include	<signal.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include 	<pwd.h>
#include	<unistd.h>
#include	<sys/un.h>		/* for Unix domain sockets */
#include	<sys/ioctl.h>
#include	<net/if.h>
#include <stdarg.h>
#include <syslog.h>
#include <limits.h>
#include <math.h>
#ifdef  HAVE_SOCKADDR_DL_STRUCT
# include       <net/if_dl.h>
#endif

#define BUFSIZE	1500      //缓冲区的最大长度
#define MAXLINE 4096      //一行的最大长度

//#define 

/* globals */
char recvbuf[BUFSIZE];    //接收缓冲区
char sendbuf[BUFSIZE];    //发送缓冲区

int datalen;	/* #bytes of data, following ICMP header */ //随ICMP回射请求一起发送的可选数据长度
char *host;     //目的主机地址
int	nsent;			/* add 1 for each sendto() */ //每发送一个数据包+1
pid_t pid;			/* our PID */ 
int	sockfd;     //套接口描述字
/* 是否详尽输出 */
int	verbose;    
/* 是否安静输出 */
int quite;
/* 记录安静输出的数据 */
int quitePackageTotal = 0; // 传送的数据包总数
int quitePackageSuccess = 0; // 成功传送的数据包总数
long quiteTransferTime = 0; // 传送数据包过程的时间
char *quiteTargetName; // 目标主机的IP或者主机名
int daemon_proc;            /* set nonzero by daemon_init() */

struct timeval start_time;

const char *usage = 
  "usage: ping [-bhqvt:] <hostname>\n \
  -h Show help information\n \
  -v Normal mode\n \
  -b Broadcast\n \
  -t ttl Set TTL(0~255)\n \
  -q Quiet mode\n";


int op;     //操作
int broadcast;
int ttl;
double min_time = -1;
double max_time = -1;
double avg_time = -1;
double stddev_time = -1;

//标志量
int ttl_flag;

/* function prototypes */
void	 proc_v4(char *, ssize_t, struct timeval *);
void	 proc_v6(char *, ssize_t, struct timeval *);
void	 send_v4(void);
void	 send_v6(void);
void	 readloop(void);
void	 sig_alrm(int);
void	 tv_sub(struct timeval *, struct timeval *);
void   show_help();

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);
void err_quit(const char *fmt, ...);
void err_sys(const char *fmt, ...);

/*
 * 处理IPv4和IPv6之间差异的结构体
 * 
 */
struct proto {
  void	 (*fproc)(char *, ssize_t, struct timeval *);
  void	 (*fsend)(void);
  struct sockaddr  *sasend;	/* sockaddr{} for send, from getaddrinfo */ //sockaddr send -> sasend
  struct sockaddr  *sarecv;	/* sockaddr{} for receiving */              //sockaddr recive -> sarecv

  /* 这两个套接字地址结构的大小及ICMP的协议值 */
  socklen_t	    salen;		/* length of sockaddr{}s */
  int	   	    icmpproto;	/* IPPROTO_xxx value for ICMP */
} *pr;  /* 全局指针变量pr将指向IPv4或IPv6的某个proto结构 */

