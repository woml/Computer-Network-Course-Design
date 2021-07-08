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
#ifdef  HAVE_SOCKADDR_DL_STRUCT
# include       <net/if_dl.h>
#endif

#define BUFSIZE	1500      //缓冲区的最大长度
#define MAXLINE 4096      //一行的最大长度

/* globals */
char recvbuf[BUFSIZE];    //接收缓冲区
char sendbuf[BUFSIZE];    //发送缓冲区

int datalen;	/* #bytes of data, following ICMP header */ //随ICMP回射请求一起发送的可选数据长度
char *host;     //目的主机地址
int	nsent;			/* add 1 for each sendto() */ //每发送一个数据包+1
pid_t pid;			/* our PID */ //进程号
int	sockfd;     //套接口描述字
int	verbose;    //是否详尽输出
int daemon_proc;            /* set nonzero by daemon_init() */

/* function prototypes */
void	 proc_v4(char *, ssize_t, struct timeval *);
void	 proc_v6(char *, ssize_t, struct timeval *);
void	 send_v4(void);
void	 send_v6(void);
void	 readloop(void);
void	 sig_alrm(int);
void	 tv_sub(struct timeval *, struct timeval *);

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);
void err_quit(const char *fmt, ...);
void err_sys(const char *fmt, ...);

struct proto {
  void	 (*fproc)(char *, ssize_t, struct timeval *);
  void	 (*fsend)(void);
  struct sockaddr  *sasend;	/* sockaddr{} for send, from getaddrinfo */
  struct sockaddr  *sarecv;	/* sockaddr{} for receiving */
  socklen_t	    salen;		/* length of sockaddr{}s */
  int	   	    icmpproto;	/* IPPROTO_xxx value for ICMP */
} *pr;

