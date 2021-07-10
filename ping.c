#include "ping.h"            

/*
 * 为IPv4和IPv6分别定义一个proto结构
 * 套接字地址结构指针置空，因为不知道最终使用IPv4还是IPv6
 */
struct proto	proto_v4 = { proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP };

#ifdef	IPV6
struct proto	proto_v6 = { proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6 };
#endif

/* 回射请求发送的可选数据量长度 */
int	datalen = 56;		/* data that goes with ICMP echo request */

/*
optarg 保存选项的参数
optind 检索下一个参数	初值为1
opterr 是否将错误信息输出到stderr (0表示不输出) 初值为1
optopt 表示不在选项字符串optstring中的选项（
*/
// 指示停止的指示位
int quitFlag = 0;

// 记录安静模式下的起止时间
__suseconds_t quiteStart;
__suseconds_t quiteEnd;

// 记录安静模式下的rtt情况
double quiteMin = (double)INT32_MAX;
double quiteMax = (double)-1;
double quiteTotal = 0.0;
double quiteTotalSquare = 0.0;

// -q模式下接收到ctrl+c指令后输出结果的函数
void quiteShowResult(int sig) {
	quitFlag = 1;
	// 判断当前是否为-q指令
		if(quite) {
			// 计算丢包率
			double loss = (double)(quitePackageTotal - quitePackageSuccess) / quitePackageTotal * 100;
			printf("\n--- %s ping statistics ---\n", quiteTargetName);
			printf("%d packats transmitted, %d received, %.0lf%% packet loss\n", quitePackageTotal, quitePackageSuccess, loss);	
			double quiteAvg = quiteTotal / quitePackageTotal;
			printf("rtt min/avg/max/medv = %.3lf ms/%.3lf ms/%.3lf ms/%.3lf ms\n", 
			quiteMin, 
			quiteAvg, 
			quiteMax, 
			sqrt((quiteTotalSquare / quiteTotal) - quiteAvg * quiteAvg));
	}
}

int
main(int argc, char **argv)
{
	int	c;
	struct addrinfo	*ai;
	char *end;
	opterr = 0;		/* don't want getopt() writing to stderr */
	while ( (c = getopt(argc, argv, "qhbvt:")) != -1) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'h':
			show_help();
			break;
		case 't':
			ttl = strtol(optarg, &end, 10);		//取得数字部分
			ttl_flag = 1;
		case 'q':
			quite++;
			break;
		case '?':
			err_quit("unrecognized option: %c", c);
		}
	}

	if (optind != argc - 1)
		err_quit("usage: ping [ -v ] <hostname>");
		
	host = argv[optind];	// optind = argc - 1 目的 hostname / IP地址	 

	pid = getpid();
	signal(SIGALRM, sig_alrm);

	/*
	 * 处理主机名参数
	 * 命令行中必须有一个主机名获IP地址参数，由host_serv处理
	 * 
	 */
	ai = host_serv(host, NULL, 0, 0);

	// 向安静模式传输IP或者主机名
	quiteTargetName = ai->ai_canonname;
	printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
		Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

	/* 
	 * 让全局指针变量pr指向正确的proto结构 
	 */
	if (ai->ai_family == AF_INET) {
		pr = &proto_v4;
#ifdef	IPV6
	} else if (ai->ai_family == AF_INET6) {
		pr = &proto_v6;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
								ai->ai_addr)->sin6_addr)))
			err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
	} else
		err_quit("unknown address family %d", ai->ai_family);

	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;

	/* 无限循环 */
	readloop();

	exit(0);
}

/*
 *	ptr 为剥去了以太网部分的IP数据报，len为数据长度。利用IP头部的参数快速跳到ICMP报文部分，IP结构
 *	的ip_hl标识IP头部的长度,ip_hl标识4字节单位，所以 << 2
 */
void
proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

	/* 
	 * 得到IPv4首部为多少字节
	 * 将指针指向ICMP首部开始的位置
	 */
	ip = (struct ip *) ptr;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)	//判断长度是否为ICMP包
		err_quit("icmplen (%d) < 8", icmplen);

	if (icmp->icmp_type == ICMP_ECHOREPLY) {	/*ICMP包类型为ICMP_ECHOREPLY（也就是reply）*/
		if (icmp->icmp_id != pid)	//进程不是本进程PID 退出
	/* 
	 * 检查标识符字段
	 * 判断该应答是否是本进程发出的请求
	 */
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			err_quit("icmplen (%d) < 16", icmplen);
	
		/* 计算rtt（往复时间）*/
		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		if(rtt > quiteMax)
			quiteMax = rtt;
		if(rtt < quiteMin)
			quiteMin = rtt;
		quiteTotal += rtt;
		quiteTotalSquare += rtt * rtt;
		

		/* 打印信息 */
		if(!quite) {
			printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
					icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
					icmp->icmp_seq, ip->ip_ttl, rtt);
		}

	} 
	/* 设置了-v（详尽输出）*/
	else if (verbose) {
		printf("  %d bytes from %s: type = %d, code = %d\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_type, icmp->icmp_code);
	}

	/* 设置了-q（安静输出）*/
	else if (quite) {
		// icmp->icmp_seq + 1 即传输包总数
		quitePackageTotal = icmp->icmp_seq + 1; 

		// icmp->icmp_type = 8 的个数即传输成功的包的个数
		if(icmp->icmp_type == 8)
			quitePackageSuccess++;
	}
}

void
proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv)
{
#ifdef	IPV6
	int					hlen1, icmp6len;
	double				rtt;
	struct ip6_hdr		*ip6;
	struct icmp6_hdr	*icmp6;
	struct timeval		*tvsend;

	ip6 = (struct ip6_hdr *) ptr;		/* start of IPv6 header */
	hlen1 = sizeof(struct ip6_hdr);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		err_quit("next header not IPPROTO_ICMPV6");

	icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
	if ( (icmp6len = len - hlen1) < 8)
		err_quit("icmp6len (%d) < 8", icmp6len);

	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
		if (icmp6->icmp6_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmp6len < 16)
			err_quit("icmp6len (%d) < 16", icmp6len);

		tvsend = (struct timeval *) (icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
				icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_seq, ip6->ip6_hlim, rtt);

	} else if (verbose) {
		printf("  %d bytes from %s: type = %d, code = %d\n",
				icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_type, icmp6->icmp6_code);
	}
#endif	/* IPV6 */
}

unsigned short
in_cksum(unsigned short *addr, int len)
{
        int nleft = len;
        int sum = 0;
        unsigned short  *w = addr;
        unsigned short  answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {	//将数据按照2字节为单位累加起来
                sum += *w++;	// unsigned short ++ 每次+2
                nleft -= 2;
        }

        /* 4mop up an odd byte, if necessary */
        if (nleft == 1) {		//如果ICMP报头为奇数个字节，会剩下最后一个字节
                *(unsigned char *)(&answer) = *(unsigned char *)w ;
                sum += answer;
        }

                /* 4add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */ 			//将溢出位加入
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void
send_v4(void)
{
	int			len;
	struct icmp	*icmp;

	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;		//ICMP回显请求
	icmp->icmp_code = 0;				//code值为0
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;			//本报的序列号，唯一递增。
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);		//gettimeofday()会把目前的时间有tv所指的结构返回，当地时区的信息则放到tz所指的结构中。

	len = 8 + datalen;		/* checksum ICMP header and data */		// 总长度 默认datelen为56字节 + 1字节类型 + 1字节code + 2字节校验和
																	// + 2字节id + 2字节seq
	icmp->icmp_cksum = 0;				//cksum先填0，便于之后的cksum计算
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);		//计算校验和

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
	/*
		sockfd为套接口描述字，sendbuf为发送数据缓冲区，len是发送数据缓冲区大小
		0是flag参数，pr->sasend是指向目的主机数据结构sockaddr_in的指针，接收
		数据的主机地址信息放在这个结构中。pr->salen为pr->sasend所指向的数据结构
		的长度。
	*/
}

void
send_v6()
{
#ifdef	IPV6
	int					len;
	struct icmp6_hdr	*icmp6;

	icmp6 = (struct icmp6_hdr *) sendbuf;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = pid;
	icmp6->icmp6_seq = nsent++;
	gettimeofday((struct timeval *) (icmp6 + 1), NULL);

	len = 8 + datalen;		/* 8-byte ICMPv6 header */

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
		/* 4kernel calculates and stores checksum for us */
#endif	/* IPV6 */
}

void
readloop(void)
{
	int				size;
	char			recvbuf[BUFSIZE];
	socklen_t		len;
	ssize_t			n;
	struct timeval	tval;

	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);	// SOCK_RAW 提供原始网络协议访问
	/* 船舰一个合适协议的原始套接字 */
	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
	setuid(getuid());		/* don't need special permissions any more */

	/* 
	 * 将套接字接收缓冲区设置得比默认值大
	 * 防止用户对IPv4广播地址执行ping
	 * 造成大量应答使接收缓冲区溢出
	 */
	size = 60 * 1024;		/* OK if setsockopt fails */
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	/*
		SOL_SOCKET为操作套接口层的选项，SO_RCVBUF为optname表示接收缓冲区大小，size为optval 
		int
	*/

	/* 
	 * 发送第一个分组
	 * 调度下一个SIGALRM信号在1秒后产生
	 */
	sig_alrm(SIGALRM);		/* send first packet */

	
	/* 
	 * 循环结束
	 * 若处于-q则应该输出结果
	 */
	signal(SIGINT, quiteShowResult);
	/* 
	 * 无限循环
	 * 读入返回的每个分组
	 */
	for ( ; !quitFlag; ) {
		len = pr->salen;
		n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
		/*
			recvbuf为接收数据缓冲区，接收到的数据将发在这个指针所指向的内存空间。sizeof(recvbuf)
			为接收缓冲区的大小，防止溢出。0为flag参数。pr->sarecv指向数据结构sockaddr_in的指针，
			发送数据时的发送方地址信息放在这个结构中。len为sockaddr_in的结构长度。返回值成功则返回
			接收到的字符数，失败则返回-1，错误原因存于errno中
		*/
		if (n < 0) {
			if (errno == EINTR)		//被信号中断
				continue;
			else
				err_sys("recvfrom error");
		}

		/* 
		 * 记录分组收取时刻
		 * 调用合适的协议函数（proc_v4或者proc_v6）处理包含在该分组中的ICMP消息
		 */
		gettimeofday(&tval, NULL);
		(*pr->fproc)(recvbuf, n, &tval);
	}
}

// sig_alrm信号处理函数。他发送一个ICMP回射请求，然后调度下一次sig_alrm在一秒后产生
void
sig_alrm(int signo)
{
        (*pr->fsend)();

        alarm(1);
        return;         /* probably interrupts recvfrom() */
}

void
tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;		//不够减，借1
		out->tv_usec += 1000000;	/* 1s = 10^6 us */
	}
	out->tv_sec -= in->tv_sec;
}




char *
sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];               /* Unix domain is largest */

        switch (sa->sa_family) {
        case AF_INET: {
                struct sockaddr_in      *sin = (struct sockaddr_in *) sa;

				/* 
					将二进制的IP地址转换字符串 AF_INET是网络类型协议族，IPv4。&sin->sin_addr
					为要转化的二进制IP地址，str指向转换之后的结果的指针，cnt为str缓冲区大小
				*/
                if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }

#ifdef  IPV6
        case AF_INET6: {
                struct sockaddr_in6     *sin6 = (struct sockaddr_in6 *) sa;

                if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }
#endif

#ifdef  HAVE_SOCKADDR_DL_STRUCT
        case AF_LINK: {
                struct sockaddr_dl      *sdl = (struct sockaddr_dl *) sa;

                if (sdl->sdl_nlen > 0)
                        snprintf(str, sizeof(str), "%*s",
                                        sdl->sdl_nlen, &sdl->sdl_data[0]);
                else
                        snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
                return(str);
        }
#endif
        default:
                snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
                                sa->sa_family, salen);
                return(str);
        }
    return (NULL);
}

char *
Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
        char    *ptr;

        if ( (ptr = sock_ntop_host(sa, salen)) == NULL)
                err_sys("sock_ntop_host error");        /* inet_ntop() sets errno */
        return(ptr);
}

//将主机名或主机IP地址转换为addrinfo结构函数
struct addrinfo *
host_serv(const char *host, const char *serv, int family, int socktype)		// family and socktype equals 0
{
        int                             n;
        struct addrinfo hints, *res;

        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_CANONNAME;  /* always return canonical name */	//2用于返回主机的规范名称
        hints.ai_family = family;       /* AF_UNSPEC, AF_INET, AF_INET6, etc. */  //也就是AF_UNSPEC 0 协议无关
        hints.ai_socktype = socktype;   /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */	// 0字段表示任何类型的套接字地址都可以

        if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)		//返回非0，表示出错
                return(NULL);		
		/*
			host为主机名或地址串，serv为一个服务名或10进制端口号字符串。hint为一个空指针
			或者指向addrinfo结构的智者嗯，调用者在这个结构中填入关于所期望返回的信息类型的
			线索。res为i指向一个addrinfo结构链表的指针。
		*/
        return(res);    /* return pointer to first on linked list */
}
/* end host_serv */

//输出错误提示并返回调用函数
static void
err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
        int errno_save, n;
        char buf[MAXLINE];

        errno_save = errno;             /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
        vsnprintf(buf, sizeof(buf), fmt, ap);   /* this is safe */
#else
        vsprintf(buf, fmt, ap);                                 /* this is not safe */
#endif
        n = strlen(buf);
        if (errnoflag)
                snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
        strcat(buf, "\n");

        if (daemon_proc) {
                syslog(level, buf);
        } else {
                fflush(stdout);         /* in case stdout and stderr are the same */
                fputs(buf, stderr);
                fflush(stderr);
        }
        return;
}


/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void
err_quit(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(0, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void
err_sys(const char *fmt, ...)
{
        va_list         ap;		//变长参数

        va_start(ap, fmt);
		//printf("YES\n");
        err_doit(1, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}

void show_help() {
	printf("%s", usage);
	exit(0);
}