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

	/*
	 * 处理命令行参数
	 * -v	显示接收到的ICMP消息
	 * 		
	 */
	opterr = 0;		/* don't want getopt() writing to stderr */
	while ( (c = getopt(argc, argv, "vq")) != -1) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'q':
			quite++;
			break;
		case '?':
			err_quit("unrecognized option: %c", c);
		}
	}

	if (optind != argc - 1)
		err_quit("usage: ping [ -v ] <hostname>");
	host = argv[optind];

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
	if ( (icmplen = len - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	/* 
	 * 检查标识符字段
	 * 判断该应答是否是本进程发出的请求
	 */
	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if (icmp->icmp_id != pid)
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
        int                             nleft = len;
        int                             sum = 0;
        unsigned short  *w = addr;
        unsigned short  answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

                /* 4mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)w ;
                sum += answer;
        }

                /* 4add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void
send_v4(void)
{
	int			len;
	struct icmp	*icmp;

	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	len = 8 + datalen;		/* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
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
		if (n < 0) {
			if (errno == EINTR)
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
		--out->tv_sec;
		out->tv_usec += 1000000;
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

struct addrinfo *
host_serv(const char *host, const char *serv, int family, int socktype)
{
        int                             n;
        struct addrinfo hints, *res;

        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_CANONNAME;  /* always return canonical name */
        hints.ai_family = family;               /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
        hints.ai_socktype = socktype;   /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

        if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
                return(NULL);

        return(res);    /* return pointer to first on linked list */
}
/* end host_serv */

static void
err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
        int             errno_save, n;
        char    buf[MAXLINE];

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
        va_list         ap;

        va_start(ap, fmt);
        err_doit(1, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}
