/* include unph */
/* Our own header.  Tabs are set for 4 spaces, not 8 */

#ifndef	__unp_h
#define	__unp_h


/* If anything changes in the following list of #includes, must change
   acsite.m4 also, for configure's tests. */

#include	<sys/types.h>	/* basic system data types */
#include	<sys/socket.h>	/* basic socket definitions */
#include	<sys/time.h>	/* timeval{} for select() */
#include	<time.h>		/* timespec{} for pselect() */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<arpa/inet.h>	/* inet(3) functions */
#include	<errno.h>
#include	<fcntl.h>		/* for nonblocking */
#include	<netdb.h>
#include	<signal.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/stat.h>	/* for S_xxx file mode constants */
#include	<sys/uio.h>		/* for iovec{} and readv/writev */
#include	<unistd.h>
#include	<sys/wait.h>
#include	<sys/un.h>		/* for Unix domain sockets */

#ifdef	HAVE_SYS_SELECT_H
# include	<sys/select.h>	/* for convenience */
#endif

#ifdef	HAVE_STRINGS_H
# include	<strings.h>		/* for convenience */
#endif

/* Three headers are normally needed for socket/file ioctl's:
 * <sys/ioctl.h>, <sys/filio.h>, and <sys/sockio.h>.
 */
#ifdef	HAVE_SYS_IOCTL_H
# include	<sys/ioctl.h>
#endif
#ifdef	HAVE_SYS_FILIO_H
# include	<sys/filio.h>
#endif
#ifdef	HAVE_SYS_SOCKIO_H
# include	<sys/sockio.h>
#endif

#ifdef	HAVE_PTHREAD_H
# include	<pthread.h>
#endif

/* Following could be derived from SOMAXCONN in <sys/socket.h>, but many
   kernels still #define it as 5, while actually supporting many more */
#define	LISTENQ		1024	/* 2nd argument to listen() */

/* Miscellaneous constants */
#define	MAXLINE		4096	/* max text line length */
#define	MAXSOCKADDR  128	/* max socket address structure size */
#define	BUFFSIZE	8192	/* buffer size for reads and writes */

/* Define some port number that can be used for client-servers */
#define	SERV_PORT		 9877			/* TCP and UDP client-servers */
#define	SERV_PORT_STR	"9877"			/* TCP and UDP client-servers */
/* Following shortens all the type casts of pointer arguments */
#define	SA	struct sockaddr

#define	FILE_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
					/* default file access permissions for new files */
#define	DIR_MODE	(FILE_MODE | S_IXUSR | S_IXGRP | S_IXOTH)
					/* default permissions for new directories */

typedef	void	Sigfunc(int);	/* for signal handlers */

#define	min(a,b)	((a) < (b) ? (a) : (b))
#define	max(a,b)	((a) > (b) ? (a) : (b))

Sigfunc *Signal(int, Sigfunc *);
Sigfunc *Signal_intr(int, Sigfunc *);
int		 Sock_bind_wild(int, int);
char	*Sock_ntop(const SA *, socklen_t);
char	*Sock_ntop_host(const SA *, socklen_t);
int		 Sockfd_to_family(int);
int		 Tcp_connect(const char *, const char *);
int		 Tcp_listen(const char *, const char *, socklen_t *);
int		 Udp_client(const char *, const char *, void **, socklen_t *);
int		 Udp_connect(const char *, const char *);
int		 Udp_server(const char *, const char *, socklen_t *);
ssize_t	 Write_fd(int, void *, size_t, int);
int		 Writable_timeo(int, int);

			/* prototypes for our Unix wrapper functions: see {Sec errors} */
void	*Calloc(size_t, size_t);
void	 Close(int);
void	 Dup2(int, int);
int		 Fcntl(int, int, int);
void	 Gettimeofday(struct timeval *, void *);
int		 Ioctl(int, int, void *);
pid_t	 Fork(void);
void	*Malloc(size_t);
void	 Mktemp(char *);
void	*Mmap(void *, size_t, int, int, int, off_t);
int		 Open(const char *, int, mode_t);
void	 Pipe(int *fds);
ssize_t	 Read(int, void *, size_t);
void	 Sigaddset(sigset_t *, int);
void	 Sigdelset(sigset_t *, int);
void	 Sigemptyset(sigset_t *);
void	 Sigfillset(sigset_t *);
int		 Sigismember(const sigset_t *, int);
void	 Sigpending(sigset_t *);
void	 Sigprocmask(int, const sigset_t *, sigset_t *);
char	*Strdup(const char *);
long	 Sysconf(int);
void	 Sysctl(int *, u_int, void *, size_t *, void *, size_t);
void	 Unlink(const char *);
pid_t	 Wait(int *);
pid_t	 Waitpid(pid_t, int *, int);
void	 Write(int, void *, size_t);

			/* prototypes for our stdio wrapper functions: see {Sec errors} */
void	 Fclose(FILE *);
FILE	*Fdopen(int, const char *);
char	*Fgets(char *, int, FILE *);
FILE	*Fopen(const char *, const char *);
void	 Fputs(const char *, FILE *);

			/* prototypes for our socket wrapper functions: see {Sec errors} */
int		 Accept(int, SA *, socklen_t *);
void	 Bind(int, const SA *, socklen_t);
void	 Connect(int, const SA *, socklen_t);
void	 Getpeername(int, SA *, socklen_t *);
void	 Getsockname(int, SA *, socklen_t *);
void	 Getsockopt(int, int, int, void *, socklen_t *);
int		 Isfdtype(int, int);
void	 Listen(int, int);
#ifdef	HAVE_POLL
int		 Poll(struct pollfd *, unsigned long, int);
#endif
ssize_t	 Readline(int, void *, size_t);
ssize_t	 Readn(int, void *, size_t);
ssize_t	 Recv(int, void *, size_t, int);
ssize_t	 Recvfrom(int, void *, size_t, int, SA *, socklen_t *);
ssize_t	 Recvmsg(int, struct msghdr *, int);
int		 Select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
void	 Send(int, const void *, size_t, int);
void	 Sendto(int, const void *, size_t, int, const SA *, socklen_t);
void	 Sendmsg(int, const struct msghdr *, int);
void	 Setsockopt(int, int, int, const void *, socklen_t);
void	 Shutdown(int, int);
int		 Sockatmark(int);
int		 Socket(int, int, int);
void	 Socketpair(int, int, int, int *);
void	 Writen(int, void *, size_t);

void	 err_dump(const char *, ...);
void	 err_msg(const char *, ...);
void	 err_quit(const char *, ...);
void	 err_ret(const char *, ...);
void	 err_sys(const char *, ...);

#endif	/* __unp_h */
