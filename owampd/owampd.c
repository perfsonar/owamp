/*! \file owampd.c */

#include "../libowamp/owampP.h"
#include "access.h"
#include "rijndael-api-fst.h"

#define LISTENQ 5
#define SERV_PORT_STR "5555"

#define MAX_MSG 60 /* XXX - currently 56 but KID to be extended by 4 bytes */

const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;
const char *DefaultIPtoClassFile = DEFAULT_IP_TO_CLASS_FILE;
char *IPtoClassFile = NULL;
const char *DefaultClassToLimitsFile = DEFAULT_CLASS_TO_LIMITS_FILE;
char *ClassToLimitsFile = NULL;
const char *DefaultPasswdFile = DEFAULT_PASSWD_FILE;
char *PasswdFile = NULL;
u_int32_t DefaultMode = OWP_MODE_OPEN;

char* ipaddr2class(u_int32_t ip_addr);
/* datum hash_fetch(hash_ptr hash, datum key); */
datum* str2datum(const char *bytes);

OWPContext ctx;
hash_ptr ip2class_hash, class2limits_hash, passwd_hash;

/* Global variable - the total number of allowed Control connections. */
#define DEFAULT_NUM_CONN 100
int free_connections = DEFAULT_NUM_CONN;


static void
usage(char *name)
{
	printf("Usage: %s [-p port] [-a ip_address] [-n num] [-h]\n", name);
	return;
}

/*!
** This function runs an initial policy check on the remote host.
** Based only on the remote IP number, it determines if the client
** is a member of BANNED_CLASS. Additional diagnostics can be
** returned via err_ret.
** 
** Return values: 0 if the client is a member of BANNED_CLASS,
**                1 otherwise.
*/

OWPBoolean
owamp_first_check(void *app_data,
		       struct sockaddr *local,
		       struct sockaddr *remote,
		       OWPErrSeverity *err_ret
		       )
{
	u_int32_t ip_addr; 
	switch (remote->sa_family){
	case AF_INET:
	    ip_addr = ntohl((((struct sockaddr_in *)remote)->sin_addr).s_addr);
	    fprintf(stderr, "DEBUG: IP = %s\n", owamp_denumberize(ip_addr));
	    fprintf(stderr, "DEBUG: class = %s\n", ipaddr2class(ip_addr));

	        if (strcmp(ipaddr2class(ip_addr), BANNED_CLASS) == 0){ 
		    *err_ret = OWPErrFATAL; /* prohibit access */
		    return 0;
	    } else {
		    *err_ret = OWPErrOK;    /* allow access */
		    return 1;
	    };
	    break;
	    
	default:
		return 0;
		break;
	}
}

static int
tcp_listen(const char *host, const char *serv, socklen_t *addrlenp)
{
	int listenfd, n;
	const int on = 1;
	struct addrinfo	hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
			 "tcp_listen error for %s, %s: %s",
			 host, serv, gai_strerror(n));
		exit(1);
	}

	ressave = res;

	do {
		listenfd = socket(res->ai_family, res->ai_socktype, 
				  res->ai_protocol);
		if (listenfd < 0){        /* error, try next one */
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "socket() error");
			continue;		
		}

		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
				&on, sizeof(on)) < 0 ){
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "setsockopt() error");
			continue;
		}
		if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0)
			break;			/* success */

		/* bind error, close and try next one */
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
			"bind() error");		
		if (close(listenfd) < 0)
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				"close() error");			
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL){	/* errno from final socket() or bind() */
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: socket/bind error for %s, %s", host, serv);
		exit(1);
	}

	if (listen(listenfd, LISTENQ) < 0){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "listen() error");
		exit(1);
	}

	if (addrlenp)
		*addrlenp = res->ai_addrlen;/* return size of proto address */

	freeaddrinfo(ressave);

	return(listenfd);
}
/* end tcp_listen */

ssize_t				       /* Read "n" bytes from a descriptor. */
readn(int fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;	   /* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}
/* end readn */

ssize_t					/* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (errno == EINTR)
				nwritten = 0;	  /* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}
/* end writen */

/* XXX - currently default. Make configurable later. */
u_int32_t
get_mode()
{
	return OWP_MODE_OPEN;
}

void
random_byte(char *ptr)
{
	*(u_int8_t *)ptr = random() / (RAND_MAX / 1<<8);
}

int
send_data(int sock, char *buf, size_t len, OWPBoolean encrypt)
{
	if (!encrypt){
		if (writen(sock, buf, len) < 0)
			return -1;
	}
	return 0;
}

void
doit(int connfd)
{
	char buf[MAX_MSG];
	char *cur;
	u_int32_t mode;
	int i, r, encrypt;
	u_int32_t mode_requested;
	u_int8_t challenge[16], token[32], session_key[16], client_iv[32];
	u_int8_t kid[8]; /* XXX - assuming Stas will extend KID to 8 bytes */

	/* Remove what's not needed. */
	BYTE cv[128/8];
	keyInstance keyInst;
	cipherInstance cipherInst;

	datum key;

	/* first generate server greeting */
	bzero(buf, sizeof(buf));
	mode = htonl(get_mode());
	*(int32_t *)(buf + 12) = mode; /* first 12 bytes unused */

	/* generate random data for the last 16 bytes.
	** We'll do it 16 times, one byte at a time, saving the result.
	*/
	for (i = 0; i < 16; i++)
		random_byte(challenge + i);
	bcopy(challenge, buf + 16, 16); /* the last 16 bytes */

	/* Send server greeting. */
	encrypt = 0;
	if (send_data(connfd, buf, 32, encrypt) < 0){
		fprintf(stderr, "Warning: send_data failed.\n");
		close(connfd);
		exit(1);
	}

	/* Read client greeting. */
	if (readn(connfd, buf, 60) != 60){
		fprintf(stderr, "Warning: client greeting too short.\n");
		exit(1);
	}

	mode_requested = htonl(*(u_int32_t *)buf);
	
	if (mode_requested & OWP_MODE_AUTHENTICATED){

		/* Save 8 bytes of kid */
		bcopy(buf + 4, kid, 8);

		/* Decrypt the token and compare the 16 bytes of challenge */
		bzero(client_iv, 16);

		key = hash_fetch(passwd_hash, *(str2datum((const char *)kid)));

		r = makeKey(&keyInst, DIR_DECRYPT, 128, key.dptr);
		if (TRUE != r) {
			fprintf(stderr,"makeKey error %d\n",r);
			exit(-1);
		}
		r = cipherInit(&cipherInst, MODE_CBC, NULL);
		if (TRUE != r) {
			fprintf(stderr,"cipherInit error %d\n",r);
			exit(-1);
		}

		/* Decrypt two 16-byte blocks */
		blockDecrypt(&cipherInst, &keyInst, buf + 12, 2*(16*8), token);

		/* Decrypted challenge is in the first 16 bytes */
		if (bcmp(challenge, token, 16)){
			fprintf(stderr, "Authentication failed.\n");
			close(connfd);
			exit(1);
		}

		/* Save 16 bytes of session key and 16 bytes of client IV*/
		bcopy(token + 16, session_key, 16);
		bcopy(buf + 44, client_iv, 16);
	}
	
}

/* 
** This function is called when the server doesn't even want
** to speak Control protocol with a particular host.
*/

void
do_ban(int fd)
{
	close(fd);
}

/*
** Handler function for SIG_CHLD. It updates the number
** of available Control connections.
*/

void
sig_chld(int signo)
{
	pid_t pid;
	int stat;

	while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0)
		free_connections++;
	return;
}

/*
** This is a basic function to report errors on the server.
*/

int
owampd_err_func(
		void           *app_data,
		OWPErrSeverity severity,
		OWPErrType     etype,
		const char     *errmsg
)
{
	syslog(LOG_ERR, errmsg);
	return 0;
}

int
main(int argc, char *argv[])
{
	char key_bytes[5];
	datum * dat;
	char class[128];
	char err_msg[128];
	int listenfd, connfd;
	char buff[MAX_LINE];
	struct sockaddr *cliaddr;
	socklen_t addrlen, len;
	extern char *optarg;
	extern int optind;
	int c;
	char* port = NULL;
	char *host = NULL; 
	pid_t pid; 
	OWPErrSeverity out;
	OWPContext ctx;
	OWPInitializeConfigRec cfg  = {
		0, 
		0,
		NULL,
		owampd_err_func, 
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

#if SCRATCH
	if ( (scratch = fopen("scratch.txt", "w")) == NULL){
		perror("fopen scratch.txt for writing.\n");
		exit(1);
	}
#endif

	/* Parse command line options. */
	while ((c = getopt(argc, argv, "f:a:p:n:h")) != -1) {
		switch (c) {
		case 'f':
			ConfigFile = strdup(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'a':
			host = strdup(optarg);
			break;
		case 'p':
			port = strdup(optarg);
			break;
		case 'n':
			free_connections = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
	if (argc != optind){
		usage(argv[0]);
		exit(1);
	}

	if (!port)
		port = strdup(SERV_PORT_STR);
	if (!IPtoClassFile)
		IPtoClassFile = strdup(DefaultIPtoClassFile);
	if (!ClassToLimitsFile)
		ClassToLimitsFile = strdup(DefaultClassToLimitsFile);
	if (!PasswdFile)
		PasswdFile = strdup(DefaultPasswdFile);

	ctx = OWPContextInitialize(&cfg);
	
	

	/* 
	   XXX - can't think of a better place to put it, but it doesn't
	   belong here. 
	*/
	openlog("owampd", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	
	/* Open the ip2class hash for writing. */
	if ((ip2class_hash = hash_init(IPtoClassFile)) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "Could not initialize hash for %s", IPtoClassFile);
		exit(1);
	}
	owamp_read_ip2class(IPtoClassFile, ip2class_hash); 
	owamp_print_ip2class(ip2class_hash); 

	/* Open the class2limits hash for writing. */
	if ((class2limits_hash = hash_init(ClassToLimitsFile)) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			"Could not initialize hash for %s", ClassToLimitsFile);
		exit(1);
	}
	owamp_read_class2limits(ClassToLimitsFile, class2limits_hash);
	owamp_print_class2limits(class2limits_hash);

	/* Open the passwd hash for writing. */
	if ((passwd_hash = hash_init(PasswdFile)) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			"Could not initialize hash for %s", PasswdFile);
		exit(1);
	}
	read_passwd_file(PasswdFile, passwd_hash);

	listenfd = tcp_listen(host, port, &addrlen);
	if (signal(SIGCHLD, sig_chld) == SIG_ERR){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "signal() failed. errno = %d", errno);	
		exit(1);
	}

#if 0
	test_policy_check();
#endif

	cliaddr = (void*)malloc(addrlen);
	if (cliaddr == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, "malloc");
		exit(1);
	}

	for ( ; ; ) {
		len = addrlen;
		
		if ( (connfd = accept(listenfd, cliaddr, &len)) < 0){
			if (errno == EINTR)
				continue;
			else
				OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
					 "accept error");
		}
		owamp_first_check(NULL, NULL, cliaddr, &out);
		switch (out) {
		case OWPErrFATAL:
			fprintf(stderr, "DEBUG: access prohibited\n");
			do_ban(connfd);
			continue;
			break;
		case OWPErrOK:
			fprintf(stderr, "DEBUG: access allowed\n");
			break;
		default:
			fprintf(stderr, "DEBUG: policy is confused\n");
			do_ban(connfd);
			continue;
			break;
		};

		if (free_connections == 0){
			do_ban(connfd);
			continue;
		}
		free_connections--;

		if ( (pid = fork()) < 0){
			OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, "fork");
			exit(1);
		}

		if (pid == 0) { /* child */
			doit(connfd);
			exit(0);
		}

		/* Parent */
		if (close(connfd) < 0)
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, "fork");
	}
	
	hash_close(ip2class_hash);
	hash_close(class2limits_hash);
	hash_close(passwd_hash);

#if SCRATCH
	fclose(scratch);
#endif

	exit(0);
}

