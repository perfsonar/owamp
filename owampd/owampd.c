/*! \file owampd.c */

#include <owamp/owamp.h>
#include <access.h>

#define LISTENQ 5
#define SERV_PORT_STR "5555"

#define DEFAULT_IP_TO_CLASS_FILE 	"ip2class.conf"
#define DEFAULT_CLASS_TO_LIMITS_FILE 	"class2limits.conf" 
#define DEFAULT_PASSWD_FILE 		"owamp_secrets.conf"

int ip2class_flag = 0;
int class2limits_flag = 0;
int passwd_flag = 0;

const char *DefaultIPtoClassFile = DEFAULT_IP_TO_CLASS_FILE;
char *IPtoClassFile = NULL;
const char *DefaultClassToLimitsFile = DEFAULT_CLASS_TO_LIMITS_FILE;
char *ClassToLimitsFile = NULL;
const char *DefaultPasswdFile = DEFAULT_PASSWD_FILE;
char *PasswdFile = NULL;

u_int32_t DefaultMode = OWP_MODE_OPEN;

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
** Return values: False if the client is a member of BANNED_CLASS,
**                True otherwise.
*/

OWPBoolean
owamp_first_check(void *app_data,
		  struct sockaddr *local,
		  struct sockaddr *remote,
		  OWPErrSeverity *err_ret
		  )
{
	u_int32_t ip_addr; 
	I2table ip2class_hash = ((policy_data *)&app_data)->ip2class;
	switch (remote->sa_family){
	case AF_INET:
	    ip_addr = ntohl((((struct sockaddr_in *)remote)->sin_addr).s_addr);
	    fprintf(stderr, "DEBUG: IP = %s\n", owamp_denumberize(ip_addr));
	    fprintf(stderr, "DEBUG: class = %s\n", 
		    ipaddr2class(ip_addr, ip2class_hash));

	        if (strcmp(ipaddr2class(ip_addr, ip2class_hash), 
			   BANNED_CLASS) == 0){ 
		    *err_ret = OWPErrFATAL; /* prohibit access */
		    return False;
	    } else {
		    *err_ret = OWPErrOK;    /* allow access */
		    return True;
	    };
	    break;
	    
	default:
		return False;
		break;
	}
}

static int
tcp_listen(OWPContext ctx, 
	   const char *host, 
	   const char *serv, 
	   socklen_t *addrlenp)
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

/* XXX - currently default. Make configurable later. */
u_int32_t
get_mode()
{
	return OWP_MODE_OPEN;
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
	policy_data* policy;
	char ctrl_msg[MAX_MSG];
	I2datum * dat;
	char class[128];
	char err_msg[128];
	int listenfd, connfd;
	char buff[MAX_LINE];
	char ip2class[MAXPATHLEN],class2limits[MAXPATHLEN],passwd[MAXPATHLEN];
	struct sockaddr cliaddr;
	socklen_t addrlen;
	char path[MAXPATHLEN]; /* various config files */
	extern char *optarg;
	extern int optind;
	int c;
	char* port = NULL;
	char *host = NULL; 
	pid_t pid; 
	OWPErrSeverity out;
	OWPContext ctx;
	OWPControl cntrl; /* XXX - remember to initialize. */
	OWPInitializeConfigRec cfg  = {
		0, 
		0,
		NULL,
		owampd_err_func, 
		NULL,
		owamp_first_check,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};
	
	fprintf(stderr, "DEBUG: OWP_CONFDIR = %s\n",OWP_CONFDIR);
	exit(0);
	
	/* Parse command line options. */
	while ((c = getopt(argc, argv, "f:a:p:n:h")) != -1) {
		switch (c) {
		case 'f':
			strncpy(ip2class, optarg, sizeof(ip2class));
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
	policy = PolicyInit(ctx, ip2class, class2limits, passwd, &out);
	/* 
	   XXX - can't think of a better place to put it, but it doesn't
	   belong here. 
	*/
	openlog("owampd", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

	/* XXX - remove eventually. */
	fprintf(stderr, "DEBUG: exiting...\n");
	exit(0);

	while (1) {
		OWPBoolean ok;
		socklen_t len = addrlen;

		if ( (connfd = accept(listenfd, &cliaddr, &addrlen)) < 0){
			if (errno == EINTR)
				continue;
			else {
				OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
					 "accept error");
				exit(1);
			}
		}

		if (OWPAddrCheck(ctx, policy, NULL, 
				 &cliaddr, ctrl_msg, &out)==False){
			do_ban(connfd);     /* access denied */
			continue;
		}
		
		if (free_connections == 0){
			do_ban(connfd);
			continue;
		}

		free_connections--;

		if ( (pid = fork()) < 0){
			OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, "fork");
			exit(1);
		}
		
		if (pid > 0) { /* parent */
			close(connfd);
			continue;
		}
		
		/* child */
		cntrl = OWPControlAccept(ctx, connfd, policy, &out);
		
		if (cntrl == NULL){
			close(connfd);
			exit(0);
		}
		
		while (ok == True) {
			ok = OWPServerControlMain(cntrl, &out);
		}
		
		/* 
		   Now start working with the valid OWPControl handle. 
		   ...
		   ...
		   ...
		*/
		
	}
	
	I2hash_close(&policy->ip2class);
	I2hash_close(&policy->class2limits);
	I2hash_close(&policy->passwd);

	exit(0);
}

