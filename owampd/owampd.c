/*! \file owampd.c */

#include <owamp.h>
#include <access.h>

#define LISTENQ 5
#define SERV_PORT_STR "5555"

#define DEFAULT_CONFIG_DIR              "/home/karp/projects/owamp/contrib"
#define DEFAULT_CONFIG_FILE 	 	"policy.conf"
#define DEFAULT_IP_TO_CLASS_FILE 	"ip2class.conf"
#define DEFAULT_CLASS_TO_LIMITS_FILE 	"class2limits.conf" 
#define DEFAULT_PASSWD_FILE 		"owamp_secrets.conf"

const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;
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

struct data {
	hash_ptr ip2class;
	hash_ptr class2limits;
	hash_ptr passwd;
};

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
	hash_ptr ip2class_hash = ((struct data *)&app_data)->ip2class;
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

void
random_bytes(char *ptr, int count)
{
	int i;
	long scale = (RAND_MAX / 1<<8);
	for (i = 0; i < count; i++)
		*(u_int8_t *)(ptr+i) = random()/scale; 
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

/*
** Accept or reject the Control Connection request.
** Code = CTRL_ACCEPT/CTRL_REJECT with the obvious meaning.
*/
void
OWPServerOK(OWPControl ctrl, int sock, u_int8_t code, char* buf)
{
	bzero(buf, 32);
	*(u_int8_t *)(buf+15) = code;
	if (code == 0){ /* accept */
		random_bytes(buf + 16, 16); /* Generate Server-IV */
		/* OWPSetWriteIV(ctrl, buf + 16); */
	}
	send_data(sock, buf, 32, 0);
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

/*
** Basic function to print out ip2class.
*/

void
print_ip2class_binding(const struct binding *p, FILE* fp)
{
	fprintf(fp, "DEBUG: the value of key %s/%u is = %s\n",
	       owamp_denumberize(get_ip_addr(p->key)), 
	       get_offset(p->key), p->value->dptr);
}

void
print_limits(OWAMPLimits * limits, FILE* fp)
{
	fprintf(fp, "bw = %lu, space = %lu, num_sessions = %u\n",
	       OWAMPGetBandwidth(limits),
	       OWAMPGetSpace(limits),
	       OWAMPGetNumSessions(limits)
	       );
}

void
print_class2limits_binding(const struct binding *p, FILE* fp)
{
	fprintf(fp, "the limits for class %s are: ", p->key->dptr);
	print_limits((OWAMPLimits *)(p->value->dptr), fp);
}


int
main(int argc, char *argv[])
{
	char ctrl_msg[MAX_MSG];
	char key_bytes[5];
	datum * dat;
	char class[128];
	char err_msg[128];
	int listenfd, connfd;
	char buff[MAX_LINE];
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
	
	struct data app_data = {
		NULL,
		NULL,
		NULL
	};
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
	snprintf(path,sizeof(path), "%s/%s", DEFAULT_CONFIG_DIR,IPtoClassFile);
	if ((app_data.ip2class = hash_init(ctx, 0, NULL, NULL, 
				       print_ip2class_binding)) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "Could not initialize hash for %s", IPtoClassFile);
		exit(1);
	}
	owamp_read_ip2class(ctx, path, app_data.ip2class); 
	hash_print(app_data.ip2class, stderr);

	/* Open the class2limits hash for writing. */
	if ((app_data.class2limits = hash_init(ctx, 0, NULL, NULL, 
					   print_class2limits_binding))==NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			"Could not initialize hash for %s", ClassToLimitsFile);
		exit(1);
	}
	snprintf(path,sizeof(path), "%s/%s", 
		 DEFAULT_CONFIG_DIR,ClassToLimitsFile);
	owamp_read_class2limits(path, app_data.class2limits);

	hash_print(app_data.class2limits, stderr); 

	/* Open the passwd hash for writing. */
	if ((app_data.passwd = hash_init(ctx, 0, NULL, NULL, NULL)) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			"Could not initialize hash for %s", PasswdFile);
		exit(1);
	}
	snprintf(path,sizeof(path), "%s/%s", 
		 DEFAULT_CONFIG_DIR,PasswdFile);
	read_passwd_file(path, app_data.passwd);
	hash_print(app_data.passwd, stderr);

	listenfd = tcp_listen(ctx, host, port, &addrlen);
	if (signal(SIGCHLD, sig_chld) == SIG_ERR){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "signal() failed. errno = %d", errno);	
		exit(1);
	}

	/* XXX - remove eventually. */
	fprintf(stderr, "DEBUG: exiting...\n");
	exit(0);

	while (1) {
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

		if (OWPAddrCheck(ctx, &app_data, NULL, 
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
		
		if (pid == 0){ /* child */
			cntrl = OWPControlAccept(ctx, connfd, &app_data, &out);
						 
			if (cntrl == NULL){
				close(connfd);
				exit(0);
			}
			
			/* 
			   Now start working with the valid OWPControl handle. 
			   ...
			   ...
			   ...
			*/
		} else { /* parent */
			close(connfd);
			continue;
		}
	}
	
	hash_close(&app_data.ip2class);
	hash_close(&app_data.class2limits);
	hash_close(&app_data.passwd);

	exit(0);
}

