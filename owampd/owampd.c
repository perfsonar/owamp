/*! \file owampd.c */

#include <owamp/owamp.h>
#include <owpcontrib/access.h>
#include <I2util/util.h>

#define LISTENQ 5
#define SERV_PORT_STR "5555"

#define DEFAULT_IP_TO_CLASS_FILE 	"ip2class.conf"
#define DEFAULT_CLASS_TO_LIMITS_FILE 	"class2limits.conf" 
#define DEFAULT_PASSWD_FILE 		"owamp_secrets.conf"

#define CNTRLNEXT return True
#define CNTRLSTOP return False

int ip2class_flag = 0;
int class2limits_flag = 0;
int passwd_flag = 0;
u_int32_t default_offered_mode = OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED
                           | OWP_MODE_ENCRYPTED;
int sig_received = 0;
int sig_name;

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
** is a member of OWP_BANNED_CLASS. Additional diagnostics can be
** returned via err_ret.
** 
** Return values: False if the client is a member of OWP_BANNED_CLASS,
**                True otherwise.
*/

OWPBoolean
owamp_first_check(void *app_data,            /* to be cast into (policy *) */
		  struct sockaddr *local,
		  struct sockaddr *remote,
		  OWPErrSeverity *err_ret
		  )
{
	u_int32_t ip_addr; 
	I2table ip2class_hash;
	if (!app_data){
		*err_ret = OWPErrFATAL;
		return False;
	}
	ip2class_hash = ((policy_data *)app_data)->ip2class;
	if (!remote){
		*err_ret = OWPErrFATAL;
		return False;
	}
	switch (remote->sa_family){
	case AF_INET:
		if (!remote){
			*err_ret = OWPErrFATAL;
			return False;
		}

	    ip_addr = ntohl((((struct sockaddr_in *)remote)->sin_addr).s_addr);
	    fprintf(stderr, "DEBUG: IP = %s\n", owamp_denumberize(ip_addr));
	    fprintf(stderr, "DEBUG: class = %s\n", 
		    ipaddr2class(ip_addr, ip2class_hash));

	        if (strcmp(ipaddr2class(ip_addr, ip2class_hash), 
			   OWP_BANNED_CLASS) == 0){ 
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

/*
** Temporary plug.
*/

char *
OWPGetClass(void *id)
{
	return NULL;
}

int
OWPGetMode(char *class)
{
	return 0;
}

/*
** This function is called by OWPControlAccept. It identifies the usage
** class of the client and, based on that, whether to grant or reject
** establishment of the Control connection.
*/
OWPBoolean 
check_control(
	      void*          app_data,
	      OWPSessionMode mode_req,
	      const char*         kid,
	      struct sockaddr *local,
	      struct sockaddr *remote,
	      OWPErrSeverity  *err_ret
)
{
	char *class;

	if (mode_req & (OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)){
		if ((class = OWPGetClass((void *)kid)) == NULL)
			class = OWP_AUTH_CLASS;
	} else if ((class = OWPGetClass((void *)remote)) == NULL)
		class = OWP_DEFAULT_OPEN_CLASS;
	
	if ((OWPGetMode(class) & mode_req) == 0)
		return False;
	return True;
}

/*
**  create TCP socket, bind it and start listening.
*/
static int
tcp_listen(OWPContext ctx, 
	   const char *host, /* hostname, or address string 
				(dotted-decimal for IPv4 or hex for IPv6)
				NULL for the server */
	   const char *serv, /* service name, or decimal port number string */
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

/*
** Handler function for SIG_CHLD. It updates the number
** of available Control connections.
*/

void
sig_chld(int signo)
{
	sig_received++;
	sig_name = signo;
	return;

	/*	pid_t pid;
	int stat;

	while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0)
		free_connections++;
	return;
	*/
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


OWPBoolean
ServerMainControl(OWPControl cntrl, OWPErrSeverity* out)
{
	pid_t pidlet;
	char buf[MAX_MSG];
	int msg_type;
	
	if ((msg_type = OWPServerReadRequest(cntrl, buf)) < 0)
		/* CNTRLNEXT; */
		return True;
				
	switch (msg_type) {
	case OWP_CTRL_REQUEST_SESSION:
		/* DEBUG only */
		fprintf(stderr, 
			"DEBUG: client issued a session request");
		CNTRLNEXT;
		
		/* XXX fill in!
		   if (ParseRest(cntrl) < 0){
		   rude_close();
		   clean_up();
		   again = False;
		   CNTRLNEXT;
		   }
		*/
		if (_OWPCallCheckTestPolicy(cntrl, NULL, False, NULL, NULL, 
					    NULL, &out) == False){
					  
			/*
			  polite_close();
			  clean_up();
			*/
			CNTRLSTOP;
		}
		/*
		  prepare_for fork();  
		  data for kid,
		  sig_handlers etc
		*/
		
		pidlet = fork();
		switch (pidlet) {
		case -1:
			/* loud_complain(); */
			exit(1);
			break;
			
		case 0: /* child */
			/*
			  do_descriptors();
			  OWPDoTest();
			  clean_up(0);
			*/
			exit(0);
			break;
			
		default: /* parent */
			/* bond_with(pidlet); */
			/* XXX 
			   - work this out
			*/
			CNTRLNEXT;
			break;
		}
		
	case OWP_CTRL_START_SESSION:
		/* DEBUG only */
		fprintf(stderr, 
			"DEBUG: client issued a session start");
		CNTRLNEXT;
		
		OWPServerProcessTestStart(cntrl, buf);
		break;
	case OWP_CTRL_STOP_SESSION:
		/* DEBUG only */
		fprintf(stderr, 
			"DEBUG: client issued a session stop");
		CNTRLNEXT;
		
		OWPServerProcessTestStop(cntrl, buf);
		break;
	case OWP_CTRL_RETRIEVE_SESSION:
		/* DEBUG only */
		fprintf(stderr, 
			"DEBUG: client issued a session retrieve");
		CNTRLNEXT;
		
		OWPServerProcessSessionRetrieve(cntrl, buf);
		break;
	default:
		return False; /* bad message type */
		break;
	}
}

/* 
** This function prints out all registered descriptors
** in a fd_set. It is used for debugging.
*/
void
print_fdset(int max, fd_set *set)
{
	int i;

	fprintf(stderr, "Printing fd set: max = %d\n", max);
	for (i = 0; i <= FD_SETSIZE; i++){
		if (FD_ISSET(i, set))
			fprintf(stderr, "fd %d is set\n", i);
	}
	fprintf(stderr, "Done printing fd set\n\n");
}

void
owampd_check_pipes(int maxfd, fd_set *mask, fd_set* readfds)
{
	int fd;
	for (fd = 0; fd <= maxfd; fd++){
		if (FD_ISSET(fd, mask)){
			char buf[1];
			int n = read(fd, buf, 1);
			if (n < 0){
				perror("FATAL: read");
				exit(1);
			}
			
			FD_CLR(fd, readfds);
			if (close(fd) < 0){
				perror("close");
				exit(1);
			};
			if (n == 0)  /* happens only if child closes */
				return; /* without writing */
			
			
			
			if (strncmp(buf, "1", 1) == 0){ /* auth */
				free_connections++;
				/* XXX - TODO:
				  pid = fd2pid{fd};
				  is_auth{pid} = 1
				*/
			} 
		}
	}
	
}


int
main(int argc, char *argv[])
{
	policy_data*           policy;
	int                    listenfd, connfd;
	char ip2class[MAXPATHLEN],class2limits[MAXPATHLEN],passwd[MAXPATHLEN];
	struct sockaddr        cliaddr;
	socklen_t              addrlen;
	extern char            *optarg;
	extern int             optind;
	char*                  progname;
	int                    c;
	char*                  port = NULL;
	char*                  host = NULL; 
	pid_t                  pid; 
	fd_set                 readfds, mask;/* listenfd, and pipes to kids */
	int                    maxfd;    /* max fd in readfds               */
	OWPErrSeverity         out;
	OWPContext             ctx;
	OWPControl             cntrl; /* XXX - remember to initialize. */
	I2ErrHandle            eh;
	I2LogImmediateAttr     ia;

	int junk = 0;

	OWPInitializeConfigRec cfg  = {
		0, 
		0,
		NULL,
		owampd_err_func, 
		NULL,
		/* owamp_first_check, */ NULL,
		/* check_control, */ NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	ia.line_info = (I2NAME | I2MSG);
	ia.fp = stderr;

	/*
	* Start an error loggin session for reporting errors to the
	* standard error
	*/
	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;
	eh = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

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

	sprintf(ip2class, "%s/owamp/owpcontrib/ip2class.conf", OWP_CONFDIR);
	sprintf(class2limits, "%s/owamp/owpcontrib/class2limits.conf", 
		OWP_CONFDIR);
	sprintf(passwd, "%s/owamp/owpcontrib/passwd.conf", OWP_CONFDIR);

	policy = PolicyInit(eh, ip2class, class2limits, passwd, &out);
	if (out == OWPErrFATAL){
		fprintf(stderr, "PolicyInit failed. Exiting...");
		exit(1);
	};

	cfg.app_data = (void *)policy;
	ctx = OWPContextInitialize(&cfg);

	listenfd = tcp_listen(ctx, NULL, SERV_PORT_STR, &addrlen);

	signal(SIGCHLD, sig_chld);
	FD_ZERO(&readfds);
	FD_SET(listenfd, &readfds);
	maxfd = listenfd;

	while (1) {
		int nfound;
		fd_set mask = readfds;
		socklen_t len = addrlen;

		/* check if any signals have occurred */
		if (sig_received){
			switch (sig_name) {
				int stat;
			case SIGCHLD:
				while (waitpid(-1, &stat, WNOHANG) > 0)
					free_connections++;
				sig_received = 0;
				break;
			default:
				sig_received = 0;
				break;
			}
		}
	AGAIN:
		nfound = select(maxfd + 1, &mask, NULL, NULL, NULL);

		fprintf(stderr, "DEBUG: select returned with nfound = %d\n", 
			nfound);
	
		if (nfound < 0){
			if (errno == EINTR)
				goto AGAIN;
			else {
				I2ErrLog(eh, "select() failed. Exiting...");
				exit(1);
			}
		}

		if (nfound == 0)  /* should not happen with infinite timeout */
			continue;

		if (FD_ISSET(listenfd, &mask)){ /* new connection */
			int        mode_available = default_offered_mode;
			int        new_pipe[2];
			pid_t      pid;
			OWPBoolean auth_ok;
			OWPBoolean again = True;

			FD_CLR(listenfd, &mask);

			if (pipe(new_pipe) < 0){
				I2ErrLog(eh, "pipe() failed. Exiting...");
				exit(1);
			}

			free_connections--;

		ACCEPT:
			connfd = accept(listenfd, &cliaddr, &len);
			if (connfd < 0){
				if (errno == EINTR)
					goto ACCEPT;
				else {
					perror("accept()");
					exit(1);
				}
			}

			pid = fork();

			if (pid < 0){
				I2ErrLog(eh, "fork() failed. Exiting...");
				exit(1);	
			}
			
			if (pid > 0){ /* Parent */
				FD_SET(new_pipe[0], &readfds);

				if (close(new_pipe[1]) < 0){
					perror("close");
					exit(1);
				}

				if (close(connfd) < 0){
					perror("close");
					exit(1);
				}

				if (new_pipe[0] > maxfd)
					maxfd = new_pipe[0];

				/* fd2pid{new_pipe[0]} = pid */

				owampd_check_pipes(maxfd, &mask, &readfds);
				continue; 
			}
			
			/* Child code */

			/* XXX - Remove. for debugging only */
			if (freopen("child.err", "w", stderr) < 0){
				perror("reopen");
				exit(1);
			}

			if (close(new_pipe[0]) < 0){
				perror("close");
				exit(1);
			}
			if (close(listenfd) < 0){
				perror("close");
				exit(1);
			}

			if (free_connections <= 0)
				mode_available &= OWP_MODE_OPEN;

			if (OWPServerCheckAddrPolicy(ctx, &cliaddr, &out) 
			    == False){
				fprintf(stderr,"DEBUG: policy check failed\n");
				close(connfd);     /* access denied */
				exit(0);
			}

			cntrl = OWPControlAccept(ctx, connfd, mode_available,
						 policy, &out);

			if (cntrl == NULL){
				fprintf(stderr, 
				  "DEBUG: CntrlAcc == NULL. Child Exiting\n");
				exit(0);	
			}

			fprintf(stderr, "DEBUG: child exiting...\n");
			exit(1); /* XXX - debug */
		
			while (again == True) {
				again = ServerMainControl(cntrl, &out);
			}
			
			exit(0); 
			/* End of child code */

		} /* if (FD_ISSET(listenfd))... */
		
		/* Fall through */
		owampd_check_pipes(maxfd, &mask, &readfds);
		continue;
		
	}
	
	I2hash_close(&policy->ip2class);
	I2hash_close(&policy->class2limits);
	I2hash_close(&policy->passwd);

	exit(0);
}
