/*! \file owampd.c */

#include <owamp/owamp.h>
#include <owpcontrib/access.h>
#include <I2util/util.h>

#define LISTENQ 5
#define SERV_PORT_STR "5555"

#define DEFAULT_IP_TO_CLASS_FILE 	"ip2class.conf"
#define DEFAULT_CLASS_TO_LIMITS_FILE 	"class2limits.conf" 
#define DEFAULT_PASSWD_FILE 		"owamp_secrets.conf"

#define OWP_CTRL_REQUEST_SESSION 1
#define OWP_CTRL_START_SESSION 2
#define OWP_CTRL_STOP_SESSION 3
#define OWP_CTRL_RETRIEVE_SESSION 4

int ip2class_flag = 0;
int class2limits_flag = 0;
int passwd_flag = 0;
u_int32_t default_offered_mode = OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED
                           | OWP_MODE_ENCRYPTED;
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
	OWPErrSeverity         out;
	OWPContext             ctx;
	OWPControl             cntrl; /* XXX - remember to initialize. */
	I2ErrHandle            eh;
	I2LogImmediateAttr     ia;
	OWPInitializeConfigRec cfg  = {
		0, 
		0,
		NULL,
		owampd_err_func, 
		NULL,
		owamp_first_check,
		check_control, 
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
	* Start an error loggin session for reporing errors to the
	* standard error
	*/
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

	while (1) {
		char buf[MAX_MSG];
		OWPBoolean again = True;
		socklen_t len = addrlen;

		if ( (connfd = accept(listenfd, &cliaddr, &addrlen)) < 0){
			if (errno == EINTR)
				continue;
			else {
				perror("accept()");
				exit(1);
			}
		}

		if (OWPServerCheckAddrPolicy(ctx, &cliaddr, &out)
		    == False){
			do_ban(connfd);     /* access denied */
			continue;
		}

		if (free_connections == 0){
			do_ban(connfd);
			continue;
		}

		free_connections--;

		if ( (pid = fork()) < 0){
			perror("fork");
			exit(1);
		}
		
		if (pid > 0) { /* parent */
			close(connfd);
			continue;
		}
		
		/* child */
		cntrl = OWPControlAccept(ctx, connfd, default_offered_mode,
					 policy, &out);
		
		if (cntrl == NULL){
			close(connfd);
			exit(0);
		}
		
		while (again == True) {
			pid_t pidlet;
			u_int8_t msg_type;
			if ( OWPGetRequestType(cntrl, &msg_type) < 0){
				/* clean_up(); */
				exit(0);
			}
			
			switch (msg_type) {
			case OWP_CTRL_REQUEST_SESSION:
				/* XXX fill in!
				if (ParseRest(cntrl) < 0){
					rude_close();
					clean_up();
					again = False;
					continue;
				}
				*/
				if (_OWPCallCheckTestPolicy(cntrl, 0, NULL,
				     NULL, NULL, NULL, &out) == False){
					/*
					polite_close();
					clean_up();
					*/
					again = False;
					continue;
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
					continue;
					break;
				}
			
			case OWP_CTRL_START_SESSION:
				OWPServerProcessTestStart(cntrl, buf);
				break;
			case OWP_CTRL_STOP_SESSION:
				OWPServerProcessTestStop(cntrl, buf);
				break;
			case OWP_CTRL_RETRIEVE_SESSION:
				OWPServerProcessSessionRetrieve(cntrl, buf);
				break;
			default:
				return False; /* bad message type */
				break;
			}
			
			/*
			  again = OWPServerControlMain(cntrl, &out);
			*/
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

