/*! \file owampd.c */
/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		owampd.c
 *
 *	Author:		Anatoly Karp
 *			Jeff W. Boote
 *			Internet2
 *
 *	Date:		Mon Jun 03 10:57:07 MDT 2002
 *
 *	Description:	
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <owamp/owamp.h>
#include <owpcontrib/access.h>
#include <I2util/util.h>

#include "owampdP.h"

/* Global variable - the total number of allowed Control connections. */
static int free_connections;
static int sigchld_received = 0;
static int sig_name;
static owampd_opts	opts;
static I2ErrHandle	errhand;

static I2OptDescRec	set_options[] = {
	/*
	 * Basic application args.
	 */
	{"verbose",0,NULL,"blah, blah, blah..."},
	{"help",0,NULL,"Print this message and exit"},

	/*
	 * policy config file options.
	 */
	{"confdir",1,OWP_CONFDIR,"Configuration directory"},
	{"id2class",1,"id2class.conf","id2class config filename"},
	{"class2limits",1,"class2limits.conf","class2limits config filename"},
	{"passwd",1,"passwd.conf","passwd config filename"},

	/*
	 * configuration options - should probably add a conf file eventually.
	 */
	{"authmode",1,NULL,
	"Default supported authmodes:[E]ncrypted,[A]uthenticated,[O]pen"},
	{"nodename",1,NULL,"Local nodename to bind to: addr:port"},
	{"maxconnections",1,OWD_MAXCONN,
		"Max unauthenticated control connections"},
	{"tmout",1,OWD_TMOUT,
		"Max time to wait for control connection reads (sec)"},
	{NULL}
};

static	I2Option	get_options[] = {
	{
	"verbose", I2CvtToBoolean, &opts.verbose,
	sizeof(opts.verbose)
	},
	{
	"help", I2CvtToBoolean, &opts.help,
	sizeof(opts.help)
	},
	{
	"confdir", I2CvtToString, &opts.confdir,
	sizeof(opts.confdir)
	},
	{
	"id2class", I2CvtToString, &opts.id2class,
	sizeof(opts.id2class)
	},
	{
	"class2limits", I2CvtToString, &opts.class2limits,
	sizeof(opts.class2limits)
	},
	{
	"passwd", I2CvtToString, &opts.passwd,
	sizeof(opts.passwd)
	},
	{
	"authmode", I2CvtToString, &opts.authmode,
	sizeof(opts.authmode)
	},
	{
	"nodename", I2CvtToString, &opts.nodename,
	sizeof(opts.nodename)
	},
	{
	"maxconnections", I2CvtToInt, &opts.maxconnections,
	sizeof(opts.maxconnections)
	},
	{
	"tmout", I2CvtToInt, &opts.tmout,
	sizeof(opts.tmout)
	},
	{NULL}
};

static void
usage(int od, const char *progname, const char *msg)
{
	if(msg) fprintf(stderr, "%s: %s\n", progname, msg);

	fprintf(stderr, "Usage: %s [options]\n", progname);
	fprintf(stderr, "\nWhere \"options\" are:\n\n");
	I2PrintOptionHelp(od,stderr);

	return;
}

/*
** Handler function for SIG_CHLD. It updates the number
** of available Control connections.
*/

void
sig_chld(int signo)
{
	sigchld_received++;
	sig_name = signo;
	return;
}

/*
** This is a basic function to report errors on the server.
*/

static int
owampd_err_func(
		void           *app_data,
		OWPErrSeverity severity,
		OWPErrType     etype,
		const char     *errmsg
)
{
	if(!opts.verbose && (severity > OWPErrWARNING))
		return 0;

	I2ErrLogP(errhand,etype,errmsg);

	return 0;
}

OWPBoolean
ServerMainControl(OWPControl cntrl, OWPErrSeverity* out)
{
	char buf[MAX_MSG];
	int msg_type;

	/* Data to be passed to the kid */
	OWPAddr     sender, receiver;
	OWPBoolean  conf_sender, conf_receiver;
	OWPTestSpec *test_spec;
	OWPSID      sid;
	
	if ((msg_type = OWPGetType(cntrl)) == 0)
		return True;
				
	switch (msg_type) {
	case OWP_CTRL_REQUEST_SESSION:
		fprintf(stderr, 
			"DEBUG: client issued a session request\n");
		return True;

		/*
		if (OWPParseTestRequest(cntrl, sender, receiver, 
					&conf_sender, &conf_receiver, 
					test_spec, sid) < 0){
			return True;
		}
		*/
		break;
		
	case OWP_CTRL_START_SESSION:
		/* DEBUG only */
		fprintf(stderr, 
			"DEBUG: client issued a session start");
		return True;
		
		OWPServerProcessTestStart(cntrl, buf);
		break;
	case OWP_CTRL_STOP_SESSION:
		/* DEBUG only */
		fprintf(stderr, 
			"DEBUG: client issued a session stop");
		return True;
		
		OWPServerProcessTestStop(cntrl, buf);
		break;
	case OWP_CTRL_RETRIEVE_SESSION:
		/* DEBUG only */
		fprintf(stderr, 
			"DEBUG: client issued a session retrieve");
		return True;
		
		OWPServerProcessSessionRetrieve(cntrl, buf);
		break;
	default:
		return False; /* bad message type */
		break;
	}
}

/*
 * This function returns the current auth value of the given pid. If *val
 * is set, this function returns the previous auth value before setting it.
 * (False is returned, if the pid was not previously in the list.)
 */
static OWPBoolean
is_auth(
	pid_t		pid,	/* process to query or set	*/
	OWPBoolean	*val	/* if !NULL, used to set value	*/
	)
{
	/*
	 * For now - nothing is authenticated, so always return false.
	 *
	 * TODO: setup a hash to hold these values.
	 */
	return False;
}


static void
ReapChildren()
{
	int	status;
	pid_t	child;

	if(!sigchld_received)
		return;

	while ( (child = waitpid(-1, &status, WNOHANG)) > 0){
		if(!is_auth(child,NULL)){
			/* TODO: remove pid from is_auth list */
			free_connections++;
		}
	}

	sigchld_received = 0;
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

/*
 * This function needs to create a new child process with a pipe to
 * communicate with it. It needs to update the free_connections count,
 * add the new pipefd into the readfds, and update maxfd if the new
 * pipefd is greater than the current max.
 */
static int
NewConnection(
	OWPContext	ctx,
	OWPAddr		listenaddr,
	int		*maxfd,
	fd_set		*readfds
	)
{
	int		connfd;
	OWPByte		sbuff[SOCK_MAXADDRLEN];
	socklen_t	sbufflen;
	int		new_pipe[2];
	pid_t		pid;
	OWPBoolean	again = True;
	int		mode_available = opts.auth_mode;
	int		listenfd = OWPAddrFD(listenaddr);
	OWPControl	cntrl=NULL;
	OWPErrSeverity	out;

ACCEPT:
	sbufflen = sizeof(sbuff);
	connfd = accept(listenfd, (struct sockaddr *)&sbuff, &sbufflen);
	if (connfd < 0){
		switch(errno){
			case EINTR:
				/*
				 * Go ahead and reap since it could make
				 * more free connections.
				 */
				ReapChildren();
				goto ACCEPT;
				break;
			case ECONNABORTED:
				return 0;
				break;
			default:
				OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
						"accept():%s",strerror(errno));
				return(-1);
				break;
		}
	}

	if (pipe(new_pipe) < 0){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
						"pipe():%s",strerror(errno));
		return(-1);
	}

	pid = fork();
	if (pid < 0){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
						"fork():%s",strerror(errno));
		return(-1);
	}
	
	if (pid > 0){
		/* Parent */

		/*
		 * If close is interupted, continue to try and close,
		 * otherwise, ignore the error.
		 */
		while((close(new_pipe[1]) < 0) && (errno == EINTR));
		while((close(connfd) < 0) && (errno == EINTR));

		/* fd2pid{new_pipe[0]} = pid */
		free_connections--;
		FD_SET(new_pipe[0], readfds);
		if (new_pipe[0] > *maxfd)
			*maxfd = new_pipe[0];
	}
	else{
		/* Child code */
		int	i;

		for(i=getdtablesize()-1;i>=0;i--){
#ifndef	NDEBUG
			if(i == fileno(stderr))
				continue;
#endif
			if((i == connfd) || (i == new_pipe[1]))
				continue;

			/*
			 * Ignore errors unless it was an interupt.
			 */
			while((close(i) < 0) && (errno == EINTR));
		}

		if (free_connections <= 0)
			mode_available &= OWP_MODE_OPEN;

		cntrl = OWPControlAccept(ctx,connfd,
					(struct sockaddr *)sbuff,sbufflen,
					listenaddr,mode_available,&out);
		if (cntrl == NULL){
			fprintf(stderr, 
			  "DEBUG: CntrlAcc == NULL. Child Exiting\n");
			exit(0);	
		}

		while (again == True) {
			again = ServerMainControl(cntrl, &out);
		}
	}
	
	return(0); 
}


int
main(int argc, char *argv[])
{
	char			*progname;
	I2LogImmediateAttr	ia;
	int			od;
	OWPErrSeverity		out = OWPErrFATAL;
	policy_data		*policy;
	char			id2class[MAXPATHLEN],
				class2limits[MAXPATHLEN],
				passwd[MAXPATHLEN];
	fd_set			readfds, mask;/* listenfd, and pipes to kids */
	int			maxfd;    /* max fd in readfds               */
	OWPContext		ctx;
	OWPControl		cntrl;
	OWPAddr			listenaddr = NULL;
	int			listenfd;
	int			rc;
	OWPInitializeConfigRec	cfg  = {
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
	errhand = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
	if(! errhand) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

	od = I2OpenOptionTbl(errhand);

	if(I2ParseOptionTable(od, &argc, argv, set_options) < 0){
		I2ErrLog(errhand, "Could not parse command line options");
		exit(1);
	}

	/*
	 * load options into opts
	 */
	if(I2GetOptions(od, get_options) < 0){
		I2ErrLog(errhand, "Could not retrieve command line options");
		exit(1);
	}

	/*
	 * Check options.
	 */
	if(opts.help){
		usage(od,progname,NULL);
		exit(0);
	}

	free_connections = opts.maxconnections;

	/*
	 * Setup paths.
	 */
	rc = snprintf(id2class,sizeof(id2class),"%s%s%s",opts.confdir,
						OWD_DIRSEP,opts.id2class);
	if(rc > sizeof(id2class)){
		I2ErrLog(errhand, "Invalid path to id2class file.");
		exit(1);
	}

	rc = snprintf(class2limits,sizeof(class2limits),"%s%s%s",opts.confdir,
						OWD_DIRSEP,opts.class2limits);
	if(rc > sizeof(class2limits)){
		I2ErrLog(errhand, "Invalid path to class2limits file.");
		exit(1);
	}

	rc = snprintf(passwd,sizeof(passwd),"%s%s%s",opts.confdir,
						OWD_DIRSEP,opts.passwd);
	if(rc > sizeof(passwd)){
		I2ErrLog(errhand, "Invalid path to passwd file.");
		exit(1);
	}

	policy = PolicyInit(errhand, id2class, class2limits, passwd, &out);
	if (out == OWPErrFATAL){
		I2ErrLog(errhand, "PolicyInit failed. Exiting...");
		exit(1);
	};

	/*
	 * Setup the "default_mode".
	 */
	if(opts.authmode){
		char	*s = opts.authmode;
		opts.auth_mode = 0;
		while(*s != '\0'){
			switch(toupper(*s)){
				case 'O':
				opts.auth_mode |= OWP_MODE_OPEN;
				break;
				case 'A':
				opts.auth_mode |= OWP_MODE_AUTHENTICATED;
				break;
				case 'E':
				opts.auth_mode |= OWP_MODE_ENCRYPTED;
				break;
				default:
				I2ErrLogP(errhand,EINVAL,
						"Invalid -authmode %c",*s);
				usage(od,progname,NULL);
				exit(1);
			}
			s++;
		}
	}
	else{
		/*
		 * Default to all modes.
		 */
		opts.auth_mode = OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|
							OWP_MODE_ENCRYPTED;
	}

	/*
	 * Set the app_data for the context - this pointer will be passed
	 * on to the gettimestamp/err_func functions.
	 *
	 * Once this is initialized, all errors should be reported using the
	 * OWPError* functions so they all go through the installed error
	 * handler.
	 */
	cfg.app_data = (void *)policy;
	ctx = OWPContextInitialize(&cfg);

	/*
	 * If the local interface was specified, use it - otherwise use NULL
	 * for wildcard.
	 */
	if(opts.nodename)
		listenaddr = OWPAddrByNode(ctx,opts.nodename);
	listenaddr = OWPServerSockCreate(ctx,listenaddr,&out);
	if(!listenaddr){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Unable to create server socket. Exiting...");
		exit(1);
	}

	signal(SIGCHLD, sig_chld);

	listenfd = OWPAddrFD(listenaddr);
	FD_ZERO(&readfds);
	FD_SET(listenfd,&readfds);
	maxfd = listenfd;

	while (1) {
		int nfound;
		fd_set mask;
		socklen_t len = OWPAddrSockLen(listenaddr);

		mask = readfds;
		nfound = select(maxfd+1,&mask,NULL,NULL,NULL);

		/*
		 * This will only print out during debugging because
		 * NDEBUG should be defined for non-development builds.
		 * (see the error handler above.)
		 */
		OWPError(ctx,OWPErrINFO,errno,"select returned:%d (%s)",
						nfound,strerror(errno));
		/*
		 * Handle select interupts/errors.
		 */
		if(nfound < 0){
			if(errno == EINTR){
				ReapChildren();
				continue;
			}
			OWPError(ctx,OWPErrFATAL,errno,"select failed:(%s)",
							strerror(errno));
			exit(1);
		}

		/*
		 * shouldn't happen, but for completeness.
		 */
		if(nfound == 0)
			continue;

		if(FD_ISSET(listenfd, &mask)){ /* new connection */
			if(NewConnection(ctx,listenaddr,&maxfd,&readfds) != 0)
				exit(1);
		}
		else
			owampd_check_pipes(&maxfd,&mask,&readfds);
		ReapChildren();
	}

	/*NOTREACHED*/
	exit(0);
}
