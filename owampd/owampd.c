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
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <owamp/owamp.h>
#include <owamp/conndata.h>
#include <owamp/access.h>
#include <I2util/util.h>

#include "owampdP.h"

#define OWP_MAX_CLASSNAME_LEN 64 /* temp plug */

/* Global variable - the total number of allowed Control connections. */
static int		sigchld_received = 0;
static owampd_opts	opts;
static I2ErrHandle	errhand;
static I2table		fdtable=NULL;
static I2table		pidtable=NULL;

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
	{"ip2class",1,"ip2class.conf","ip2class config filename"},
	{"class2limits",1,"class2limits.conf","class2limits config filename"},
	{"passwd",1,"passwd.conf","passwd config filename"},

	/*
	 * configuration options - should probably add a conf file eventually.
	 */
	{"datadir",1,OWP_DATADIR,"Data directory"},

	{"authmode",1,NULL,
	"Default supported authmodes:[E]ncrypted,[A]uthenticated,[O]pen"},
	{"nodename",1,NULL,"Local nodename to bind to: addr:port"},
	{"tmout",1,OWD_TMOUT,
		"Max time to wait for control connection reads (sec)"},
	{"lossThreshold",1,"120",
		"elapsed time when recv declares packet lost (sec)"},
#ifndef	NDEBUG
	{"childwait",0,NULL,
		"Debugging: busy-wait children after fork to allow attachment"},
#endif
	{NULL,0,NULL,NULL}
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
	"ip2class", I2CvtToString, &opts.ip2class,
	sizeof(opts.ip2class)
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
	"datadir", I2CvtToString, &opts.datadir,
	sizeof(opts.datadir)
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
	"tmout", I2CvtToInt, &opts.tmout,
	sizeof(opts.tmout)
	},
	{
	"lossThreshold", I2CvtToInt, &opts.lossThreshold,
	sizeof(opts.lossThreshold)
	},
#ifndef	NDEBUG
	{
	"childwait", I2CvtToBoolean, &opts.childwait,
	sizeof(opts.childwait)
	},
#endif
	{NULL, NULL, NULL,0}
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
sig_chld(
	int	signo	__attribute__((unused))
	)
{
	sigchld_received++;
	return;
}

/*
** This is a basic function to report errors on the server.
*/

#if	NOT
static int
owampd_err_func(
		void           *app_data	__attribute__((unused)),
		OWPErrSeverity severity,
		OWPErrType     etype,
		const char     *errmsg
)
{
	/*
	 * TODO: Add a logging file (OWPErrINFO && OWPErrPOLICY)
	 * indicates logging information...
	 */
#ifdef	NDEBUG
	if(!opts.verbose && (severity > OWPErrWARNING))
		return 0;
#endif

	I2ErrLogP(errhand,etype,errmsg);

	return 0;
}
#endif

struct ChldStateRec{
	OWPContext	ctx;
	pid_t		pid;
	int		fd;
	OWPSessionMode	authmode;
	char		*class;
	char		classbuf[OWP_MAX_CLASSNAME_LEN];
	/*
	 * Put the datum for the key's and value right in this
	 * structure so we don't have to alloc/free them seperately.
	 */
	I2datum		pidkey;
	I2datum		fdkey;
	I2datum		value;
};

typedef struct ChldStateRec ChldStateRec, *ChldState;

static ChldState
AllocChldState(
	OWPContext	ctx,
	pid_t		pid,
	int		fd
	)
{
	ChldState	cstate = malloc(sizeof(*cstate));

	if(!cstate){
		OWPError(ctx,OWPErrFATAL,ENOMEM,"malloc():%M");
		return NULL;
	}

	cstate->ctx = ctx;
	cstate->pid = pid;
	cstate->fd = fd;
	cstate->authmode = 0;
	cstate->class = NULL;
	cstate->classbuf[0] = '\0';

	/*
	 * setup datum for hash's.
	 */
	cstate->pidkey.dptr = NULL;
	cstate->pidkey.dsize = (unsigned long)pid;
	cstate->fdkey.dptr = NULL;
	cstate->fdkey.dsize = (unsigned long)fd;

	cstate->value.dptr = cstate;
	cstate->value.dsize = sizeof(*cstate);

	/*
	 * Add cstate into the hash's.
	 */
	assert(!I2hash_fetch(pidtable,&cstate->pidkey));
	assert(!I2hash_fetch(fdtable,&cstate->fdkey));

	if((I2hash_store(pidtable,&cstate->pidkey,&cstate->value) != 0) ||
		(I2hash_store(fdtable,&cstate->fdkey,&cstate->value) != 0)){
		free(cstate);
		return NULL;
	}

	return cstate;
}

static void
FreeChldState(
	ChldState	cstate,
	fd_set		*readfds
	)
{
	if(cstate->fd >= 0){

		while((close(cstate->fd) < 0) && (errno == EINTR));
		FD_CLR(cstate->fd, readfds);
		if(I2hash_delete(fdtable,&cstate->fdkey) != 0){
			OWPError(cstate->ctx,OWPErrWARNING,OWPErrUNKNOWN,
					"fd(%d) not in fdtable!?!",cstate->fd);
		}
	}

	if(I2hash_delete(pidtable,&cstate->pidkey) != 0){
		OWPError(cstate->ctx,OWPErrWARNING,OWPErrUNKNOWN,
				"pid(%d) not in pidtable!?!",cstate->pid);
	}

	/*
	 * TODO:Do we need to keep track of the number of fd's in use?
	 * decrement that count here...
	 */
	free(cstate);

	return;
}

static void
ReapChildren(
	int	*maxfd,
	fd_set	*readfds
	)
{
	int		status;
	pid_t		child;
	I2datum		key;
	I2datum		*val;
	ChldState	cstate;

	if(!sigchld_received)
		return;

	key.dptr = NULL;
	while ( (child = waitpid(-1, &status, WNOHANG)) > 0){
		key.dsize = child;
		if(!(val = I2hash_fetch(pidtable,&key))){
			OWPError(cstate->ctx,OWPErrWARNING,
				OWPErrUNKNOWN,
				"pid(%d) not in pidtable!?!",child);
		}
		cstate = val->dptr;

		/*
		 * Let main loop know maxfd needs to be recomputed.
		 */
		if(cstate->fd == *maxfd)
			*maxfd = -1;

		/*
		 * TODO: free the resouces allocated to this child from
		 * the "class" allotment.
		 */
		FreeChldState(cstate,readfds);
	}


	sigchld_received = 0;
}

struct CleanPipeArgRec{
	int	*maxfd;
	fd_set	*avail;
	fd_set	*readfds;
};

static I2Boolean
CheckFD(
	const I2datum	*key	__attribute__((unused)),
	I2datum		*value,
	void		*app_data
	)
{
	struct CleanPipeArgRec	*arg = (struct CleanPipeArgRec *)app_data;
	ChldState		cstate = value->dptr;

	if(!FD_ISSET(cstate->fd,arg->avail))
		return True;

	/*
	 * child initialization - first message.
	 */
	if(!cstate->authmode){
		ssize_t	in,out;

		in = sizeof(cstate->authmode);
		if((out = I2Readn(cstate->fd,&cstate->authmode,in)) != in){
			if(out != 0){
				OWPError(cstate->ctx,OWPErrWARNING,
					OWPErrUNKNOWN,"read error:(%M)");
			}
			(void)kill(cstate->pid,SIGKILL);
		}
		/* TODO: validate authmode received. */
	}
	else{
		/* TODO:read child request for resources */
	}

	return True;
}

/*
 * avail contains the fd_set of fd's that are currently readable, readfds is
 * the set of all fd's that the server needs to pay attention to.
 * maxfd is the largest of those.
 */
static void
CleanPipes(
	fd_set	*avail,
	int	*maxfd,
	fd_set	*readfds
	)
{
	struct CleanPipeArgRec	cpargs;
	
	cpargs.avail = avail;
	cpargs.maxfd = maxfd;
	cpargs.readfds = readfds;

	I2hash_iterate(fdtable,CheckFD,&cpargs);

	return;
}

/*
 * This function needs to create a new child process with a pipe to
 * communicate with it. It needs to add the new pipefd into the readfds,
 * and update maxfd if the new pipefd is greater than the current max.
 */
static void
NewConnection(
	OWPContext	ctx,
	OWPAddr		listenaddr,
	int		*maxfd,
	fd_set		*readfds,
	owp_policy_data	*policy
	)
{
	int			connfd;
	struct sockaddr_storage	sbuff;
	socklen_t		sbufflen;
	int			new_pipe[2];
	pid_t			pid;
	OWPSessionMode		mode = opts.auth_mode;
	int			listenfd = OWPAddrFD(listenaddr);
	OWPControl		cntrl=NULL;
	OWPErrSeverity		out;

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
				ReapChildren(maxfd,readfds);
				goto ACCEPT;
				break;
			case ECONNABORTED:
				return;
				break;
			default:
				OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"accept():%M");
				return;
				break;
		}
	}

	if (pipe(new_pipe) < 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"pipe():%M");
		(void)close(connfd);
		return;
	}

	pid = fork();

	/* fork error */
	if (pid < 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fork():%M");
		(void)close(new_pipe[0]);
		(void)close(new_pipe[1]);
		(void)close(connfd);
		return;
	}
	
	/* Parent */
	if (pid > 0){
		ChldState	chld;
		

		/*
		 * If close is interupted, continue to try and close,
		 * otherwise, ignore the error.
		 */
		while((close(new_pipe[1]) < 0) && (errno == EINTR));
		while((close(connfd) < 0) && (errno == EINTR));

		if(!(chld = AllocChldState(ctx,pid,new_pipe[0]))){
			(void)close(new_pipe[0]);
			(void)kill(pid,SIGKILL);
			return;
		}

		FD_SET(chld->fd, readfds);
		if((*maxfd > -1) && (chld->fd > *maxfd))
			*maxfd = chld->fd;
	}
	/* Child */
	else{
		ssize_t			n;
		OWPPerConnDataRec	conndata;

#ifndef	NDEBUG
		int		childwait;

		childwait = opts.childwait;
		while(childwait);
#endif

		/*
		 * TODO: Could check if the class from this IP allows
		 * open_mode, and modify "mode" if open is not allowed...
		 * For now, just leave it alone and if open is not allowed
		 * for this address, then OWPControlAccept will fail when it calls
		 * the CheckControlPolicy function.
		 */
		memset(&conndata,0,sizeof(conndata));
		conndata.pipefd = new_pipe[1];
		conndata.datadir = opts.datadir;
		conndata.policy = policy;
		conndata.lossThreshold = opts.lossThreshold;
		conndata.node = NULL;
#ifndef	NDEBUG
		conndata.childwait = opts.childwait;
#endif

		cntrl = OWPControlAccept(ctx,connfd,
					(struct sockaddr *)&sbuff,sbufflen,
					mode,(void*)&conndata,&out);
		/*
		 * session not accepted.
		 */
		if(!cntrl){
			exit(out);	
		}
		conndata.cntrl = cntrl;

		/*
		 * Send the mode to the parent.
		 */
		mode = OWPGetMode(cntrl);
		n = sizeof(mode);
		if(I2Writen(new_pipe[1],&mode,n) < n){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Write on pipe failed:(%M)");
			exit(-1);
		}

		if(OWPProcessRequests(cntrl) != OWPErrOK){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Control session terminated abnormally...");
		}

		OWPControlClose(cntrl);

		exit(0);
	}
	
	return; 
}

/*
 * hash functions...
 * I cheat - I use the "dsize" part of the datum for the key data since
 * pid and fd are both integers.
 */
static int
intcmp(
	const I2datum	*x,
	const I2datum	*y
	)
{
	assert(x);
	assert(y);

	return(x->dsize != y->dsize);
}

static unsigned long
inthash(
	const I2datum	*key
	)
{
	return (unsigned long)key->dsize>>2;
}

static I2Boolean
FindMaxFD(
	const I2datum	*key,
	I2datum		*value	__attribute__((unused)),
	void		*app_data
	)
{
	int		*maxfd = (int *)app_data;
	unsigned long	tmp = (unsigned long)*maxfd;
	
	if((*maxfd < 0) || (key->dsize > tmp))
		*maxfd = (int)key->dsize;

	return True;
}

int
main(int argc, char *argv[])
{
	char			*progname;
	I2LogImmediateAttr	ia;
	int			od;
	OWPErrSeverity		out = OWPErrFATAL;
	owp_policy_data		*policy;
	char			ip2class[MAXPATHLEN],
				class2limits[MAXPATHLEN],
				passwd[MAXPATHLEN];
	fd_set			readfds;
	int			maxfd;    /* max fd in readfds               */
	OWPContext		ctx;
	OWPAddr			listenaddr = NULL;
	int			listenfd;
	int			rc;
	I2datum			data;
	OWPInitializeConfigRec	cfg  = {
	/*	tm_out			*/	{0, 
						0},
	/*	eh			*/	NULL,
	/*	get_aes_key_func	*/	owp_get_aes_key,
	/*	check_control_func	*/	owp_check_control,
	/*	check_test_func		*/	owp_check_test,
	/*	rand_type		*/	I2RAND_DEV,
	/*	rand_data		*/	NULL
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

	/*
	 * Initialize the context. (Set the error handler to the app defined
	 * one.)
	 */
	cfg.eh = errhand;
	ctx = OWPContextInitialize(&cfg);

	/*
	 * Setup paths.
	 */

	rc = snprintf(ip2class,sizeof(ip2class),"%s%s%s",opts.confdir,
					OWP_PATH_SEPARATOR,opts.ip2class);
	if(rc > (int)sizeof(ip2class)){
		I2ErrLog(errhand, "Invalid path to ip2class file.");
		exit(1);
	}

	rc = snprintf(class2limits,sizeof(class2limits),"%s%s%s",opts.confdir,
					OWP_PATH_SEPARATOR,opts.class2limits);
	if(rc > (int)sizeof(class2limits)){
		I2ErrLog(errhand, "Invalid path to class2limits file.");
		exit(1);
	}

	rc = snprintf(passwd,sizeof(passwd),"%s%s%s",opts.confdir,
					OWP_PATH_SEPARATOR,opts.passwd);
	if(rc > (int)sizeof(passwd)){
		I2ErrLog(errhand, "Invalid path to passwd file.");
		exit(1);
	}

	policy = OWPPolicyInit(ctx, ip2class, class2limits, passwd, &out);
	if (out != OWPErrOK){
		I2ErrLog(errhand, "PolicyInit failed. Exiting...");
		exit(1);
	};

#ifdef	NOTYET
	printf("DEBUG: policy init ok. Printing out ip2class hash...\n");
	I2hash_print(policy->ip2class, stdout);
#endif
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
	 * setup hash's to keep track of child process state.
	 */

	/*
	 * TODO: a config test for this would probably be cleaner...
	 */
	{	/* ensure intcmp will work */
		size_t	psize = sizeof(pid_t);
		assert(psize<=sizeof(data.dsize));
	}

	pidtable = I2hash_init(errhand,0,intcmp,inthash,NULL);
	fdtable = I2hash_init(errhand,0,intcmp,inthash,NULL);
	if(!pidtable || !fdtable){
		I2ErrLogP(errhand,0,"Unable to setup hash tables...");
		exit(1);
	}

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

	/*
	 * Set up mechanism to track child state.
	 */
	signal(SIGCHLD, sig_chld);

	listenfd = OWPAddrFD(listenaddr);
	FD_ZERO(&readfds);
	FD_SET(listenfd,&readfds);
	maxfd = listenfd;

	while (1) {
		int nfound;
		fd_set ready;

		if(maxfd < 0){
			I2hash_iterate(fdtable,FindMaxFD,&maxfd);
			maxfd = MAX(maxfd,listenfd);
		}
		ready = readfds;
		nfound = select(maxfd+1,&ready,NULL,NULL,NULL);

		/*
		 * Handle select interupts/errors.
		 */
		if(nfound < 0){
			if(errno == EINTR){
				ReapChildren(&maxfd,&readfds);
				continue;
			}
			OWPError(ctx,OWPErrFATAL,errno,"select():%M");
			exit(1);
		}

		/*
		 * shouldn't happen, but for completeness...
		 */
		if(nfound == 0)
			continue;

		if(FD_ISSET(listenfd, &ready)){ /* new connection */
			NewConnection(ctx,listenaddr,&maxfd,&readfds, policy);
		}
		else
			CleanPipes(&ready,&maxfd,&readfds);

		ReapChildren(&maxfd,&readfds);
	}

	exit(0);
}
