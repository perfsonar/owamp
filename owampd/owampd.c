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
#include <pwd.h>
#include <grp.h>

#include <owamp/owamp.h>
#include <owamp/conndata.h>
#include <owamp/access.h>
#include <I2util/util.h>

#include "owampdP.h"

#define OWP_MAX_CLASSNAME_LEN 64 /* temp plug */

/* Global variable - the total number of allowed Control connections. */
static int			sigchld_received = 0;
static owampd_opts		opts;
static I2ErrLogSyslogAttr	syslogattr;
static I2ErrHandle		errhand;
static I2table			fdtable=NULL;
static I2table			pidtable=NULL;

static void
usage(
	const char *progname,
	const char *msg	__attribute__((unused))
	)
{
	fprintf(stderr, "Usage: %s [options]\n", progname);
	fprintf(stderr, "\nWhere \"options\" are:\n\n");

		fprintf(stderr,
		"   -v                verbose output\n"
		"   -h                Print this message and exit\n"
		"   -c confidr        Configuration directory\n"
		"   -d datadir        Data directory\n"
		"   -a authmode       Default supported authmodes:[E]ncrypted,[A]uthenticated,[O]pen\n"
	        "   -S nodename:port  Srcaddr to bind to\n"
		"   -t tmout          Max time to wait for control connection reads (sec)\n"
		"   -L timeout        Maximum time to wait for a packet before declaring it lost\n"
		"      -U/-G options only used if run as root\n"
		"   -U user           Run as user \"user\" :-uid also valid\n"
		"   -G group          Run as group \"group\" :-gid also valid\n"
		"   -w                Debugging: busy-wait children after fork to allow attachment\n"
		"   -Z                Debugging: Run in foreground\n"
			"\n"
			);
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

static int
ReadConfLine(
	FILE	*fp,
	int	rc,
	char	**line_buf,
	int	*line_buf_size
	)
{
	int	c;
	char	*line = *line_buf;
	int	i=0;

	while((c = fgetc(fp)) != EOF){
		if(c == '\n'){
			rc++;
			if(i) break;
			continue;
		}

		if(!i && c == '#'){
			while((c = fgetc(fp)) != EOF)
				if(c == '\n'){
					rc++;
					break;
				}
			continue;
		}

		if(!i && isspace(c))
			continue;

		if(i+2 > *line_buf_size){
			*line_buf_size *= 2;
			*line_buf = realloc(line,sizeof(char) * *line_buf_size);
			if(!*line_buf){
				free(line);
				fprintf(stderr,"malloc(): %s\n",
							strerror(errno));
				exit(1);
			}
			line = *line_buf;
		}
		line[i++] = c;
	}

	line[i] = '\0';
	if(!i) return 0;
	if(c==EOF) rc++;

	return rc;
}

static int
ReadConfVar(
	FILE	*fp,
	int	rc,
	char	**key,
	char	**val,
	int	max
	)
{
	char	*line;
	char	*lbuf=NULL;
	int	lbuf_max= MAXPATHLEN;
	char	*cptr;

	if(!(lbuf = (char*)malloc(sizeof(char)*lbuf_max))){
		fprintf(stderr,"malloc(): %s\n",strerror(errno));
		exit(1);
	}

	if((rc = ReadConfLine(fp,rc,&lbuf,&lbuf_max)) > 0){
		int	i;
		
		line = lbuf;

		i=0;
		cptr = *key;
		while(i<(max-1)){
			if(isspace(*line) || (*line == '\0'))
				break;
			*cptr++ = *line++;
			i++;
		}
		if(i >= (max-1)){
			rc = -rc;
			goto BADLINE;
		}
		*cptr = '\0';

		while(isspace(*line))
			line++;

		i=0;
		cptr = *val;
		while(i<(max-1)){
			if(*line == '\0')
				break;
			*cptr++ = *line++;
			i++;
		}
		if(i >= (max-1)){
			rc = -rc;
			goto BADLINE;
		}
		*cptr = '\0';
		/*
		 * Remove trailing spaces
		 */
		while(i>0){
			cptr--;
			if(!isspace(*cptr))
				break;
			*cptr = '\0';
		}
	}

BADLINE:
	free(lbuf);
	return rc;
}

static void
LoadConfig()
{
	FILE	*conf;
	char	conf_file[MAXPATHLEN];
	char	keybuf[MAXPATHLEN],valbuf[MAXPATHLEN];
	char	*key = keybuf;
	char	*val = valbuf;
	int	rc=0;

	conf_file[0] = '\0';
	if(opts.confdir){
		strcpy(conf_file, opts.confdir);
		strcat(conf_file, OWP_PATH_SEPARATOR);
	}
	strcat(conf_file, "owampd.conf");

	if(!(conf = fopen(conf_file, "r"))){
		if(opts.confdir){
			fprintf(stderr,"Unable to open %s: %s\n",conf_file,
					strerror(errno));
			exit(1);
		}
		return;
	}

	while((rc = ReadConfVar(conf,rc,&key,&val,MAXPATHLEN)) > 0){
		/*
		 * TODO: eventually set up a table of all opts, types, and
		 * getopt flags so this is more automatic, but it isn't worth
		 * it yet.
		 */

		/* syslog facility */
		if(!strncasecmp(key,"facility",8)){
			int fac = I2ErrLogSyslogFacility(val);
			if(fac == -1){
				fprintf(stderr,
				"Invalid -e: Syslog facility \"%s\" unknown\n",
				val);
				exit(1);
			}
			syslogattr.facility = fac;
		}
		else if(!strncasecmp(key,"loglocation",11)){
			syslogattr.line_info |= I2FILE|I2LINE;
		}
		else if(!strncasecmp(key,"datadir",7)){
		     if(!(opts.datadir = strdup(val))) {
			     fprintf(stderr,"strdup(): %s\n",strerror(errno));
			     exit(1);
		     }
		}
		else if(!strncasecmp(key,"user",4)){
		     if(!(opts.user = strdup(val))) {
			     fprintf(stderr,"strdup(): %s\n",strerror(errno));
			     exit(1);
		     }
		}
		else if(!strncasecmp(key,"group",5)){
		     if(!(opts.group = strdup(val))) {
			     fprintf(stderr,"strdup(): %s\n",strerror(errno));
			     exit(1);
		     }
		}
		else if(!strncasecmp(key,"verbose",7)){
			opts.verbose = True;
		}
		else if(!strncasecmp(key,"authmode",8)){
		     if(!(opts.authmode = strdup(val))) {
			     fprintf(stderr,"strdup(): %s\n",strerror(errno));
			     exit(1);
		     }
		}
		else if(!strncasecmp(key,"srcnode",7)){
		     if(!(opts.srcnode = strdup(val))) {
			     fprintf(stderr,"strdup(): %s\n",strerror(errno));
			     exit(1);
		     }
		}
		else if(!strncasecmp(key,"timeout",7)){
			opts.tmout = strtoul(optarg,NULL,10);
			if(errno != 0) {
				fprintf(stderr,
			"Invalid -t value (%s): Positive integer expected\n",
					val);
				exit(1);
			}
		}
		else if(!strncasecmp(key,"vardir",6)){
		     if(!(opts.vardir = strdup(val))) {
			     fprintf(stderr,"strdup(): %s\n",strerror(errno));
			     exit(1);
		     }
		}
		else{
			fprintf(stderr,"Unknown key=%s in %s\n",key,conf_file);
			exit(1);
		}
	}

	if(rc < 0){
		fprintf(stderr,"Invalid config file! %s line %d\n",
				conf_file,-rc);
		exit(1);
	}

	return;
}

int
main(int argc, char *argv[])
{
	char			*progname;
	OWPErrSeverity		out = OWPErrFATAL;
	owp_policy_data		*policy;
	char			ip2class[MAXPATHLEN],
				class2limits[MAXPATHLEN],
		                passwd[MAXPATHLEN],
                 		pid_file[MAXPATHLEN],
		                info_file[MAXPATHLEN];
		
	fd_set			readfds;
	int			maxfd;    /* max fd in readfds */
	OWPContext		ctx;
	OWPAddr			listenaddr = NULL;
	int			listenfd;
	int			rc;
	I2datum			data;
	pid_t                   mypid;
	struct flock            flk;
	int                     pid_fd;
	FILE                    *pid_fp, *info_fp;
	OWPTimeStamp	        currtime;	
	OWPnum64	        cnum;
	int ch;
	uid_t			setuser=0;
	gid_t			setgroup=0;

#ifndef NDEBUG
	char *optstring = "hvc:d:R:a:S:t:L:e:ZU:G:w";
#else	
	char *optstring = "hvc:d:R:a:S:t:L:e:ZU:G:";
#endif

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


	/*
	* Start an error loggin session for reporting errors to the
	* standard error
	*/
	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;
	syslogattr.ident = progname;
	syslogattr.logopt = LOG_PID;
	syslogattr.facility = LOG_DAEMON;
	syslogattr.priority = LOG_ERR;
	syslogattr.line_info = I2MSG;

	/* Set up options defaults */
	opts.verbose = False;
	opts.ip2class = "ip2class.conf";
	opts.class2limits = "class2limits.conf";
	opts.passwd = "passwd.conf";
	opts.vardir = opts.confdir = opts.datadir = NULL;
	opts.authmode = NULL; 
	opts.srcnode = NULL;
	opts.lossThreshold = 10;
	opts.tmout = 10;
	opts.daemon = 1;
	opts.user = opts.group = NULL;

	/*
	 * Fetch config file option if present
	 */
	opterr = 0;
	while((ch = getopt(argc, argv, optstring)) != -1){
		switch (ch){
		case 'c':	/* -c "Config directory" */
			if (!(opts.confdir = strdup(optarg))) {
				I2ErrLog(cfg.eh,"malloc: %M");
				exit(1);
			}
			break;
		default:
			break;
		}
	}
	opterr = optreset = optind = 1;

	/*
	 * Load Config file.
	 */
	LoadConfig();

	/*
	 * If the confdir wasn't specified on the cmdline above, then
	 * we set it to "." here so that passwd files etc, are relative
	 * to current directory.
	 */
	if(!opts.confdir)
		opts.confdir = ".";


	/*
	 * Read cmdline options that effect syslog so the rest of cmdline
	 * processing can be reported via syslog.
	 */
	opterr = 0;
	while((ch = getopt(argc, argv, optstring)) != -1){
		switch (ch){
			int fac;
		case 'e':	/* -e "syslog err facility" */
			fac = I2ErrLogSyslogFacility(optarg);
			if(fac == -1){
				fprintf(stderr,
				"Invalid -e: Syslog facility \"%s\" unknown\n",
				optarg);
				exit(1);
			}
			syslogattr.facility = fac;
			break;
		case 'Z':
			opts.daemon = 0;
			break;
		default:
			break;
		}
	}
	opterr = optreset = optind = 1;

	/*
	 * Always use LOG_PERROR - if daemonizing, stderr will be closed,
	 * and this hurts nothing. And... commandline reporting is good
	 * until after the fork.
	 */
	syslogattr.logopt |= LOG_PERROR;
	errhand = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);
	if(! errhand) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

	/*
	 * Initialize the context. (Set the error handler to the app defined
	 * one.)
	 */
	cfg.eh = errhand;
	ctx = OWPContextInitialize(&cfg);

	/*
	 * Now deal with "all" cmdline options.
	 */
	while ((ch = getopt(argc, argv, optstring)) != -1){
		switch (ch) {
		/* Connection options. */
		case 'v':	/* -v "verbose" */
			opts.verbose = True;
			break;
		case 'd':	/* -d "data directory" */
			if (!(opts.datadir = strdup(optarg))) {
				I2ErrLog(cfg.eh,"malloc: %M");
				exit(1);
			}
			break;
		case 'a':	/* -a "authmode" */
			if (!(opts.authmode = strdup(optarg))) {
				I2ErrLog(cfg.eh,"malloc: %M");
				exit(1);
			}
			break;
		case 'S':  /* -S "src addr" */
			if (!(opts.srcnode = strdup(optarg))) {
				I2ErrLog(cfg.eh,"malloc: %M");
				exit(1);
			}
			break;
		case 't':
			opts.tmout = strtoul(optarg,NULL,10);
			if(errno != 0) {
				I2ErrLog(cfg.eh,
			"Invalid -t value (%s): Positive integer expected",
						optarg);
				exit(1);
			}
			break;
		case 'L':
			opts.lossThreshold = strtoul(optarg,NULL,10);
			if(errno != 0) {
				I2ErrLog(cfg.eh,
			"Invalid -L value (%s). Positive integer expected",
					optarg);
				exit(1);
			}
			break;
		case 'U':
			if(!(opts.user = strdup(optarg))){
				I2ErrLog(cfg.eh,"malloc: %M");
				exit(1);
			}
			break;
		case 'G':
			if(!(opts.group = strdup(optarg))){
				I2ErrLog(cfg.eh,"malloc: %M");
				exit(1);
			}
			break;
		case 'R':	/* -R "var/run directory" */
			if (!(opts.vardir = strdup(optarg))) {
				I2ErrLog(cfg.eh,"malloc: %M");
				exit(1);
			}
			break;
		case 'c':
		case 'e':
		case 'Z':
			break;
#ifndef NDEBUG
		case 'w':
			opts.childwait = True;
		break;
#endif
		case 'h':
		case '?':
		default:
			usage(progname, "");
			exit(0);
			/* UNREACHED */ 
		}
	}
	argc -= optind;
	argv += optind;

	if (argc) {
		     usage(progname, "");
		     exit(1);
	}

	if(!opts.datadir)
		opts.datadir = "";

	if(!opts.vardir)
		opts.vardir = ".";

	/*  Get exclusive lock for pid file. */
	strcpy(pid_file, opts.vardir);
	strcat(pid_file, OWP_PATH_SEPARATOR);
	strcat(pid_file, "owampd.pid");
	if ((pid_fd = open(pid_file, O_RDWR|O_CREAT,
			   S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
		I2ErrLog(errhand, "open(%s): %M", pid_file);
		exit(1);
	}
	flk.l_start = 0;
	flk.l_len = 0;
	flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET; 
	while((rc=fcntl(pid_fd, F_SETLK, &flk)) < 0 && errno == EINTR);
	if(rc < 0){
		I2ErrLog(errhand,"Unable to lock file %s:%M", pid_file);
		exit(1);
	}
	if ((pid_fp = fdopen(pid_fd, "wr")) == NULL) {
		I2ErrLog(errhand, "fdopen(): %M");
		exit(1);
	}

	/*
	 * If running as root warn if the -U/-G flags not set.
	 */
	if(!geteuid()){
		struct passwd	*pw;
		struct group	*gr;

		if(!opts.user){
			I2ErrLog(errhand,"Running owampd as root is folly!");
			I2ErrLog(errhand,"Use the -U option!");
			exit(1);
		}

		/*
		 * Validate user option.
		 */
		if((pw = getpwnam(opts.user))){
			setuser = pw->pw_uid;
		}
		else if(opts.user[0] == '-'){
			setuser = strtoul(&opts.user[1],NULL,10);
			if(errno || !getpwuid(setuser))
				setuser = 0;
		}
		if(!setuser){
			I2ErrLog(errhand,"Invalid user/-U option: %s",
					opts.user);
			exit(1);
		}

		/*
		 * Validate group option.
		 */
		if(opts.group){
			if((gr = getgrnam(opts.group))){
				setgroup = gr->gr_gid;
			}
			else if(opts.group[0] == '-'){
				setgroup = strtoul(&opts.group[1],NULL,10);
				if(errno || !getgrgid(setgroup))
					setgroup = 0;
			}
			if(!setgroup){
				I2ErrLog(errhand,"Invalid user/-G option: %s",
					opts.group);
				exit(1);
			}
		}

		/*
		 * Only setting effective id for now. This will catch
		 * errors, and will still allow the rename of the
		 * pid/info file later.
		 */
		if(setgroup && (setegid(setgroup) != 0)){
			I2ErrLog(errhand,"Unable to setgid to \"%s\": %M",
					opts.group);
			exit(1);
		}
		if(seteuid(setuser) != 0){
			I2ErrLog(errhand,"Unable to setuid to \"%s\": %M",
					opts.user);
			exit(1);
		}

	}

	/*
	 * Setup paths.
	 */

	rc = snprintf(ip2class,sizeof(ip2class),"%s%s%s",opts.confdir,
					OWP_PATH_SEPARATOR,opts.ip2class);
	if(rc >= (int)sizeof(ip2class)){
		I2ErrLog(errhand, "Invalid path to ip2class file.");
		exit(1);
	}

	rc = snprintf(class2limits,sizeof(class2limits),"%s%s%s",opts.confdir,
					OWP_PATH_SEPARATOR,opts.class2limits);
	if(rc >= (int)sizeof(class2limits)){
		I2ErrLog(errhand, "Invalid path to class2limits file.");
		exit(1);
	}

	rc = snprintf(passwd,sizeof(passwd),"%s%s%s",opts.confdir,
					OWP_PATH_SEPARATOR,opts.passwd);
	if(rc >= (int)sizeof(passwd)){
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
				usage(progname,NULL);
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
	 * daemonize here
	 */
	mypid = 0;
	if(opts.daemon){
		/*
		 * TODO: Need to think about this one... It would be
		 * good to chdir to '/' so file systems can be unmounted,
		 * however... this breaks relative path names.
		 */
#if	NOT
		if(chdir("/") < 0){
			I2ErrLog(errhand,"Unable to chdir to /: %M");
			exit(1);
		}
#endif
		for(rc=0;rc<3;rc++){
			if(close(rc) == -1 || open("/dev/null",O_RDWR) != rc){
				I2ErrLog(errhand,"Unable to reopen fd(%d): %M",
						rc);
				exit(1);
			}
		}

		mypid = fork();
		if(mypid < 0){
			I2ErrLog(errhand,"Unable to fork: %M");
			exit(1);
		}
		if((mypid == 0) && (setsid() == -1)){
			I2ErrLog(errhand,"Unable to setsid: %M");
			exit(1);
		}
	}
	else{
		mypid = getpid();
	}

	/*
	 * Temporarily take root permissions back.
	 * (If this is parent of daemonizing - exit immediately after
	 * updating pid/info files. If not daemonizing, setuid/setgid
	 * is called after the mypid if to return to lesser
	 * permissions.)
	 */
	if((setuser) && (seteuid(getuid()) != 0)){
		I2ErrLog(errhand,"seteuid(): %M");
		kill(mypid,SIGTERM);
		exit(1);
	}
	if((setgroup) && (setegid(getgid()) != 0)){
		I2ErrLog(errhand,"setegid(): %M");
		kill(mypid,SIGTERM);
		exit(1);
	}

	/*
	 * If this is the parent process (or not daemonizing) - write the pid
	 * and info files.
	 */
	if(mypid > 0){

		/* Record pid.  */
		fprintf(pid_fp, "%lld\n", (long long)mypid);
		if (fflush(pid_fp) < 0) {
			I2ErrLogP(errhand, errno, "fflush: %M");
			kill(mypid,SIGTERM);
			exit(1);
		}

		/* Record the start timestamp in the info file. */
		strcpy(info_file, opts.vardir);
		strcat(info_file, OWP_PATH_SEPARATOR);
		strcat(info_file, "owampd.infoi");
		if ((info_fp = fopen(info_file, "w")) == NULL) {
			I2ErrLog(errhand, "fopen(%s): %M", info_file);
			kill(mypid,SIGTERM);
			exit(1);
		}

		if(!OWPGetTimeOfDay(&currtime)){
			I2ErrLogP(errhand, errno, "OWPGetTimeOfDay:%M");
			kill(mypid,SIGTERM);
			exit(1);
		}
		cnum = OWPTimeStamp2num64(&currtime);
		fprintf(info_fp, "START="OWP_TSTAMPFMT"\n", cnum);
		fprintf(info_fp, "PID=%lld\n", (long long)mypid);
		while ((rc = fclose(info_fp)) < 0 && errno == EINTR);
		if(rc < 0){
			I2ErrLog(errhand,"fclose(): %M");
			kill(mypid,SIGTERM);
			exit(1);
		}
		strcpy(pid_file,info_file);
		info_file[strlen(info_file)-1] = '\0'; // remove trailing "i"
		if(rename(pid_file,info_file) != 0){
			I2ErrLog(errhand,"rename(): %M");
			kill(mypid,SIGTERM);
			exit(1);
		}

		/*
		 * If daemonizing - this is parent - exit.
		 */
		if(opts.daemon) exit(0);
	}

	/*
	 * If the local interface was specified, use it - otherwise use NULL
	 * for wildcard.
	 */
	if(opts.srcnode && !(listenaddr = OWPAddrByNode(ctx,opts.srcnode))){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"Invalid source address specified: %s",opts.srcnode);
		exit(1);
	}
	listenaddr = OWPServerSockCreate(ctx,listenaddr,&out);
	if(!listenaddr){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Unable to create server socket. Exiting...");
		exit(1);
	}

	/*
	 * set real uid/gid, not just effective.
	 */
	if((setgroup) && (setgid(setgroup) != 0)){
		I2ErrLog(errhand,"setegid(): %M");
		exit(1);
	}
	if((setuser) && (setuid(setuser) != 0)){
		I2ErrLog(errhand,"setuid(): %M");
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
