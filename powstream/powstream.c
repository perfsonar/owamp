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
 *	File:		powstream.c
 *
 *	Authors:	Jeff Boote
 *                      Anatoly Karp
 *			Internet2
 *
 *	Date:		Tue Sep  3 15:47:26 MDT 2002
 *
 *	Description:	
 *
 *	Initial implementation of powstream commandline application. This
 *	application will measure active one-way udp latencies. And it will
 *	set up perpetual tests and keep them going until this application
 *	is killed.
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>

#include <I2util/util.h>
/*
 * TODO: Remove encode/decode timestamps and replace with a write_record
 * function - then this can include owamp.h instead of owampP.h.
 */
#include <owamp/owampP.h>
#include <owamp/conndata.h>
#include <owamp/access.h>

#include "./powstreamP.h"

/*
 * The powstream context
 */
static	powapp_trec		appctx;
static	I2ErrHandle		eh;
static	pow_cntrl_rec		pcntrl[2];
static	OWPTestSpecPoisson	test_spec;
static	u_int32_t		sessionTime;
static	u_int32_t		file_offset,ext_offset;
static	int			pow_reset = 0;
static	int			pow_exit = 0;

/*
 * Library initialization structure;
 */
static	OWPInitializeConfigRec	OWPCfg = {{
	/* tm_out.tv_sec		*/	0,
	/* tm_out.tv_usec		*/	0},
	/* eh				*/	NULL,
	/* get_aes_key			*/	owp_get_aes_key,
	/* check_control_func		*/	NULL,
	/* check_test_func		*/	NULL,
	/* rand_type                    */      I2RAND_DEV,
	/* rand_data                    */      NULL
};

static void
print_conn_args()
{
	fprintf(stderr,"              [Connection Args]\n\n"
"   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen\n"
"   -k keyfile     AES keyfile to use with Authenticated/Encrypted modes\n"
"   -u username    username to use with Authenticated/Encrypted modes\n"
"   -S srcaddr     use this as a local address for control connection and tests\n"
	);
}

static void
print_test_args()
{
	fprintf(stderr,
"              [Test Args]\n\n"
"   -c count       number of test packets\n"
"   -i wait        mean average time between packets (seconds)\n"
"   -L timeout     maximum time to wait for a packet before declaring it lost\n"
"   -s padding     size of the padding added to each packet (bytes)\n");
}

static void
print_output_args()
{
	fprintf(stderr,
		"              [Output Args]\n\n"
		"   -d dir         directory to save session file in\n"
		"   -h             print this message and exit\n"
		);
}

static void
usage(const char *progname, const char *msg)
{
	if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
	fprintf(stderr,"usage: %s %s\n", 
			progname, "[arguments] testaddr [servaddr]",
			"[arguments] are as follows: "
			);
	fprintf(stderr, "\n");
	print_conn_args();
		
	fprintf(stderr, "\n");
	print_test_args();
		
	fprintf(stderr, "\n");
	print_output_args();

	return;
}

/*
** Initialize authentication and policy data (used by owping and owfetch)
*/
void
owp_set_auth(powapp_trec *pctx, 
	     owp_policy_data **policy, 
	     char *progname,
	     OWPContext ctx)
{
	OWPErrSeverity err_ret;

	if(pctx->opt.identity){
		/*
		 * Eventually need to modify the policy init for the
		 * client to deal with a pass-phrase instead of/ or in
		 * addition to the passwd file.
		 */
		*policy = OWPPolicyInit(ctx, NULL, NULL, pctx->opt.passwd, 
				       &err_ret);
		if (err_ret == OWPErrFATAL){
			I2ErrLog(eh, "PolicyInit failed. Exiting...");
			exit(1);
		};
	}


	/*
	 * Verify/decode auth options.
	 */
	if(pctx->opt.authmode){
		char	*s = appctx.opt.authmode;
		pctx->auth_mode = 0;
		while(*s != '\0'){
			switch (toupper(*s)){
				case 'O':
				pctx->auth_mode |= OWP_MODE_OPEN;
				break;
				case 'A':
				pctx->auth_mode |= OWP_MODE_AUTHENTICATED;
				break;
				case 'E':
				pctx->auth_mode |= OWP_MODE_ENCRYPTED;
				break;
				default:
				I2ErrLogP(eh,EINVAL,"Invalid -authmode %c",*s);
				usage(progname, NULL);
				exit(1);
			}
			s++;
		}
	}else{
		/*
		 * Default to all modes.
		 * If identity not set - library will ignore A/E.
		 */
		pctx->auth_mode = OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|
							OWP_MODE_ENCRYPTED;
	}
}

/*
 * TODO: Find real max padding sizes based upon size of headers
 */
#define	MAX_PADDING_SIZE	65000

static void
ResetSession(
	pow_cntrl	p,	/* connection we are configuring	*/
	pow_cntrl	q	/* other connection			*/
	)
{
	OWPAcceptType	aval = OWP_CNTRL_ACCEPT;

	if(p->numPackets && p->cntrl &&
			(OWPStopSessions(p->cntrl,&aval) < OWPErrWARNING)){
		OWPControlClose(p->cntrl);
		p->cntrl = NULL;
	}
	p->numPackets = 0;
	p->sessionStart = NULL;
	q->sessionStart = NULL;

	return;
}

static void
CloseSessions(
		)
{
	ResetSession(&pcntrl[0],&pcntrl[1]);
	ResetSession(&pcntrl[1],&pcntrl[0]);
	if(pcntrl[0].cntrl)
		OWPControlClose(pcntrl[0].cntrl);
	if(pcntrl[1].cntrl)
		OWPControlClose(pcntrl[1].cntrl);
	pcntrl[0].cntrl = NULL;
	pcntrl[1].cntrl = NULL;

	return;
}

static void
sig_catch(
		int		signo
		)
{
	switch(signo){
		case SIGINT:
		case SIGTERM:
			pow_exit++;
			break;
		case SIGHUP:
			pow_reset++;
			break;
		default:
			I2ErrLog(eh,"sig_catch(%d):UNEXPECTED SIGNAL NUMBER",
									signo);
			exit(1);
	}

	return;
}

static int
sig_check()
{
	if(pow_exit || pow_reset)
		CloseSessions();
	if(pow_exit)
		exit(0);
	if(pow_reset){
		pow_reset = 0;
		return 1;
	}
	
	return 0;
}

static int
SetupSession(
	OWPContext	ctx,
	OWPPerConnData	conndata,
	pow_cntrl	p,	/* connection we are configuring	*/
	pow_cntrl	q,	/* other connection			*/
	OWPTimeStamp	*stop	/* return by this time			*/
	)
{
	OWPErrSeverity	err;
	OWPTimeStamp	currtime;
	OWPnum64	cnum;
	unsigned int	stime;
	int		fd;

	if(p->numPackets)
		return 0;
	/*
	 * First open a connection if we don't have one.
	 */
	while(!p->cntrl){

		if(stop){
			if(!OWPGetTimeOfDay(&currtime)){
				I2ErrLog(eh,"OWPGetTimeOfDay:%M");
				exit(1);
			}

			if(OWPTimeStampCmp(&currtime,stop,>)){
				if(p->sessionStart){
					q->sessionStart = &q->tstamp_mem;
					*q->sessionStart = *p->sessionStart;
				}else
					q->sessionStart = NULL;
				return 0;
			}
		}

		if(!(p->cntrl = OWPControlOpen(ctx,
				OWPAddrByNode(ctx, appctx.opt.srcaddr),
				OWPAddrByNode(ctx, appctx.remote_serv),
				appctx.auth_mode,appctx.opt.identity,
				(void*)conndata, &err))){
			stime = MIN(sessionTime,SETUP_ESTIMATE);
			I2ErrLog(eh,"OWPControlOpen():%M:Retry in-%d seconds",
									stime);
			while((stime = sleep(stime))){
				if(sig_check())
					return 1;
			}
		}
	}
	if(sig_check())
		return 1;

	if(!OWPGetTimeOfDay(&currtime)){
		I2ErrLogP(eh,errno,"OWPGetTimeOfDay:%M");
		exit(1);
	}
	currtime.sec += SETUP_ESTIMATE;

	if(p->sessionStart){
		if(OWPTimeStampCmp(&currtime,p->sessionStart,>))
			p->sessionStart = NULL;
	}

	if(!p->sessionStart){
		p->tstamp_mem = currtime;
		p->sessionStart = &p->tstamp_mem;
	}
	else
		currtime = *p->sessionStart;

	cnum = OWPTimeStamp2num64(p->sessionStart);

	strcpy(&p->fname[file_offset],POWTMPFILEFMT);
	if((fd = mkstemp(p->fname)) < 0){
		I2ErrLog(eh,"mkstemp(%s):%M",p->fname);
		return 0;
	}
	if(!(p->fp = fdopen(fd,"wb+"))){
		I2ErrLog(eh,"fdopen(%s:(%d)):%M",p->fname,fd);
		return 0;
	}
	if(unlink(p->fname) != 0){
		I2ErrLog(eh,"unlink():%M");
		while((fclose(p->fp) != 0) && errno==EINTR);
		p->fp = NULL;
		return 0;
	}

	test_spec.start_time = *p->sessionStart;
	if(!OWPSessionRequest(p->cntrl,
			OWPAddrByNode(ctx,appctx.remote_test),
			True, NULL, False,
			(OWPTestSpec*)&test_spec, p->sid,
			p->fp,&err)){
		while((fclose(p->fp) != 0) && errno==EINTR);
		p->fp = NULL;
		if(err == OWPErrFATAL){
			OWPControlClose(p->cntrl);
			p->cntrl = NULL;
		}
		return 0;
	}
	if(sig_check())
		return 1;

	if(OWPStartSessions(p->cntrl) < OWPErrINFO){
		fclose(p->fp);
		p->fp = NULL;
		OWPControlClose(p->cntrl);
		p->cntrl = NULL;
		return 0;
	}
	p->numPackets = test_spec.npackets;

	cnum += OWPSessionDuration(p->cntrl,p->sid);
	q->sessionStart = &q->tstamp_mem;
	OWPnum64toTimeStamp(q->sessionStart,cnum);

	return 0;
}

static int
WriteSubSession(
		void		*data,
		OWPDataRecPtr	rec
		)
{
	struct pow_parse_rec	*parse = (struct pow_parse_rec*)data;
				/* for alignment */
	u_int32_t		msg[20/sizeof(u_int32_t)];
	u_int8_t		*buf = (u_int8_t*)msg;

	/*
	 * Mark the first offset that has a record greater than this
	 * sub-session so the next sub-session can start searching here.
	 */
	if(!parse->next && (rec->seq_no > parse->last))
		parse->next = parse->begin + parse->i * parse->hdr->rec_size;

	parse->i++;

	if((rec->seq_no < parse->first) || (rec->seq_no > parse->last))
		return 0;

	/*
	 * Short-cut... recv process doesn't put any real data in once
	 * these start, so stop processing now.
	 */
	if(OWPIsLostRecord(rec))
		return 1;

	rec->seq_no -= parse->first;
	parse->seen[rec->seq_no]=True;

	/*
	 * Write rec to fp...
	 * TODO: The format for this changes in V5... Perhaps it should
	 * have an api too, but I need to get this done right now.
	 */
	*(u_int32_t*)&buf[0] = htonl(rec->seq_no);
	OWPEncodeTimeStamp(&buf[4],&rec->send);
	OWPEncodeTimeStamp(&buf[12],&rec->recv);

	if(fwrite(buf,1,20,parse->fp) < 20)
		return -1;

	return 0;
}

static int
WriteSubSessionLost(
	struct pow_parse_rec	*parse
		)
{
				/* for alignment */
	u_int32_t	msg[20/sizeof(u_int32_t)];
	u_int8_t	*buf = (u_int8_t*)msg;
	u_int32_t	i,n;

	memset(msg,0,sizeof(msg));
	n = parse->last - parse->first + 1;

	for(i=0;i<n;i++){
		if(parse->seen[i])
			continue;
		/*
		 * Write 0rec to fp...
		 * TODO: The format for this changes in V5... Perhaps it should
		 * have an api too, but I need to get this done right now.
		 */
		*(u_int32_t*)&buf[0] = htonl(i);
		if(fwrite(buf,1,20,parse->fp) < 20)
			return -1;
	}

	return 0;
}




int
main(
	int	argc,
	char	**argv
)
{
	char			*progname;
	int			lockfd;
	char			lockpath[PATH_MAX];
	int			rc;
	OWPErrSeverity		err_ret = OWPErrOK;
	I2LogImmediateAttr	ia;
	owp_policy_data		*policy;
	OWPContext		ctx;
	OWPPerConnDataRec	conndata;

	int			fname_len;
	int			ch;
	char                    *endptr = NULL;
	char                    optstring[128];
	static char		*conn_opts = "A:S:k:u:";
	static char		*test_opts = "c:i:s:L:";
	static char		*out_opts = "d:I:";
	static char		*gen_opts = "hw";

	int			which=0;	/* which cntrl connect used */
	u_int32_t		numSessions;
	char			dirpath[PATH_MAX];
	u_int32_t		iotime;
	struct pow_parse_rec	parse;
	OWPnum64		*schedule;
	struct flock		flk;
	struct sigaction	act;

	ia.line_info = (I2NAME | I2MSG | I2FILE | I2LINE);
	ia.fp = stderr;

	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	/*
	* Start an error logging session for reporing errors to the
	* standard error
	*/
	eh = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}
	OWPCfg.eh = eh;

	/* Set default options. */
	memset(&appctx,0,sizeof(appctx));
	appctx.opt.numPackets = 300;
	appctx.opt.lossThreshold = 10;
	appctx.opt.meanWait = (float)0.1;
	appctx.opt.seriesInterval = 1;

	/* Create options strings for this program. */
	strcpy(optstring, conn_opts);
	strcat(optstring, test_opts);
	strcat(optstring, out_opts);
	strcat(optstring, gen_opts);
		
	while ((ch = getopt(argc, argv, optstring)) != -1)
             switch (ch) {
		     /* Connection options. */
             case 'A':
		     if (!(appctx.opt.authmode = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
             case 'S':
		     if (!(appctx.opt.srcaddr = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
             case 'u':
		     if (!(appctx.opt.identity = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
	     case 'k':
		     if (!(appctx.opt.passwd = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
             case 'c':
		     appctx.opt.numPackets = strtoul(optarg, &endptr, 10);
		     if (*endptr != '\0') {
			     usage(progname, 
				   "Invalid value. Positive integer expected");
			     exit(1);
		     }
                     break;
             case 'i':
		     appctx.opt.meanWait = (float)(strtod(optarg, &endptr));
		     if (*endptr != '\0') {
			     usage(progname, 
			   "Invalid value. Positive floating number expected");
			     exit(1);
		     }
                     break;
             case 's':
		     appctx.opt.padding = strtoul(optarg, &endptr, 10);
		     if (*endptr != '\0') {
			     usage(progname, 
				   "Invalid value. Positive integer expected");
			     exit(1);
		     }
                     break;
             case 'L':
		     appctx.opt.lossThreshold = strtoul(optarg, &endptr, 10);
		     if (*endptr != '\0') {
			     usage(progname, 
				   "Invalid value. Positive integer expected");
			     exit(1);
		     }
                     break;
#ifndef	NDEBUG
	     case 'w':
		     appctx.opt.childwait = True;
                     break;
#endif

	     case 'd':
		     if (!(appctx.opt.savedir = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
             case 'I':
		     appctx.opt.seriesInterval = strtoul(optarg, &endptr, 10);
		     if (*endptr != '\0') {
			     usage(progname, 
				   "Invalid value. Positive integer expected");
			     exit(1);
		     }
                     break;

		     /* Generic options.*/
             case 'h':
             case '?':
             default:
                     usage(progname, "");
		     exit(0);
		     /* UNREACHED */
             }
	argc -= optind;
	argv += optind;

	if((argc < 1) || (argc > 2)){
		usage(progname, NULL);
		exit(1);
	}

	appctx.remote_test = argv[0];
	if(argc > 1)
		appctx.remote_serv = argv[1];
	else
		appctx.remote_serv = appctx.remote_test;

	/*
	 * This is in reality dependent upon the actual protocol used
	 * (ipv4/ipv6) - it is also dependent upon the auth mode since
	 * authentication implies 128bit block sizes.
	 */
	if(appctx.opt.padding > MAX_PADDING_SIZE)
		appctx.opt.padding = MAX_PADDING_SIZE;

	/*
	 * Check savedir option. Make sure it will not make fnames
	 * exceed PATH_MAX even with the nul byte.
	 * Also set file_offset and ext_offset to the lengths needed.
	 */
	fname_len = 2*OWP_TSTAMPCHARS + strlen(OWP_NAME_SEP) +
		MAX(strlen(OWP_FILE_EXT),strlen(OWP_INCOMPLETE_EXT));
	assert((fname_len+1)<PATH_MAX);
	if(appctx.opt.savedir){
		if((strlen(appctx.opt.savedir) + strlen(OWP_PATH_SEPARATOR)+
						fname_len + 1) > PATH_MAX){
			usage(progname,"-d: pathname too long.");
			exit(1);
		}
		strcpy(dirpath,appctx.opt.savedir);
		strcat(dirpath,OWP_PATH_SEPARATOR);
	}else
		dirpath[0] = '\0';

	/*
	 * Lock the directory for powstream.
	 * (May need a more complex mutex eventually - but for now, just
	 * try and lock it, and fail completely if can't.)
	 * 	could read pid out of file, etc...
	 */
	strcpy(lockpath,dirpath);
	strcat(lockpath,POWLOCK);
	lockfd = open(lockpath,O_RDWR|O_CREAT,
					S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if(lockfd < 0){
	     I2ErrLog(eh,"open(%s):%M",lockpath);
	     exit(1);
	}

	flk.l_start = 0;
	flk.l_len = 0;
	flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;
	while((rc = fcntl(lockfd,F_SETLK,&flk)) < 0 && errno == EINTR);
	if(rc < 0){
		I2ErrLog(eh,"Unable to lock file %s:%M",lockpath);
		if(I2Readn(lockfd,&ch,sizeof(ch)) == sizeof(ch)){
			I2ErrLog(eh,"Possibly locked by pid(%d)",ch);
		}
		exit(1);
	}

	ch = getpid();
	if(I2Writen(lockfd,&ch,sizeof(ch)) != sizeof(ch)){
		I2ErrLog(eh,"Unable to write to lockfile:%M");
		exit(1);
	}

	file_offset = strlen(dirpath);
	ext_offset = file_offset + OWP_TSTAMPCHARS;

	if(!(parse.seen = malloc(sizeof(u_int8_t)*appctx.opt.numPackets))){
		I2ErrLog(eh,"malloc():%M");
		exit(1);
	}

	/*
	 * Determine how many pseudo sessions need to be combined to create
	 * the longer sessionInterval requested.
	 */
	sessionTime = appctx.opt.numPackets * appctx.opt.meanWait;
	numSessions = appctx.opt.seriesInterval/sessionTime;
	if(appctx.opt.seriesInterval%sessionTime)
		numSessions++;

	I2ErrLog(eh,
		"%d sub-sessions per session:approx seriesInterval:%d seconds",
				numSessions,numSessions*sessionTime);

	if(sessionTime <  SETUP_ESTIMATE + appctx.opt.lossThreshold){
		I2ErrLog(eh,"Holes in data are likely because lossThreshold"
				" is too large a fraction of sessionTime");
	}


	test_spec.test_type = OWPTestPoisson;
	test_spec.npackets = appctx.opt.numPackets * numSessions;

	if(!(schedule = malloc(sizeof(OWPnum64)*test_spec.npackets))){
		I2ErrLog(eh,"malloc():%M");
		exit(1);
	}

	/*
	 * TODO: Figure out typeP...
	 */
	test_spec.typeP = 0;      /* so it's in host byte order then */
	test_spec.packet_size_padding = appctx.opt.padding;

	/* InvLambda is mean wait time in usec */
	test_spec.InvLambda = (double)1000000.0 * appctx.opt.meanWait;

	conndata.pipefd = -1;
	owp_set_auth(&appctx, &policy, progname, ctx); 
	conndata.policy = policy;
	conndata.node = NULL;

#ifndef	NDEBUG
	conndata.childwait = appctx.opt.childwait;
#endif

	/*
	 * Set the connect timeout to the lossThreshold.
	 */
	OWPCfg.tm_out.tv_sec = appctx.opt.lossThreshold;

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(appctx.lib_ctx = OWPContextInitialize(&OWPCfg))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}
	ctx = appctx.lib_ctx;

	/*
	 * Hack to set lossThreshold for v3 of protocol. Fixed in v5.
	 */
	conndata.lossThreshold = appctx.opt.lossThreshold;

	memset(&pcntrl,0,2*sizeof(pow_cntrl_rec));
	strcpy(pcntrl[0].fname,dirpath);
	strcpy(pcntrl[1].fname,dirpath);

	/*
	 * Add time for file buffering. (Buffering is
	 * optimized to try and keep only one second
	 * of data buffered, but that doesn't work if
	 * the mean interval is greater than 1 second.
	 * So, add 2 seconds to the max of (1,-i).
	 * (2 seconds is because the recv process waits 1 after the end
	 * of the test before it does it's clean-up, and we want to wait
	 * until it is done with it's clean-up.)
	 */
	iotime = MAX(appctx.opt.meanWait,1) + 2;

	/*
	 * Setup signal handlers.
	 */
	pow_reset = 0;
	pow_exit = 0;
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if(		(sigaction(SIGUSR1,&act,NULL) != 0) ||
			(sigaction(SIGUSR2,&act,NULL) != 0)){
		I2ErrLog(eh,"sigaction():%M");
		exit(1);
	}

	act.sa_handler = sig_catch;

	if(	(sigaction(SIGTERM,&act,NULL) != 0) ||
		(sigaction(SIGINT,&act,NULL) != 0) ||
		(sigaction(SIGHUP,&act,NULL) != 0)){
		I2ErrLog(eh,"sigaction():%M");
		exit(1);
	}

	/*
	 * Main loop - loop over two connections collecting the data
	 * and placing it in the directory when the sub-session is complete.
	 *
	 * (Complete here just means that the receiver declares the session
	 * over - we don't have enough information to "validate" the data -
	 * that will happen at the collector which will have all up/down
	 * time information for every node in the mesh.)
	 *
	 * Here is a rough outline of the algorithm:
	 * wait(): collects outstanding sessions
	 * setup(): sets up and kick's off sessions (may including connecting)
	 *
	 * 		conn #1		conn #2
	 * 		wait()*
	 * 		setup()
	 * 				wait()*
	 * 				setup()
	 * 		wait()
	 * 		setup()
	 * 				wait()
	 * 				setup()
	 * 		...
	 * 		...
	 *
	 * *first time does nothing since there are no outstanding sessions.
	 *
	 * Eventually handle signals...
	 */
	while(1){
		pow_cntrl		p,q;
		int			call_stop;
		OWPAcceptType		aval;
		u_int32_t		sub;
		OWPTimeStamp		stop;
		OWPnum64		*schedptr;
		OWPnum64		sessionStartnum,startnum,lastnum;

NextConnection:
		sig_check();
		/*
		 * p is the "connection" we are dealing with this loop
		 * iteration. We need a pointer to q to tell it what series
		 * start time to use based upon the end of the p series.
		 */
		p = &pcntrl[which++];
		which %= 2;
		q = &pcntrl[which];

		if(!p->numPackets){
			(void)SetupSession(ctx,&conndata,q,p,NULL);
			goto NextConnection;
	
		}

		/* init vars for loop */
		parse.begin=0;
		lastnum=0;
		call_stop = True;
		schedptr = OWPSessionSchedule(p->cntrl,p->sid);
		assert(schedptr);
		memcpy(schedule,schedptr,sizeof(OWPnum64)*test_spec.npackets);
		sessionStartnum = OWPTimeStamp2num64(p->sessionStart);

		/*
		 * This loops on each "sub" session - it completes when
		 * there are no more sub-sessions to fetch - i.e. the real
		 * test session is complete.
		 */
		for(sub=0;sub<numSessions;sub++){
			char			fname[PATH_MAX];
			char			endname[PATH_MAX];
			char			newpath[PATH_MAX];
			u_int32_t		nrecs;
			u_int32_t		hlen;
			OWPSessionHeaderRec	hdr;
			OWPnum64		stopnum;

			if(sig_check())
				goto NextConnection;

			memset(parse.seen,0,
				sizeof(*parse.seen)*appctx.opt.numPackets);
			parse.first = appctx.opt.numPackets*sub;
			parse.last = (appctx.opt.numPackets*(sub+1))-1;
			parse.i = 0;
			parse.next = 0;

			/*
			 * lastnum contains offset for previous sub.
			 * So - sessionStart + lastnum is new
			 * startnum.
			 */
			startnum = sessionStartnum + lastnum;

			/*
			 * set stopnum to time of final packet.
			 */
			lastnum = schedule[parse.last];
			stopnum = sessionStartnum+lastnum;

			/*
			 * set stop to the time we should collect this
			 * session.
			 */
			OWPnum64toTimeStamp(&stop,stopnum);

			/*
			 * subsession can't be over until after
			 * lossThresh, then add iotime.
			 */
			stop.sec += appctx.opt.lossThreshold + iotime;

			/*
			 * Now try and setup the next session.
			 * SetupSession checks for reset signals, and returns
			 * non-zero if one happend.
			 */
			if(SetupSession(ctx,&conndata,q,p,&stop))
				goto NextConnection;
AGAIN:
			/*
			 * Wait until this "subsession" is complete.
			 */
			if(call_stop)
				rc = OWPStopSessionsWait(p->cntrl,&stop,&aval,
								&err_ret);
			else
				rc=1; /* no more data coming */

			if(rc<0){
				/* error */
				OWPControlClose(p->cntrl);
				p->cntrl = NULL;
				break;
			}
			if(rc==0){
				/* session over */
				call_stop = False;
				/*
				 * If aval non-zero, session data is invalid.
				 */
				if(aval)
					break;
			}
			if(rc==2){
				/* system event - eventually handle
				 * signals here. (reopen connections,
				 * unlink files - whatever.)
				 */
				if(sig_check())
					goto NextConnection;
				goto AGAIN;
			}
			/* Else - time's up! Get to work.	*/

			nrecs = OWPReadDataHeader(ctx,p->fp,&hlen,&hdr);
			parse.hdr = &hdr;

			/*
			 * Modify hdr for subsession.
			 */
			OWPnum64toTimeStamp(&hdr.test_spec.any.start_time,
								startnum);
			hdr.test_spec.any.npackets = appctx.opt.numPackets;

			/*
			 * Position of first record we need to look at.
			 */
			if(parse.begin < hlen)
				parse.begin = hlen;
			if(fseeko(p->fp,parse.begin,SEEK_SET) != 0){
				I2ErrLog(eh,"fseeko():%M");
				exit(1);
			}

			/*
			 * How many records from "begin" to end of file.
			 */
			if(nrecs)
				nrecs -= (parse.begin-hlen)/hdr.rec_size;
			/*
			 * No more data to parse.
			 */
			if(!call_stop && !nrecs)
				break;

			/*
			 * Open a file for the sub-session
			 */
			strcpy(fname,dirpath);
			sprintf(&fname[file_offset],OWP_TSTAMPFMT,startnum);
			strcpy(&fname[ext_offset],OWP_INCOMPLETE_EXT);
			while(!(parse.fp = fopen(fname,"wb+")) && errno==EINTR);
			if(!parse.fp){
				I2ErrLog(eh,"fopen(%s):%M",fname);
				/*
				 * Can't open the file.
				 */
				switch(errno){
					/*
					 * reasons to go to the next
					 * sub-session
					 * (Temporary resource problems.)
					 */
					case ENOMEM:
					case EMFILE:
					case ENFILE:
					case ENOSPC:
						break;
					/*
					 * Everything else is a reason to exit
					 * (Probably permissions.)
					 */
					default:
						exit(1);
						break;
				}

				/*
				 * Skip to next sub-session.
				 */
				continue;
			}

			/*
			 * New file is created - all errors from here to
			 * the end of the loop are sent to the error handling
			 * section at the end of the loop.
			 */

			/* write the file header */
			if(OWPWriteDataHeader(ctx,parse.fp,&hdr) != 0){
				I2ErrLog(eh,"OWPWriteDataHeader:%M");
				goto error;
			}

			/* write relevant records to file */
			if(OWPParseRecords(p->fp,nrecs,&hdr,
					WriteSubSession,&parse) != OWPErrOK){
				I2ErrLog(eh,"WriteSubSession:???:%M");
				goto error;
			}

			if(WriteSubSessionLost(&parse)){
				I2ErrLog(eh,"WriteSubSessionLost:???:%M");
				goto error;
			}

			/*
			 * Flush the FILE before linking to the "complete"
			 * name.
			 */
			fflush(parse.fp);

			sprintf(endname,OWP_TSTAMPFMT,stopnum);
			strcpy(newpath,fname);
			sprintf(&newpath[ext_offset],"%s%s%s",
					OWP_NAME_SEP,endname,OWP_FILE_EXT);
			if(link(fname,newpath) != 0){
				I2ErrLog(eh,"link():%M");
			}
error:
			fclose(parse.fp);
			parse.fp = NULL;
			/* unlink old name */
			if(unlink(fname) != 0){
				I2ErrLog(eh,"unlink():%M");
			}

			/*
			 * Setup begin offset for next time around.
			 */
			if(parse.next)
				parse.begin = parse.next;
			else
				parse.begin += parse.i * hdr.rec_size;

		}

		if(p->cntrl && call_stop){
			if(OWPStopSessions(p->cntrl,&aval) < OWPErrWARNING){
				OWPControlClose(p->cntrl);
				p->cntrl = NULL;
			}
		}
		/*
		 * This session is complete - reset p.
		 */
		p->numPackets = 0;
		while((fclose(p->fp) != 0) && errno==EINTR);
		p->fp = NULL;

		if(sub < numSessions){
			/*
			 * This session ended prematurely - q needs to
			 * be reset for an immediate start time!.
			 */
			ResetSession(q,p);
		}
	}

	exit(0);
}
