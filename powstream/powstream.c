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
#include <string.h>
#include <ctype.h>
#include <netdb.h>

#include <I2util/util.h>
#include <owamp/owamp.h>
#include <owamp/conndata.h>
#include <owamp/access.h>

#include "./powstreamP.h"

/*
 * The powstream context
 */
static	powapp_trec	appctx;
static	I2ErrHandle	eh;
static	pow_cntrl_rec	pcntrl[2];

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

int
main(
	int	argc,
	char	**argv
)
{
	char			*progname;
	OWPErrSeverity		err_ret = OWPErrOK;
	I2LogImmediateAttr	ia;
	owp_policy_data		*policy;
	OWPContext		ctx;
	OWPTestSpecPoisson	test_spec;
	OWPPerConnDataRec	conndata;

	int			ch;
	char                    *endptr = NULL;
	char                    optstring[128];
	static char		*conn_opts = "A:S:k:u:";
	static char		*test_opts = "c:i:s:L:";
	static char		*out_opts = "d:I:";
	static char		*gen_opts = "hw";

	struct timeval		delay_tval;
	u_int32_t		numSessions,seriesTime,setupTime;
	int			which=0;	/* which cntrl connect used */
	u_int32_t		file_offset;
	u_int32_t		ext_offset;
	char			dirpath[PATH_MAX];
	u_int32_t		s;
	unsigned int		delay,stime;

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
	appctx.opt.lossThreshold = 120;
	appctx.opt.meanWait = (float)0.1;

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
	ch = 2*OWP_TSTAMPCHARS + strlen(OWP_NAME_SEP) +
		MAX(strlen(OWP_FILE_EXT),strlen(OWP_INCOMPLETE_EXT));
	assert((ch+1)<PATH_MAX);
	if(appctx.opt.savedir){
		if((strlen(appctx.opt.savedir) + strlen(OWP_PATH_SEPARATOR)+
							ch + 1) > PATH_MAX){
			usage(progname,"-d: pathname too long.");
			exit(1);
		}
		strcpy(dirpath,appctx.opt.savedir);
		strcat(dirpath,OWP_PATH_SEPARATOR);
	}else
		dirpath[0] = '\0';

	file_offset = strlen(dirpath);
	ext_offset = file_offset + OWP_TSTAMPCHARS;

	owp_set_auth(&appctx, &policy, progname, ctx); 

	test_spec.test_type = OWPTestPoisson;
	test_spec.npackets = appctx.opt.numPackets;

	/*
	 * TODO: Figure out typeP...
	 */
	test_spec.typeP = 0;      /* so it's in host byte order then */
	test_spec.packet_size_padding = appctx.opt.padding;

	/* InvLambda is mean wait time in usec */
	test_spec.InvLambda = (double)1000000.0 * appctx.opt.meanWait;

	conndata.pipefd = -1;
	conndata.policy = policy;
	conndata.node = NULL;

#ifndef	NDEBUG
	conndata.childwait = appctx.opt.childwait;
#endif

	/*
	 * Set the connect timeout to the lossThreshold. This ensures
	 * we have enough time to read current session while still trying
	 * to reconnect in the case of a broken control connection.
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
	 * Open initial connection to owampd. (This one must succeed before
	 * we can continue since we need the delay estimate.)
	 */

	while(!(pcntrl[0].cntrl = OWPControlOpen(ctx, 
					OWPAddrByNode(ctx, appctx.opt.srcaddr),
					OWPAddrByNode(ctx, appctx.remote_serv),
					appctx.auth_mode, 
					appctx.opt.identity,
					(void*)&conndata, &err_ret))){

		stime = RTT_REQ_ESTIMATE;
		I2ErrLog(eh, "OWPControlOpen():%M...Retrying in %d seconds",
				stime);
		while((stime = sleep(stime)));
	}

	OWPGetDelay(pcntrl[0].cntrl,&delay_tval);
	delay = delay_tval.tv_sec;
	delay++;	/* add one sec for file creation time.	*/
	delay++;	/* add one sec to round to seconds	*/
	delay = MAX(delay,RTT_REQ_ESTIMATE);

	/*
	 * Hack to set lossThreshold for v3 of protocol. Fixed in v5.
	 */
	conndata.lossThreshold = appctx.opt.lossThreshold;

	/*
	 * Determine how many test sessions should be in a "series".
	 *
	 * Assume a test request will take ~1 delay_tval. And then a
	 * StartSessions message will also take ~1 delay_tval.
	 * And, being very pessimistic, assume you have to completely
	 * reinitialize the control connection - ~2 delay_tval. This
	 * makes numSessions+4 delay times.
	 * The length of time a series takes MUST be greater than the length
	 * of time it takes to set up that series by a "reasonable" amount
	 * to ensure each test session series is stiched right up to the
	 * one before it. To ensure this "reasonable" amount, delay can
	 * not be larger than .5 of the mean session duration.
	 */
	if(delay >= (u_int32_t)(appctx.opt.numPackets*appctx.opt.meanWait*0.5)){
		I2ErrLog(eh,"Individual test sessions are too small.\n"
			"(It can take more time to set one  up than for\n"
			"it to occur.)");
		exit(1);
	}

	/*
	 * First make sure numSessions is enough to allow time to setup
	 * a series.
	 */
	numSessions = 0;
	do{
		numSessions++;
		seriesTime = numSessions *
				appctx.opt.numPackets * appctx.opt.meanWait;
		setupTime = (numSessions+4) * delay;
	} while(seriesTime < (setupTime + appctx.opt.lossThreshold));

	/*
	 * Now - ensure it is at least as long as the user requested.
	 * (This also ensures that numSessions is at least 1 greater than
	 * needed for setupTime/lossThreshold. This is the "reasonable"
	 * amount from the comment above. We will see with use how well
	 * this guess works...)
	 */
	do{
		numSessions++;
		seriesTime = numSessions *
				appctx.opt.numPackets * appctx.opt.meanWait;
		setupTime = (numSessions+4) * delay;
	} while(seriesTime < appctx.opt.seriesInterval);

	I2ErrLog(eh,"%d sessions per/series:approx seriesInterval:%d seconds",
							numSessions,seriesTime);
	pcntrl[0].sessions = calloc(numSessions,sizeof(pow_session_rec));
	pcntrl[1].sessions = calloc(numSessions,sizeof(pow_session_rec));
	if(!pcntrl[0].sessions || !pcntrl[1].sessions){
		I2ErrLog(eh,"calloc(%d,%d):%M",numSessions,
						sizeof(pow_session_rec));
		exit(1);
	}

	if(appctx.opt.savedir)
		for(s=0;s<numSessions;s++){
			strcpy(pcntrl[0].sessions[s].fname_mem,dirpath);
			strcpy(pcntrl[1].sessions[s].fname_mem,dirpath);
		}

	/*
	 * Main loop - loop over two connections collecting the data
	 * and placing it in the directory when the session is complete.
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
		pow_cntrl	p,q;
		pow_session	tst;
		OWPTimeStamp	endtime;
		OWPTimeStamp	currtime;
		int		call_stop;
		OWPAcceptType	series_aval;
		OWPnum64	cnum,dnum;

NextConnection:
		/*
		 * p is the "connection" we are dealing with this loop
		 * iteration. We need a pointer to q to tell it what series
		 * start time to use based upon the end of the p series.
		 */
		p = &pcntrl[which++];
		which %= 2;
		q = &pcntrl[which];

		/*
		 * First wait for all active sessions on this
		 * connection to complete.
		 */
		call_stop = (p->activeSessions)?True:False;
		series_aval = OWP_CNTRL_ACCEPT;
		for(s=0;s<p->activeSessions;s++){
			OWPAcceptType	aval;
			int		rc;

			tst = &p->sessions[s];
			if(!tst->fp)
				continue;

			OWPnum64toTimeStamp(&endtime,tst->end);
			endtime.sec += appctx.opt.lossThreshold;
			endtime.sec++;	/* allow some system time. */

			aval = OWP_CNTRL_INVALID;
			if(OWPSessionStatus(p->cntrl,tst->sid,False,&aval)){
				while(p->cntrl && call_stop && (aval < 0)){
					rc = OWPStopSessionsWait(p->cntrl,
						&endtime,&series_aval,&err_ret);
					if(rc<0){
						/* error */
						OWPControlClose(p->cntrl);
						p->cntrl = NULL;
					}
					if(rc<1){
						call_stop = False;
						break;
					}
					/*
					 * If time is up, or signal received,
					 * get the session status.
					 */
					if(!OWPSessionStatus(p->cntrl,tst->sid,
							False,&aval))
						break;
					if(rc==1)	/* times up. */
						break;
					/*
					 * TODO: Check for signal indicating
					 * other node may have restarted. Add
					 * logic here to check, and invalidate
					 * current connections if true.
					 * if(chk_cntrlstatus_sig_received)
					 * 	....
					 */
				}
			}

			if(!call_stop)
				aval = series_aval;

			/*
			 *  test is over...
			 */
			if(!aval){
				/* success - rename the file. */
				char	endname[PATH_MAX];
				char	newpath[PATH_MAX];

				sprintf(endname,OWP_TSTAMPFMT,tst->end);
				strcpy(newpath,tst->fname);
				sprintf(&newpath[ext_offset],"%s%s%s",
					OWP_NAME_SEP,endname,OWP_FILE_EXT);

				if(link(tst->fname,newpath) != 0){
					I2ErrLog(eh,"link():%M");
				}
			}

			fclose(tst->fp);
			tst->fp = NULL;
			if(unlink(tst->fname) != 0){
				I2ErrLog(eh,"unlink():%M");
			}
			tst->fname = NULL;
		}
		p->activeSessions = 0;

		if(p->cntrl && call_stop){
			if(OWPStopSessions(p->cntrl,&series_aval) <
								OWPErrWARNING){
				OWPControlClose(p->cntrl);
				p->cntrl = NULL;
			}
		}

		/*
		 * Now setup new sessions on this connection.
		 */

		/*
		 * First open a connection if we don't have one.
		 */
		delay = delay_tval.tv_sec;
		while(!p->cntrl){

			if(p->seriesStart){
				/*
				 * Fail out of here if we need to go
				 * to the other connection and collect it's
				 * sessions.
				 * Basically, we fail out of here if we can't
				 * open the connection before we get within
				 * "setupTime" of when we should start
				 * new sessions.
				 * (Most likely that control connection will
				 * fail as well - so it will end up in this
				 * loop too, but if not - it has a better
				 * chance of starting them on time.)
				 */
				if(!OWPGetTimeOfDay(&currtime)){
					I2ErrLog(eh,"OWPGetTimeOfDay:%M");
					exit(1);
				}
				currtime.sec += setupTime;

				if(OWPTimeStampCmp(&currtime,p->seriesStart,>)){
					q->seriesStart = p->seriesStart;
					p->seriesStart = NULL;
					goto NextConnection;
				}
			}

			if(!(p->cntrl = OWPControlOpen(ctx,
					OWPAddrByNode(ctx, appctx.opt.srcaddr),
					OWPAddrByNode(ctx, appctx.remote_serv),
					appctx.auth_mode,appctx.opt.identity,
					(void*)&conndata, &err_ret))){
				I2ErrLog(eh,
				"OWPControlOpen():%M:Retry-%d seconds",delay);
				stime = delay;
				while((stime = sleep(stime)));
				delay *= 2;
				if(delay > RTT_REQ_ESTIMATE)
					delay = RTT_REQ_ESTIMATE;
			}
		}

		if(!OWPGetTimeOfDay(&currtime)){
			I2ErrLogP(eh,errno,"OWPGetTimeOfDay:%M");
			exit(1);
		}
		currtime.sec += setupTime;

		if(p->seriesStart){
			if(OWPTimeStampCmp(&currtime,p->seriesStart,>))
				p->seriesStart = NULL;
		}

		if(!p->seriesStart){
			p->tstamp_mem = currtime;
			p->seriesStart = &p->tstamp_mem;
			p->seriesStart->sec += setupTime;
		}

		currtime = *p->seriesStart;
		cnum = OWPTimeStamp2num64(&currtime);
		for(s=0;s<numSessions;s++){

			/*
			 * Setup sessions.
			 */
			tst = &p->sessions[s];

			tst->fname = tst->fname_mem;
			sprintf(&tst->fname[file_offset],OWP_TSTAMPFMT,cnum);
			strcpy(&tst->fname[ext_offset],OWP_INCOMPLETE_EXT);

			if(!(tst->fp = fopen(tst->fname,"wb+"))){
				I2ErrLog(eh,"fopen(%s):%M");
				break;
			}

			test_spec.start_time = currtime;
			if(!OWPSessionRequest(p->cntrl,
					OWPAddrByNode(ctx,appctx.remote_test),
					True, NULL, False,
					(OWPTestSpec*)&test_spec, tst->sid,
					tst->fp,&err_ret)){
				/*
				 * It doesn't really matter why the
				 * request failed... we just break out
				 * and let the next connection try and
				 * set it up.
				 */
				fclose(tst->fp);
				tst->fp = NULL;
				tst->fname = NULL;
				break;
			}
			dnum = OWPSessionDuration(p->cntrl,tst->sid);
			cnum += dnum;
			tst->end = cnum;
			OWPnum64toTimeStamp(&currtime,cnum);
		}

		if(s && (OWPStartSessions(p->cntrl) >= OWPErrINFO))
			p->activeSessions = s;

		if(p->activeSessions){
			q->tstamp_mem = currtime;
			q->seriesStart = &q->tstamp_mem;
		}else{
			q->seriesStart = NULL;
		}

	}

	exit(0);
}
