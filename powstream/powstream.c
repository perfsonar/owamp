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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <assert.h>
#include <syslog.h>
#include <math.h>

#include <owamp/owamp.h>


#if defined HAVE_DECL_OPTRESET && !HAVE_DECL_OPTRESET
int optreset;
#endif

#include "./powstreamP.h"

/*
 * This just ensures the padding requested fits in the "type" used to
 * make the request from the command-line options. (If the padding requested
 * is larger than is possible due to IP/UDP/OWAMP headers - then the
 * TestRequest will be denied, but this isn't easily checked during
 * initial command-line option parsing because of the dependancies involved.)
 */
#define	MAX_PADDING_SIZE	0xFFFF


/*
 * The powstream context
 */
static	powapp_trec		appctx;
static	I2ErrHandle		eh;
static	pow_cntrl_rec		pcntrl[2];
static	OWPTestSpec		tspec;
static	OWPSlot			slot;
static	u_int32_t		sessionTime;
static	u_int32_t		file_offset,ext_offset;
static	int			pow_reset = 0;
static	int			pow_exit = 0;

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
"   -c count       number of test packets (per file)\n"
"   -i wait        mean average time between packets (seconds)\n"
"   -L timeout     maximum time to wait for a packet (seconds)\n"
"   -s padding     size of the padding added to each packet (bytes)\n");
}

static void
print_output_args()
{
	fprintf(stderr,
		"              [Output Args]\n\n"
		"   -d dir         directory to save session file in\n"
		"   -I Interval    duration for OWP test sessions(seconds)\n"
		"   -p             print completed filenames to stdout\n"
		"   -b bucketWidth create summary files with buckets(seconds)\n"
		"   -h             print this message and exit\n"
		"   -e             syslog facility to log to\n"
		);
}

static void
usage(const char *progname, const char *msg)
{
	if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
	fprintf(stderr,"usage: %s %s\n", 
			progname,
			 "[arguments] testaddr [servaddr]"
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
owp_set_auth(
	powapp_trec	*pctx, 
	char		*progname,
	OWPContext	ctx __attribute__((unused))
	)
{
#if	NOT
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
#endif


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

static void
ResetSession(
	pow_cntrl	p,	/* connection we are configuring	*/
	pow_cntrl	q	/* other connection			*/
	)
{
	OWPAcceptType	aval = OWP_CNTRL_ACCEPT;
	int		intr=1;

	if(p->numPackets && p->cntrl &&
			(OWPStopSessions(p->cntrl,&intr,&aval)<OWPErrWARNING)){
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
	if(pow_exit || pow_reset){
		CloseSessions();
	}
	if(pow_exit){
		exit(0);
	}
	if(pow_reset){
		pow_reset = 0;
		return 1;
	}
	
	return 0;
}

static int
SetupSession(
	OWPContext	ctx,
	pow_cntrl	p,	/* connection we are configuring	*/
	pow_cntrl	q,	/* other connection			*/
	OWPNum64	*stop	/* return by this time			*/
	)
{
	OWPErrSeverity	err;
	OWPTimeStamp	currtime;
	unsigned int	stime;
	int		fd;
	u_int64_t	i;

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

			if(OWPNum64Cmp(currtime.owptime,*stop) > 0){
				if(p->sessionStart){
					q->sessionStart = &q->owptime_mem;
					*q->sessionStart = *p->sessionStart;
				}else
					q->sessionStart = NULL;
				return 0;
			}
		}

		if(!p->sctx){
			if(!(p->sctx = OWPScheduleContextCreate(ctx,p->sid,
								&tspec))){
				I2ErrLog(eh,"OWPScheduleContextCreate: %M");
				while((stime = sleep(stime))){
					if(sig_check())
						return 1;
				}
				continue;
			}
		}

		if(!(p->cntrl = OWPControlOpen(ctx,
				OWPAddrByNode(ctx, appctx.opt.srcaddr),
				OWPAddrByNode(ctx, appctx.remote_serv),
				appctx.auth_mode,appctx.opt.identity,
				NULL,&err))){
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
	currtime.owptime = OWPNum64Add(currtime.owptime,
				OWPULongToNum64(SETUP_ESTIMATE));

	if(p->sessionStart){
		if(OWPNum64Cmp(currtime.owptime,*p->sessionStart) > 0){
			p->sessionStart = NULL;
		}
	}

	if(!p->sessionStart){
		p->owptime_mem = currtime.owptime;
		p->sessionStart = &p->owptime_mem;
	}

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

	tspec.start_time = *p->sessionStart;
	if(!OWPSessionRequest(p->cntrl,OWPAddrByNode(ctx,appctx.remote_test),
				True, NULL, False,
				(OWPTestSpec*)&tspec,p->fp,p->sid,&err)){
		I2ErrLog(eh,"OWPSessionRequest: Failed");
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
		I2ErrLog(eh,"OWPStartSessions: Failed");
		fclose(p->fp);
		p->fp = NULL;
		OWPControlClose(p->cntrl);
		p->cntrl = NULL;
		return 0;
	}

	/*
	 * Assign new sid to schedule context.
	 */
	if(OWPScheduleContextReset(p->sctx,p->sid,&tspec) != OWPErrOK){
		I2ErrLog(eh,"Schedule Initialization Failed");
		fclose(p->fp);
		p->fp = NULL;
		OWPControlClose(p->cntrl);
		p->cntrl = NULL;
		return 0;
	}

	p->numPackets = tspec.npackets;

	/*
	 * Set q->owptime_mem to end of p's session. (First use p's start
	 * time and then go through the schedule and add p's "duration"
	 * to get q's start time.
	 */
	q->owptime_mem = *p->sessionStart;
	for(i=0;i<p->numPackets;i++){
		q->owptime_mem = OWPNum64Add(q->owptime_mem,
				OWPScheduleContextGenerateNextDelta(p->sctx));
	}
	q->sessionStart = &q->owptime_mem;

	/*
	 * Reset the schedule index's. (shouldn't be possible to fail that
	 * part...)
	 */
	(void)OWPScheduleContextReset(p->sctx,NULL,NULL);

	return 0;
}

static int
WriteSubSession(
		OWPDataRec	*rec,
		void		*data
		)
{
	struct pow_parse_rec	*parse = (struct pow_parse_rec*)data;

	/*
	 * Mark the first offset that has a record greater than this
	 * sub-session so the next sub-session can start searching here.
	 */
	if(!parse->next && (rec->seq_no > parse->last))
		parse->next = parse->begin + parse->i * parse->hdr->rec_size;

	parse->i++;

	if((rec->seq_no < parse->first) || (rec->seq_no > parse->last))
		return 0;

	rec->seq_no -= parse->first;
	parse->seen[rec->seq_no].seen++;

	if(OWPWriteDataRecord(parse->ctx,parse->fp,rec) != 0){
		return -1;
	}

	if(parse->buckets && !OWPIsLostRecord(rec)){
		I2Datum	key,val;
		double	d;
		int	b;

		/*
		 * If either side is unsynchronized, record that.
		 */
		if(!rec->send.sync || !rec->recv.sync){
			parse->sync = 0;
		}
		/*
		 * Comute error from send/recv.
		 */
		d = OWPGetTimeStampError(&rec->send) +
					OWPGetTimeStampError(&rec->recv);
		parse->maxerr = MAX(parse->maxerr,d);

		/*
		 * Compute bucket value.
		 */
		d = OWPDelay(&rec->send,&rec->recv)/appctx.opt.bucketWidth;
		b = (d<0)?floor(d):ceil(d);

		key.dsize = b;
		key.dptr = &key.dsize;
		if(I2HashFetch(parse->buckets,key,&val)){
			(*(u_int32_t*)val.dptr)++;
		}
		else{
			val.dsize = sizeof(u_int32_t);
			val.dptr = &parse->bucketvals[parse->nbuckets];
			parse->bucketvals[parse->nbuckets++] = 1;

			if(I2HashStore(parse->buckets,key,val) != 0){
				I2ErrLog(eh,
				"I2HashStore(): Unable to store bucket!");
				return -1;
			}

		}
	}

	return 0;
}

static int
WriteSubSessionLost(
	struct pow_parse_rec	*parse
		)
{
	u_int32_t	i,n;
	OWPDataRec	rec;

	memset(&rec,0,sizeof(rec));

	n = parse->last - parse->first + 1;

	for(i=0;i<n;i++){
		if(parse->seen[i].seen){
			parse->dups += (parse->seen[i].seen - 1);
			continue;
		}
		parse->lost++;

		rec.seq_no = i;
		rec.send.owptime = parse->seen[i].sendtime;

		if(OWPWriteDataRecord(parse->ctx,parse->fp,&rec) != 0){
			return -1;
		}
	}

	return 0;
}

static u_int32_t
inthash(
	I2Datum	key
	)
{
	return (u_int32_t)key.dsize;
}

static int
intcmp(
	const I2Datum	x,
	const I2Datum	y
	)
{
	return(x.dsize != y.dsize);
}

static I2Boolean
PrintBuckets(
	I2Datum	key,
	I2Datum	value,
	void	*data
	)
{
	struct pow_parse_rec	*parse = (struct pow_parse_rec*)data;

	fprintf(parse->sfp,"\t%d\t%u\n",(int)key.dsize,*(u_int32_t*)value.dptr);
	if(I2HashDelete(parse->buckets,key) != 0){
		I2ErrLog(eh,"I2HashDelete(): Unable to remove bucket!");
		parse->bucketerror = True;
		return False;
	}

	return True;
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
	I2ErrLogSyslogAttr	syslogattr;
	OWPContext		ctx;

	int			fname_len;
	int			ch;
	char                    *endptr = NULL;
	char                    optstring[128];
	static char		*conn_opts = "A:S:k:u:";
	static char		*test_opts = "c:i:s:L:";
	static char		*out_opts = "d:I:pe:rb:";
	static char		*gen_opts = "hw";

	int			which=0;	/* which cntrl connect used */
	u_int32_t		numSessions;
	char			dirpath[PATH_MAX];
	u_int32_t		iotime;
	struct pow_parse_rec	parse;
	struct flock		flk;
	struct sigaction	act;

	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	/* Create options strings for this program. */
	strcpy(optstring, conn_opts);
	strcat(optstring, test_opts);
	strcat(optstring, out_opts);
	strcat(optstring, gen_opts);
		

	syslogattr.ident = progname;
	syslogattr.logopt = LOG_PID;
	syslogattr.facility = LOG_USER;
	syslogattr.priority = LOG_ERR;
	syslogattr.line_info = I2MSG;
#ifndef	NDEBUG
	syslogattr.line_info |= I2FILE | I2LINE;
#endif

	opterr = 0;
	while((ch = getopt(argc, argv, optstring)) != -1){
		if(ch == 'e'){
			int fac;
			if((fac = I2ErrLogSyslogFacility(optarg)) == -1){
				fprintf(stderr,
				"Invalid -e: Syslog facility \"%s\" unknown\n",
				optarg);
				exit(1);
			}
			syslogattr.facility = fac;
		}
		else if(ch == 'r'){
			syslogattr.logopt |= LOG_PERROR;
		}
	}
	opterr = optreset = optind = 1;

	/*
	* Start an error logging session for reporing errors to the
	* standard error
	*/
	eh = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);
	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

	/* Set default options. */
	memset(&appctx,0,sizeof(appctx));
	appctx.opt.numPackets = 300;
	appctx.opt.lossThreshold = 10.0;
	appctx.opt.meanWait = (float)0.1;
	appctx.opt.seriesInterval = 1;

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
			appctx.opt.meanWait = strtod(optarg, &endptr);
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
			appctx.opt.lossThreshold = strtod(optarg, &endptr);
			if((*endptr != '\0') || (appctx.opt.lossThreshold < 0)){
				usage(progname, 
			"Invalid value. Positive floating number expected");
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
			appctx.opt.seriesInterval =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'p':
			appctx.opt.printfiles = True;
			break;
		case 'b':
			/* TODO: Add -b option to powmaster */
			appctx.opt.bucketWidth = strtod(optarg, &endptr);
			if (*endptr != '\0') {
				usage(progname, 
			"Invalid value. Positive floating number expected");
				exit(1);
			}
			break;
		case 'e':
		case 'r':
			/* handled in prior getopt call... */
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
		strlen(OWP_FILE_EXT) + strlen(SUMMARY_EXT);
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

	memset(&parse,0,sizeof(struct pow_parse_rec));
	if(!(parse.seen = malloc(sizeof(pow_seen_rec)*appctx.opt.numPackets))){
		I2ErrLog(eh,"malloc(): %M");
		exit(1);
	}
	if(appctx.opt.bucketWidth != 0.0){

		/*
		 * NOTE:
		 * Will use the dsize of the key datum to actually hold
		 * the bucket index, therefore I need to install the cmp
		 * and hash functions. The "actual" datatype is 'unsigned'
		 * so be careful to cast appropriately.
		 */
		if(!(parse.buckets = I2HashInit(eh,0,intcmp,inthash))){
			I2ErrLog(eh,"I2HashInit(): %M");
			exit(1);
		}
		/*
		 * Can't use more buckets than we have packets, so this is
		 * definitely enough memory.
		 */
		if(!(parse.bucketvals = malloc(sizeof(u_int32_t) *
						appctx.opt.numPackets))){
			I2ErrLog(eh,"malloc(): %M");
			exit(1);
		}
		parse.nbuckets = 0;
	}


	/*
	 * Determine how many pseudo sessions need to be combined to create
	 * the longer sessionInterval requested.
	 */
	sessionTime = appctx.opt.numPackets * appctx.opt.meanWait;
	numSessions = appctx.opt.seriesInterval/sessionTime;
	if(appctx.opt.seriesInterval%sessionTime)
		numSessions++;

	if((sessionTime * numSessions) <
				SETUP_ESTIMATE + appctx.opt.lossThreshold){
		I2ErrLog(eh,"Holes in data are likely because lossThreshold(%d)"
				" is too large a fraction of seriesLength(%d)",
				appctx.opt.lossThreshold,
				sessionTime*numSessions);
	}


	/*
	 * Setup Test Session record.
	 */
	/* skip start_time - set per/test */
	tspec.loss_timeout = OWPDoubleToNum64(appctx.opt.lossThreshold);
	tspec.typeP = 0;
	tspec.packet_size_padding = appctx.opt.padding;
	tspec.npackets = appctx.opt.numPackets * numSessions;

	/*
	 * powstream uses a single slot with exp distribution.
	 */
	slot.slot_type = OWPSlotRandExpType;
	slot.rand_exp.mean = OWPDoubleToNum64(appctx.opt.meanWait);
	tspec.nslots = 1;
	tspec.slots = &slot;

	/*
	 * TODO: Fix this.
	 * Setup policy stuff - this currently sucks.
	 */
	owp_set_auth(&appctx,progname, ctx); 

#if	NOT
#ifndef	NDEBUG
	somestate.childwait = appctx.opt.childwait;
#endif
#endif

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(appctx.lib_ctx = OWPContextCreate(eh))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}
	ctx = appctx.lib_ctx;
	parse.ctx = ctx;

	memset(&pcntrl,0,2*sizeof(pow_cntrl_rec));
	strcpy(pcntrl[0].fname,dirpath);
	strcpy(pcntrl[1].fname,dirpath);

	/*
	 * Add time for file buffering. 
	 * Add 2 seconds to the max of (1,mu). file io is optimized to
	 * try and only buffer 1 second of data - but if mu is > one
	 * second, then we have to wait mu, because each record will
	 * be flushed individually in this case.
	 * (2 seconds is because the recv process waits 1 after the end
	 * of the test before it does it's clean-up, and we want to wait
	 * until it is done with it's clean-up. It should definitely not
	 * take longer than 1 second to clean-up.)
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
		OWPNum64		stopnum;
		OWPNum64		sessionStartnum,startnum,lastnum;

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
			(void)SetupSession(ctx,q,p,NULL);
			goto NextConnection;
	
		}

		/* init vars for loop */
		parse.begin=0;
		lastnum=OWPULongToNum64(0);
		call_stop = True;
		sessionStartnum = *p->sessionStart;

		/*
		 * This loops on each "sub" session - it completes when
		 * there are no more sub-sessions to fetch - i.e. the real
		 * test session is complete.
		 */
		for(sub=0;sub<numSessions;sub++){
			char			fname[PATH_MAX];
			char			endname[PATH_MAX];
			char			newpath[PATH_MAX];
			u_int64_t		nrecs;
			off_t			hlen;
			OWPSessionHeaderRec	hdr;
			OWPNum64		localstop;

			if(sig_check())
				goto NextConnection;

			parse.first = appctx.opt.numPackets*sub;
			parse.last = (appctx.opt.numPackets*(sub+1))-1;
			parse.i = 0;
			parse.next = 0;
			parse.sync = 1;
			parse.maxerr = 0.0;
			parse.dups = parse.lost = 0;
			parse.nbuckets = 0;
			assert(!parse.buckets ||
					(I2HashNumEntries(parse.buckets)==0));

			/*
			 * lastnum contains offset for previous sub.
			 * So - sessionStart + lastnum is new
			 * startnum.
			 */
			startnum = OWPNum64Add(sessionStartnum,lastnum);

			/*
			 * This loop sets lastnum to the relative lastnum
			 * of this sub-session. (It starts at the relative
			 * offset of the lastnum from the previous session.)
			 * It also initializes the "seen" array for this
			 * sub-session. This array saves the presumed sendtimes
			 * in the event "lost" records for those packets
			 * need to be generated.
			 */
			for(nrecs=0;nrecs<appctx.opt.numPackets;nrecs++){
				lastnum = OWPNum64Add(lastnum,
					OWPScheduleContextGenerateNextDelta(
								p->sctx));
				parse.seen[nrecs].sendtime =
					OWPNum64Add(sessionStartnum,lastnum);
				parse.seen[nrecs].seen = 0;
			}
			/*
			 * set localstop to absolute time of final packet.
			 */
			localstop = OWPNum64Add(sessionStartnum,lastnum);

			/*
			 * set stopnum to the time we should collect this
			 * session.
			 * subsession can't be over until after
			 * lossThresh, then add iotime.
			 */
			stopnum = OWPNum64Add(localstop,
					OWPNum64Add(tspec.loss_timeout,
						OWPULongToNum64(iotime)));

			/*
			 * Now try and setup the next session.
			 * SetupSession checks for reset signals, and returns
			 * non-zero if one happend.
			 */
			if(SetupSession(ctx,q,p,&stopnum))
				goto NextConnection;
AGAIN:
			/*
			 * Wait until this "subsession" is complete.
			 */
			if(call_stop){
				rc = OWPStopSessionsWait(p->cntrl,&stopnum,
							NULL,&aval,&err_ret);
			}
			else{
				rc=1; /* no more data coming */
			}

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
				/*
				 * system event
				 */
				if(sig_check())
					goto NextConnection;

				if(OWPSessionsActive(p->cntrl,NULL)){
					goto AGAIN;
				}
			}
			/* Else - time's up! Get to work.	*/

			nrecs = OWPReadDataHeader(ctx,p->fp,&hlen,&hdr);
			parse.hdr = &hdr;

			/*
			 * Modify hdr for subsession.
			 */
			hdr.test_spec.start_time = startnum;
			hdr.test_spec.npackets = appctx.opt.numPackets;
			hdr.test_spec.slots = &slot;

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
			strcpy(&fname[ext_offset],INCOMPLETE_EXT);
			while(!(parse.fp = fopen(fname,"wb+")) && errno==EINTR);
			if(!parse.fp){
				I2ErrLog(eh,"fopen(%s): %M",fname);
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
				I2ErrLog(eh,"OWPWriteDataHeader: %M");
				goto error;
			}

			/* write relevant records to file */
			if(OWPParseRecords(ctx,p->fp,nrecs,hdr.version,
				WriteSubSession,(void*)&parse) != OWPErrOK){
				I2ErrLog(eh,"WriteSubSession: %M");
				goto error;
			}

			if(WriteSubSessionLost(&parse)){
				I2ErrLog(eh,"WriteSubSessionLost: %M");
				goto error;
			}

			/*
			 * Flush the FILE before linking to the "complete"
			 * name.
			 */
			fflush(parse.fp);

			sprintf(endname,OWP_TSTAMPFMT,localstop);
			strcpy(newpath,fname);
			sprintf(&newpath[ext_offset],"%s%s%s",
					OWP_NAME_SEP,endname,OWP_FILE_EXT);
			if(link(fname,newpath) != 0){
				I2ErrLog(eh,"link(): %M");
			}

			if(parse.buckets){
				char	sfname[PATH_MAX];

				/*
				 * -b indicates we want to save "summary"
				 * stats.
				 */
				strcpy(sfname,newpath);
				strcat(sfname,SUMMARY_EXT);
				while(!(parse.sfp = fopen(sfname,"w")) &&
								errno==EINTR);
				/* (Ignore errors...) */
				if(parse.sfp){
					/*
					 * TODO: compute session stats!
					 */

					/* PRINT version 1 STATS */
					fprintf(parse.sfp,"SUMMARY\t1.0\n");
					fprintf(parse.sfp,"SENT\t%u\n",
							appctx.opt.numPackets);
					fprintf(parse.sfp,"MAXERR\t%g\n",
								parse.maxerr);
					fprintf(parse.sfp,"SYNC\t%u\n",
								parse.sync);
					fprintf(parse.sfp,"DUPS\t%u\n",
								parse.dups);
					fprintf(parse.sfp,"LOST\t%u\n",
								parse.lost);
					fprintf(parse.sfp,"BUCKETWIDTH\t%g\n",
							appctx.opt.bucketWidth);

					/*
					 * TODO: PRINT out the BUCKETS
					 */
					fprintf(parse.sfp,"<BUCKETS>\n");
					I2HashIterate(parse.buckets,
							PrintBuckets,
							&parse);
					fprintf(parse.sfp,"</BUCKETS>\n");

					fclose(parse.sfp);
					parse.sfp = NULL;

					assert(!parse.bucketerror);
				}
			}

			if(appctx.opt.printfiles){
				/* Now print the filename to stdout */
				fprintf(stdout,"%s\n",newpath);
				fflush(stdout);
			}
error:
			fclose(parse.fp);
			parse.fp = NULL;
			/* unlink old name */
			if(unlink(fname) != 0){
				I2ErrLog(eh,"unlink(): %M");
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
			if(OWPStopSessions(p->cntrl,NULL,&aval)<OWPErrWARNING){
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
