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
 *	File:		owping.c
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Thu Apr 25 12:22:31  2002
 *
 *	Description:	
 *
 *	Initial implementation of owping commandline application. This
 *	application will measure active one-way udp latencies.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include <I2util/util.h>
#include <owamp/owamp.h>
#include <owamp/conndata.h>
#include <owpcontrib/unixtime.h>
#include <owpcontrib/access.h>

#include "./owpingP.h"
#include "./localnode.h"

/*
 * The owping context
 */
static	ow_ping_trec	ping_ctx;

/*
** State to be maintained by client during Fetch.
*/
typedef struct fetch_state {
	double    tmin;             /* max delay                    */
	double    tmax;             /* min delay                    */     
	double    tsum;             /* sum of delays                */
	double    tsumsq;           /* sum of squared delays        */
	u_int32_t numpack_received; /* number of received packets   */
	FILE*     fp;               /* stream to report records     */
} fetch_state, *fetch_state_ptr;


/*
** Initialize the state.
*/
void
fetch_state_init(fetch_state_ptr state, FILE *fp)
{
	assert(state);

	state->tmin = 9999.999;
	state->tmax = state->tsum = state->tsumsq = 0.0;
	state->numpack_received = 0;
	state->fp = fp;
}

static int
OWPingErrFunc(
	void		*app_data,
	OWPErrSeverity	severity	__attribute__((unused)),
	OWPErrType	etype,
	const char	*errmsg
)
{
	ow_ping_t		pctx = (ow_ping_t)app_data;

	/*
	 * If not debugging - only print messages of warning or worse.
	 * (unless of course verbose is specified...
	 */
#ifdef	NDEBUG
	if(!pctx->opt.verbose && (severity > OWPErrWARNING))
		return 0;
#endif

	I2ErrLogP(pctx->eh,etype,errmsg);

	return 0;
}
	
/*
 * Library initialization structure;
 */
static	OWPInitializeConfigRec	OWPCfg = {{
	/* tm_out.tv_sec		*/	0,
	/* tm_out.tv_usec		*/	0},
	/* app_data			*/	(void*)&ping_ctx,
	/* err_func			*/	OWPingErrFunc,
	/* get_aes_key			*/	owp_get_aes_key,
	/* check_control_func		*/	owp_check_control,
	/* check_test_func		*/	owp_check_test,
	/* endpoint_init_func		*/	NULL,
	/* endpoint_init_hook_func	*/	NULL,
	/* endpoint_start_func		*/	NULL,
	/* endpoint_stop_func		*/	NULL,
	/* get_timestamp_func		*/	NULL,
	/* rand_type                    */      RAND_DEV,
	/* rand_data                    */      "/dev/urandom",
	/* rand_eh                      */      NULL
};

/*
 *      the options that we want to have parsed
 */
static	I2OptDescRec	set_options[] = {
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
	 * Control connection specific stuff.
	 */
	{"authmode",1,NULL,"Requested modes:[E]ncrypted,[A]uthenticated,[O]pen"},
	{"identity",1,NULL,"ID for shared secret"},
	{"tmout",1,"30","Max time to wait for control connection reads (sec)"},


	/*
	 * test setup args
	 */
	{"sender", -2, NULL, "IP address/node name of sender [and server]"},
	{"receiver", -2, NULL, "IP address/node name of receiver [and server]"},

	{"padding", 1, "0", "min size of padding for test packets (octets)"},
	{"rate", 1, "1.0", "rate of test packets (packets/sec)"},
	{"numPackets", 1, "10", "number of test packets"},

	/*
	 * Recv specific args.
	 */
	{"lossThreshold", 1, "120",
			"elapsed time when recv declares packet lost (sec)"},
	{"datadir", 1, OWP_DATADIR,
				"Data directory to store test session data"},
	{NULL,0,NULL,NULL}
};

/*
**      return structure for loading options. We load them straight
**	into the context variable.
*/
static  I2Option  get_options[] = {
        {
	"verbose", I2CvtToBoolean, &ping_ctx.opt.verbose,
	sizeof(ping_ctx.opt.verbose)
	},
        {
	"help", I2CvtToBoolean, &ping_ctx.opt.help,
	sizeof(ping_ctx.opt.help)
	},
	{
	"confdir", I2CvtToString, &ping_ctx.opt.confdir,
	sizeof(ping_ctx.opt.confdir)
	},
	{
	"ip2class", I2CvtToString, &ping_ctx.opt.ip2class,
	sizeof(ping_ctx.opt.ip2class)
	},
	{
	"class2limits", I2CvtToString, &ping_ctx.opt.class2limits,
	sizeof(ping_ctx.opt.class2limits)
	},
	{
	"passwd", I2CvtToString, &ping_ctx.opt.passwd,
	sizeof(ping_ctx.opt.passwd)
	},
        {
	"authmode", I2CvtToString, &ping_ctx.opt.authmode,
	sizeof(ping_ctx.opt.authmode)
	},
        {
	"identity", I2CvtToString, &ping_ctx.opt.identity,
	sizeof(ping_ctx.opt.identity)
	},
        {
	"tmout", I2CvtToInt, &ping_ctx.opt.tmout,
	sizeof(ping_ctx.opt.tmout)
	},
        {
	"sender", I2CvtToString, &ping_ctx.opt.sender,
	sizeof(ping_ctx.opt.sender)
	},
        {
	"receiver", I2CvtToString, &ping_ctx.opt.receiver,
	sizeof(ping_ctx.opt.receiver)
	},
        {
	"padding", I2CvtToUInt, &ping_ctx.opt.padding,
	sizeof(ping_ctx.opt.padding)
	},
        {
	"rate", I2CvtToFloat, &ping_ctx.opt.rate,
	sizeof(ping_ctx.opt.rate)
	},
        {
	"numPackets", I2CvtToUInt, &ping_ctx.opt.numPackets,
	sizeof(ping_ctx.opt.numPackets)
	},
        {
	"datadir", I2CvtToString, &ping_ctx.opt.datadir,
	sizeof(ping_ctx.opt.datadir)
	},
        {
	"lossThreshold", I2CvtToUInt, &ping_ctx.opt.lossThreshold,
	sizeof(ping_ctx.opt.lossThreshold)
	},
	{NULL,NULL,NULL,0}
};

static void	usage(int od, const char *progname, const char *msg)
{
	if(msg) fprintf(stderr, "%s: %s\n", progname, msg);

	fprintf(stderr,"Usage: %s [options]\n", progname);
	fprintf(stderr, "\nWhere \"options\" are:\n\n");
	I2PrintOptionHelp(od, stderr);

	return;
}

static I2ErrHandle		eh;

static void
FailSession(
	OWPControl	control_handle	__attribute__((unused))
	   )
{
	/*
	 * Session denied - report error, close connection, and exit.
	 */
	I2ErrLog(eh, "Session Failed!");
	fflush(stderr);

	/* TODO: determine "reason" for denial and report */
	(void)OWPControlClose(ping_ctx.cntrl);
	exit(1);
}

/*
** Given a pointer to a 20-byte data record, print it out, in a 
** machine-readable form, to a given file (if not NULL), or stdout otherwise.
*/
int
print_record(void *calldata,          /* currently just a file pointer */
	     u_int32_t seq_num,
	     OWPTimeStamp *send_time,
	     OWPTimeStamp *recv_time)
{
	FILE* fp = (calldata)? (FILE *)calldata : stdout;

	fprintf(fp, "seq_no=%u send=%u.%us recv=%u.%us\n",
		seq_num, send_time->sec, send_time->frac_sec,
		recv_time->sec, recv_time->frac_sec);
	return 0;
}

#define THOUSAND 1000.0

/*
** Print delay for the current record (ping-like style) and update the stats.
*/
int
print_delay(void *calldata,      /* fetch_state_ptr */
	    u_int32_t seq_num,
	    OWPTimeStamp *send_time,
	    OWPTimeStamp *recv_time
	    )
{
	fetch_state_ptr state = (fetch_state_ptr)calldata;
	double delay = owp_delay(send_time, recv_time);

	assert(state);
	
	/* Update the state. */
	if (delay < state->tmin)
		state->tmin = delay;

	if (delay > state->tmax)
		state->tmax = delay;

	state->tsum += delay;
	state->tsumsq += (delay*delay);
	state->numpack_received++;

	fprintf(state->fp, "seq_no=%u delay=%.3f ms\n", seq_num, 
		delay*THOUSAND);

	return 0;
}

/*
** Print out summary results, ping-like style.
*/
int
owp_do_summary(fetch_state_ptr state)
{
	double min = ((double)(state->tmin)) * THOUSAND;    /* msec */
	double max = ((double)(state->tmax)) * THOUSAND;    /* msec */
	double   n = (double)(state->numpack_received);   
	double avg = ((state->tsum)/n) * THOUSAND;
	double vari = ((state->tsumsq / n) - avg * avg) * THOUSAND;
	
	fprintf(state->fp, "%u records received\n", state->numpack_received);
	fprintf(state->fp, 
		"one-way delay min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		min, avg, max, sqrt(vari));
	return 0;
}

/*
** Master output function - reads the records sent by the server
** and prints them to the stdout in a style specified by <type>.
** Its value is interpreted as follows:
** 0 - print out send and recv timestamsps for each record in machine-readable
** format;
** 1 - print one-way delay in msec for each record, and final summary
**     (original ping style: max/avg/min/stdev) at the end.
*/
int
do_records_all(OWPControl cntrl, u_int32_t num_rec, int type, FILE *fp)
{
	assert(fp);

	switch (type) {
	case 0:          /* print the full record in machine-readable form */
		OWPFetchRecords(cntrl, num_rec, print_record, fp);
		break;
	case 1:
		{
		      fetch_state state;
		      
		      fetch_state_init(&state, fp);
		      OWPFetchRecords(cntrl, num_rec, print_delay, &state);
		      owp_do_summary(&state);
		      break;
		}
	default:
		break;
	}
	return 0;
}

/*
 * TODO: Find real max padding sizes based upon size of headers
 */
#define	MAX_PADDING_SIZE	65000

int
main(
	int	argc,
	char	**argv
) {
	char			*progname;
	OWPErrSeverity		err_ret=OWPErrOK;
	I2LogImmediateAttr	ia;
	int			od;
	policy_data		*policy;
	char			ip2class[MAXPATHLEN],
				class2limits[MAXPATHLEN],
				passwd[MAXPATHLEN];
	int			rc;
	OWPContext		ctx;
	OWPTestSpecPoisson	test_spec;
	OWPSID			sid_ret;
	OWPTimeStamp		start_time_rec={0,0,0,0};
	OWPPerConnDataRec	conndata;

	ia.line_info = (I2NAME | I2MSG);
	ia.fp = stderr;

	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	/*
	* Start an error loggin session for reporing errors to the
	* standard error
	*/
	eh = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}
	ping_ctx.eh = eh;

	od = I2OpenOptionTbl(eh);

	/*
	* register the options we're interested in and have them parsed
	*/
	if(I2ParseOptionTable(od, &argc, argv, set_options) < 0) {
		I2ErrLog(eh, "Could not parse command line options");
		exit(1);
	}

	/*
	* load the options into opt
	*/
	if(I2GetOptions(od, get_options) < 0) {
		I2ErrLog(eh, "Could not retrieve command line options");
		exit(1);
	}

	/*
	 * Print help.
	 */
	if(ping_ctx.opt.help) {
		usage(od, progname, NULL);
		exit(0);
	}

	/*
	 * Setup paths.
	 */

	rc = snprintf(ip2class,sizeof(ip2class),"%s%s%s",ping_ctx.opt.confdir,
			OWP_PATH_SEPARATOR,ping_ctx.opt.ip2class);
	if(rc > (int)sizeof(ip2class)){
		I2ErrLog(eh, "Invalid path to ip2class file.");
		exit(1);
	}

	rc = snprintf(class2limits,sizeof(class2limits),"%s%s%s",
			ping_ctx.opt.confdir,OWP_PATH_SEPARATOR,
			ping_ctx.opt.class2limits);
	if(rc > (int)sizeof(class2limits)){
		I2ErrLog(eh, "Invalid path to class2limits file.");
		exit(1);
	}

	rc = snprintf(passwd,sizeof(passwd),"%s%s%s",ping_ctx.opt.confdir,
			OWP_PATH_SEPARATOR,ping_ctx.opt.passwd);
	if(rc > (int)sizeof(passwd)){
		I2ErrLog(eh, "Invalid path to passwd file.");
		exit(1);
	}

	policy = PolicyInit(eh, ip2class, class2limits, passwd, &err_ret);
	if (err_ret == OWPErrFATAL){
		I2ErrLog(eh, "PolicyInit failed. Exiting...");
		exit(1);
	};

	/*
	 * This is in reality dependent upon the actual protocol used
	 * (ipv4/ipv6) - it is also dependent upon the auth mode since
	 * authentication implies 128bit block sizes.
	 *
	 * Here MAX_PADDING_SIZE is just used to thow out obviously bad
	 * values - however, the socket will have Path MTU discovery
	 * turned on - and we will not allow any datagrams to be sent
	 * that are larger than this value. This will be our attempt
	 * to ensure that we are measuring singleton's in the network, and
	 * not multiple fragments.
	 *
	 * (For IPv4 this means setting IP_PMTUDISC_DO - then any "send"
	 * with data greater than the current PMTU will cause EMSGSIZE.)
	 *
	 * For IPv6 this is a little more complicated because the
	 * Advanced Socket API is not yet formalized - for the current
	 * version see: draft-ietf-ipngwg-rfc2292bis - currently in draft 7.
	 * (Section 11.3 specifies setting IPV6_RECVPATHMTU to get our
	 * desired behavior. - however, most OS's don't have this option
	 * yet. If this option is not available, I will use IPV6_USEMTU
	 * and set it to 1280 - the minimum MTU required by IPv6 (RFC2460)
	 */
	if(ping_ctx.opt.padding > MAX_PADDING_SIZE)
		ping_ctx.opt.padding = MAX_PADDING_SIZE;

	/*
	 * Verify/decode auth options.
	 */
	if(ping_ctx.opt.authmode){
		char	*s = ping_ctx.opt.authmode;
		ping_ctx.auth_mode = 0;
		while(*s != '\0'){
			switch (toupper(*s)){
				case 'O':
				ping_ctx.auth_mode |= OWP_MODE_OPEN;
				break;
				case 'A':
				ping_ctx.auth_mode |= OWP_MODE_AUTHENTICATED;
				break;
				case 'E':
				ping_ctx.auth_mode |= OWP_MODE_ENCRYPTED;
				break;
				default:
				I2ErrLogP(eh,EINVAL,"Invalid -authmode %c",*s);
				usage(od, progname, NULL);
				exit(1);
			}
			s++;
		}
	}else{
		/*
		 * Default to all modes.
		 * If identity not set - library will ignore A/E.
		 */
		ping_ctx.auth_mode = OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|
							OWP_MODE_ENCRYPTED;
	}

	/*
	 * Control connections should go to the "server" address for
	 * each connection if it is different from the send/recv address.
	 * If no "server" specified, assume same address as send/recv
	 * address.
	 */
	if(!ping_ctx.opt.senderServ && ping_ctx.opt.sender)
		ping_ctx.opt.senderServ = strdup(ping_ctx.opt.sender);
	if(!ping_ctx.opt.receiverServ && ping_ctx.opt.receiver)
		ping_ctx.opt.receiverServ = strdup(ping_ctx.opt.receiver);

	OWPCfg.tm_out.tv_sec = ping_ctx.opt.tmout;

	/*
	 * Determine "locality" of server addresses.
	 */
	ping_ctx.sender_local = is_local_node(ping_ctx.opt.senderServ,0);
	ping_ctx.receiver_local = is_local_node(ping_ctx.opt.receiverServ,0);

	/*
	 * If both send/recv server addrs are not local, then they MUST be the
	 * same - otherwise this is a request for a 3rd party transaction and
	 * it can't work.
	 * ("same" is fairly simply defined as the same string here - it is
	 * possible that 2 different names would resolv to the same
	 * address, but we ignore that complexity here.)
	 *
	 */
	if(!ping_ctx.sender_local && !ping_ctx.receiver_local &&
		strcmp(ping_ctx.opt.senderServ,ping_ctx.opt.receiverServ)){
		I2ErrLog(eh,"Unable to broker 3rd party transactions...");
		exit(1);
	}

	/*
	 * If both are local - then this process will handle receiver, and
	 * contact a local owampd to be sender.
	 * (probably not real useful... but non-fatal defaults are good.)
	 */
	if(ping_ctx.receiver_local){
		ping_ctx.local_addr = ping_ctx.opt.receiverServ;
		ping_ctx.remote_addr = ping_ctx.opt.senderServ;
		ping_ctx.sender_local = False;
	}else{
		ping_ctx.local_addr = ping_ctx.opt.senderServ;
		ping_ctx.remote_addr = ping_ctx.opt.receiverServ;
	}

	/*
	 * Start test one second from now.
	 */
	if(!OWPGetTimeOfDay(&start_time_rec)){
		I2ErrLogP(eh,errno,"Unable to get current time:%M");
		exit(1);
	}
	start_time_rec.sec++;

	test_spec.test_type = OWPTestPoisson;
	test_spec.start_time = start_time_rec;
	test_spec.npackets = ping_ctx.opt.numPackets;

	/*
	 * TODO: Figure out typeP...
	 */
	test_spec.typeP = 0;
	test_spec.packet_size_padding = ping_ctx.opt.padding;
	/*
	 * InvLambda is mean in usec so, to convert from rate_sec:
	 * rate_usec = rate_sec/1000000 and because
	 * InvLambda = 1/rate_usec then
	 * InvLambda = 1/rate_sec/1000000.0 or
	 * InvLambda = 1000000.0/rate_sec
	 */
	test_spec.InvLambda = (double)1000000.0 / ping_ctx.opt.rate;

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(ping_ctx.lib_ctx = OWPContextInitialize(&OWPCfg))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}
	ctx = ping_ctx.lib_ctx;

	/*
	 * TODO: Figure out how the client is going to make policy
	 * requests. could just leave it empty I suppose. (Could also
	 * make the policy functions make the request directly if
	 * the pipefd portion of PerConnData is -1....
	 */
	conndata.pipefd = -1;
	conndata.datadir = ping_ctx.opt.datadir;
	conndata.policy = policy;
	conndata.lossThreshold = ping_ctx.opt.lossThreshold;
	conndata.node = NULL;

	/*
	 * Open connection to owampd.
	 */
	if( !(ping_ctx.cntrl = OWPControlOpen(ctx,
			OWPAddrByNode(ctx,ping_ctx.local_addr),
			OWPAddrByNode(ctx,ping_ctx.remote_addr),
			ping_ctx.auth_mode,
			ping_ctx.opt.identity,
			(void*)&conndata,
			&err_ret))){
		I2ErrLog(eh, "Unable to open control connection.");
		exit(1);
	}
	conndata.cntrl = ping_ctx.cntrl;

	/*
	 * Now ready to make test requests...
	 */
	if( !OWPRequestTestSession(ping_ctx.cntrl,
			OWPAddrByNode(ctx,ping_ctx.opt.sender),
			!ping_ctx.sender_local,
			OWPAddrByNode(ctx,ping_ctx.opt.receiver),
			!ping_ctx.receiver_local,
			(OWPTestSpec*)&test_spec,
			sid_ret,
			&err_ret))
		FailSession(ping_ctx.cntrl);
	
	if(OWPStartTestSessions(ping_ctx.cntrl) != OWPErrOK)
		FailSession(ping_ctx.cntrl);
	/*
	 * TODO install sig handler for keyboard interupt - to send stop
	 * sessions.
	 */

	exit(0);
}
