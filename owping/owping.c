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

#include "./owpingP.h"
#include "./localnode.h"

/*
 * The owping context
 */
static	ow_ping_trec	ping_ctx;

static int
OWPingErrFunc(
	void		*app_data,
	OWPErrSeverity	severity,
	OWPErrType	etype,
	const char	*errmsg
)
{
	ow_ping_t		pctx = (ow_ping_t)app_data;

	/*
	 * If not debugging - only print messages of warning or worse.
	 */
#ifdef	NDEBUG
	if(severity > OWPErrWARNING)
		return 0;
#endif

	I2ErrLogP(pctx->eh,etype,errmsg);

	return 0;
}
	
/*
 * Library initialization structure;
 */
static	OWPInitializeConfigRec	OWPCfg = {
	/* tm_out.tv_sec		*/	0,
	/* tm_out.tv_usec		*/	0,
	/* app_data			*/	(void*)&ping_ctx,
	/* err_func			*/	OWPingErrFunc,
	/* get_aes_key			*/	NULL,
	/* check_addr_func		*/	NULL,
	/* check_control_func		*/	NULL,
	/* check_test_func		*/	NULL,
	/* endpoint_init_func		*/	NULL,
	/* endpoint_init_hook_func	*/	NULL,
	/* endpoint_start_func		*/	NULL,
	/* endpoint_stop_func		*/	NULL,
	/* get_timestamp_func		*/	NULL
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
	{"lambda", 1, "1000000", "mean time between test packets (usec)"},
	{"numPackets", 1, "10", "number of test packets"},

	/*
	 * Recv specific args.
	 */
	{"lossThreshold", 1, "600", "elapsed time when recv declares packet lost (sec)"},
	{NULL}
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
	"lambda", I2CvtToUInt, &ping_ctx.opt.lambda,
	sizeof(ping_ctx.opt.lambda)
	},
        {
	"numPackets", I2CvtToUInt, &ping_ctx.opt.numPackets,
	sizeof(ping_ctx.opt.numPackets)
	},
        {
	"lossThreshold", I2CvtToUInt, &ping_ctx.opt.lossThreshold,
	sizeof(ping_ctx.opt.lossThreshold)
	},
	{NULL}
};

static void	usage(int od, const char *progname, const char *msg)
{
	if(msg) fprintf(stderr, "%s: %s\n", progname, msg);

	fprintf(stderr,"Usage: %s [options]\n", progname);
	fprintf(stderr, "\nWhere \"options\" are:\n\n");
	I2PrintOptionHelp(od, stderr);

	return;
}

static void
FailSession(
	OWPControl	control_handle
	   )
{
	/*
	 * Session denied - report error, close connection, and exit.
	 */

	/* TODO: determine "reason" for denial and report */
	(void)OWPControlClose(ping_ctx.cntrl);
	exit(1);
}

main(
	int	argc,
	char	**argv
) {
	char			*progname;
	OWPErrSeverity		err_ret=OWPErrOK;
	I2ErrHandle		eh;
	I2LogImmediateAttr	ia;
	int			od;
	OWPContext		ctx;
	I2table			local_addr_table;
	OWPPoissonTestSpec	test_spec;
	OWPSID			sid_ret;
	OWPTimeStamp		zero_time={0};

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
	 * TODO test_spec and verify options.
	 */
	test_spec.test_type = OWPTestPoisson;
	test_spec.start_time = zero_time;
	test_spec.npackets = 1;
	test_spec.typeP = 0;
	test_spec.packet_size_padding = 0;
	test_spec.InvLambda = 1;

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(ping_ctx.lib_ctx = OWPContextInitialize(&OWPCfg))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}
	ctx = ping_ctx.lib_ctx;

	/*
	 * Open connection to owampd.
	 */
	if( !(ping_ctx.cntrl = OWPControlOpen(ctx,
			OWPAddrByNode(ctx,ping_ctx.local_addr),
			OWPAddrByNode(ctx,ping_ctx.remote_addr),
			ping_ctx.auth_mode,
			ping_ctx.opt.identity,
			&err_ret))){
		I2ErrLog(eh, "Unable to open control connection.");
		exit(1);
	}

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

	if( (OWPStartTestSessions(ping_ctx.cntrl) != OWPErrOK))
		FailSession(ping_ctx.cntrl);
	/*
	 * TODO install sig handler for keyboard interupt - to send stop
	 * sessions.
	 */

	exit(0);
}
