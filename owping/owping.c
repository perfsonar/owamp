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
#include "./localaddr.h"

/*
 * The owping context
 */
static	OWPingTRec	OWPingCtx;

static int
OWPingErrFunc(
	void		*app_data,
	OWPErrSeverity	severity,
	OWPErrType	etype,
	const char	*errmsg
)
{
	OWPingT		pctx = (OWPingT)app_data;

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
	/* app_data			*/	(void*)&OWPingCtx,
	/* err_func			*/	OWPingErrFunc,
	/* get_aes_key			*/	NULL,
	/* check_addr_func		*/	NULL,
	/* check_control_func		*/	NULL,
	/* check_test_func		*/	NULL,
	/* endpoint_init_func		*/	NULL,
	/* endpoint_init_hook_func	*/	NULL,
	/* endpoint_start_func		*/	NULL,
	/* endpoint_stop_func		*/	NULL
	/* get_timestamp_func		*/	NULL,
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
	"verbose", I2CvtToBoolean, &OWPingCtx.opt.verbose,
	sizeof(OWPingCtx.opt.verbose)
	},
        {
	"help", I2CvtToBoolean, &OWPingCtx.opt.help,
	sizeof(OWPingCtx.opt.help)
	},
        {
	"authmode", I2CvtToString, &OWPingCtx.opt.authmode,
	sizeof(OWPingCtx.opt.authmode)
	},
        {
	"identity", I2CvtToString, &OWPingCtx.opt.identity,
	sizeof(OWPingCtx.opt.identity)
	},
        {
	"tmout", I2CvtToInt, &OWPingCtx.opt.tmout,
	sizeof(OWPingCtx.opt.tmout)
	},
        {
	"sender", I2CvtToString, &OWPingCtx.opt.sender,
	sizeof(OWPingCtx.opt.sender)
	},
        {
	"receiver", I2CvtToString, &OWPingCtx.opt.receiver,
	sizeof(OWPingCtx.opt.receiver)
	},
        {
	"padding", I2CvtToUInt, &OWPingCtx.opt.padding,
	sizeof(OWPingCtx.opt.padding)
	},
        {
	"lambda", I2CvtToUInt, &OWPingCtx.opt.lambda,
	sizeof(OWPingCtx.opt.lambda)
	},
        {
	"numPackets", I2CvtToUInt, &OWPingCtx.opt.numPackets,
	sizeof(OWPingCtx.opt.numPackets)
	},
        {
	"lossThreshold", I2CvtToUInt, &OWPingCtx.opt.lossThreshold,
	sizeof(OWPingCtx.opt.lossThreshold)
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
	(void)OWPControlClose(OWPingCtx.cntrl);
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
	OWPPoissonTestSpec	poisson_test;

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
	OWPingCtx.eh = eh;

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
	if(OWPingCtx.opt.help) {
		usage(od, progname, NULL);
		exit(0);
	}

	/*
	 * Verify/decode auth options.
	 */
	if(OWPingCtx.opt.authmode){
		char	*s = OWPingCtx.opt.authmode;
		OWPingCtx.auth_mode = 0;
		while(*s != '\0'){
			switch (toupper(*s)){
				case 'O':
				OWPingCtx.auth_mode |= OWP_MODE_OPEN;
				break;
				case 'A':
				OWPingCtx.auth_mode |= OWP_MODE_AUTHENTICATED;
				break;
				case 'E':
				OWPingCtx.auth_mode |= OWP_MODE_ENCRYPTED;
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
		OWPingCtx.auth_mode = OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|
							OWP_MODE_ENCRYPTED;
	}

	/*
	 * Control connections should go to the "server" address for
	 * each connection if it is different from the send/recv address.
	 * If no "server" specified, assume same address as send/recv
	 * address.
	 */
	if(!OWPingCtx.opt.senderServ && OWPingCtx.opt.sender)
		OWPingCtx.opt.senderServ = strdup(OWPingCtx.opt.sender);
	if(!OWPingCtx.opt.receiverServ && OWPingCtx.opt.receiver)
		OWPingCtx.opt.receiverServ = strdup(OWPingCtx.opt.receiver);

	OWPCfg.tm_out.tv_sec = OWPingCtx.opt.tmout;

	/*
	 * Determine "locality" of server addresses.
	 */
	OWPingCtx.sender_local = is_local_addr(OWPingCtx.opt.senderServ,0);
	OWPingCtx.receiver_local = is_local_addr(OWPingCtx.opt.receiverServ,0);

	/*
	 * If both send/recv server addrs are not local, then they MUST be the
	 * same - otherwise this is a request for a 3rd party transaction and
	 * it can't work.
	 * ("same" is fairly simply defined as the same string here - it is
	 * possible that 2 different names would resolv to the same
	 * address, but we ignore that complexity here.)
	 *
	 */
	if(!OWPingCtx.sender_local && !OWPingCtx.receiver_local &&
		strcmp(OWPingCtx.opt.senderServ,OWPingCtx.opt.receiverServ)){
		I2ErrLog(eh,"Unable to broker 3rd party transactions...");
		exit(1);
	}

	/*
	 * If both are local - then this process will handle receiver, and
	 * contact a local owampd to be sender.
	 * (probably not real useful... but non-fatal defaults are good.)
	 */
	if(OWPingCtx.receiver_local){
		OWPingCtx.local_addr = OWPingCtx.opt.receiverServ;
		OWPingCtx.remote_addr = OWPingCtx.opt.senderServ;
		OWPingCtx.sender_local = False;
	}else{
		OWPingCtx.local_addr = OWPingCtx.opt.senderServ;
		OWPingCtx.remote_addr = OWPingCtx.opt.receiverServ;
	}

	/*
	 * Setup test_spec and verify options.
	 */

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(OWPingCtx.lib_ctx = OWPContextInitialize(&OWPCfg))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}
	ctx = OWPingCtx.lib_ctx;

	/*
	 * Open connection to owampd.
	 */
	if( !(OWPingCtx.cntrl = OWPControlOpen(ctx,
			OWPAddrByNode(ctx,OWPingCtx.local_addr),
			OWPAddrByNode(ctx,OWPingCtx.remote_addr),
			OWPingCtx.auth_mode,
			OWPingCtx.opt.identity,
			&err_ret))){
		I2ErrLog(eh, "Unable to open control connection.");
		exit(1);
	}

	/*
	 * Now ready to make test requests...
	 */
	if( !OWPRequestTestSession(OWPingCtx.cntrl,
			OWPAddrByNode(ctx,OWPingCtx.opt.sender),
			!OWPingCtx.sender_local,
			OWPAddrByNode(ctx,OWPingCtx.opt.receiver),
			!OWPingCtx.receiver_local,
			test_spec,
			sid_ret,
			&err_ret))
		FailSession(OWPingCtx.cntrl);

	if( (OWPStartTestSessions(OWPingCtx.cntrl) != OWPErrOK))
		FailSession(OWPingCtx.cntrl);
	/*
	 * TODO install sig handler for keyboard interupt - to send stop
	 * sessions.
	 */

	exit(0);
}
