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

#include <I2util/util.h>
#include "owpingP.h"

/*
 * The owping context
 */
static	OWPingTRec	OWPingCtx;

static int
OWPingErrFunc(
	void		*app_data,
	OWPErrSeverity	severity,
	OWPErrType	etype,
	cont char	*errmsg
)
{
	OWPingT		pctx = (OWPingT)app_data;

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
	/* check_control_func		*/	NULL,
	/* check_test_func		*/	NULL,
	/* get_aes_key			*/	NULL,
	/* get_timestamp_func		*/	NULL,
	/* endpoint_init_func		*/	NULL,
	/* endpoint_init_hook_func	*/	NULL,
	/* endpoint_start_func		*/	NULL,
	/* endpoint_stop_func		*/	NULL
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
	{"tmout",1,"30","Max time to wait for control connection reads (sec)"},

	/*
	 * Control/ test setup args
	 */
	{"sender", -2, NULL, "IP address/node name of local control socket"},
	{"receiver", -2, NULL, "IP address/node name of receiver server"},

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

main(
	int	argc,
	char	**argv
) {
	char			*progname;
	I2ErrHandle		eh;
	I2LogImmediateAttr	ia;
	int			od;
	OWPContext		ctx;

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

	if(OWPingCtx.opt.help) {
		usage(od, progname, NULL);
		exit(0);
	}

	if((!OWPingCtx.opt.sender && !OWPingCtx.opt.receiver) ||
		(OWPingCtx.opt.sender && OWPingCtx.opt.receiver)){
		I2ErrLog(eh, "Must specify exactly one of either -sender or -receiver");
		usage(od, progname, NULL);
		exit(1);
	}

	if(!OWPingCtx.opt.senderServ)
		OWPingCtx.opt.senderServ = OWPingCtx.opt.sender;

	if(!OWPingCtx.opt.receiverServ)
		OWPingCtx.opt.receiverServ = OWPingCtx.opt.receiver;

	OWPCfg.tm_out.tv_sec = OWPingCtx.opt.tmout;

	if( !(OWPingCtx.lib_ctx = OWPContextInitialize(&OWPCfg))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}

	ctx = OWPingCtx.lib_ctx;

	if( !(OWPingCtx.cntrl =
		OWPControlOpen(ctx,
			OWPAddrByNode(ctx,OWPingCtx.opt.

	exit(0);
}
