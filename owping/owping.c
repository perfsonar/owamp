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
#include <owamp/access.h>

#include "./owpingP.h"
#include "./localnode.h"

/*
 * The owping context
 */
static	ow_ping_trec	ping_ctx;

static I2ErrHandle		eh;

/*
** Retrieve records from remote server and save them in a file
** on the local disk (in directory <datadir>). Returns 0 on success,
** or -1 on failure. NOTE: currently just asks for complete session.
*/
int
owp_fetch_to_local(OWPControl cntrl, 
		   char       *datadir,
		   OWPSID     sid)
{
	char datafile[PATH_MAX]; /* full path to data file */
	char *new_name;
	int  fd;
	char sid_name[(sizeof(OWPSID)*2)+1];

	/* First create an "incomplete" path */
	strcpy(datafile, datadir);
	strcat(datafile,OWP_PATH_SEPARATOR);
	OWPHexEncode(sid_name, sid, sizeof(OWPSID));
	strcat(datafile, sid_name);
	strcat(datafile, OWP_INCOMPLETE_EXT);

	fd = open(datafile, O_WRONLY);
	if (fd < 0) {
		I2ErrLog(eh, "FATAL: open():%M");
		return -1;
	}

	/* Ask for complete session - for now. */
	if (OWPFetchSession(cntrl, 0, (u_int32_t)0xFFFFFFFF, sid, fd) 
		    == OWPErrFATAL) {
		I2ErrLog(eh, "main: OWPFetchSession failed");
		goto fatal;
	}

	/* Prepare "complete" name */
	new_name = strdup(datafile);
	if (!new_name) {
		I2ErrLog(eh, "FATAL: strdup():%M");
		goto fatal;
	}
	new_name[strlen(datafile) - strlen(OWP_INCOMPLETE_EXT)] = '\0';
	if (rename(datafile, new_name) < 0) {
		free(new_name);
		I2ErrLog(eh, "FATAL: strdup():%M");
		goto fatal;
	}

	free(new_name);
	if (close(fd) < 0)
		I2ErrLog(eh, "main: close():%M");
	return 0;

 fatal:
	if (close(fd) < 0)
		I2ErrLog(eh, "main: close():%M");
	if (unlink(datafile) < 0)
		I2ErrLog(eh, "main: unlink():%M");
	return -1;
}

/* Template for temporary directory to keep fetched data records. */
#define OWP_TMPDIR_TEMPLATE "/tmp/XXXXXXXXXXXXXXXX"

/*
** Data structures for a window of records being processed.
** Implemented as a linked list since in the most common case
** new nodes will just be added at the end.
*/
typedef struct rec_link *rec_link_ptr;
typedef struct rec_link {
	OWPCookedDataRec record;
	rec_link_ptr     next;
	rec_link_ptr     previous;
} rec_link;

/*
** The list structure - keep track of tail to make typical insert easier.
*/
typedef struct rec_list {
	rec_link_ptr head;
	rec_link_ptr tail;
} rec_list, *rec_list_ptr;

/*
** Initialize the linked list.
*/
void
list_init(rec_list_ptr list)
{
	assert(list);
	list->head = list->tail = NULL;
}

/*
** Free the linked list.
*/
void
list_free(rec_list_ptr list)
{
	rec_link_ptr ptr;
	assert(list);

	for (ptr = list->head; ptr; ptr = ptr->next)
		free(ptr);
}

/*
** Insert a new record in the <list> right after the given <current>.
** If <current> is NULL, insert at the head of the list. Return 0 on
** success, or -1 on failure.
*/
int
rec_insert_next(rec_list_ptr list, 
		rec_link_ptr current, 
		OWPCookedDataRecPtr data)
{
	rec_link_ptr new_record;

	if ((new_record = (rec_link_ptr)malloc(sizeof(*new_record))) == NULL){
		I2ErrLog(eh, "rec_link_new: malloc(%d) failed", 
			 sizeof(*new_record));
		return -1;
	}

	memcpy(&new_record->record, data, sizeof(*data));

	if (current == NULL) {
		if (list->head)
			list->head->previous = new_record;
		new_record->previous = NULL;
		new_record->next = list->head;
		list->head = new_record;

		if (list->tail == NULL)
			list->tail = new_record;

	} else {
		if (current->next == NULL) /* inserting at the tail */
			list->tail = new_record;
		else
			current->next->previous = new_record;
		new_record->previous = current;
		new_record->next = current->next;
		current->next = new_record;
	}

	return 0;
}

/* Various styles of owping output. */
#define OWP_MACHINE_READ         0    /* full dump of each record, ASCII     */
#define OWP_PING_STYLE           1    /* seq_no, one-way delay + final stats */
#define OWP_PING_QUIET           2    /* quiet, just summary at the end      */

/*
** State to be maintained by client during Fetch.
*/
typedef struct fetch_state {
	FILE*        fp;               /* stream to report records         */
	rec_list_ptr window;           /* window of read records           */
	int          type;             /* OWP_MACHINE_READ, OWP_PING_STYLE,
					  OPW_PING_QUIET                   */
	double       tmin;             /* max delay                        */
	double       tmax;             /* min delay                        */  
	double       tsum;             /* sum of delays                    */
	double       tsumsq;           /* sum of squared delays            */
	u_int32_t    numpack_received; /* number of received packets       */
	int64_t      last_seqno;       /* seqno of last output record      */
	int          order_disrupted;  /* flag */
} fetch_state, *fetch_state_ptr;

/*
** Initialize the state.
*/
void
fetch_state_init(fetch_state_ptr state, FILE *fp, rec_list_ptr window,int type)
{
	assert(state);

	state->fp = fp;
	state->window = window;
	state->type = type;

	state->tmin = 9999.999;
	state->tmax = state->tsum = state->tsumsq = 0.0;
	state->numpack_received = 0;
	state->last_seqno = -1;
	state->order_disrupted = 0;
}

#ifdef	NOT
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
#endif
	
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
	/* endpoint_init_func		*/	NULL,
	/* endpoint_init_hook_func	*/	NULL,
	/* endpoint_start_func		*/	NULL,
	/* endpoint_status_func		*/	NULL,
	/* endpoint_stop_func		*/	NULL,
	/* rand_type                    */      I2RAND_DEV,
	/* rand_data                    */      NULL
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
	{"authmode",1,NULL,
			"Requested modes:[E]ncrypted,[A]uthenticated,[O]pen"},
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

#ifndef	NDEBUG
	{"childwait",0,NULL,
		"Debugging: busy-wait children after fork to allow attach"},
#endif

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
        {
	"childwait", I2CvtToBoolean, &ping_ctx.opt.childwait,
	sizeof(ping_ctx.opt.childwait)
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

#define THOUSAND 1000.0

/*
** Update statistics due to the new record having given <delay>.
*/
void
owp_update_stats(fetch_state_ptr state,
		 double delay
		 )
{
	assert(state);
	
	/* Update the state. */
	if (delay < state->tmin)
		state->tmin = delay;

	if (delay > state->tmax)
		state->tmax = delay;

	state->tsum += delay;
	state->tsumsq += (delay*delay);
	state->numpack_received++;
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

#define OWP_CMP(a,b) ((a) < (b))? -1 : (((a) == (b))? 0 : 1)

/* 
   Width of Fetch receiver window - MUST be divisible by 4.
*/
#define OWP_WIN_WIDTH   16
/*
** Given two timestamp records, compare their sequence numbers.
** The function returns -1. 0 or 1 if the first record's sequence
** number is respectively less than, equal to, or greater than that 
** of the second.
*/
int
owp_seqno_cmp(OWPCookedDataRecPtr a, OWPCookedDataRecPtr b)
{
	assert(a);
	assert(b);

	return OWP_CMP(a->seq_no, b->seq_no);
}

/*
** Given a list of records ordered by seq_no (from lowest to
** highest) find a location in the list after which the record <rec>
** should be inserted. Return NULL if <rec> is to be inserted at
** the head of the list.
*/
rec_link_ptr
owp_find_location(rec_list_ptr list, OWPCookedDataRecPtr rec)
{
	rec_link_ptr ret;

	assert(list);
	assert(rec);

	for (ret = list->tail; ret; ret = ret->previous)
		if (owp_seqno_cmp(rec, &ret->record) > 0)
			return ret;

	return NULL;
}

/*
** Generic function to output timestamp record in given format
** as encoded in <state>.
*/
void
owp_record_out(OWPCookedDataRecPtr rec, fetch_state_ptr state)
{
	OWPTimeStamp send, recv;
	double delay;

	assert(rec);
	assert(state);

	switch (state->type) {
	case OWP_MACHINE_READ:
		assert(state->fp);
		fprintf(state->fp, 
"seq_no=%u send=%u.%us sync=%u prec=%u recv=%u.%us sync=%u prec=%u\n",
			rec->seq_no, rec->send.sec, rec->send.frac_sec, 
			rec->send.sync, rec->send.prec,
			rec->recv.sec, rec->recv.frac_sec, rec->recv.sync, 
			rec->recv.prec);
		break;
	case OWP_PING_STYLE:
		delay = owp_delay(&send, &recv);
		fprintf(state->fp, "seq_no=%u delay=%.3f ms\n", rec->seq_no, 
			delay*THOUSAND);
		owp_update_stats(state, delay);
		break;
	case OWP_PING_QUIET:
		delay = owp_delay(&rec->send, &rec->recv);
		owp_update_stats(state, delay);
		break;
	default:
		fprintf(stderr, "FATAL: Internal error - bad 'type' value\n");
		exit(1);
	}
}

/*
** Insert a new timestamp record in a window. Return 0 on success,
** or -1 on failure.
*/
int
fill_window(void *calldata,  
	    OWPCookedDataRecPtr rec
	    )
{
	fetch_state_ptr state = (fetch_state_ptr)calldata;

	assert(state);
	assert(state->window);

	owp_record_out(rec, state); /* Output is done in all cases. */

	if (state->type == OWP_MACHINE_READ)
		return 0;

	return rec_insert_next(state->window, 
			       owp_find_location(state->window, rec), rec);
}

/*
** Process newly arrived data record, and do any necessary output
** as encoded in state.
*/
int
do_rest(void *calldata, 
	OWPCookedDataRecPtr rec
	)
{
	fetch_state_ptr state = (fetch_state_ptr)calldata;

	assert(state);
	assert(state->window);
	assert(rec);

	owp_record_out(rec, state); /* Output is done in all cases. */

	/* If ordering is not important - done. */
	if (state->type == OWP_MACHINE_READ)
		return 0;

	/* If ordering is important - handle it here. */
	if (state->order_disrupted)
		return 0;
	if ((int64_t)(rec->seq_no) < state->last_seqno) {
		state->order_disrupted = 1;
		return 0; /* No error but all stats processing is off now. */
	}

	return 0;
}

/*
** Master output function - reads the records from the disk
** and prints them to <out> in a style specified by <type>.
** Its value is interpreted as follows:
** 0 - print out send and recv timestamsps for each record in machine-readable
** format;
** 1 - print one-way delay in msec for each record, and final summary
**     (original ping style: max/avg/min/stdev) at the end.
*/
int
do_records_all(int fd, u_int32_t num_rec, int type, FILE *out)
{
	rec_list window;
	fetch_state state;

	assert(out);
	assert((type == OWP_MACHINE_READ)
	       || (type == OWP_PING_STYLE)
	       || (type == OWP_PING_QUIET));

	list_init(&window);
	fetch_state_init(&state, out, &window, type);

	/* If few records - fill the window and flush immediately */
	if (num_rec <= OWP_WIN_WIDTH) {
		OWPFetchLocalRecords(fd, num_rec, fill_window, &state);
		
		/*
		  XXX - TODO: flush AND free the window and return
		*/
		list_free(&window);
		return 0;
	}
	
	OWPFetchLocalRecords(fd, OWP_WIN_WIDTH, fill_window, &state);
	OWPFetchLocalRecords(fd, num_rec - OWP_WIN_WIDTH, do_rest, &state);
	
	/*
	  XXX - TODO: flush AND free the window.
	*/

	list_free(&window);

	if (close(fd) < 0)
		I2ErrLog(eh, "WARNING: close(%d) failed", fd);

	/* Stats are requested and failed to keep records sorted - redo */
	if (((type == OWP_PING_STYLE) || (type == OWP_PING_QUIET))
		&& state.order_disrupted) {
		I2ErrLog(eh, "Severe out-of-order condition observed.");
		I2ErrLog(eh, 
	     "Producing statistics for this case is currently unimplemented.");
		exit(1);
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
	owp_policy_data		*policy;
	char			passwd[PATH_MAX];
	int			rc;
	OWPContext		ctx;
	OWPTestSpecPoisson	test_spec;
	OWPSID			sid_ret;
	OWPTimeStamp		start_time_rec={0,0,0,0};
	OWPPerConnDataRec	conndata;
	OWPAcceptType		acceptval;
	OWPErrSeverity		err;

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
	OWPCfg.eh = eh;

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

	OWPCfg.tm_out.tv_sec = ping_ctx.opt.tmout;

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(ping_ctx.lib_ctx = OWPContextInitialize(&OWPCfg))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}
	ctx = ping_ctx.lib_ctx;

	/*
	 * Setup paths.
	 */
	rc = snprintf(passwd,sizeof(passwd),"%s%s%s",ping_ctx.opt.confdir,
			OWP_PATH_SEPARATOR,ping_ctx.opt.passwd);
	if(rc > (int)sizeof(passwd)){
		I2ErrLog(eh, "Invalid path to passwd file.");
		exit(1);
	}

	policy = OWPPolicyInit(ctx, NULL, NULL, passwd, &err_ret);
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
	 * TODO: Figure out how the client is going to make policy
	 * requests. could just leave it empty I suppose. (Could also
	 * make the policy functions make the request directly if
	 * the pipefd portion of PerConnData is -1....
	 */
	conndata.pipefd = -1;
	conndata.link_data_dir = NULL;

	if (ping_ctx.opt.datadir) {
		/*
		  XXX - TODO: create the directory.
		*/
		  conndata.real_data_dir = ping_ctx.opt.datadir;
	}	
	else { /* create a unique temp dir */
		conndata.real_data_dir = strdup(OWP_TMPDIR_TEMPLATE);
		if (!conndata.real_data_dir) {
			I2ErrLog(eh, "FATAL: main: malloc(%d) failed",
				 strlen(OWP_TMPDIR_TEMPLATE) + 1);
			exit(1);
		}
		if (mkdtemp(conndata.real_data_dir) == NULL) {
			I2ErrLog(eh, 
		       "FATAL: main: mkdtemp: failed to create temp data dir");
			free(conndata.real_data_dir);
			exit(1);
		}
	}

	conndata.policy = policy;
	conndata.lossThreshold = ping_ctx.opt.lossThreshold;
	conndata.node = NULL;
#ifndef	NDEBUG
	conndata.childwait = ping_ctx.opt.childwait;
#endif

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
	if(!OWPSessionRequest(ping_ctx.cntrl,
			OWPAddrByNode(ctx,ping_ctx.opt.sender),
			!ping_ctx.sender_local,
			OWPAddrByNode(ctx,ping_ctx.opt.receiver),
			!ping_ctx.receiver_local,
			(OWPTestSpec*)&test_spec,
			sid_ret,
			&err_ret))
		FailSession(ping_ctx.cntrl);
	
	if(OWPStartSessions(ping_ctx.cntrl)< OWPErrINFO)
		FailSession(ping_ctx.cntrl);
	/*
	 * TODO install sig handler for keyboard interupt - to send stop
	 * sessions.
	 */
	if(OWPStopSessionsWait(ping_ctx.cntrl,NULL,&acceptval,&err) != 0)
		exit(1);

	/*
	  TODO - do the Fetch here.
	*/
	exit(0);
}
