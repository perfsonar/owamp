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
 *	Authors:	Jeff Boote
 *                      Anatoly Karp
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
owp_fetch_to_local(OWPControl cntrl, char *datadir, OWPSID sid)
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

	fd = open(datafile, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		I2ErrLog(eh, "FATAL: open(%s):%M", datafile);
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
 again:
	if (close(fd) < 0) {
		if (errno == EINTR)
			goto again;
		I2ErrLog(eh, "main: close():%M");
	}
	return 0;
	
 fatal:

 close_again:
	if (close(fd) < 0) {
		if (errno == EINTR)
			goto close_again;
		I2ErrLog(eh, "main: close(%d):%M", fd);
	}
 unlink_again:
	if (unlink(datafile) < 0) {
		if (errno == EINTR)
			goto unlink_again;
		I2ErrLog(eh, "main: unlink(%s):%M", datafile);
	}
	return -1;
}


/* Template for temporary directory to keep fetched data records. */
#define OWP_TMPDIR "/tmp"

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

	{"to",0,NULL,"Only test toward test address"},
	{"from",0,NULL,"Only test from test address"},
	{"srcaddr",1,NULL,"Local address for test"},
	/*
	 * policy config file options.
	 */
	{"confdir",1,OWP_CONFDIR,"Configuration directory"},
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
	{"padding", 1, "0", "min size of padding for test packets (octets)"},
	{"rate", 1, "1.0", "rate of test packets (packets/sec)"},
	{"percentile", 1, "50.0", "report given percentile of delays (0-100)"},
	{"numPackets", 1, "10", "number of test packets"},

	/*
	 * Recv specific args.
	 */
	{"lossThreshold", 1, "120",
			"elapsed time when recv declares packet lost (sec)"},
	{"datadir", 1, NULL, "Data directory to store test session data"},
	{"readfrom", 1, NULL, "Read binary data from file."},
	{"keepdata", 0, 0, "do not delete binary test session data "},
	{"full", 0, 0,    "print out full records in human-readable form"},
	{"records", 0, 0, "Show timestamp records."},

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
	"to", I2CvtToBoolean, &ping_ctx.opt.to,
	sizeof(ping_ctx.opt.to)
	},
        {
	"from", I2CvtToBoolean, &ping_ctx.opt.from,
	sizeof(ping_ctx.opt.from)
	},
	{
	"srcaddr", I2CvtToString, &ping_ctx.opt.srcaddr,
	sizeof(ping_ctx.opt.srcaddr)
	},
	{
	"confdir", I2CvtToString, &ping_ctx.opt.confdir,
	sizeof(ping_ctx.opt.confdir)
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
#if	NOT
        {
	"sender", I2CvtToString, &ping_ctx.opt.sender,
	sizeof(ping_ctx.opt.sender)
	},
        {
	"zreceiver", I2CvtToString, &ping_ctx.opt.receiver,
	sizeof(ping_ctx.opt.receiver)
	},
#endif
        {
	"padding", I2CvtToUInt, &ping_ctx.opt.padding,
	sizeof(ping_ctx.opt.padding)
	},
        {
	"rate", I2CvtToFloat, &ping_ctx.opt.rate,
	sizeof(ping_ctx.opt.rate)
	},
        {
	"percentile", I2CvtToFloat, &ping_ctx.opt.percentile,
	sizeof(ping_ctx.opt.percentile)
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
	"readfrom", I2CvtToString, &ping_ctx.opt.readfrom,
	sizeof(ping_ctx.opt.readfrom)
	},
        {
	"lossThreshold", I2CvtToUInt, &ping_ctx.opt.lossThreshold,
	sizeof(ping_ctx.opt.lossThreshold)
	},
        {
	"full", I2CvtToBoolean, &ping_ctx.opt.full,
	sizeof(ping_ctx.opt.full)
	},
        {
	"records", I2CvtToBoolean, &ping_ctx.opt.records,
	sizeof(ping_ctx.opt.records)
	},
	{
	"keepdata", I2CvtToBoolean, &ping_ctx.opt.keepdata,
	sizeof(ping_ctx.opt.keepdata)
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

	fprintf(stderr,"Usage: %s [options] testaddress [servaddr]\n",
								progname);
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

/* Width of Fetch receiver window. */
#define OWP_WIN_WIDTH   64

#define OWP_NUM_LOW         10000
#define OWP_NUM_MID         1000
#define OWP_NUM_HIGH        1000

#define OWP_CUTOFF_LOW      0.1
#define OWP_CUTOFF_MID      1.0
#define OWP_CUTOFF_HIGH     ((double)(ping_ctx.opt.lossThreshold))

/* These are NOT configurable. */
#define OWP_MESH_LOW        ((double)OWP_CUTOFF_LOW/(double)OWP_NUM_LOW)
#define OWP_MESH_MID        ((double)(OWP_CUTOFF_MID-OWP_CUTOFF_LOW)         \
			     /(double)OWP_NUM_MID) 
#define OWP_MESH_HIGH       ((double)(OWP_CUTOFF_HIGH-OWP_CUTOFF_MID)        \
                             /(double)OWP_NUM_HIGH)

#define OWP_MAX_N           100  /* N-reordering statistics parameter */
#define OWP_LOOP(x)         ((x) >= 0? (x): (x) + OWP_MAX_N)

/*
** Generic state to be maintained by client during Fetch.
*/
typedef struct fetch_state {
	FILE*        fp;               /* stream to report records           */
	OWPCookedDataRec window[OWP_WIN_WIDTH]; /* window of read records    */
	OWPCookedDataRec last_out; /* last processed record            */
	int          cur_win_size;     /* number of records in the window    */
	double       tmin;             /* min delay                          */
	double       tmax;             /* max delay                          */
	u_int32_t    num_received;     /* number of received packets         */
	u_int32_t    dup_packets;      /* number of duplicate packets        */
	int          order_disrupted;  /* flag                               */
	u_int32_t    max_seqno;        /* max sequence number seen           */
	u_int32_t    *buckets;         /* array of buckets of counts         */

	/* N-reodering state variables. */
	u_int32_t        m[OWP_MAX_N];       /* We have m[j-1] == number of
						j-reordered packets.         */
        u_int32_t        ring[OWP_MAX_N];    /* Last sequence numbers seen.  */
        u_int32_t        r;                  /* Ring pointer for next write. */
        u_int32_t        l;                  /* Number of seq numbers read.  */

} fetch_state, *fetch_state_ptr;

#define OWP_CMP(a,b) ((a) < (b))? -1 : (((a) == (b))? 0 : 1)
#define OWP_MIN(a,b) ((a) < (b))? (a) : (b)

/*
** The function returns -1. 0 or 1 if the first record's sequence
** number is respectively less than, equal to, or greater than that 
** of the second.
*/
int
owp_seqno_cmp(OWPCookedDataRecPtr a, OWPCookedDataRecPtr b)
{
	assert(a); assert(b);
	return OWP_CMP(a->seq_no, b->seq_no);
}

/*
** Find the right spot in the window to insert the new record <rec>
** Return max {i| 0 <= i <= cur_win_size-1 and <rec> is later than the i_th
** record in the state window}, or -1 if no such index is found.
*/
int
look_for_spot(fetch_state_ptr state,
	      OWPCookedDataRecPtr rec)
{
	int i;
	assert(state->cur_win_size);

	for (i = state->cur_win_size - 1; i >= 0; i--) {
		if (owp_seqno_cmp(&state->window[i], rec) < 0)
			return i;
	}
	
	return -1;
}

double
owp_bits2prec(int nbits)
{
	return 1.0/pow(2.0, (double)(nbits - 32));
}

/*
** Generic function to output timestamp record <rec> in given format
** as encoded in <state>.
*/
void
owp_record_out(fetch_state_ptr state, OWPCookedDataRecPtr rec)
{
	double delay;

	assert(rec);
	assert(state);

	if (!ping_ctx.opt.records)
		return;

	assert(state->fp);
	delay = owp_delay(&rec->send, &rec->recv);
	if (ping_ctx.opt.full)
		fprintf(state->fp, 
	 "#%-10u send=%8X:%-8X %u%c     recv=%8X:%-8X %u%c\n",
			rec->seq_no, rec->send.sec, rec->send.frac_sec, 
			rec->send.prec, (rec->send.sync)? 'S' : 'U', 
			rec->recv.sec, rec->recv.frac_sec, 
			rec->recv.prec, (rec->recv.sync)? 'S' : 'U');
	else {
		if (rec->send.sync && rec->recv.sync) {
			double prec = owp_bits2prec(rec->send.prec) 
				+ owp_bits2prec(rec->recv.prec);
    fprintf(state->fp, 
	    "seq_no=%-10u delay=%.3f ms       (sync, precision %.3f ms)\n", 
				rec->seq_no, delay*THOUSAND, prec);
		} else 
			fprintf(state->fp,"seq_no=%u delay=%.3f ms (unsync)\n",
				rec->seq_no, delay*THOUSAND);
	}
}


#define OWP_MAX_BUCKET  (OWP_NUM_LOW + OWP_NUM_MID + OWP_NUM_HIGH - 1)
/*
** Given a delay, compute index of the corresponding bucket.
*/
int
owp_bucket(double delay)
{
	if (delay < 0)
		return 0;
	if (delay < OWP_CUTOFF_LOW)
		return (int)(delay/OWP_MESH_LOW);
	if (delay < OWP_CUTOFF_MID)
		return OWP_NUM_LOW 
			+ (int)((delay-OWP_CUTOFF_LOW)/OWP_MESH_MID); 
	return OWP_MIN(OWP_NUM_LOW + OWP_NUM_MID 
		       + (int)((delay - OWP_CUTOFF_MID)/OWP_MESH_HIGH),
		       OWP_MAX_BUCKET);
}

void
owp_update_stats(fetch_state_ptr state, OWPCookedDataRecPtr rec) {
	double delay;  
	int bucket;

	assert(state); assert(rec);

	if (state->num_received++ && !owp_seqno_cmp(rec, &state->last_out)){
		state->dup_packets++;
		return;
	}

	delay =  owp_delay(&rec->send, &rec->recv);
	bucket = owp_bucket(delay);
	
	assert((0 <= bucket) && (bucket <= OWP_MAX_BUCKET));
	state->buckets[bucket]++;

	if (delay < state->tmin)
		state->tmin = delay;
	if (delay > state->tmax)
		state->tmax = delay;
	
	if (rec->seq_no > state->max_seqno)
		state->max_seqno = rec->seq_no;

	memcpy(&state->last_out, rec, sizeof(*rec));
}

/*
** Given a number <alpha> in [0, 1], compute
** min {x: F(x) >= alpha}
** where F is the empirical distribution function (in our case,
** with a fuzz factor due to use of buckets.
*/
double
owp_get_percentile(fetch_state_ptr state, double alpha)
{
	int i;
	double sum = 0;
	u_int32_t unique = state->num_received - state->dup_packets;

	assert((0.0 <= alpha) && (alpha <= 1.0));
	
	for (i = 0; (i <= OWP_MAX_BUCKET) && (sum < alpha*unique); i++)
		sum += state->buckets[i];

	if (i <= OWP_NUM_LOW)
		return i*OWP_MESH_LOW;
	if (i <= OWP_NUM_LOW + OWP_NUM_MID)
		return OWP_CUTOFF_LOW + (i - OWP_NUM_LOW)*OWP_MESH_MID;
	return OWP_CUTOFF_MID + (i - (OWP_NUM_LOW+OWP_NUM_MID))*OWP_MESH_HIGH;
}

/* True if the first timestamp is earlier than the second. */
#define OWP_EARLIER_THAN(a, b)                                \
( ((a).sec < (b).sec)                                         \
  || ( ((a).sec == (b).sec)                                   \
       && ((a).frac_sec < (b).frac_sec)                       \
     )                                                        \
) 

#define OWP_OUT_OF_ORDER(new, last_out)                       \
(                                                             \
((new)->seq_no < (last_out)->seq_no)                          \
|| (                                                          \
      ((new)->seq_no == (last_out)->seq_no)                   \
      && OWP_EARLIER_THAN(((new)->recv), ((last_out)->recv))  \
   )                                                          \
)

/*
** Processs a single record, updating statistics and internal state.
** Return 0 on success, or -1 on failure.
*/
int
do_single_record(void *calldata, OWPCookedDataRecPtr rec) 
{
	int i;
	fetch_state_ptr state = (fetch_state_ptr)calldata;
	u_int32_t j;

	assert(state);

	owp_record_out(state, rec); /* Output is done in all cases. */

	/* If ordering is important - handle it here. */
	if (state->order_disrupted)
		return 0;
	
	/* Update N-reordering state. */
	for (j = 0; j < OWP_MIN(state->l, OWP_MAX_N); j++) { 
		 if (!((rec->seq_no) 
		       < state->ring[OWP_LOOP((state->r) - j - 1)]))
			 break;
		 state->m[j]++;
	}
	state->ring[state->r] = rec->seq_no;
	state->l++;
	state->r = (state->r + 1) % OWP_MAX_N;

	if (state->cur_win_size < OWP_WIN_WIDTH){/* insert - no stats updates*/
		if (state->cur_win_size) { /* Grow window. */
			int num_records_to_move;
			i = look_for_spot(state, rec);
			num_records_to_move = state->cur_win_size - i - 1;

			/* Cut and paste if needed - then insert. */
			if (num_records_to_move) 
				memmove(&state->window[i+2], 
					&state->window[i+1], 
					num_records_to_move*sizeof(*rec));
			memcpy(&state->window[i+1], rec, sizeof(*rec)); 
		}  else /* Initialize window. */
			memmove(&state->window[0], rec, sizeof(*rec));
		state->cur_win_size++;
	} else { /* rotate - update state*/
		OWPCookedDataRecPtr out_rec = rec;		
		if (state->num_received
		    && OWP_OUT_OF_ORDER(rec, &(state->last_out))) {
				state->order_disrupted = 1;
				return 0; 
		}

		i = look_for_spot(state, rec);

		if (i != -1)
			out_rec = &state->window[0];
		owp_update_stats(state, out_rec);

		/* Update the window.*/
		if (i != -1) {  /* Shift if needed - then insert.*/
			if (i) 
				memmove(&state->window[0],
					&state->window[1], i*sizeof(*rec));
			memcpy(&state->window[i], rec, sizeof(*rec));
		} 
	}
	
	return 0;
}

/*
** Print out summary results, ping-like style. sent + dup == lost +recv.
*/
int
owp_do_summary(fetch_state_ptr state)
{
	double min = ((double)(state->tmin)) * THOUSAND;    /* msec */
	u_int32_t sent = state->max_seqno + 1;
	u_int32_t lost = state->dup_packets + sent - state->num_received; 
	double percent_lost = (100.0*(double)lost)/(double)sent;
	int j;

	assert(state); assert(state->fp);

	fprintf(state->fp, "\n--- owping statistics ---\n");
	if (state->dup_packets)
		fprintf(state->fp, 
 "%u packets transmitted, %u packets lost (%.1f%% loss), %u duplicates\n",
			sent, lost, percent_lost, state->dup_packets);
	else	
		fprintf(state->fp, 
		     "%u packets transmitted, %u packets lost (%.1f%% loss)\n",
			sent ,lost, percent_lost);

	fprintf(state->fp, "one-way delay min/median = %.3f/%.3f ms\n", 
		min, owp_get_percentile(state, 0.5)*THOUSAND);

	for (j = 0; j < OWP_MAX_N && state->m[j]; j++)
                fprintf(state->fp,
			"%d-reordering = %f%%\n", j+1, 
			100.0*state->m[j]/(state->l - j - 1));
        if (j == 0) 
		fprintf(state->fp, "no reordering\n");
        else 
		if (j < OWP_MAX_N) 
			fprintf(state->fp, "no %d-reordering\n", j+1);
        else 
		fprintf(state->fp, 
			"only up to %d-reordering is handled\n", OWP_MAX_N);

	if (fabs(ping_ctx.opt.percentile - 50.0) > 0.000001) {
		float x = ping_ctx.opt.percentile/100.0;
		fprintf(state->fp, 
			"%.2f percentile of one-way delays: %.3f ms\n",
			ping_ctx.opt.percentile,
			owp_get_percentile(state, x) * THOUSAND);
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
do_records_all(
		char		*datadir,
		OWPSID		sid,
		fetch_state_ptr	state
		)
{
	int		fd, i, num_buckets;
	u_int32_t	num_rec, typeP;
	struct stat	stat_buf;
	char		datafile[PATH_MAX]; /* full path to data file */
	char		sid_name[(sizeof(OWPSID)*2)+1];
	
	if(sid){
		strcpy(datafile,datadir);
		strcat(datafile,OWP_PATH_SEPARATOR);
		OWPHexEncode(sid_name,sid,sizeof(OWPSID));
		strcat(datafile, sid_name);
	}
	else
		strcpy(datafile,datadir);

 open_again:
	if ((fd = open(datafile, O_RDONLY)) < 0) {
		if (errno == EINTR)
			goto open_again;
		I2ErrLog(eh, "FATAL: open(%s) failed:%M", datafile);
		return -1;
	}

	if (!ping_ctx.opt.keepdata) {
	unlink_again:
		if (unlink(datafile) < 0) {
			if (errno == EINTR)
				goto unlink_again;
			I2ErrLog(eh, "WARNING: unlink(%s) failed:%M",datafile);
		}
	}

	if (fstat(fd, &stat_buf) < 0) {
		I2ErrLog(eh, "FATAL: open():%M");
		return -1;
	}   
	
	num_rec = (stat_buf.st_size - 4) / 20;
	if ((stat_buf.st_size - 4)%20) {
		I2ErrLog(eh, 
		       "FATAL: data file %s contains uneven number of records",
			 datafile);
		return -1;
	}

	if (OWPGetDataHeader(fd, &typeP) != OWPErrOK) {
		I2ErrLog(eh, "FATAL: could not get data header");
		return -1;
	}
	
	/*
	  Initialize fields of state to keep track of.
	*/
	state->cur_win_size = 0;
	state->tmin = 9999.999;
	state->tmax = 0.0;
	state->num_received = state->dup_packets = state->max_seqno = 0;

	state->order_disrupted = 0;

	/* N-reodering fields/ */
	state->r = state->l = 0;
	for (i = 0; i < OWP_MAX_N; i++) 
		state->m[i] = 0;

	num_buckets = OWP_NUM_LOW + OWP_NUM_MID + OWP_NUM_HIGH;

	state->buckets 
		= (u_int32_t *)malloc(num_buckets*sizeof(*(state->buckets)));
	if (!state->buckets) {
		I2ErrLog(eh, "FATAL: main: malloc(%d) failed: %M",num_buckets);
		exit(1);
	}
	for (i = 0; i <= OWP_MAX_BUCKET; i++)
		state->buckets[i] = 0;

	OWPFetchLocalRecords(fd, num_rec, do_single_record, state);
	
 close_again:
	if (close(fd) < 0) {
		if (errno == EINTR)
			goto close_again;
		I2ErrLog(eh, "WARNING: close(%d) failed: %M", fd);
	}

	/* Stats are requested and failed to keep records sorted - redo */
	if (state->order_disrupted) {
		I2ErrLog(eh, "Severe out-of-order condition observed.");
		I2ErrLog(eh, 
	     "Producing statistics for this case is currently unimplemented.");
		exit(1);
	}

	/* Incorporate remaining records left in the window. */
	for (i = 0; i < state->cur_win_size; i++)
		owp_update_stats(state, &state->window[i]);

	owp_do_summary(state);
	free(state->buckets);
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
	OWPSID			tosid,fromsid;
	OWPTimeStamp		start_time_rec={0,0,0,0};
	OWPPerConnDataRec	conndata;
	OWPAcceptType		acceptval;
	OWPErrSeverity		err;
	fetch_state             state;

	ia.line_info = (I2NAME | I2MSG);
	ia.fp = stderr;

	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	state.fp = stdout;

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

	od = I2OpenOptionTbl(eh);

	/*
	* register the options we're interested in and have them parsed
	*/
	if(I2ParseOptionTable(od, &argc, argv, set_options) < 0) {
		I2ErrLog(eh, "Could not parse command line options");
		exit(1);
	}

	if((argc < 2) || (argc > 3)){
		usage(od, progname, NULL);
		exit(1);
	}

	ping_ctx.remote_test = argv[1];
	if(argc > 2)
		ping_ctx.remote_serv = argv[2];
	else
		ping_ctx.remote_serv = ping_ctx.remote_test;

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

	if ((ping_ctx.opt.percentile < 0.0) 
		|| (ping_ctx.opt.percentile > 100.0)) {
		usage(od, progname, NULL);
		exit(0);
	}

	if (ping_ctx.opt.readfrom) {
		ping_ctx.opt.keepdata = 1;
		if (do_records_all(ping_ctx.opt.readfrom, NULL, &state) < 0){
			I2ErrLog(eh, 
			 "FATAL: do_records_all(%s): failure processing data",
				 ping_ctx.opt.readfrom);
			exit(1);
		}
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

	if(ping_ctx.opt.identity){
		/*
		 * Eventually need to modify the policy init for the
		 * client to deal with a pass-phrase instead of/ or in
		 * addition to the passwd file.
		 */
		policy = OWPPolicyInit(ctx, NULL, NULL, passwd, &err_ret);
		if (err_ret == OWPErrFATAL){
			I2ErrLog(eh, "PolicyInit failed. Exiting...");
			exit(1);
		};
	}

	/*
	 * This is in reality dependent upon the actual protocol used
	 * (ipv4/ipv6) - it is also dependent upon the auth mode since
	 * authentication implies 128bit block sizes.
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

	if(!ping_ctx.opt.to && !ping_ctx.opt.from)
		ping_ctx.opt.to = ping_ctx.opt.from = True;

	/*
	 * TODO: create a "start" option.
	 *
	 * For now, start test two seconds from now.
	 */
	if(!OWPGetTimeOfDay(&start_time_rec)){
		I2ErrLogP(eh,errno,"Unable to get current time:%M");
		exit(1);
	}

	start_time_rec.sec += 2;

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

	conndata.pipefd = -1;
	conndata.link_data_dir = NULL;

	/* Set up data dir.*/

	if (ping_ctx.opt.datadir) {
		  conndata.real_data_dir = ping_ctx.opt.datadir;
	} else { /* create a unique temp dir */	
		conndata.real_data_dir = conndata.real_data_dir_mem;
		strcpy(conndata.real_data_dir, OWP_TMPDIR);
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
			OWPAddrByNode(ctx,ping_ctx.opt.srcaddr),
			OWPAddrByNode(ctx,ping_ctx.remote_serv),
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
	if(ping_ctx.opt.to &&
		!OWPSessionRequest(ping_ctx.cntrl,
			NULL,False,
			OWPAddrByNode(ctx,ping_ctx.remote_test),True,
			(OWPTestSpec*)&test_spec, tosid, &err_ret))
		FailSession(ping_ctx.cntrl);
	if(ping_ctx.opt.from &&
		!OWPSessionRequest(ping_ctx.cntrl,
			OWPAddrByNode(ctx,ping_ctx.remote_test),True,
			NULL,False,
			(OWPTestSpec*)&test_spec, fromsid, &err_ret))
		FailSession(ping_ctx.cntrl);
	
	if(OWPStartSessions(ping_ctx.cntrl)< OWPErrINFO)
		FailSession(ping_ctx.cntrl);

	/*
	 * TODO install sig handler for keyboard interupt - to send stop
	 * sessions. (Currently SIGINT causes everything to be killed and
	 * lost - might be reasonable to keep it that way.)
	 */
	if(OWPStopSessionsWait(ping_ctx.cntrl,NULL,&acceptval,&err) != 0)
		exit(1);

	if (acceptval != 0) {
		I2ErrLog(eh, "Test session(s) Questionable...");
	}

	if(ping_ctx.opt.to){
		if(owp_fetch_to_local(conndata.cntrl, 
				       conndata.real_data_dir, tosid) < 0){
			I2ErrLog(eh, "Failed to fetch remote records");
			goto next_test;
		}
		fprintf(state.fp,"\n--------to session-----------\n");
		if(do_records_all(conndata.real_data_dir, tosid, &state) < 0){
			I2ErrLog(eh,"FATAL: do_records_all(to session)");
		}
		fprintf(state.fp,"--------end to session--------\n");
	}
next_test:
	if(ping_ctx.opt.from){
		fprintf(state.fp,"\n------from session--------\n");
		if(do_records_all(conndata.real_data_dir, fromsid, &state) < 0){
			I2ErrLog(eh,"FATAL: do_records_all(from session)");
		}
		fprintf(state.fp,"--------end from session--------\n");
	}

	exit(0);
}
