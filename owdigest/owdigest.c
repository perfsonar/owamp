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
 *	File:		owdigest.c
 *
 *	Author: 	Anatoly Karp
 *                      Internet2    
 *			
 *
 *	Date:		Mon Sep 9 12:22:31  2002
 *
 *	Description:	create a digest of bucket counts from
 *                      the raw data files.
 *
 *      
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include <I2util/util.h>
#include <owamp/owamp.h>

static I2ErrHandle	eh;

#define OWP_MAX_BUCKET  (OWP_NUM_LOW + OWP_NUM_MID + OWP_NUM_HIGH - 1)

#define OWP_NUM_LOW         50000
#define OWP_NUM_MID         1000
#define OWP_NUM_HIGH        49900

#define OWP_CUTOFF_A        (double)(-50.0)
#define OWP_CUTOFF_B        (double)0.0
#define OWP_CUTOFF_C        (double)0.1
#define OWP_CUTOFF_D        (double)50.0

const double mesh_low = (OWP_CUTOFF_B - OWP_CUTOFF_A)/OWP_NUM_LOW;
const double mesh_mid = (OWP_CUTOFF_C - OWP_CUTOFF_B)/OWP_NUM_MID;
const double mesh_high = (OWP_CUTOFF_D - OWP_CUTOFF_C)/OWP_NUM_HIGH;

/* Width of Fetch receiver window. */
#define OWP_WIN_WIDTH   64

#define OWP_MAX_N           100  /* N-reordering statistics parameter */
#define OWP_LOOP(x)         ((x) >= 0? (x): (x) + OWP_MAX_N)

/*
** Generic state to be maintained by client during Fetch.
*/
typedef struct state {
	OWPDataRec window[OWP_WIN_WIDTH]; /* window of read records          */
	OWPDataRec last_out;           /* last processed record              */
	u_int32_t    cur_win_size;     /* number of records in the window    */
	u_int32_t    num_received;     /* number of good received packets    */
	u_int32_t    dup_packets;      /* number of duplicate packets        */
	int          order_disrupted;  /* flag                               */
	u_int32_t    max_seqno;        /* max sequence number seen           */
	u_int16_t    *buckets;         /* array of buckets of counts         */
	u_int32_t    count_out;        /* number of printed packets          */

	/* worst case precision is determined by the lexicographically
	   smallest pair of precision bits */
	int          bits_low;
	int          bits_high;
	int          sync;           /* flag set if never saw unsync packets */
} state, *state_ptr;

#define OWP_CMP(a,b) ((a) < (b))? -1 : (((a) == (b))? 0 : 1)
#define OWP_MIN(a,b) ((a) < (b))? (a) : (b)

/*
** The function returns -1. 0 or 1 if the first record's sequence
** number is respectively less than, equal to, or greater than that 
** of the second.
*/
int
owp_seqno_cmp(OWPDataRecPtr a, OWPDataRecPtr b)
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
look_for_spot(state_ptr s,
	      OWPDataRecPtr rec)
{
	int i;
	assert(s->cur_win_size);

	for (i = s->cur_win_size - 1; i >= 0; i--) {
		if (owp_seqno_cmp(&s->window[i], rec) < 0)
			return i;
	}
	
	return -1;
}

double
owp_bits2prec(int nbits)
{
	return (nbits >= 32)? 1.0/(1 << (nbits - 32)) 
		: (double)(1 << (32 - nbits));
}

int
owp_bucket(double delay)
{
	if (delay < OWP_CUTOFF_A)
		return 0;

	if (delay < OWP_CUTOFF_B)
		return OWP_NUM_LOW + (int)(delay/mesh_low);

	if (delay < OWP_CUTOFF_C)
		return OWP_NUM_LOW +  (int)(delay/mesh_mid);

	if (delay < OWP_CUTOFF_D)
		return OWP_NUM_LOW + OWP_NUM_MID 
			+ (int)((delay - OWP_CUTOFF_C)/mesh_high);
	
	return OWP_MAX_BUCKET;
}

void
owp_update_stats(state_ptr s, OWPDataRecPtr rec) {
	double delay;  
	int bucket, low, high;

	assert(s); assert(rec);

	if (s->num_received && !owp_seqno_cmp(rec, &s->last_out)){
		s->dup_packets++;
		s->num_received++;
		return;
	}

	if (rec->seq_no > s->max_seqno)
		s->max_seqno = rec->seq_no;
	if (OWPIsLostRecord(rec))
		return;
	s->num_received++;

	delay =  owp_delay(&rec->send, &rec->recv);

	low = MIN(rec->send.prec, rec->recv.prec);
	high = MAX(rec->send.prec, rec->recv.prec);
	if ((low < s->bits_low) 
	    || ((low == s->bits_low) && (high < s->bits_high))) {
		s->bits_low = low;
		s->bits_high = high;
	}

	if (!rec->send.sync || !rec->send.sync)
		s->sync = 0;

	bucket = owp_bucket(delay);
	
	assert((0 <= bucket) && (bucket <= OWP_MAX_BUCKET));
	s->buckets[bucket]++;

	memcpy(&s->last_out, rec, sizeof(*rec));
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

int
do_single_record(void *calldata, OWPDataRecPtr rec) 
{
	int i;
	state_ptr s = (state_ptr)calldata;

	assert(s);

	if (OWPIsLostRecord(rec)) {
		owp_update_stats(s, rec);
		return 0;       /* May do something better later. */
	}

	/* If ordering is important - handle it here. */
	if (s->order_disrupted)
		return 0;
	
	if (s->cur_win_size < OWP_WIN_WIDTH){/* insert - no stats updates*/
		if (s->cur_win_size) { /* Grow window. */
			int num_records_to_move;
			i = look_for_spot(s, rec);
			num_records_to_move = s->cur_win_size - i - 1;

			/* Cut and paste if needed - then insert. */
			if (num_records_to_move) 
				memmove(&s->window[i+2], 
					&s->window[i+1], 
					num_records_to_move*sizeof(*rec));
			memcpy(&s->window[i+1], rec, sizeof(*rec)); 
		}  else /* Initialize window. */
			memmove(&s->window[0], rec, sizeof(*rec));
		s->cur_win_size++;
	} else { /* rotate - update s*/
		OWPDataRecPtr out_rec = rec;		
		if (s->num_received
		    && OWP_OUT_OF_ORDER(rec, &(s->last_out))) {
				s->order_disrupted = 1;
				/* terminate parsing */
				return 1; 
		}

		i = look_for_spot(s, rec);

		if (i != -1)
			out_rec = &s->window[0];
		owp_update_stats(s, out_rec);

		/* Update the window.*/
		if (i != -1) {  /* Shift if needed - then insert.*/
			if (i) 
				memmove(&s->window[0],
					&s->window[1], i*sizeof(*rec));
			memcpy(&s->window[i], rec, sizeof(*rec));
		} 
	}
	
	return 0;
}

void
usage()
{
	fprintf(stderr, "usage: owdigest [-o out_file] datafile [...]\n");
	exit(1);
}

int
main(int argc, char *argv[]) 
{
	FILE *fp, *out = stdout;
	u_int32_t hdr_len, num_rec, i;
	state s;
	char *progname;
	int num_buckets, nonempty, ch, outflag = 0;
	I2LogImmediateAttr	ia;

	ia.line_info = (I2NAME | I2MSG);
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

	while ((ch = getopt(argc, argv, "o:")) != -1)
             switch (ch) {
             case 'o':
		     outflag = 1;
                     break;
             case '?':
             default:
                     usage();
             }

	if (outflag) 
		if ((out = fopen(optarg, "w")) == NULL)
			err(1, "%s", optarg);

	argc -= optind;
	argv += optind;

	if (!argc)
		usage();

	while (argc > 0) {
		if(!(fp = fopen(argv[0],"rb"))){
			I2ErrLog(eh,"fopen(%s):%M",argv[0]);
			exit(1);
		}
		
		if (!(num_rec = OWPReadDataHeader(fp,&hdr_len))) {
			I2ErrLog(eh,"do_records_all() failed.");
			exit(1);
		}

		/* Initialize state here. */
		s.cur_win_size = 0;
		s.num_received = s.dup_packets = s.max_seqno = 0;
		
		s.order_disrupted = 0;
		
		s.count_out = 0;
		
		s.bits_low = s.bits_high = 56;
		s.sync = 1;
		
		num_buckets = OWP_NUM_LOW + OWP_NUM_MID + OWP_NUM_HIGH;
		
		s.buckets = 
			(u_int16_t *)malloc(num_buckets*sizeof(*(s.buckets)));
			
		if (!s.buckets) {
			I2ErrLog(eh, 
			     "FATAL: main: malloc(%d) failed: %M",num_buckets);
			exit(1);
		}
		for (i = 0; i <= OWP_MAX_BUCKET; i++)
			s.buckets[i] = 0;
		
		if(OWPParseRecords(fp, num_rec, do_single_record, 
				   &s) < OWPErrWARNING){
			I2ErrLog(eh,"OWPParseRecords():%M");
			return -1;
		}
		
		if (s.order_disrupted) {
			I2ErrLog(eh,"Severe out-of-order condition observed.");
			I2ErrLog(eh, 
	     "Producing statistics for this case is currently unimplemented.");
			return 0;
		}
		
		/* Incorporate remaining records left in the window. */
		for (i = 0; i < s.cur_win_size; i++)
			owp_update_stats(&s, &s.window[i]);
		
		nonempty = 0;
		for (i = 0; i <= OWP_MAX_BUCKET; i++) {
			if (s.buckets[i]) {
				if ((fwrite(&i, sizeof(i), 1, out) < 1)
					|| (fwrite(&s.buckets[i],
						   sizeof(*(s.buckets)),
						   1, out) < 1)) {
					I2ErrLog(eh, 
						 "FATAL: fwrite() failed: %M");
					exit(1);
				}
				fprintf(stderr, 
					"printed index = %u, count = %u\n", 
					i, s.buckets[i]);
				nonempty++;
			}
		}
		free(s.buckets);
		fclose(fp);
		argv++;
		argc--;
	}
	fflush(out);
	exit(0);
}
