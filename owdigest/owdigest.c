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
 *                      the raw data files. A given raw datafile
 *                      is split into a given number of chunks
 *                      and a digest is produced for each.
 *
 *      
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <I2util/util.h>
#include <owamp/owamp.h>

#ifndef HAVE_MERGESORT
#define mergesort(base, nmemb, size, compar)    \
(qsort(base, nmemb, size, compar), 0)
#endif

#define PREC_THRESHOLD  ((u_int8_t)35)   /* packets where EITHER sender OR
					    receiver has fewer precision bits
					    get thrown out */

static I2ErrHandle	eh;
static char magic[9] = "OwDigest";
static u_int8_t version = 1;

#define OWP_MAX_N           100  /* N-reordering statistics parameter */
#define OWP_LOOP(x)         ((x) >= 0? (x): (x) + OWP_MAX_N)

/*
** Generic state to be maintained by client during Fetch (from disk).
*/
typedef struct state {
	OWPDataRec *records;            /* records to be sorted              */
	int        cur;                 /* current index to place new record */
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

int
owp_bucket(double delay)
{
	if (delay < OWP_CUTOFF_A)
		return 0;

	if (delay < OWP_CUTOFF_B)
		return (int)((delay - OWP_CUTOFF_A)/mesh_low);

	if (delay < OWP_CUTOFF_C)
		return OWP_NUM_LOW +  (int)((delay - OWP_CUTOFF_B)/mesh_mid);

	if (delay < OWP_CUTOFF_D)
		return OWP_NUM_LOW + OWP_NUM_MID 
			+ (int)((delay - OWP_CUTOFF_C)/mesh_high);
	
	return OWP_MAX_BUCKET;
}

int
tstamp_cmp(const void *a, const void *b)
{
	OWPDataRecPtr first = (OWPDataRecPtr)a;
	OWPDataRecPtr second  = (OWPDataRecPtr)b;

	if (first->send.sec < second->send.sec
	    || (first->send.sec == second->send.sec 
		&& first->send.frac_sec < second->send.frac_sec))
		return -1;

	if (first->send.sec > second->send.sec
	    || (first->send.sec == second->send.sec 
		&& first->send.frac_sec > second->send.frac_sec))
		return 1;

	return 0;
}

int
do_single_record(void *calldata, OWPDataRecPtr rec) 
{
	state_ptr s = (state_ptr)calldata;
	assert(s); assert(rec);

	memcpy(&s->records[s->cur], rec, sizeof(*rec));
	s->cur++;
	
	return 0;
}

void
usage()
{
	fprintf(stderr, 
		"usage: owdigest [-p prec_bits] [-v] datafile out_file\n");
	exit(1);
}

#define THOUSAND    ((double)1000.0)

/*
** Print out a record. Used for debugging.
*/
void
print_rec(OWPDataRecPtr rec, int full)
{
	double delay = owp_delay(&rec->send, &rec->recv);
				 
	if (full) {
		if (!OWPIsLostRecord(rec))
			fprintf(stdout, 
			  "#%-10u send=%8X:%-8X %u%c     recv=%8X:%-8X %u%c\n",
				rec->seq_no, rec->send.sec, 
				rec->send.frac_sec, rec->send.prec, 
				(rec->send.sync)? 'S' : 'U', 
				rec->recv.sec, rec->recv.frac_sec, 
				rec->recv.prec, 
				(rec->recv.sync)? 'S' : 'U');
		else
			fprintf(stdout, 
				"#%-10u send=%8X:%-8X %u%c     *LOST*\n",
				rec->seq_no, rec->send.sec, 
				rec->send.frac_sec, rec->send.prec, 
				(rec->send.sync)? 'S' : 'U');
		return;
	}
	
	if (!OWPIsLostRecord(rec)) {
		if (rec->send.sync && rec->recv.sync) {
			double prec = owp_bits2prec(rec->send.prec) 
				+ owp_bits2prec(rec->recv.prec);
			fprintf(stdout, 
	      "seq_no=%-10u delay=%.3f ms       (sync, precision %.3f ms)\n", 
				rec->seq_no, delay*THOUSAND, 
				prec*THOUSAND);
		} else
			fprintf(stdout, 
				"seq_no=%u delay=%.3f ms (unsync)\n",
				rec->seq_no, delay*THOUSAND);
		return;
	}
	fprintf(stdout, "seq_no=%-10u *LOST*\n", rec->seq_no);
}


int
main(int argc, char *argv[]) 
{
	FILE *fp, *out = stdout;
	u_int32_t hdr_len, num_rec, i, last_seqno, dup, sent, lost;
	state s;
	u_int8_t prec = PREC_THRESHOLD;
	u_int32_t *counts;
	double delay;
	
	char     *progname;
	int num_buckets, ch, verbose = 0;
	I2LogImmediateAttr	ia;
	u_int8_t out_hdrlen = sizeof(magic) + sizeof(version) 
		+ sizeof(prec) + sizeof(out_hdrlen) + sizeof(sent) 
		+ sizeof(lost) + sizeof(dup);

	OWPInitializeConfigRec	owpcfg = {{0,0},NULL,NULL,NULL,NULL,0,NULL};
	OWPContext		ctx;

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

	owpcfg.eh = eh;
	if(!(ctx = OWPContextInitialize(&owpcfg))){
		I2ErrLog(eh,"Unable to initialize OWP library.");
		exit(1);
	}


	while ((ch = getopt(argc, argv, "hp:v")) != -1)
             switch (ch) {
		     /* Connection options. */
             case 'p':
		     prec = (u_int8_t)atoi(optarg);
		     break;
	     case 'v':
		     verbose = 1;
		     break;
	     case 'h':
             case '?':
             default:
                     usage();
	     }

	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	if (verbose) {
		fprintf(stderr, "hdr_len = %u\n", out_hdrlen);
		fprintf(stderr, 
		    "magic: %u\nversion: %u\nheader_len: %u\n", sizeof(magic), 
			sizeof(version), sizeof(out_hdrlen));
		
		fprintf(stderr, 
			"precision: %u\nsent: %u\nlost: %u\ndup: %u\n", 
			sizeof(prec), sizeof(sent), sizeof(lost), sizeof(dup));
	}

	num_buckets = OWP_NUM_LOW + OWP_NUM_MID + OWP_NUM_HIGH;
	counts = (u_int32_t *)malloc(num_buckets*sizeof(*counts));
		
	if (!counts) {
		I2ErrLog(eh, "FATAL: main: malloc failed: %M");
		exit(1);
	}
	for (i = 0; i <= OWP_MAX_BUCKET; i++)
		counts[i] = 0;
	
	if ((fp = fopen(argv[0], "rb")) == NULL){
		I2ErrLog(eh, "fopen(%s):%M", argv[0]);
		exit(1);
	}

	if ((out = fopen(argv[1], "w")) == NULL) {
		I2ErrLog(eh, "fopen(%s): %N", argv[1]);
		exit(1);
	}
		
	if (!(num_rec = OWPReadDataHeader(ctx,fp,&hdr_len,NULL))) {
		I2ErrLog(eh,"OWPReadDataHeader");
		exit(1);
	}

	s.records = (OWPDataRec *)malloc(num_rec * sizeof(OWPDataRec));
	if (s.records == NULL) {
		I2ErrLog(eh, "malloc():%M");
		exit(1);
	}
	s.cur = 0;
	
	if(OWPParseRecords(fp,num_rec,NULL,do_single_record,&s)
							< OWPErrWARNING){
		I2ErrLog(eh,"OWPParseRecords():%M");
		exit(1);
	}

	/* Computing reordering stats is done here. */

	if (mergesort(s.records, num_rec, sizeof(OWPDataRec), tstamp_cmp) < 0){
		I2ErrLog(eh,"mergesort():%M");
		exit(1);
	}

	sent = lost = dup = 0;
	last_seqno = 0xFFFFFFFF;

	/* Do a single pass through the sorted records. */
	for (i = 0; i < num_rec; i++) {
		int bucket;
		if (verbose)
			printf("prec = %u\n", prec);
		if (OWPGetPrecBits(&s.records[i]) < prec)
			continue;

		if (s.records[i].seq_no == last_seqno) {
			dup++;
			continue;
		}

		sent++;
		last_seqno = s.records[i].seq_no;

		if (OWPIsLostRecord(&s.records[i])) {
			lost++;
			continue;
		}

		delay = owp_delay(&s.records[i].send, &s.records[i].recv); 
		bucket = owp_bucket(delay);
		assert((0 <= bucket) && (bucket <= OWP_MAX_BUCKET));
		counts[bucket]++;
		
		if (verbose)
			print_rec(&s.records[i], 0);
	}

	/* 
	   Header contains: magic number, version, header length,
	   precision, sent, lost and dup. NOTE: precision is
	   given as the worse of send/recv - rather than the sum.
	   Otherwise every merge would lead to worsening precision.
	   Meaning of the first 3 fields are fixed for all header versions.
	*/
	if ((fwrite(magic, 1, sizeof(magic), out) < 1) 
	    || (fwrite(&version, sizeof(version), 1, out) < 1)
	    || (fwrite(&out_hdrlen, sizeof(out_hdrlen), 1, out) < 1)
	    || (fwrite(&prec, sizeof(prec), 1, out) < 1)
	    || (fwrite(&sent, sizeof(sent), 1, out) < 1)
	    || (fwrite(&lost, sizeof(lost), 1, out) < 1)
	    || (fwrite(&dup, sizeof(dup), 1, out) < 1)) {
		I2ErrLog(eh, "FATAL: fwrite() failed: %M");
		exit(1);     
	}
	    
	for (i = 0; i <= OWP_MAX_BUCKET; i++) {
		if (counts[i]) {
			if ((fwrite(&i, sizeof(i), 1, out) < 1)
			    || (fwrite(&counts[i], sizeof(*counts),
				       1, out) < 1)) {
				I2ErrLog(eh, "FATAL: fwrite() failed: %M");
				exit(1);
			}
			if (verbose)
				fprintf(stderr, "index = %u, counts = %u\n", 
					i, counts[i]);
		}
	}
	if (verbose)
		fprintf(stderr, "sent = %u, lost = %u, dup = %u\n", 
			sent, lost, dup); 

	free(counts);
	fclose(fp);
	fclose(out);

	exit(0);
}
