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
#include <syslog.h>

#include <I2util/util.h>
#include <owamp/owamp.h>

#ifndef HAVE_MERGESORT
#define mergesort(base, nmemb, size, compar)    \
(qsort(base, nmemb, size, compar), 0)
#endif

/*
 * Default threshold for ignoring data. If the error estimate isn't
 * at least within 125 msec's, treat it as missing data.
 */
#define PREC_THRESHOLD  (0.125)


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


#define OWP_MAX_BUCKET  (OWP_NUM_LOW + OWP_NUM_MID + OWP_NUM_HIGH - 1)

#define OWP_NUM_LOW         50000
#define OWP_NUM_MID         10000
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

/*
** The function returns <0. 0 or >0 if the first record's sequence
** number is respectively less than, equal to, or greater than that 
** of the second.
*/
int
owp_seqno_cmp(
	const void	*a,
	const void	*b
	)
{
	OWPDataRec	*ar = (OWPDataRec*)a;
	OWPDataRec	*br = (OWPDataRec*)b;

	return ar->seq_no - br->seq_no;
}

int
do_single_record(
		OWPDataRec	*rec,
		void		*calldata
		)
{
	state_ptr s = (state_ptr)calldata;

	s->records[s->cur++] = *rec;
	
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
print_rec(
	OWPDataRec	*rec,
	int		full
	)
{
	double delay = OWPDelay(&rec->send, &rec->recv);
				 
	if (full) {
		if (!OWPIsLostRecord(rec))
			fprintf(stdout, 
			  "#%-10u send=%f %f%c     recv=%f %f%c\n",
				rec->seq_no,
				OWPNum64ToDouble(rec->send.owptime),
				OWPGetTimeStampError(&rec->send),
				(rec->send.sync)? 'S' : 'U', 
				OWPNum64ToDouble(rec->recv.owptime),
				OWPGetTimeStampError(&rec->recv),
				(rec->recv.sync)? 'S' : 'U');
		else
			fprintf(stdout, 
				"#%-10u send=%f		*LOST*\n",
				rec->seq_no,
				OWPNum64ToDouble(rec->send.owptime));
		return;
	}
	
	if (!OWPIsLostRecord(rec)) {
		if (rec->send.sync && rec->recv.sync) {
			double prec = OWPGetTimeStampError(&rec->send) +
					OWPGetTimeStampError(&rec->recv);
			fprintf(stdout, 
	      "seq_no=%-10u delay=%.3f ms       (sync, precision %.3f ms)\n", 
				rec->seq_no, delay*THOUSAND, prec*THOUSAND);
		} else
			fprintf(stdout, 
				"seq_no=%u delay=%.3f ms (unsync)\n",
				rec->seq_no, delay*THOUSAND);
		return;
	}
	fprintf(stdout, "seq_no=%-10u *LOST*\n", rec->seq_no);
}

#define MILLION 1000000 /* microseconds per seconds */

int
main(int argc, char *argv[]) 
{
	FILE			*fp,
				*out = stdout;
	OWPSessionHeaderRec	hdr;
	off_t			hdr_len;
	u_int32_t		num_rec, i, last_seqno,
				dup, sent, lost;
	state			s;
	double			prec = PREC_THRESHOLD;
	u_int32_t		*counts;
	double			delay, min;
	double			worst_prec;
	double			best_prec;

	I2ErrLogSyslogAttr	syslogattr;
	int			fac;
	
	char			*progname;
	int			num_buckets, ch, verbose = 0;
	I2LogImmediateAttr	ia;
	u_int8_t		out_hdrlen;
	OWPContext		ctx;
	int			first;

	out_hdrlen = sizeof(magic) + sizeof(version) + sizeof(prec) +
			sizeof(out_hdrlen) + sizeof(sent) + sizeof(lost) +
			sizeof(dup) + sizeof(min);

	ia.line_info = (I2NAME | I2MSG);
	ia.fp = stderr;
	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	syslogattr.ident = progname;
	syslogattr.logopt = LOG_PID;
	syslogattr.facility = LOG_USER;
	syslogattr.priority = LOG_ERR;
	syslogattr.line_info = I2MSG;
#ifndef	NDEBUG
	syslogattr.line_info |= I2FILE | I2LINE;
#endif

	while((ch = getopt(argc, argv, "hp:v")) != -1){
		char	*endptr;

		switch (ch) {
			/* Connection options. */
		case 'p':
			prec = strtod(optarg, &endptr);
			if(*endptr != '\0'){
				fprintf(stderr,
				"Invalid -p: min acceptable precision \"%s\"",
					optarg);
				exit(1);
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'e':
			if((fac = I2ErrLogSyslogFacility(optarg)) == -1){
				fprintf(stderr,
				"Invalid -e: Syslog facility \"%s\" unknown\n",
					optarg);
				exit(1);
			}
			syslogattr.facility = fac;
			break;
		case 'r':
			syslogattr.logopt |= LOG_PERROR;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	/*
	* Start an error logging session for reporing errors to the
	* standard error
	*/

	eh = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);

	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

	if(!(ctx = OWPContextCreate(eh))){
		I2ErrLog(eh,"Unable to initialize OWP library.");
		exit(1);
	}

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
		I2ErrLog(eh, "fopen(%s): %M", argv[0]);
		exit(1);
	}

	if ((out = fopen(argv[1], "w")) == NULL) {
		I2ErrLog(eh, "fopen(%s): %N", argv[1]);
		exit(1);
	}
		
	if(!(num_rec = OWPReadDataHeader(ctx,fp,&hdr_len,&hdr))){
		I2ErrLog(eh,"OWPReadDataHeader");
		exit(1);
	}

	s.records = (OWPDataRec *)malloc(num_rec * sizeof(OWPDataRec));
	if (s.records == NULL) {
		I2ErrLog(eh, "malloc(): %M");
		exit(1);
	}
	s.cur = 0;
	
	if(OWPParseRecords(ctx,fp,num_rec,hdr.version,do_single_record,&s)
							< OWPErrWARNING){
		I2ErrLog(eh,"OWPParseRecords(): %M");
		exit(1);
	}

	/* sort the records in seq_no order */

	if(mergesort(s.records,num_rec,sizeof(OWPDataRec),owp_seqno_cmp) < 0){
		I2ErrLog(eh,"mergesort(): %M");
		exit(1);
	}

	first=1;
	sent = lost = dup = 0;

	/* Do a single pass through the sorted records. */
	for (i = 0; i < num_rec; i++) {
		int	bucket;
		double	rec_prec;

		if (OWPIsLostRecord(&s.records[i])) {
			lost++;
			continue;
		}

		rec_prec = OWPGetTimeStampError(&s.records[i].send) +
			OWPGetTimeStampError(&s.records[i].recv);

		if (rec_prec > prec) {
			fprintf(stderr,
				"Bad Record: prec required=%f, rec prec=%f\n",
				prec, rec_prec);
			continue;
		}

		if(!first && (s.records[i].seq_no == last_seqno)){
			dup++;
			continue;
		}

		sent++;
		last_seqno = s.records[i].seq_no;

		delay = OWPDelay(&s.records[i].send, &s.records[i].recv);
		if(first || (delay < min)){
			min = delay;
		}

		if(first || (rec_prec > worst_prec)){
			worst_prec = rec_prec;
		}

		if(first || (rec_prec < best_prec)){
			best_prec = rec_prec;
		}

		first=0;
#ifdef DIGEST_DEBUG
		fprintf(stderr, "DEBUG: worst = %f\n", worst_prec);
#endif
		bucket = owp_bucket(delay);
		assert((0 <= bucket) && (bucket <= OWP_MAX_BUCKET));
		counts[bucket]++;
		
		if (verbose)
			print_rec(&s.records[i], 0);
	}

	/* 
	   Header contains: magic number, version, header length,
	   precision, sent, lost, dup and min delay (in seconds). 
	   NOTE: precision is given as the worse of send/recv - rather 
	   than the sum. Otherwise every merge would lead to worsening 
	   precision. Meaning of the first 3 fields is fixed for all 
	   header versions.
	*/
	if (sent == 0) {
		I2ErrLog(eh,
			"all packets discarded - session had best prec == %f",
			best_prec);
	}

	if ((fwrite(magic, 1, sizeof(magic), out) < 1) 
	    || (fwrite(&version, sizeof(version), 1, out) < 1)
	    || (fwrite(&out_hdrlen, sizeof(out_hdrlen), 1, out) < 1)
	    || (fwrite(&worst_prec, sizeof(worst_prec), 1, out) < 1)
	    || (fwrite(&sent, sizeof(sent), 1, out) < 1)
	    || (fwrite(&lost, sizeof(lost), 1, out) < 1)
	    || (fwrite(&dup, sizeof(dup), 1, out) < 1)
	    || (fwrite(&min, sizeof(min), 1, out) < 1)) {
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
