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
 *	File:		powstreamP.h
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Tue Sep  3 15:44:17 MDT 2002
 *
 *	Description:	
 */
#ifndef	_powstreamp_h_
#define	_powstreamp_h_

#include <I2util/table.h>

/*
 * Bound of the RTT in seconds. This application needs an estimate of how
 * long it takes to request a test session. It uses this estimate to make
 * sure that it has enough time to make the test requests before those
 * tests actually need to start. (It times the first connection to get
 * a good idea, but does not dynamically modifiy the number of sessions
 * per series based on changes to the RTT over time.) This constant
 * is used to bound that estimate. i.e. we hope that the RTT never gets
 * worse then this value, or the initial value retrieved dynamically.
 * If the RTT gets worse than this, there will be breaks between the
 * sessions.
 */
#define	SETUP_ESTIMATE	10

/*
 * Lock file name. This file is created in the output directory to ensure
 * there is not more than one powstream process writing there.
 */
#define	POWLOCK	".powlock"
#define	POWTMPFILEFMT	"pow.XXXXXX"
#define POW_INC_EXT	".i"
#define POW_SUM_EXT	".sum"

/*
 * Reasonable limits on these so dynamic memory is not needed.
 */
#define	MAX_PASSPROMPT	256
#define	MAX_PASSPHRASE	256

/*
 * Application "context" structure
 */
typedef	struct {
	/*
	**	Command line options
	*/
	struct  {
		/* Flags */

		char		*srcaddr;         /* -S */
		char		*authmode;        /* -A */
		char		*identity;        /* -u */
		char		*keyfile;          /* -k */

#ifndef	NDEBUG
		I2Boolean	childwait;        /* -w */
#endif

		u_int32_t	numPackets;       /* -c */
		double		lossThreshold;    /* -L (seconds) */
		double		meanWait;        /* -i  (seconds) */
		u_int32_t	padding;          /* -s */

		char		*savedir;	/* -d */
		I2Boolean	printfiles;	/* -p */
		int		facility;	/* -e */
		I2Boolean	verbose;	/* -r stderr too */
		double		bucketWidth;	/* -b (seconds) */
                u_int32_t       numBucketPackets;   /* -C */

	} opt;

	char			*remote_test;
	char			*remote_serv;

	u_int32_t		auth_mode;

	OWPContext		lib_ctx;

} powapp_trec, *powapp_t;

typedef struct pow_cntrl_rec{
	OWPControl		cntrl;
	OWPScheduleContext	sctx;
	OWPSID			sid;
	OWPNum64		*sessionStart;
	OWPNum64		sessionStartNum;
	OWPNum64		sessionEndNum;
	FILE			*fp;
	FILE			*testfp;
	char			fname[PATH_MAX];
	u_int32_t		numPackets;
} pow_cntrl_rec, *pow_cntrl;

typedef struct pow_seen_rec{
	OWPNum64	sendtime;	/* presumed send time. */
	u_int32_t	seen;
} pow_seen_rec, *pow_seen;

struct pow_parse_rec{
    OWPContext	        ctx;
    u_int32_t	        i;
    u_int32_t	        first;
    u_int32_t	        last;
    off_t		begin;
    off_t		next;
    pow_seen	        seen;
    OWPSessionHeader    hdr;
    I2Table		buckets;
    u_int32_t	        *bucketvals;
    u_int32_t	        nbuckets;
    I2Boolean	        bucketerror;
    double		maxerr;
    u_int32_t	        sync;
    u_int32_t	        dups;
    u_int32_t	        lost;
    double		min_delay;
    double		max_delay;
    u_int32_t           min_ttl;
    u_int32_t           max_ttl;
    u_int32_t           ttl_count[256];
    FILE                *fp;
};
#endif
