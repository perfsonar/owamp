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
#define INCOMPLETE_EXT	".i"
#define SUMMARY_EXT	".sum"

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
		char		*passwd;          /* -k */

#ifndef	NDEBUG
		I2Boolean	childwait;        /* -w */
#endif

		u_int32_t	numPackets;       /* -c */
		double		lossThreshold;    /* -L (seconds) */
		double		meanWait;        /* -i  (seconds) */
		u_int32_t	padding;          /* -s */

		char		*savedir;	/* -d */
		u_int32_t	seriesInterval;	/* -I (seconds) */
		I2Boolean	printfiles;	/* -p */
		int		facility;	/* -e */
		I2Boolean	verbose;	/* -r stderr too */
		double		bucketWidth;	/* -b (seconds) */

	} opt;

	char			*remote_test;
	char			*remote_serv;

	u_int32_t		auth_mode;

	OWPContext		lib_ctx;

} powapp_trec, *powapp_t;

typedef struct pow_session_rec{
	OWPSID		sid;
	FILE		*fp;
	char		*fname;
	char		fname_mem[PATH_MAX];
	OWPNum64	end;
} pow_session_rec, *pow_session;

typedef struct pow_cntrl_rec{
	OWPControl		cntrl;
	OWPScheduleContext	sctx;
	OWPSID			sid;
	OWPNum64		*sessionStart;
	OWPNum64		owptime_mem;
	FILE			*fp;
	char			fname[PATH_MAX];
	u_int32_t		numPackets;
} pow_cntrl_rec, *pow_cntrl;

typedef struct pow_seen_rec{
	OWPNum64	sendtime;	/* presumed send time. */
	u_int32_t	seen;
} pow_seen_rec, *pow_seen;

struct pow_parse_rec{
	OWPContext		ctx;
	u_int32_t		i;
	FILE			*fp;	/* sub-session data file	*/
	u_int32_t		first;
	u_int32_t		last;
	off_t			begin;
	off_t			next;
	pow_seen		seen;
	OWPSessionHeader	hdr;
	FILE			*sfp;	/* summary file			*/
	I2Table			buckets;
	u_int32_t		*bucketvals;
	u_int32_t		nbuckets;
	I2Boolean		bucketerror;
	double			maxerr;
	u_int32_t		sync;
	u_int32_t		dups;
	u_int32_t		lost;
};
#endif
