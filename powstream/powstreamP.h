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
		u_int32_t	lossThreshold;    /* -L (seconds) */
		float		meanWait;        /* -i  (seconds) */
		u_int32_t	padding;          /* -s */

		char		*savedir;	/* -d */
		u_int32_t	seriesInterval;	/* -I (seconds) */

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
	OWPTimeStamp	*sessionEnd;
	OWPTimeStamp	tstamp_mem;
} pow_session_rec, *pow_session;

typedef struct pow_cntrl_rec{
	OWPControl	cntrl;
	OWPTimeStamp	*seriesStart;
	OWPTimeStamp	tstamp_mem;
	pow_session	sessions;
	u_int32_t	activeSessions;
} pow_cntrl_rec, *pow_cntrl;

#endif
