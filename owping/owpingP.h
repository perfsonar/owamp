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
 *	File:		owpingP.h
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Thu Apr 25 13:00:00  2002
 *
 *	Description:	
 */
#ifndef	_owpingp_h_
#define	_owpingp_h_

/*
 * Application "context" structure
 */
typedef	struct {
	/*
	**	Command line options
	*/
	struct  {
		/* Flags */
		I2Boolean       records;          /* -v */
		I2Boolean       full;             /* -V */
		I2Boolean	quiet;            /* -Q */

		I2Boolean	to;               /* -t */
		I2Boolean	from;             /* -f */
		char            *save_to_test;    /* -T */
		char            *save_from_test;  /* -F */

		char		*authmode;        /* -A */
		char		*identity;        /* -u */
		u_int32_t	numPackets;       /* -c */

		double		lossThreshold;    /* -l */
		float           percentile;       /* -a */

		char		*passwd;          /* -P */
		char		*srcaddr;         /* -S */

#ifndef	NDEBUG
		I2Boolean	childwait;        /* -w */
#endif

		float		mean_wait;        /* -i  (seconds) */
		u_int32_t	padding;          /* -s */

	} opt;

	char			*remote_test;
	char			*remote_serv;

	u_int32_t		auth_mode;

	OWPContext		lib_ctx;
	OWPControl		cntrl;

} ow_ping_trec, *ow_ping_t;

#endif
