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

#define	_OWPING_DEF_TMPDIR	"/tmp"
#define	_OWPING_PATH_SEPARATOR	"/"
#define	_OWPING_TMPFILEFMT	"owamp.XXXXXX"

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
		I2Boolean       records;          /* -v */
		I2Boolean	quiet;            /* -Q */
		I2Boolean	raw;		/* -R */

		I2Boolean	to;               /* -t */
		I2Boolean	from;             /* -f */
		char            *save_to_test;    /* -T */
		char            *save_from_test;  /* -F */

		char		*authmode;        /* -A */
		char		*identity;        /* -u */
		char		*keyfile;	  /* -k */
		u_int32_t	numPackets;       /* -c */

		double		lossThreshold;    /* -l */
		float           percentile;       /* -a */

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
