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
		I2Boolean	verbose;
		I2Boolean	help;

		I2Boolean	to;
		I2Boolean	from;

		char		*srcaddr;
		char		*confdir;
		char		*passwd;

		char		*authmode;
		char		*identity;

		int		tmout;

		u_int32_t	padding;
		float		rate;
		u_int32_t	numPackets;

		char		*datadir;
		char		*readfrom;

		float           percentile;

		u_int32_t	lossThreshold;

		/* Flags */
		I2Boolean       full;
		I2Boolean       keepdata;
		I2Boolean       records;

#ifndef	NDEBUG
		I2Boolean	childwait;
#endif


	} opt;

	char			*remote_test;
	char			*remote_serv;

	u_int32_t		auth_mode;

	OWPContext		lib_ctx;
	OWPControl		cntrl;

} ow_ping_trec, *ow_ping_t;

#endif
