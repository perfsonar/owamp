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

		char		*confdir;
		char		*ip2class;
		char		*class2limits;
		char		*passwd;

		char		*authmode;
		char		*identity;

		int		tmout;

		char		*sender;
		char		*senderServ;

		char		*receiver;
		char		*receiverServ;

		u_int32_t	padding;
		float		rate;
		u_int32_t	numPackets;

		char		*datadir;

		u_int32_t	lossThreshold;

		/* Flags */
		I2Boolean       full;
		I2Boolean       keepdata;
		I2Boolean       quiet;

#ifndef	NDEBUG
		I2Boolean	childwait;
#endif


	} opt;

	I2table			local_addr_table;
	I2Boolean		sender_local;
	I2Boolean		receiver_local;

	char			*local_addr;
	char			*remote_addr;

	u_int32_t		auth_mode;

	OWPContext		lib_ctx;
	OWPControl		cntrl;

} ow_ping_trec, *ow_ping_t;

#endif
