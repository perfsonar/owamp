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
 *	File:		owampdP.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Mon Jun 03 15:31:22 MDT 2002
 *
 *	Description:	
 */
#ifndef	_owampdp_h_
#define	_owampdp_h_

/*
 * Portability constants. (Should put these in the build system eventually.)
 */
#define	OWD_DIRSEP	"/"
/*
 * Default Constants
 */
#define	OWD_MAXCONN	"100"
#define	OWD_TMOUT	"30"

/*
 * Types
 */
typedef struct {

	I2Boolean	verbose;
	I2Boolean	help;

	char		*confdir;
	char		*ip2class;
	char		*class2limits;
	char		*passwd;

	char		*datadir;

	char		*authmode;
	u_int32_t	auth_mode;	/* cooked version of authmode */
	char		*nodename;

	int		maxconnections;
	int		tmout;
	unsigned int	lossThreshold;

#ifndef	NDEBUG
	I2Boolean	childwait;
#endif
} owampd_opts;

#endif	/*	_owampdp_h_	*/
