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
 *	File:		unixtime.h
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Mon May 13 22:41:08  2002
 *
 *	Description:	
 */
#ifndef	_OWPCONTRIB_UNIXTIME_H_
#define	_OWPCONTRIB_UNIXTIME_H_
#include <sys/time.h>
#include <time.h>
#include <owamp/owamp.h>

#define	OWPJAN_1970	(unsigned long)0x83aa7e80	/* diffs in epoch*/

extern OWPTimeStamp *
OWPCvtTVtoTS(
	OWPTimeStamp	*tstamp,
	struct timeval	*tval
);

extern OWPTimeStamp *
OWPGetTimeOfDay(
	OWPTimeStamp	*tstamp
);

extern OWPTimeStamp *
OWPCvtTimespec2Timestamp(
	OWPTimeStamp	*tstamp,
	struct timespec	*tval,
	u_int32_t	*errest,	/* usec's */
	u_int32_t	*last_errest	/* usec's */
	);

extern struct timespec *
OWPCvtTimestamp2Timespec(
	struct timespec	*tval,
	OWPTimeStamp	*tstamp
	);

#endif	/*	_OWPCONTRIB_UNIXTIME_H_ */
