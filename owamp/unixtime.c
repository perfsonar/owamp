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
 *	File:		unixtime.c
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Mon May 13 13:01:54  2002
 *
 *	Description:	
 *	Functions to deal with time on unix including conversions between
 *	common unix formats like struct timeval to owamp timestamp
 *	representations.
 */

#include <owamp/owamp.h>
#include <owpcontrib/unixtime.h>

/*
 * Function:	OWPCvtTVtoTS
 *
 * Description:	
 * 	Precision in the timestamp is set only taking into account the
 * 	loss of precision from usec to fractional seconds and does not
 * 	address the precision of how the struct timeval was determined.
 * 	It is the responsibility of the caller to adjust the precision/sync
 * 	bits as needed by the actual implementation.
 */
OWPTimeStamp *
OWPCvtTVtoTS(
	OWPTimeStamp	*tstamp,
	struct timeval	*tval
)
{
	if(!tstamp || !tval)
		return NULL;

	tstamp->sec = tval->tv_sec + OWPJAN_1970;
	tstamp->frac_sec = ((double)tval->tv_usec/1000000.0) * (1<<24);
	tstamp->prec = 19; /* usec is 20 bits - 1(rounding errors)	*/
	tstamp->sync = 0;

	return(tstamp);
}

/*
 * Function:	OWPGetTimeOfDay
 *
 * Description:	
 * 	mimic's unix gettimeofday but takes OWPTimestamp's instead
 * 	of struct timeval's.
 *
 * 	Precision in the timestamp is set only taking into account the
 * 	loss of precision from usec to fractional seconds and does not
 * 	address the precision of the underlying clock used by gettimeofday.
 * 	It is the responsibility of the caller to adjust the precision/sync
 * 	bits as needed by the actual implementation.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
OWPTimeStamp *
OWPGetTimeOfDay(
	OWPTimeStamp	*tstamp
	       )
{
	struct timeval	tval;
	int		rc;

	if(!tstamp)
		return NULL;

	if(gettimeofday(&tval,NULL) != 0)
		return NULL;

	return OWPCvtTVtoTS(tstamp,&tval);
}
