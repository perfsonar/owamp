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
	tstamp->prec = 19+32; /* usec is 20 bits of prec - 1(rounding errors)*/
	tstamp->sync = 0;

	return(tstamp);
}


/*
 * Function:	OWPCvtTimespec2Timestamp
 *
 * Description:	
 * 	If errest (error estimate) is not set:
 * 	Precision in the timestamp is set only taking into account the
 * 	loss of precision from nsec to fractional seconds and does not
 * 	address the precision of how the struct timespec was determined.
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
OWPCvtTimespec2Timestamp(
	OWPTimeStamp	*tstamp,
	struct timespec	*tval,
	u_int32_t	*errest,	/* usec's */
	u_int32_t	*last_errest
	)
{
	u_int64_t	err_frac;

	if(!tstamp || !tval)
		return NULL;

	tstamp->sec = tval->tv_sec + OWPJAN_1970;
	tstamp->frac_sec = ((double)tval->tv_nsec/1000000000.0) * (1<<24);
	if(errest){
		/*
		 * If last_errest is set, and the error hasn't changed,
		 * then we don't touch the prec portion assuming it is
		 * already correct.
		 */
		if(!last_errest || (*errest != *last_errest)){
			tstamp->prec = 56;
			err_frac = OWPusec2num64(*errest);
			/*
			 * count digits in err_frac to determine how many digits
			 * must be discounted from precision.
			 */
			err_frac >>= 8;	/* lowest 8 don't count. */
			while(err_frac){
				tstamp->prec--;
				err_frac >>= 1;
			}
		}
		tstamp->sync = 1;
	}
	else{
		tstamp->prec = 56;
		tstamp->sync = 0;
	}

	return tstamp;
}

struct timespec *
OWPCvtTimestamp2Timespec(
	struct timespec	*tval,
	OWPTimeStamp	*tstamp
	)
{
	u_int32_t	frac;
	u_int32_t	shift;

	if(!tval || !tstamp)
		return NULL;

	frac = tstamp->frac_sec & 0xFFFFF;
	if(tstamp->prec < 33)
		frac = 0;
	else{
		/* shift for num sig digits in frac */
		shift = 24 - (MIN(56,tstamp->prec) - 32);
		frac = ((frac>>shift)<<shift);
	}

	tval->tv_sec = tstamp->sec - OWPJAN_1970;
	tval->tv_nsec =((double)frac * 1000000000.0) / (double)(1<<24);

	return tval;
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

	if(!tstamp)
		return NULL;

	if(gettimeofday(&tval,NULL) != 0)
		return NULL;

	return OWPCvtTVtoTS(tstamp,&tval);
}
