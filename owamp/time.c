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
 *	File:		time.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Thu May 30 11:37:48 MDT 2002
 *
 *	Description:	
 *
 *	functions to encode and decode OWPTimeStamp into 8 octet
 *	buffer for transmitting over the network.
 *
 *	The format for a timestamp messages is as follows:
 *
 *	   0                   1                   2                   3
 *	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                Integer part of seconds			  |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|     Fractional part of seconds                |S|U| Prec      |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 */
#include <owamp/owamp.h>

/*
 * Function:	OWPEncodeTimeStamp
 *
 * Description:	
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
void
OWPEncodeTimeStamp(
	u_int8_t	buf[8],
	OWPTimeStamp	*tstamp
	)
{
	u_int32_t	t32;

	/*
	 * seconds is straight forward.
	 */
	t32 = htonl(tstamp->sec);
	memcpy(&buf[0],&t32,4);

	/*
	 * frac_sec: to get byte ordering correct - need to convert to big
	 * endien, then copy 3 low order bytes.
	 */
	t32 = htonl((u_int32_t)tstamp->frac_sec);
	memcpy(&buf[4],((u_int8_t*)&t32)+1,3);

	/*
	 * Now, fill in the last byte with the prec/sync values.
	 */
	buf[7] = tstamp->prec;
	if(tstamp->sync)
		buf[7] |= 0x80;
	else
		buf[7] &= 0x7F;

	return;
}

void
OWPDecodeTimeStamp(
	OWPTimeStamp	*tstamp,
	u_int8_t	buf[8]
	)
{
	u_int32_t	t32 = 0;

	/*
	 * seconds is straight forward.
	 */
	memcpy(&tstamp->sec,&buf[0],4);
	tstamp->sec = ntohl(tstamp->sec);

	/*
	 * network order is big endian - so copy 24 bit fraction to low
	 * order 3 bytes of t32 in big endian ordering, then use the
	 * ntohl macro to covert it to the correct byte ordering for
	 * the host.
	 */
	memcpy(((u_int8_t*)&t32)+1,&buf[4],3);
	tstamp->frac_sec = ntohl(t32);

	tstamp->sync = (buf[7] & 0x80)?1:0;
	tstamp->prec = buf[7] & 0x3F;

	return;
}

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
OWPCvtTimeval2Timestamp(
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

struct timeval *
OWPCvtTimestamp2Timeval(
	struct timeval	*tval,
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
	tval->tv_usec =((double)frac * 1000000.0) / (double)(1<<24);

	return tval;
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

double
owp_bits2prec(int nbits)
{
	return (nbits >= 32)? 1.0/(1 << (nbits - 32)) 
		: (double)(1 << (32 - nbits));
}

double
OWPPrecision(OWPDataRecPtr rec)
{
	return owp_bits2prec(rec->send.prec) + owp_bits2prec(rec->recv.prec);
}

u_int8_t
OWPGetPrecBits(OWPDataRecPtr rec)
{
	return MIN(rec->send.prec, rec->recv.prec);
}
