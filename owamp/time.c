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
	u_int32_t	buf_aligned[2],
	OWPTimeStamp	*tstamp
	)
{
	u_int32_t	t32;
	u_int8_t	*buf = (u_int8_t *)buf_aligned;

	/*
	 * seconds is straight forward.
	 */
	*(u_int32_t*)&buf[0] = htonl(tstamp->sec);

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
	u_int32_t	buf_aligned[2]
	)
{
	u_int32_t	t32 = 0;
	u_int8_t	*buf = (u_int8_t*)buf_aligned;

	/*
	 * seconds is straight forward.
	 */
	tstamp->sec = ntohl(*(u_int32_t*)&buf[0]);

	/*
	 * network order is big endien - so copy 24 bit fraction to low
	 * order 3 bytes of t32 in big endien ordering, then use the
	 * ntohl macro to covert it to the correct byte ordering for
	 * the host.
	 */
	memcpy(((u_int8_t*)&t32)+1,&buf[4],3);
	tstamp->frac_sec = ntohl(t32);

	tstamp->sync = (buf[7] & 0x80)?1:0;
	tstamp->prec = buf[7] & 0x3F;

	return;
}
