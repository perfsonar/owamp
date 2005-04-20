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
 *	File:		arithm64.c
 *
 *	Author:		Anatoly Karp
 *	                Jeff W. Boote
 *			Internet2
 *
 *	Date:		Sun Jun 20 12:29:20 MDT 2002
 *
 *	Description:
 *		Arithmatic and conversion functions for the OWPNum64
 *		type.
 *
 * OWPNum64 is interpreted as 32bits of "seconds" and 32bits of
 * "fractional seconds".
 * The byte ordering is defined by the hardware for this value. 4 MSBytes are
 * seconds, 4 LSBytes are fractional. Each set of 4 Bytes is pulled out
 * via shifts/masks as a 32bit unsigned int when needed independently.
 */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <owamp/owamp.h>

#define MASK32(x) ((x) & 0xFFFFFFFFUL)
#define BILLION 1000000000UL
#define MILLION 1000000UL
#define	EXP2POW32	0x100000000ULL

/************************************************************************
 *									*	
 *			Arithmetic functions				*
 *									*	
 ************************************************************************/

/*
 * Function:	OWPNum64Mult
 *
 * Description:	
 *	Multiplication. Allows overflow. Straightforward implementation
 *	of Knuth vol.2 Algorithm 4.3.1.M (p.268)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
OWPNum64
OWPNum64Mult(
	OWPNum64	x,
	OWPNum64	y
	)
{
	unsigned long w[4];
	u_int64_t xdec[2];
	u_int64_t ydec[2];

	int i, j;
	u_int64_t k, t;
	OWPNum64 ret;

	xdec[0] = MASK32(x);
	xdec[1] = MASK32(x>>32);
	ydec[0] = MASK32(y);
	ydec[1] = MASK32(y>>32);

	for (j = 0; j < 4; j++)
		w[j] = 0; 

	for (j = 0;  j < 2; j++) {
		k = 0;
		for (i = 0; ; ) {
			t = k + (xdec[i]*ydec[j]) + w[i + j];
			w[i + j] = t%EXP2POW32;
			k = t/EXP2POW32;
			if (++i < 2)
				continue;
			else {
				w[j + 2] = k;
				break;
			}
		}
	}

	ret = w[2];
	ret <<= 32;
	return w[1] + ret;
}

/************************************************************************
 *									*	
 *			Conversion functions				*
 *									*	
 ************************************************************************/

/*
 * Function:	OWPULongToNum64
 *
 * Description:	
 *	Convert an unsigned 32-bit integer into a OWPNum64 struct..
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
OWPNum64
OWPULongToNum64(u_int32_t a)
{
	return ((u_int64_t)a << 32);
}


/*
 * Function:	OWPNum64toTimespec
 *
 * Description:	
 * 	Convert a time value in OWPNum64 representation to timespec
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) OWPNum64 values are
 * 	unsigned 64 integral types with the MS (Most Significant) 32 bits
 * 	representing seconds, and the LS (Least Significant) 32 bits
 * 	representing fractional seconds (at a resolution of 32 bits).
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
OWPNum64ToTimespec(
	struct timespec	*to,
	OWPNum64	from
	)
{
	/*
	 * MS 32 bits represent seconds
	 */
	to->tv_sec = MASK32(from >> 32);

	/*
	 * LS 32 bits represent fractional seconds, normalize them to nsecs:
	 * frac/2^32 == nano/(10^9), so
	 * nano = frac * 10^9 / 2^32
	 */
	to->tv_nsec = MASK32((MASK32(from)*BILLION) >> 32);

	while(to->tv_nsec >= (long)BILLION){
		to->tv_sec++;
		to->tv_nsec -= BILLION;
	}
}

/*
 * Function:	OWPTimespecToNum64
 *
 * Description:	
 *
 * 	Convert a time value in timespec representation to an OWPNum64
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) OWPNum64 values are
 * 	unsigned 64 integral types with the Most Significant 32 of those
 * 	64 bits representing seconds. The Least Significant 32 bits
 * 	represent fractional seconds at a resolution of 32 bits.
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
OWPTimespecToNum64(
	OWPNum64	*to,
	struct timespec	*from
	)
{
	u_int32_t	sec = from->tv_sec;
	u_int32_t	nsec = from->tv_nsec;

	*to = 0;

	/*
	 * Ensure nsec's is only fractional.
	 */
	while(nsec >= BILLION){
		sec++;
		nsec -= BILLION;
	}

	/*
	 * Place seconds in MS 32 bits.
	 */
	*to = (u_int64_t)MASK32(sec) << 32;
	/*
	 * Normalize nsecs to 32bit fraction, then set that to LS 32 bits.
	 */
	*to |= MASK32(((u_int64_t)nsec << 32)/BILLION);

	return;
}
/*
 * Function:	OWPNum64toTimeval
 *
 * Description:	
 * 	Convert a time value in OWPNum64 representation to timeval
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) OWPNum64 values are
 * 	unsigned 64 integral types with the MS (Most Significant) 32 bits
 * 	representing seconds, and the LS (Least Significant) 32 bits
 * 	representing fractional seconds (at a resolution of 32 bits).
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
OWPNum64ToTimeval(
	struct timeval	*to,
	OWPNum64	from
	)
{
	/*
	 * MS 32 bits represent seconds
	 */
	to->tv_sec = MASK32(from >> 32);

	/*
	 * LS 32 bits represent fractional seconds, normalize them to usecs:
	 * frac/2^32 == micro/(10^6), so
	 * nano = frac * 10^6 / 2^32
	 */
	to->tv_usec = MASK32((MASK32(from)*MILLION) >> 32);

	while(to->tv_usec >= (long)MILLION){
		to->tv_sec++;
		to->tv_usec -= MILLION;
	}
}

/*
 * Function:	OWPTimevalToNum64
 *
 * Description:	
 *
 * 	Convert a time value in timeval representation to an OWPNum64
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) OWPNum64 values are
 * 	unsigned 64 integral types with the Most Significant 32 of those
 * 	64 bits representing seconds. The Least Significant 32 bits
 * 	represent fractional seconds at a resolution of 32 bits.
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
OWPTimevalToNum64(
	OWPNum64	*to,
	struct timeval	*from
	)
{
	u_int32_t	sec = from->tv_sec;
	u_int32_t	usec = from->tv_usec;

	*to = 0;

	/*
	 * Ensure usec's is only fractional.
	 */
	while(usec >= MILLION){
		sec++;
		usec -= MILLION;
	}

	/*
	 * Place seconds in MS 32 bits.
	 */
	*to = (u_int64_t)MASK32(sec) << 32;
	/*
	 * Normalize usecs to 32bit fraction, then set that to LS 32 bits.
	 */
	*to |= MASK32(((u_int64_t)usec << 32)/MILLION);

	return;
}

/*
 * Function:	OWPNum64toDouble
 *
 * Description:	
 * 	Convert an OWPNum64 time value to a double representation. 
 * 	The double will contain the number of seconds with the fractional
 * 	portion of the OWPNum64 mapping to the portion of the double
 * 	represented after the radix point. This will obviously loose
 * 	some precision after the radix point, however - larger values
 * 	will be representable in double than an OWPNum64.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
double
OWPNum64ToDouble(
	OWPNum64	from
	)
{
	return (double)from / EXP2POW32;
}

/*
 * Function:	OWPDoubleToNum64
 *
 * Description:	
 * 	Convert a double value to an OWPNum64 representation.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
OWPNum64
OWPDoubleToNum64(
	double	from
	)
{
	if(from < 0){
		return 0;
	}
	return (OWPNum64)(from * EXP2POW32);
}

/*
 * Function:	OWPUsecToNum64
 *
 * Description:	
 * 	Convert an unsigned 32bit number representing some number of
 * 	microseconds to an OWPNum64 representation.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
OWPNum64
OWPUsecToNum64(u_int32_t usec)
{
	return ((u_int64_t)usec << 32)/MILLION;
}
