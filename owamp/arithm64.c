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
 *			Internet2
 *
 *	Date:		Sun Jun 20 12:29:20 MDT 2002
 *
 *	Description:	Generation of uniform(0,1) and	 
 *			exponential (mean 1) random variates in	 
 *                      [32].[32] format.                        
 */

/*
This part of the document describes in greater detail the way
exponential random quantities used in the protocol are generated.
The following is algorithm 3.4.1.S in volume 2 of "The Art of
Computer Programming" (1998) by D.Knuth, the way its use is
prescribed by this RFC. It produces exponential (mean mu)
random deviates.

Algorithm S: the constants

Q[k] = (ln2)/(1!) + (ln2)^2/(2!) + ... + (ln2)^k/(k!),    1 <= k <= 18

are precomputed. NOTE: all scalar quantities and arithmetical
operations are in fixed-precision 64-bit arithmetic (32 bits before
and after the decimal point). All 32-bit uniform random strings are
obtained by applying AES in counter mode to a 128-bit unsigned integer
(initialized to be zero) written in network byte order, then picking the
i_th quartet of bytes of the encrypted block, where i is equal to
the value of the counter modulo 4. (Thus, one encrypted block gives
rise to four 32-bit random strings)

S1. [Get U and shift.] Generate a 32-bit uniform random binary fraction

              U = (.b0 b1 b2 ... b31)    [note the decimal point]

    Locate the first zero bit b_j, and shift off the leading (j+1) bits,
    setting U <- (.b_{j+1} ... b31)

    NOTE: in the rare case that the zero has not been found it is prescribed
    that the algorithm return (mu*32*ln2).

S2. [Immediate acceptance?] If U < ln2, set X <- mu*(j*ln2 + U) and terminate
    the algorithm. (Note that Q[1] = ln2.)

S3. [Minimize.] Find the least k >= 2 sich that U < Q[k]. Generate
    k new uniform random binary fractions U1,...,Uk and set
    V <- min(U1,...,Uk).

S4. [Deliver the answer.] Set X <- mu*(j + V)*ln2.
*/

/*
** Example usage: generate a stream of exponential (mean 1)
** random quantities (ignoring error checking during initialization).
**
** unsigned char sid[] = "7a91b6d691c2d36d";
** OWPrand_context* next = OWPrand_context_init(sid);
**
** while (1) {
**    OWPnum64 num = OWPexp_rand64(next);
** }
*/

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "arithm64.h"

#define K 12 /* So (K - 1) is the first k such that Q[k] > 1 - 1/(2^64). */

#define MASK32(x) ((x) & 0xFFFFFFFF)

/*
** The array has been computed according to the formula:
**
**       Q[k] = (ln2)/(1!) + (ln2)^2/(2!) + ... + (ln2)^k/(k!)
**
** as described in the Knuth algorithm. (The values below have been
** multiplied by 2^32 and rounded to the nearest integer.)
*/
static OWPnum64 Q[K] = {
	0,          /* Placeholder. */
	0xB17217F8,
	0xEEF193F7,
	0xFD271862,
	0xFF9D6DD0,
	0xFFF4CFD0,
	0xFFFEE819,
	0xFFFFE7FF,
	0xFFFFFE2B,
	0xFFFFFFE0,
	0xFFFFFFFE,
	0xFFFFFFFF
};

#define LN2 Q[1] /* this element represents ln2 */

/* 
** Convert an unsigned 32-bit integer into a OWPnum64 struct..
*/
OWPnum64
OWPulong2num64(u_int32_t a)
{
	return ((u_int64_t)1 << 32) * a;
}

/*
** Arithmetic functions on OWPnum64 numbers.
*/

/*
** Addition.
*/
OWPnum64
OWPnum64_add(OWPnum64 x, OWPnum64 y)
{
	return x + y;
}

/*
** Multiplication. Allows overflow. Straightforward implementation
** of Knuth vol.2 Algorithm 4.3.1.M (p.268)
*/
OWPnum64
OWPnum64_mul(OWPnum64 x, OWPnum64 y)
{
	unsigned long w[4];
	u_int64_t xdec[2];
	u_int64_t ydec[2];

	int i, j;
	u_int64_t k, t;
	OWPnum64 ret;

	xdec[0] = x & 0xFFFFFFFF;
	xdec[1] = x >> 32;
	ydec[0] = y & 0xFFFFFFFF;
	ydec[1] = y >> 32;

	for (j = 0; j < 4; j++)
		w[j] = 0; 

	for (j = 0;  j < 2; j++) {
		k = 0;
		for (i = 0; ; ) {
			t = k + (xdec[i]*ydec[j]) + w[i + j];
			w[i + j] = t%0xFFFFFFFF;
			k = t/0xFFFFFFFF;
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

/*
** Conversion functions.
*/

/* 
** The next two functions perform conversion between the OWPnum64 space and
** Unix timeval structs.
*/

#define MILLION 1000000UL
#define BILLION 1000000000UL

/*
** Discussion: A + B/(2^32) = C + D/(10^6), so
** C = A, and
** D = (B*10^6)/(2^32)
*/
void
OWPnum64totimeval(OWPnum64 from, struct timeval *to)
{
	to->tv_sec = from >> 32;
	to->tv_usec = (MASK32(from)*MILLION) >> 32;
}

/*
** Discussion: given struct timeval {sec, u_sec}, the goal is to compute 
**   OWPnum64 C = (sec*10^6 + usec)*2^32 / 10^6 
**              = (sec*10^6 + usec)*2^26 / 5^6 
**              = (sec*10^6 + usec)*[4294 +  15114/(5^6 )]
**
** - the rest is obvious from the code
*/ 
OWPnum64
OWPtimeval2num64(struct timeval *from)
{
	u_int64_t res = ((u_int64_t)(from->tv_sec))*MILLION + from->tv_usec;

	return (res*4294) + (res*15114)/0x3D09; 
}



/*
** Discussion: A + B/(2^32) = C + D/(10^9), so
** C = A, and
** D = (B*10^9)/(2^32)
*/
void
OWPnum64totimespec(OWPnum64 from, struct timespec *to)
{
	to->tv_sec = from >> 32;
	to->tv_nsec = (MASK32(from)*BILLION) >> 32;
}

/*
** Discussion: given struct timeval {sec, u_sec}, the goal is to compute 
**   OWPnum64 C = (sec*10^9 + usec)*2^32 / 10^9 
**              = (sec*10^6 + usec)*2^23 / 5^9 
**              = (sec*10^6 + usec)*[4 +  576108/(5^9)]
**
** - the rest is obvious from the code. 
** Note: 576108 = 0x8CA6C; 5^9 = 0x1DCD65
*/ 
OWPnum64
OWPtimespec2num64(struct timespec *from)
{
	u_int64_t res = ((u_int64_t)(from->tv_sec))*BILLION + from->tv_nsec;

	return (res*4) + (res*0x8CA6C)/0x1DCD65;
}

/*
** Convert the protocol representation of InvLambda (32-but unsigned
** int relative to microseconds) to the OWPnum64 representation.
**
** Discussion: given <inv_lambda_usec>, the goal is to compute
** (inv_lambda_usec*2^32)/10^6 = (inv_lambda_usec)*[(2^26)/(5^6)] = 
** (inv_lambda_usec)*[4294 + (15114)/0x3D09]. The rest is obvious
** from the code.
*/
OWPnum64
OWPusec2num64(u_int32_t usec)
{
	return ((u_int64_t)usec*4294) + ((u_int64_t)usec*15114)/0x3D09;
}
/*
** This function converts a 32-bit binary string (network byte order)
** into a OWPnum64 number (32 least significant bits).
*/
static OWPnum64
OWPraw2num64(const unsigned char *raw)
{
	return ((u_int32_t)(raw[0]) << 24) 
		+ ((u_int32_t)(raw[1]) << 16) 
		+ ((u_int32_t)(raw[2]) << 8) 
		+ (u_int32_t)raw[3];
}

/*
** Random number generating functions.
*/

/*
** Generate and return a 32-bit uniform random string (saved in the lower
** half of the OWPnum64.
*/
OWPnum64
OWPunif_rand64(OWPrand_context64 *next)
{
	int j;
	u_int8_t res = next->counter[15] & (u_int8_t)3;

	if (!res)
		rijndaelEncrypt(next->key.rk, next->key.Nr, next->counter, 
				next->out);

	/* Increment next.counter as an 128-bit single quantity in network
	   byte order for AES counter mode. */
	for (j = 15; j >= 0; j--)
		if (++next->counter[j])
			break;
	return OWPraw2num64((next->out) + 4*res);
}

/*
** Seed the random number generator using a 16-byte string.
*/
OWPrand_context64*
OWPrand_context64_init(BYTE *sid)
{
	int i;
	OWPrand_context64 *next;

	next = malloc(sizeof(*next));
	if (!next)
		return NULL;

	bytes2Key(&next->key, sid);
	memset(next->out, 0, 16);
	for (i = 0; i < 16; i++)
		next->counter[i] = 0UL;

	return(next);
}

void
OWPrand_context64_free(OWPrand_context64 *next)
{
	assert(next);
	free(next);
}

/* 
** Generate an exponential deviate using a 32-bit binary string as an input
** This is algorithm 3.4.1.S from Knuth's v.2 of "Art of Computer Programming" 
** (1998), p.133.
*/
OWPnum64 
OWPexp_rand64(OWPrand_context64 *next)
{
	unsigned long i, k;
	u_int32_t j = 0;
	OWPnum64 U, V, J, tmp; 
	u_int32_t mask = 0x80000000; /* see if first bit in the lower
			   		     32 bits is zero */

	/* Get U and shift */
	U = OWPunif_rand64(next);

	while (U & mask && j < 32){ /* shift until find first '0' */
		U <<= 1;
		j++;
	}
	/* remove the '0' itself */
	U <<= 1;
	
	U &= 0xFFFFFFFF;  /* Keep only the fractional part. */
	J = OWPulong2num64(j);
	
	/* Immediate acceptance? */
	if (U < LN2) 	   /* return  (j*ln2 + U) */ 
		return OWPnum64_add(OWPnum64_mul(J, LN2), U);   

	/* Minimize */
	for (k = 2; k < K; k++)
		if (U < Q[k])
			break;
	assert(k < K);
	V = OWPunif_rand64(next);
	for (i = 2; i <= k; i++){
		tmp = OWPunif_rand64(next);
		if (tmp < V)
			V = tmp;
	}

	/* Return (j+V)*ln2 */
	return OWPnum64_mul(OWPnum64_add(J, V), LN2);
}

/*
**  Debugging functions.
*/

/*
** Print out a OWPnum64 number.
*/
void
OWPnum_print64(OWPnum64 x)
{
#if 0
	fprintf(stdout, "%llX \n", x);
#endif
	fprintf(stdout, "%.16f\n", (double)x/(double)0xFFFFFFFF);
}


