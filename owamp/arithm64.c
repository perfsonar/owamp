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
operations are in fixed-precision 128-bit arithmetic (64 bits before
and after the decimal point). All 64-bit uniform random strings are
obtained by applying AES in counter mode to a 128-bit unsigned integer
(initialized to be zero) written in network byte order, then picking the
lower or upper half of the encrypted 128-bit block, depending as the
counter is even or odd, respectively.

S1. [Get U and shift.] Generate a 64-bit uniform random binary fraction

              U = (.b0 b1 b2 ... b63)    [note the decimal point]

    Locate the first zero bit b_j, and shift off the leading (j+1) bits,
    setting U <- (.b_{j+1} ... b63)

    NOTE: in the rare case that the zero has not been found it is prescribed
    that the algorithm return (mu*64*ln2).

S2. [Immediate acceptance?] If U < ln2, set X <- mu*(j*ln2 + U) and terminate
    the algorithm. (Note that Q[1] = ln2.)

S3. [Minimize.] Find the least k >= 2 sich that U < Q[k]. Generate
    k new uniform random binary fractions U1,...,Uk and set
    V <- min(U1,...,Uk).

S4. [Deliver the answer.] Set X <- mu*(j + V)*ln2.
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
** as described in the Knuth algorithm.
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
static OWPnum64
OWPulong2num64(u_int32_t a)
{
	return ((u_int64_t)1 << 32) * a;
}

/*
** Arithmetic functions on OWPnum64 structs.
*/

/*
** Addition. The result is saved in the variable z.
*/
static OWPnum64
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
	unsigned long tmp[4];
	unsigned long long xdec[2];
	unsigned long long ydec[2];

	int i, j;
	unsigned long long k, t;
	OWPnum64 ret;

	xdec[0] = x & 0xFFFFFFFF;
	xdec[1] = x >> 32;
	ydec[0] = y & 0xFFFFFFFF;
	ydec[1] = y >> 32;

	for (j = 0; j < 4; j++)
		tmp[j] = 0; 

	for (j = 0;  j < 2; j++) {
		k = 0;
		for (i = 0; ; ) {
			t = k + (xdec[i]*ydec[j]) + tmp[i + j];
			tmp[i + j] = t%0xFFFFFFFF;
			k = t/0xFFFFFFFF;
			if (++i < 2)
				continue;
			else {
				tmp[j + 2] = k;
				break;
			}
			
		}
	}

	ret = tmp[2];
	ret <<= 32;
	return tmp[1] + ret;
}

#if 0
/*
** Conversion functions.
*/

/* 
** The next two functions perform conversion between the num space and
** Unix timeval structs.
*/

/*
** Discussion: fractional part - e/(2^16) + f/(2^32) = (B/10^6), 
** hence B = [e/(2^16) + f/(2^32)]*(10^6) < 2^20.
** Integer part: A = c*(2^16) + d. 
*/
void
OWPnum2timeval(OWPnum64 from, struct timeval *to)
{
	OWPnum64 res;
	static OWPnum64 million = {{0, 0, 0, 0, 16960, 15, 0, 0}}; 

	/* first convert the fractional part */
	OWPnum64 tmp = {{0, 0, 0, 0, 0, 0, 0, 0}};
	tmp.digits[2] = from->digits[2];
	tmp.digits[3] = from->digits[3];

	/* See discussion: it may take two digits of res to express tv_usec. */
	OWPnum64_mul(&tmp, &million, &res);
	to->tv_usec = ((unsigned long)(res.digits[5]) << 16) +
		(unsigned long)(res.digits[4]); 

	/* now the integer part */
	to->tv_sec = ((unsigned long)(from->digits[5]) << 16) + 
		(unsigned long)(from->digits[4]);
}

/*
** Discussion: given struct timeval {sec, u_sec}, the goal is
** to compute C/(10^6), where C = [sec*(10^6) + u_sec] < (2^64).
** It is done as follows: observe that
**
** C/(10^6) = {C/[(10^6) >> 4]} << 4
**
** where '>>' and '<<' are right and left shift operations
** in the base 2^16.
**
** Thus, assume that C = a*(2^48) + b*(2^32) + c*(2^16) + d, 
** 0 <= a,b,c,d <= 2^16 - 1, is the expansion of C in base 2^16.
** Similarly, (10^6) = e*(2^16) + f, where e = 15 and f = 16960.
** An integer-arithmetic division of "abcd0000" by "ef" is performed,
** and the 7-digit result, when interpreted as a OWPnum64 struct
** is the sought answer. The task is, moreover, simplified by
** being implemented as *single*-digit division in the base 2^32.
*/ 
OWPnum64
OWPtimeval2num(struct timeval *from)
{
	unsigned long carry = 0;
	static OWPnum64 million = {{0, 0, 0, 0, 16960, 15, 0, 0}}; 

	int i;
	OWPnum64 C, tmp; 

	OWPnum64 sec = OWPulong2num(from->tv_sec);
	OWPnum64 usec = OWPulong2num(from->tv_usec);

	OWPnum64_mul(&sec, &million, &tmp);
	OWPnum64_add(&tmp, &usec, &C);

	/* First divide by 2^6 using shifts. */
	C.digits[7] = 0; 
	for (i = 0; i < 7; i++)
		C.digits[i] = MASK16(C.digits[i] >> 6) 
			| MASK16(C.digits[i+1] << 10);

	/* Do division by 5^6 (= 0x3D09). */
	for (i = 7; i >= 0; i--){
		carry = (carry << 16) + (unsigned long)(C.digits[i]);
		to->digits[i] = carry/0x3D09;
		carry %= 0x3D09;
	}
}
#endif


/*
** This function converts a 32-bit binary string (network byte order)
** into num struct (fractional part only). The integer part iz zero.
*/
static OWPnum64
OWPraw2num64(const unsigned char *raw)
{
	return (u_int32_t)(raw[0] << 24) 
		+ (u_int32_t)(raw[1] << 16) 
		+ (u_int32_t)(raw[2] << 8) 
		+ (u_int32_t)raw[3];
}

/*
** Random number generating functions.
*/

/*
** Generate and return a 32-bit uniform random string (saved in the lower
** ha.
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
** Generate an exponential deviate using 64-bit binary string as an input
** This is algorithm 3.4.1.S from Knuth's v.2 of "Art of Computer Programming" 
** (1998), p.133.
*/
OWPnum64 
OWPexp_rand64(OWPrand_context64 *next)
{
	static unsigned long ct = 0;
	unsigned long i, k;
	u_int32_t j = 0;
	OWPnum64 two = OWPulong2num64(2);
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
** Print out a OWPnum64 struct. More significant digits are printed first.
*/
void
OWPnum_print64(OWPnum64 x)
{
	double t;
#if 0
	fprintf(stdout, "%llX \n", x);
#endif

	fprintf(stdout, "%.16f\n", (double)x/(double)0xFFFFFFFF);
}


