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
 *	File:		arithm128.c
 *
 *	Author:		Anatoly Karp
 *			Internet2
 *
 *	Date:		Sun Jun 02 12:29:20 MDT 2002
 *
 *	Description:	Implementation of extended-precision arithmetic.
 *                      It uses eight 16-bit quantities to represent
 *                      and manipulate Owamp's [64].[64] space of timestamps.
 *
 *                      Also, generation of uniform(0,1) and
 *                      exponential (mean 1) random variates in
 *                      [64].[64] format.
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
#include "arithm128.h"

#define K 19 /* So (K - 1) is the first k such that Q[k] > 1 - 1/(2^64). */

/* Insure that all longs are 32-bit and shorts are 16-bit. */
#define MASK8(x)  ((x) & 0xFF)
#define MASK16(x) ((x) & 0xFFFF)
#define MASK32(x) ((x) & 0xFFFFFFFF)

/*
** The array has been computed according to the formula:
**
**       Q[k] = (ln2)/(1!) + (ln2)^2/(2!) + ... + (ln2)^k/(k!)
**
** as described in the Knuth algorithm.
*/
static struct OWPnum128 Q[K] = {
	{{     0,      0,      0,      0, 0, 0, 0, 0}},  /* Placeholder. */
	{{0x79AC, 0xD1CF, 0x17F7, 0xB172, 0, 0, 0, 0}},
	{{0x96FD, 0xD75A, 0x93F6, 0xEEF1, 0, 0, 0, 0}},
	{{0xF6C2, 0x59AA, 0x1862, 0xFD27, 0, 0, 0, 0}},
	{{0xC5A7, 0x50F4, 0x6DD0, 0xFF9D, 0, 0, 0, 0}},
	{{0x626C, 0xEF1E, 0xCFCF, 0xFFF4, 0, 0, 0, 0}},
	{{0xC62F, 0x86E1, 0xE818, 0xFFFE, 0, 0, 0, 0}},
	{{0x0BB6, 0x850E, 0xE7FE, 0xFFFF, 0, 0, 0, 0}},
	{{0xB17E, 0x8731, 0xFE2A, 0xFFFF, 0, 0, 0, 0}},
	{{0xEADC, 0xAC6E, 0xFFDF, 0xFFFF, 0, 0, 0, 0}},
	{{0x0068, 0xF964, 0xFFFD, 0xFFFF, 0, 0, 0, 0}},
	{{0xC79D, 0xE22E, 0xFFFF, 0xFFFF, 0, 0, 0, 0}},
	{{0x9DEE, 0xFE6A, 0xFFFF, 0xFFFF, 0, 0, 0, 0}},
	{{0xFF81, 0xFFEB, 0xFFFF, 0xFFFF, 0, 0, 0, 0}},
	{{0x1417, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0, 0, 0}},
	{{0xF5CF, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0, 0, 0}},
	{{0xFF96, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0, 0, 0}},
	{{0xFFFC, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0, 0, 0}},
	{{0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0, 0, 0}}
};

#define LN2 &Q[1] /* this element represents ln2 */

/* 
** Convert an unsigned 32-bit integer into a OWPnum128 struct..
*/
static struct OWPnum128
OWPulong2num(unsigned long a)
{
	int i;
	struct OWPnum128 ret;
	
	for (i = 0; i < NUM_DIGITS; i++)
		ret.digits[i] = 0;

	ret.digits[5] = MASK32(a) >> 16;
	ret.digits[4] = MASK32(a) & 0xffff;

	return ret;
}

/*
** Arithmetic functions on OWPnum128 structs.
*/

/*
** Addition. The result is saved in the variable z.
*/
static void 
OWPnum128_add(OWPnum128 x, OWPnum128 y, OWPnum128 z)
{
	int i;
	unsigned long carry = 0; 	 /* Can only be 0 or 1. */
	unsigned long sum;

	assert(x); assert(y); assert(z);
	for (i = 0; i < NUM_DIGITS; i++){
		sum = (unsigned long)x->digits[i] + (unsigned long)y->digits[i]
			+ carry;
		carry = (sum > 0xFFFF? 1: 0);
		z->digits[i] = MASK16(sum);
	}
}

/*
** Multiplication. The result is saved in the variable z.
*/
static void
OWPnum128_mul(OWPnum128 x, OWPnum128 y, OWPnum128 z)
{
	int i, j;
	unsigned long carry; /* Always < 2^32. */
	unsigned short tmp[(2*NUM_DIGITS)];

	assert(x); assert(y); assert(z);
	for (i = 0; i < (2*NUM_DIGITS); i++)
		tmp[i] = 0UL;

	for (i = 0; i < NUM_DIGITS; i++) {
		carry = 0;
		for (j = 0; j < (2*NUM_DIGITS) - i; j++) {
			carry += tmp[i+j];
			if (j < NUM_DIGITS)
				carry += x->digits[i] * y->digits[j];
			tmp[i+j] = MASK16(carry);
			carry >>= 16;
		}
	}
	assert(carry == MASK32(carry));	/* Sanity check if long is 64-bit. */

	/* Need to shift by NUM_DIGITS/2 digits now. */
	for (i = 0; i < NUM_DIGITS; i++)
		z->digits[i] = tmp[i+(NUM_DIGITS/2)];
}

/*
** This functions compares numerically fractional parts of the numbers 
** represented by x and y. It returns a negative number, 0, or a positive
** number depending as x is <, =, or > than y, respectively.
*/
static int
OWPnum128_cmp(OWPnum128 x, OWPnum128 y)
{
	int i = 3;
	
	while (i > 0 && x->digits[i] == y->digits[i])
		i--;

	return (x->digits[i] - y->digits[i]);
}

/*
** Conversion functions.
*/

/*
** Discussion: abcd.efgh = A.B, where LHS is in base 2^16,
** 0 <= A <= 2^32 - 1, 0 <= B <= 2^24 - 1, then
** A = c*(2^16) + d, and (multiplying fractional parts by 2^24)
** B = e*(2^8) + f/(2^8) [commit to always rounding down - shifting]
**
** NOTE: since e*(2^8) <= (2^16 - 1)*(2^8) = 2^24 - 2^8
** and f/(2^8) <= 2^8 - 1, we have B <= 2^24 - 1, and thus
** B can never overflow.
*/
void
OWPnum2formatted(OWPnum128 from, OWPFormattedTime to)
{
	to->t[0] = ((unsigned long)(from->digits[5]) << 16) + from->digits[4];
	to->t[1] = ((unsigned long)(from->digits[3]) << 8)
		+ ((unsigned long)(from->digits[2])>> 8);
	to->t[1] <<= 8; /* place the result into 24 most significant bits */
}

/*
** Discussion: only handling of the fractional parts is interesting.
** Let e/(2^16) + f/(2^32) = B/(2^24), then (multiplying by 2^32)
** e*(2^16) + f = B*(2^8) [which is the same as from->t[1] below].
** Thus both e and f can be recovered by performing division
** with remainder by 2^16.
*/
void
OWPformatted2num(OWPFormattedTime from, OWPnum128 to)
{
	to->digits[7] = to->digits[6] = 0;
	to->digits[5] = (unsigned short)(MASK32(from->t[0]) >> 16);
	to->digits[4] = (unsigned short)(MASK32(from->t[0]) & 0xffff);

	/* the fractional part has been left-shifted by 8 bits already */
	to->digits[3] = (unsigned short)(MASK32(from->t[1]) >> 16);
	to->digits[2] = (unsigned short)(MASK32(from->t[1]) & 0xffff);
	to->digits[1] = to->digits[0] = 0;
}

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
OWPnum2timeval(OWPnum128 from, struct timeval *to)
{
	struct OWPnum128 res;
	static struct OWPnum128 million = {{0, 0, 0, 0, 16960, 15, 0, 0}}; 

	/* first convert the fractional part */
	struct OWPnum128 tmp = {{0, 0, 0, 0, 0, 0, 0, 0}};
	tmp.digits[2] = from->digits[2];
	tmp.digits[3] = from->digits[3];

	/* See discussion: it may take two digits of res to express tv_usec. */
	OWPnum128_mul(&tmp, &million, &res);
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
** and the 7-digit result, when interpreted as a OWPnum128 struct
** is the sought answer. The task is, moreover, simplified by
** being implemented as *single*-digit division in the base 2^32.
*/ 
void
OWPtimeval2num(struct timeval *from, OWPnum128 to)
{
	unsigned long carry = 0;
	static struct OWPnum128 million = {{0, 0, 0, 0, 16960, 15, 0, 0}}; 

	int i;
	struct OWPnum128 C, tmp; 

	struct OWPnum128 sec = OWPulong2num(from->tv_sec);
	struct OWPnum128 usec = OWPulong2num(from->tv_usec);

	OWPnum128_mul(&sec, &million, &tmp);
	OWPnum128_add(&tmp, &usec, &C);

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

/*
** This function converts a 64-bit binary string (network byte order)
** into num struct (fractional part only). The integer part iz zero.
*/
static struct OWPnum128
OWPraw2num(const unsigned char *raw)
{
	int i;
	struct OWPnum128 x = {{0, 0, 0, 0, 0, 0, 0, 0}};

	for (i = 0; i < 4; i++)
		x.digits[3-i] = (((unsigned short)(*(raw + 2*i))) << 8) 
			+ *(raw + 2*i + 1);
	return x;
}

/*
** Random number generating functions.
*/

/*
** Generate a 64-bit uniform random string and save it in the lower
** part of the struct.
*/
static struct OWPnum128
OWPunif_rand(OWPrand_context *next)
{
	int j;

	next->reuse = 1 - next->reuse;
	if (next->reuse)
		return OWPraw2num(next->out + 8);

	rijndaelEncrypt(next->key.rk, next->key.Nr, next->counter, next->out);
	
	/* Increment next.counter as an 128-bit single quantity in network
	   byte order for AES counter mode. */
	for (j = 15; j >= 0; j--)
		if (++next->counter[j])
			break;
	
	return OWPraw2num(next->out);
}

/*
** Seed the random number generator using a 16-byte string.
*/
OWPrand_context*
OWPrand_context_init(BYTE *sid)
{
	int i;
	OWPrand_context *next;

	next = malloc(sizeof(*next));
	if (!next)
		return NULL;

		
	bytes2Key(&next->key, sid);
	memset(next->out, 0, 16);
	next->reuse = 1;
	for (i = 0; i < 16; i++)
		next->counter[i] = 0UL;

	return(next);
}

void
OWPrand_context_free(OWPrand_context *next)
{
	assert(next);
	free(next);
}

/* 
** Generate an exponential deviate using 64-bit binary string as an input
** This is algorithm 3.4.1.S from Knuth's v.2 of "Art of Computer Programming" 
** (1998), p.133.
*/
struct OWPnum128 
OWPexp_rand(OWPrand_context *next)
{
	unsigned long i, k;
	unsigned long j = 0;
	struct OWPnum128 U, V, J, two, tmp, ret; 
	unsigned short mask = 0x8000; /* test if first bit == zero */

	two = OWPulong2num(2UL);

	/* Get U and shift */
	U = OWPunif_rand(next);
	
	while (U.digits[3] & mask && j < 64){ /* shift until find first '0' */
		OWPnum128_mul(&U, &two, &V);
		U = V;
		j++;
	}

	/* remove the '0' itself */
	OWPnum128_mul(&U, &two, &V);
	U = V;
	for (i = 4; i < 8; i++) 
		U.digits[i] = 0; /* Keep only the fractional part. */

	J = OWPulong2num(j);

	/* Immediate acceptance? */
	if (OWPnum128_cmp(&U, LN2) < 0){ 	   /* return  (j*ln2 + U) */ 
		OWPnum128_mul(&J, LN2, &tmp);   
		OWPnum128_add(&tmp, &U, &ret);
		return ret;
	}

	/* Minimize */
	for (k = 2; k < K; k++)
		if (OWPnum128_cmp(&U, &Q[k]) < 0)
			break;

	assert(k < K);
	V = OWPunif_rand(next);
	for (i = 2; i <= k; i++){
		tmp = OWPunif_rand(next);
		if (OWPnum128_cmp(&tmp, &V) < 0)
			V = tmp;
	}

	/* Return (j+V)*ln2 */
	OWPnum128_add(&J, &V, &tmp);
	OWPnum128_mul(&tmp, LN2, &ret);
	return ret;
}

/*
**  Debugging functions.
*/

/*
** Print out a OWPnum128 struct. More significant digits are printed first.
*/
void
OWPnum_print(OWPnum128 x)
{
	int i;
	assert(x);
	
	for (i = NUM_DIGITS - 1; i >= 0; i--)
		fprintf(stdout, "%hx ", x->digits[i]);
	fprintf(stdout, "\n");
}
