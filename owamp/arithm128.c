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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "arithm128.h"

struct num_128 raw2num(const unsigned char *raw);
struct num_128 unif_rand();      /* Generate a Unif(0, 1) random quantity. */

/* We often need to scale by 10^6 so let's fix a struct for that. */
static struct num_128 million = {{0, 0, 0, 0, 16960, 15, 0, 0}};

/* Initialize the RNG counter. */
static rand_context next;

#define K 19 /* As in Knuth: the first k such that Q[k] > 1 - 1/(2^64). */

/* Insure that all longs are 32-bit and shorts are 16-bit. */
#define MASK8(x)  ((x) & 0xFF)
#define MASK16(x) ((x) & 0xFFFF)
#define MASK32(x) ((x) & 0xFFFFFFFF)

static struct num_128 Q[K] = {
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
** Convert an unsigned 32-bit integer into a num_128 struct..
*/
static struct num_128
ulong2num(unsigned long a)
{
	int i;
	struct num_128 ret;
	
	for (i = 0; i < NUM_DIGITS; i++)
		ret.digits[i] = 0;

	ret.digits[5] = MASK32(a) >> 16;
	ret.digits[4] = MASK32(a) & 0xffff;

	return ret;
}

/*
** Arithmetic functions on num_128 structs.
*/

/*
** Addition. The result is saved in the variable z.
*/
static void 
num_add(num_128 x, num_128 y, num_128 z)
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
void
num_mul(num_128 x, num_128 y, num_128 z)
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
num_cmp(num_128 x, num_128 y)
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
num2formatted(num_128 from, OWPFormattedTime to)
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
formatted2num(OWPFormattedTime from, num_128 to)
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
num2timeval(num_128 from, struct timeval *to)
{
	struct num_128 res;

	/* first convert the fractional part */
	struct num_128 tmp = {{0, 0, 0, 0, 0, 0, 0, 0}};
	tmp.digits[2] = from->digits[2];
	tmp.digits[3] = from->digits[3];

	/* See discussion: it may take two digits of res to express tv_usec. */
	num_mul(&tmp, &million, &res);
	to->tv_usec = ((unsigned long)(res.digits[5]) << 16) +
		(unsigned long)(res.digits[4]); 

	/* now the integer part */
	to->tv_sec = ((unsigned long)(from->digits[5]) << 16) + 
		(unsigned long)(from->digits[4]);
}

void
timeval2num(struct timeval *from, num_128 to)
{
	
}

/*
** This function treats a num struct as representing an unsigned long
** integer, and returns that integer.
*/
unsigned long 
num2ulong(num_128 x)
{
	return (x->digits[5] << 16) + x->digits[4];
}

/*
** This function converts a 64-bit binary string (network byte order)
** into num struct (fractional part only). The integer part iz zero.
*/
struct num_128
raw2num(const unsigned char *raw)
{
	int i;
	struct num_128 x = {{0, 0, 0, 0, 0, 0, 0, 0}};

	for (i = 0; i < 4; i++)
		x.digits[3-i] = (((unsigned short)(*(raw + 2*i))) << 8) 
			+ *(raw + 2*i + 1);
	return x;
}

/*
** Exported functions.
*/

/*
** Seed the random number generator using a 16-byte string.
*/
void 
rand_context_init(BYTE *sid)
{
	int i;
	
	bytes2Key(&next.key, sid);
	memset(next.out, 0, 16);
	for (i = 0; i < 4; i++)
		next.counter[i] = 0UL;
}

/* 
** Generate an exponential deviate using 64-bit binary string as an input
** (encoded using 2 unsigned long integers). This is algorithm 3.4.1.S from
** Knuth's v.2 of "Art of Computer Programming" (1998), p.133.
*/
struct num_128 
exp_rand()
{
	unsigned long i, k;
	unsigned long j = 0;
	struct num_128 U, V, J, two, tmp, ret; 
	unsigned short mask = 0x8000; /* test if first bit == zero */

	two = ulong2num(2UL);

	/* Get U and shift */
	U = unif_rand();
	
	while (U.digits[3] & mask && j < 65){ /* shift until find first '0' */
		num_mul(&U, &two, &V);
		U = V;
		j++;
	}

	/* remove the '0' itself */
	num_mul(&U, &two, &V);
	U = V;
	for (i = 4; i < 8; i++) U.digits[i] = 0; /*Keep only fractional part.*/

	J = ulong2num(j);

	/* Immediate acceptance? */
	if (num_cmp(&U, LN2) < 0){ 	   /* return  (j*ln2 + U) */ 
		num_mul(&J, LN2, &tmp);   
		num_add(&tmp, &U, &ret);
		return ret;
	}

	/* Minimize */
	for (k = 2; k < K; k++)
		if (num_cmp(&U, &Q[k]) < 0)
			break;

	assert(k < K);
	V = unif_rand();
	for (i = 2; i <= k; i++){
		tmp = unif_rand();
		if (num_cmp(&tmp, &V) < 0)
			V = tmp;
	}

	/* Return (j+V)*ln2 */
	num_add(&J, &V, &tmp);
	num_mul(&tmp, LN2, &ret);
	return ret;
}

/*
** Generate a 64-bit uniform random string and save it in the lower
** part of the struct.
*/
struct num_128
unif_rand()
{
	static int reuse = 1;
	BYTE input[16];
	int j, i;

	reuse = 1 - reuse;
	if (reuse)
		return raw2num(next.out + 8);

	/* Prepare the block for encryption. */
	for (j = 0; j < 4; j++)	/* More significant digits come first. */
		for (i = 0; i < 4; i++)
			input[4*j+i] = MASK8((next.counter[3-j]>>(24-8*i)));
		
	rijndaelEncrypt(next.key.rk, next.key.Nr, input, next.out);
	
	/* Increment next.counter as an 128-bit single quantity for
	   AES counter mode. */
	for (j = 0; j < 4; j++)
		if ((next.counter[j] = MASK32(next.counter[j] + 1)))
			break;

	return raw2num(next.out);
}

/*
**  Debugging functions.
*/

/*
** Print out a num_128 struct. More significant digits are printed first.
*/
void
num_print(num_128 x)
{
	int i;
	assert(x);
	
	for (i = NUM_DIGITS - 1; i >= 0; i--)
		fprintf(stdout, "%hx ", x->digits[i]);
	fprintf(stdout, "\n");
}

/*
** DEBUG only. Print out binary expansion of an unsigned short.
*/
void
print_bin(unsigned short n)
{
	int i;
	unsigned short tmp = n;
	unsigned short div = (unsigned short)1 << 15;
	
	for (i = 1; i <= 15; i++){
		if ((tmp/div) == 0){
			fprintf(stderr, "0");
		} else {
			fprintf(stderr, "1");
			tmp -= div;
		}
		div >>= 1;
	}
	fprintf(stderr, "%hu ", tmp);
}

/*
** Print out the binary expansion of a num_128 struct.
*/
void
num_binprint(num_128 x)
{
	int i;
	assert(x);
	
	for (i = (NUM_DIGITS/2) - 1; i >= 0; i--)
		print_bin(MASK16(x->digits[i]));
	fprintf(stdout, "\n");
}

#ifdef LONGLONG
/*
** This function treats a num struct as representing an unsigned long long
** integer, and returns that integer. 
**
** NOTE: used for debugging only - not included in the final distribution.
*/
unsigned long long 
num2ulonglong(num_128 x)
{
	unsigned long long ret = ((unsigned long long)(x->digits[7]) << 48)
	        + ((unsigned long long)(x->digits[6]) << 32)
		+ ((unsigned long long)(x->digits[5]) << 16)
		+ x->digits[4]; 

	return ret;
}

/*
** This function converts an unsigned long long integer into a num struct.
**
** NOTE: used for debugging only - not included in the final distribution.
*/
struct num_128
ulonglong2num(unsigned long long a)
{
	int i;
	struct num_128 ret;
	
	for (i = 0; i < NUM_DIGITS; i++)
		ret.digits[i] = 0;

	ret.digits[7] = (unsigned short)(a >> 48);
	ret.digits[6] = (unsigned short)((a & 0xffff00000000ULL) >> 32);
	ret.digits[5] = (unsigned short)((a & 0xffff0000ULL) >> 16);
	ret.digits[4] = (unsigned short)(a & 0xffffULL);

	return ret;
}
#endif

