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
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "arithm128.h"

/* we often need to scale by 10^6 so let's fix a struct for that */
static struct num_128 million = {{0, 0, 0, 0, 16960, 15, 0, 0}};

/* initialize the RNG counter */
static rand_context next;

#define K 19 /* As in Knuth: the first k such that Q[k] > 1 - 1/(2^64) */

#define EXPDEBUG 0

/*
** Obtained by running:
** perl -lne '$_=~m/(.{4})(.{4})(.{4})(.{4})/; \
** print "0x$4, 0x$3, 0x$2, 0x$1, 0, 0, 0, 0,"' ques.dat.pure
*/
static struct num_128 Q[K] = {
	{{     0,      0,      0,      0, 0, 0, 0, 0}},  /* fake */
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
** The next two arrays of masks facilitate cutting an unsigned short
** into 2 pieces to implement bitwise shifts on num_128 structs.
*/
static unsigned short mask1[16] = {
	0,                 /* fake */
	0x8000, 0xc000, 0xe000, 0xf000, 0xf800, 0xfc00, 0xfe00, 0xff00, 
	0xff80, 0xffc0, 0xffe0, 0xfff0, 0xfff8, 0xfffc, 0xfffe 
};

static unsigned short mask2[16] = {
	0,                 /* fake */ 
	0x7fff, 0x3fff, 0x1fff, 0xfff, 0x7ff, 0x3ff, 0x1ff, 
	0xff, 0x7f, 0x3f, 0x1f, 0xf, 0x7, 0x3, 0x1
};

#define first(x, i)  (((x) & mask1[(i)]) >> (16-(i)))
#define second(x, i) (((x) & mask2[(i)]) << (i))

/*
** Constructor function. Create a num struct out of its components.
** In the argument, more significant digits go first. 
** Thus, (a, b, c, d, e, f, g, h) gives rise to the number
**        a*(2^48) + b*(2^32) + c*(2^16) + d + 
**        e/(2^16) + f/(2^32) + g*(2^48) + h/(2^64)
*/

#define BASE 0x10000 /* i.e., arithmetic is done modulo 2^16 */

/* 
** This function embeds the unsigned 32-bit integers into the
** num space.
*/
struct num_128
ulong2num(unsigned long a)
{
	int i;
	struct num_128 ret;
	
	for (i = 0; i < NUM_DIGITS; i++)
		ret.digits[i] = 0;

	ret.digits[5] = (unsigned short)(a >> 16);
	ret.digits[4] = (unsigned short)(a & 0xffff);

	return ret;
}

/*
** This function is used primarily for debugging.
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
** This function is used primarily for debugging.
*/
void
num_binprint(num_128 x)
{
	int i;
	assert(x);
	
	for (i = (NUM_DIGITS/2) - 1; i >= 0; i--)
		print_bin(x->digits[i]);
	fprintf(stdout, "\n");
}

/*
** The next two functions implement the basic arithmetic
** operation in the num space. The result is saved
** in the variable z.
*/
void 
num_add(num_128 x, num_128 y, num_128 z)
{
	int i;
	unsigned short carry = 0;

	assert(x); assert(y); assert(z);
	for (i = 0; i < NUM_DIGITS; i++){
		/* now carry is 0 or 1 */
		z->digits[i] = x->digits[i] + y->digits[i];

		if(z->digits[i] < x->digits[i] || z->digits[i] < y->digits[i]){
 			z->digits[i] += carry;  /* overflow happened */
			carry = 1;
		} else {
			if (!carry)
				continue;
			z->digits[i] += carry;

			/* now only need to update carry */
			if (z->digits[i] != 0)
				carry = 0;
		}
	}
}

void 
num_mul(num_128 x, num_128 y, num_128 z)
{
	int i, j;
	unsigned short tmp[(2*NUM_DIGITS)];
	
	assert(x); assert(y); assert(z);
	for (i = 0; i < (2*NUM_DIGITS); i++)
		tmp[i] = 0UL;

	for (i = 0; i < NUM_DIGITS; i++){
		unsigned long int carry = 0;
		for (j = 0; j < NUM_DIGITS; j++){
			carry += x->digits[i]*y->digits[j] + tmp[i+j];
			tmp[i+j] = carry & 0xffff;
			carry >>= 16;
		}

		for ( ; j < (2*NUM_DIGITS) - i; j++){
			carry += tmp[i+j];
			tmp[i+j] = carry & 0xffff;
			carry >>= 16;
		}
	}

	/* Need to shift by NUM_DIGITS/2 digits now */
	for (i = 0; i < NUM_DIGITS; i++)
		z->digits[i] = tmp[i+(NUM_DIGITS/2)];
}

/*
** This functions compares numerically fractional parts of the numbers 
** represented by x and y. It returns a negative number, 0, or a positive
** number depending as x is <, =, or > than y, respectively.
*/
int
num_cmp(num_128 x, num_128 y)
{
	int i = 3;
	
	while (i > 0 && x->digits[i] == y->digits[i])
		i--;

	return (x->digits[i] - y->digits[i]);
}

/*
** The next two functions perform conversion between the num space
** and Owamp 32/24 space of timestamps (32-bit number of integer
** seconds, and 24-bit number of fractional seconds).
*/

/*
** Discussion: abcd.efgh = A.B, where LHS is in base 2^16,
** 0 <= A <= 2^32 - 1, 0 <= B <= 2^24 - 1, then
** A = c*(2^16) + d, and (multiplying fractional parts by 2^24)
** B = e*(2^8) + f/(2^8) [commit to always rounding down - shifting]
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
	to->digits[5] = (unsigned short)(from->t[0] >> 16);
	to->digits[4] = (unsigned short)(from->t[0] & 0xffff);

	/* the fractional part has been left-shifted by 8 bits already */
	to->digits[3] = (unsigned short)(from->t[1] >> 16);
	to->digits[2] = (unsigned short)(from->t[1] & 0xffff);
	to->digits[1] = to->digits[0] = 0;
}

/* 
** The next two functions perform conversion between the num space and
** Unix timeval structs.
*/

void 
num2timeval(num_128 from, struct timeval *to)
{
	struct num_128 res;

	/* first convert the fractional part */
	struct num_128 tmp = {{0, 0, 0, 0, 0, 0, 0, 0}};
	tmp.digits[2] = from->digits[2];
	tmp.digits[3] = from->digits[3];

	num_mul(&tmp, &million, &res);
	to->tv_usec = res.digits[4];

	/* now the integer part */
	to->tv_sec = ((unsigned long)(from->digits[5])<<16) + from->digits[4];
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
** Generate an exponential deviate using 64-bit binary string as an input
** (encoded using 2 unsigned long integers). This is algorithm S from
** Knuth's v.2 of "Art of Computer Programming" (1998), p.133.
*/
struct num_128 
random_exp()
{
	struct num_128 ret;
	int i, j, k, count;
	struct num_128 U, V; 
	struct num_128 tmp1, tmp2;   /* structs to hold intermediate results */

	U = rand_get();
#if EXPDEBUG
	printf("Start of random_exp - generated rand number\n");
	num_print(&U);
#endif
	/* Get U and shift */
	count = 1;
	for (i = 3; i >= 0; i--){
		unsigned short mask = 0x8000;

		for (j = 0; j < 16; j++){

			if (!(U.digits[i] & mask))
				goto FOUND; /* found the first '1' */
			mask >>= 1;
			count++;
		}
	}

 FOUND: 
	if (count == 65){ /* '1' was never found. */
		/* XXX - TODO - handle this case */
	}

	j = count - 1;
	num_leftshift(&U, count);
#if EXPDEBUG	
	printf("shifted U now is:\n");
	num_print(&U);
#endif		

	/* Immediate acceptance? */
	if (num_cmp(&U, LN2) < 0){ 
		/* return  (j*ln2 + U) */ 
		tmp1 = ulong2num(j);     
		num_mul(&tmp1, LN2, &tmp2);   
		num_add(&tmp2, &U, &ret);
		return ret;
	}
	
	/* Minimize */
	for (k = 2; k < K; k++)
		if (num_cmp(&U, &Q[k]) < 0)
			break;

	if (k == K){
		fprintf(stderr, "FATAL: random_exp");
		exit(1);
	}

	V = rand_get();
	
	for (i = 2; i <= k; i++){
		tmp1 = rand_get();
		if (num_cmp(&tmp1, &V) < 0)
			V = tmp1;
	}

	/* Return (j+V)*ln2 */
	tmp1 = ulong2num(j);     
	num_add(&tmp1, &V, &tmp2);
	num_mul(&tmp2, LN2, &ret);
	return ret;
}

/*
** DEBUG only.
*/
void
print_macros()
{
	int i;

	fprintf(stderr, "DEBUG: printing values of macros:\n");
	for (i = 1; i <= 15; i++)
		fprintf(stderr, "first(150, %d) = %x, second(150, %d) = %x\n", 
			i, first(150, i), i, second(150, i));
}

/*
** Print out binary expansion of an unsigned short.
*/
void
print_bin(unsigned short n)
{
	int i;
	unsigned short tmp = n;
	unsigned short div = (unsigned short)1 << 15;
	
	for (i = 1; i <= 15; i++){
		/* fprintf(stderr, "div = %hu\n", div); */
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
** Left-shift the fractional part of a num_128 struct U by <count> many bits.
*/
void
num_leftshift(num_128 U, int count)
{
	int num_blocks, num_bits, i;
	
	assert(1 <= count);
	assert(count <= 64);

	/* Normal case. 1 <= count <= 64. Shift by count bits. */
	num_blocks = count/16; /* integer number of 16-bit blocks to shift */
	num_bits   = count%16; /* remaining number of bits                 */

	if (num_blocks > 0){ /* do the whole number of blocks first */
		for (i = 3; i >= num_blocks; i--)
			U->digits[i] = U->digits[i - num_blocks];

		for (i = num_blocks - 1; i >= 0; i--)
			U->digits[i] = (unsigned short)0;
	}

	for (i = 3; i >= 1; i--){
		U->digits[i] = second(U->digits[i], num_bits)
			| first(U->digits[i-1], num_bits);
	}
	
	U->digits[0] = 
		second(U->digits[0], num_bits);
	
}

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
** Generate a 64-bit uniform random string and save it in the lower
** part of the struct.
*/
struct num_128
rand_get()
{
	static int reuse = 1;
	BYTE input[16];
	int j;
	u_long dig;
#if 1
	reuse = 1 - reuse;
	if (reuse)
		return raw2num(next.out + 8);
#endif

	/* Prepare the block for encryption */
	memset(input, 0, 16);
	for (j = 0; j < 4; j++){ /* most significant digits come first */
		dig = htonl(next.counter[3-j]);
		memcpy(input + 4*j, &dig, 4);
	}
		
	rijndaelEncrypt(next.key.rk, next.key.Nr, input, next.out);

	next.counter[0]++;
	/* XXX - TODO - do the real counter increment */
	return raw2num(next.out);
}
