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
 *	File:		vector.c
 *
 *	Author:		Anatoly Karp
 *			Internet2
 *
 *	Date:		Mon Dec 9 12:29:20 MDT 2002
 *
 *	Description:	Compute a vector to verify correctness
 *                      and reproducibility of exponential random
 *                      number generator. For a fixed value of seed,
 *                      compute the value of the millionth member
 *                      of the sequence.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "rijndael-alg-ref.h"
#include "rijndael-api-ref.h"

typedef u_int64_t OWPnum64;

#define MILLION   1000000
#define NUM_DRAWS MILLION

void
OWPnum_print64(OWPnum64 x);

#define K 12 /* So (K - 1) is the first k such that Q[k] > 1 - 1/(2^32). */
#define SCALE ((u_int64_t)0x100000000)  /* == 2^32 */

#define MASK32(x) ((x) & 0xFFFFFFFF)

typedef struct OWPrand_context64 {
	unsigned char counter[16]; /* 128-bit counter (network byte ordered) */
	keyInstance key;           /* key used to encrypt the counter.       */
	BYTE out[16];              /* the encrypted block is kept there.     */
	cipherInstance cipher;
} OWPrand_context64;

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

	if (!res) {
		if (blockEncrypt(&next->cipher, &next->key, next->counter, 128,
				 next->out) < 0) {
			fprintf(stderr, "DEBUG: encryption failed\n");
			exit(1);
		}
	}

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
void
OWPrand_context64_init(OWPrand_context64 *next, char *seed)
{
	int i;

	/* Initialize the key */

	if (makeKey(&next->key, DIR_ENCRYPT, 128, seed) < 0) {
		fprintf(stderr, "makekey failed\n");
		exit(1);
	}

	next->cipher.mode = MODE_ECB;
	next->cipher.blockLen = 128;

	memset(next->out, 0, 16);
	for (i = 0; i < 16; i++)
		next->counter[i] = 0UL;


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
** Print out a OWPnum64 number - used for debugging.
*/
void
OWPnum_print64(OWPnum64 x)
{
#if 1
	fprintf(stdout, "%llX \n", x);
#else
	fprintf(stdout, "%.16f\n", (double)x/(double)0xFFFFFFFF);
#endif
}


/* 
** Generate many exponential draws and run the chi-square test on them.
*/
int
main()
{
	char seed[] = "7a91b6d691c2d36d7a91b6d691c2d36d";
	OWPnum64 num;
	unsigned long i;
	OWPrand_context64 next;

	OWPrand_context64_init(&next, seed);

	for (i = 0; i < NUM_DRAWS; i++){
		num = OWPexp_rand64(&next); 
		/*		OWPnum_print64(num);    */
	}

	OWPnum_print64(num);

	/*
	  resulting number should be: 7F6EDDE6 
	*/
	exit(0);
}

