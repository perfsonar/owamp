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
 *	File:		arithm128.h
 *
 *	Author:		Anatoly Karp
 *			Internet2
 *
 *	Date:		Sun Jun 02 12:28:55 MDT 2002
 *
 *	Description:	Header file for an implementation of extended-precision
 *                      arithmetic (64 bits before and after the decimal point)
 */

#ifndef OWP_ARITHM128_INCLUDED
#define OWP_ARITHM128_INCLUDED

#include <sys/time.h>
#include "rijndael-api-fst.h"
#include "rijndael-alg-fst.h"

#define NUM_DIGITS 8

typedef struct OWPnum128 {
	unsigned short digits[NUM_DIGITS];
} *OWPnum128;

/*
** Context for seeding AES-based random-number generator.
*/
typedef struct OWPrand_context {
	unsigned char counter[16]; /* 128-bit counter (network byte ordered) */
	keyInstance key;           /* key used to encrypt the counter.       */
	BYTE out[16];              /* the encrypted block is kept there.     */
	unsigned char reuse;       /* use the upper 64 bits of out if set    */
} OWPrand_context;

/* 
** This structure represents 32.24 style time format (32-bit number of seconds,
** and 24-bit number of fractional seconds), i.e. A + (B/2^24), where
** 0 <= A <= 2^32 - 1, and 0 <= B <= 2^24 - 1. The interpretation is: 
** 
** t[0] = A
** t[1] = B << 8 (thus, the 8 least significant bits are unused)
*/
typedef struct {
	unsigned long t[2];
} *OWPFormattedTime;

/* Conversion operations */
void OWPnum2formatted(OWPnum128 from, OWPFormattedTime to);
void OWPformatted2num(OWPFormattedTime from, OWPnum128 to);
void OWPnum2timeval(OWPnum128 from, struct timeval *to);
void OWPtimeval2num(struct timeval *from, OWPnum128 to);

/* Random number generating functions */
OWPrand_context *OWPrand_context_init(BYTE *sid);  /* Initialize generator. */
struct OWPnum128 OWPexp_rand(OWPrand_context *next);  /* Generate exponential 
						      (mean 1) deviate */
/* Debugging and auxilliary functions */
void OWPnum_print(OWPnum128 x);
#endif
