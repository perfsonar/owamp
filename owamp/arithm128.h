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

#ifndef ARITHM128_INCLUDED
#define ARITHM128_INCLUDED

#include <sys/time.h>
#include "rijndael-api-fst.h"
#include "rijndael-alg-fst.h"

#define NUM_DIGITS 8

typedef struct num128 {
	unsigned short digits[NUM_DIGITS];
} *num128;

/*
** Context for seeding AES-based random-number generator.
*/
typedef struct rand_context {
	unsigned char counter[16]; /* 128-bit counter (network byte ordered) */
	keyInstance key;           /* key used to encrypt the counter.       */
	BYTE out[16];              /* the encrypted block is kept there.     */
} rand_context;

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
void num2formatted(num128 from, OWPFormattedTime to);
void formatted2num(OWPFormattedTime from, num128 to);
void num2timeval(num128 from, struct timeval *to);
void timeval2num(struct timeval *from, num128 to);

/* Random number generating functions */
void rand_context_init(BYTE *sid);  /* Initialize the generator */
struct num128 exp_rand();       /* Generate an exponential (mean 1) deviate */

/* Debugging and auxilliary functions */
void num_print(num128 x);
#endif
