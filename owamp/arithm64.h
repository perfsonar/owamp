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
 *	File:		arithm64.h
 *
 *	Author:		Anatoly Karp
 *			Internet2
 *
 *	Date:		Sun Jun 20 12:28:55 MDT 2002
 *
 *	Description:	
 */
/*
** Context for seeding AES-based random-number generator.
*/
#ifndef OWP_ARITHM64_INCLUDED
#define OWP_ARITHM64_INCLUDED

#include <sys/time.h>
#include "rijndael-api-fst.h"
#include "rijndael-alg-fst.h"

typedef u_int64_t OWPnum64;

typedef struct OWPrand_context64 {
	unsigned char counter[16]; /* 128-bit counter (network byte ordered) */
	keyInstance key;           /* key used to encrypt the counter.       */
	BYTE out[16];              /* the encrypted block is kept there.     */
} OWPrand_context64;

/* Conversion operations */
#if 0
void OWPnum2timeval(OWPnum64 from, struct timeval *to);
OWPnum64  OWPtimeval2num(struct timeval *from);
void OWPnum2timespec(OWPnum64 from, struct timespec *to);
OWPnum64 OWPtimespec2num(struct timespec *from);
#endif

/* Random number generating functions */
OWPrand_context64 *OWPrand_context64_init(BYTE *sid); /*Initialize generator.*/
void OWPrand_context64_free(OWPrand_context64 *next);
OWPnum64 OWPexp_rand64(OWPrand_context64 *next);  /* Generate exponential 
						      (mean 1) deviate */
/* Debugging and auxilliary functions */
void OWPnum_print64(OWPnum64 x);
#endif
