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

#define NUM_DIGITS 8

typedef struct num_128 {
	unsigned short digits[NUM_DIGITS];
} *num_128;

/* 
** This structure represents 32.24 style time format
** (32-bit number of seconds, and 24-bit number of
** fractional seconds), i.e. A + (B/2^24), where
** 0 <= A <= 2^32 - 1, and 0 <= B <= 2^24 - 1.
**
** The interpretation is: 
** t[0] = A
** t[1] = B << 8 (thus, the 8 least significant bits are unused)
*/
typedef struct {
	unsigned long t[2];
} *OWPFormattedTime;

/* Constructors. */
struct num_128 num_new(unsigned short a, 
		 unsigned short b, 
		 unsigned short c, 
		 unsigned short d,
		 unsigned short e, 
		 unsigned short f, 
		 unsigned short g, 
 		 unsigned short h
		 );
struct num_128 ulong2num(unsigned long a);
struct num_128 new_random(keyInstance *key, unsigned long in, BYTE *outBuffer);

/* Arithmetic operations */
void num_add(num_128 x, num_128 y, num_128 z);
void num_mul(num_128 x, num_128 y, num_128 z);
int num_cmp(num_128 x, num_128 y);
/* Conversion operations */
void num2formatted(num_128 from, OWPFormattedTime to);
void formatted2num(OWPFormattedTime from, num_128 to);
void num2timeval(num_128 from, struct timeval *to);
void timeval2num(struct timeval *from, num_128 to);
struct num_128 raw2num(unsigned char *raw);

/* Debugging and auxilliary functions */
void num_print(num_128 x);
unsigned long num2ulong(num_128 x);
unsigned long long num2ulonglong(num_128 x);
struct num_128 ulonglong2num(unsigned long long a);

/* Generate an exponential deviate using 64-bit binary string as an input. */
struct num_128 random_exp(keyInstance *key, unsigned long in);
#undef T 
#endif
