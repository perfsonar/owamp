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
 *	File:		arithm.h
 *
 *	Author:		Anatoly Karp
 *			Internet2
 *
 *	Date:		Sun Jun 02 12:28:55 MDT 2002
 *
 *	Description:	
 */
/*
** Header file for an implementation of extended-precision
** arithmetic (64 bits before and after the decimal point)
*/

#ifndef XP_INCLUDED
#define XP_INCLUDED

#include <sys/time.h>
#define T OWPTime

#define NUM_DIGITS 8

typedef struct T {
	unsigned short digits[NUM_DIGITS];
} *T;

/* 
** This structure represents 32.24 style time format
** (32-bit number of seconds, and 24-bit number of
** fractional seconds), i.e. A + (B/2^24), where
** 0 <= A <= 2^32 - 1, and 0 <= B <= 2^24 - 1.
** The interpretation is: 
** t[0] = A
** t[1] = B << 8 (thus, the 8 least significant bits are unused)
*/
typedef struct {
	unsigned long t[2];
} *OWPFormattedTime;

/* Constructors. */
struct T OWPTime_new(unsigned short a, 
		 unsigned short b, 
		 unsigned short c, 
		 unsigned short d,
		 unsigned short e, 
		 unsigned short f, 
		 unsigned short g, 
		 unsigned short h, 
		 int set_flag
		 );
struct T OWP_ulong2Time(unsigned long a);

/* Arithmetic operations */
void OWPTime_add(T x, T y, T z);
void OWPTime_mul(T x, T y, T z);

/* Conversion operations */
void OWPTime2Formatted(T from, OWPFormattedTime to);
void OWPFormatted2Time(OWPFormattedTime from, T to);

void OWPTime2timeval(T from, struct timeval *to);
void OWPtimeval2Time(struct timeval *from, T to);

/* Debugging and auxilliary functions */
void OWPTime_print(T x);
unsigned long OWPTime2ulong(T x);
unsigned long long OWPTime2ulonglong(T x);
struct T OWP_ulonglong2Time(unsigned long long a);

#undef T 
#endif
