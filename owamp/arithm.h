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

#define T OWPTime

#define NUM_DIGITS 8

typedef struct {
	unsigned short digits[NUM_DIGITS];
} *T;

/* Constructors. */
T OWPTime_new(unsigned short a, 
		 unsigned short b, 
		 unsigned short c, 
		 unsigned short d,
		 unsigned short e, 
		 unsigned short f, 
		 unsigned short g, 
		 unsigned short h, 
		 int set_flag
		 );
T OWPTime_from_ulong(unsigned long a);

/* Destructor */
void OWPTime_destroy(T x); 

void OWPTime_print(T x);

/* Arithmetic operations */
void OWPTime_add(T x, T y, T z);
void OWPTime_mul(T x, T y, T z);

#undef T 
#endif
