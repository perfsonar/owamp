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

#include <owamp/owamp.h>
#include <sys/time.h>

typedef u_int64_t OWPnum64;
typedef struct OWPrand_context64 OWPrand_context64;

/* Conversion operations */

extern void
OWPnum64totimespec(
		struct timespec	*to,
		OWPnum64	from
		);

extern OWPnum64
OWPtimespec2num64(
		struct timespec	*from
		);

extern OWPnum64
OWPusec2num64(u_int32_t usec);

extern void
OWPnum64toTimeStamp(
		OWPTimeStamp	*to,
		OWPnum64	from
		);
extern OWPnum64
OWPTimeStamp2num64(
		OWPTimeStamp	*from
		);

/* Arithmetic support. */
extern OWPnum64 OWPulong2num64(u_int32_t a);
extern OWPnum64 OWPnum64_add(OWPnum64 x, OWPnum64 y);
extern OWPnum64 OWPnum64_mul(OWPnum64 x, OWPnum64 y);

/* Random number generating functions */
extern OWPrand_context64 *OWPrand_context64_init(BYTE *sid); /*Initialize generator.*/
extern void OWPrand_context64_free(OWPrand_context64 *next);
extern OWPnum64 OWPexp_rand64(OWPrand_context64 *next);  /* Generate exponential 
						      (mean 1) deviate */
/* Debugging and auxilliary functions */
extern void OWPnum_print64(OWPnum64 x);
#endif
