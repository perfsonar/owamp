/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
**	File:		table.h
**
**	Author:		Anatoly Karp
**
**	Date:		Thu Apr 19 13:47:17  2002
**
**	Description:	Simple hash table - header file.
*/
#ifndef TABLE_INCLUDED
#define TABLE_INCLUDED

#include "../owamp/owamp.h"

#define hash_ptr Table_T 
typedef struct hash_ptr *hash_ptr;

typedef struct {
             char *dptr;
             int dsize;
} datum;

extern hash_ptr hash_init(
		   OWPContext ctx,
		   int hint,
		   int cmp(const datum *x, const datum *y),
		   unsigned long hash(const datum *key)
		   );
extern datum* hash_fetch(hash_ptr hash, const datum *key);
extern int hash_store(
		      OWPContext ctx, 
		      hash_ptr table, 
		      const datum *key, 
		      datum *value
		      );
extern void hash_close(hash_ptr *table);

/* #undef hash_ptr */
#endif
