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
**	Date:		Thu Apr 19 13:47:17  EDT 2002
**
**	Description:	Simple hash table - header file.
*/
#ifndef TABLE_INCLUDED
#define TABLE_INCLUDED

#include "../owamp/owamp.h"

#define T hash_ptr
typedef struct T *T;

typedef struct {
             char *dptr;
             int dsize;
} datum;

struct binding {
	struct binding *link;
	const datum *key;
	datum *value;
};

typedef void (*print_binding_func)(const struct binding *p, FILE* fp);

extern T hash_init(
		   OWPContext ctx,
		   int hint,
		   int cmp(const datum *x, const datum *y),
		   unsigned long hash(const datum *key),
		   void print_binding(const struct binding *p, FILE* fp)
		   );
extern datum* hash_fetch(T hash, const datum *key);
extern int hash_store(
		      OWPContext ctx, 
		      T table, 
		      const datum *key, 
		      datum *value
		      );
extern void hash_print(T table, FILE* fp);
extern void hash_close(T *table);

#undef T
#endif
