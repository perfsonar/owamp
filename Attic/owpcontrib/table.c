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
**	File:		table.c
**
**	Author:		Anatoly Karp
**
**	Date:		Thu Apr 19 13:47:17  2002
**
**	Description:	Simple hash table - implementation.
*/
#include <limits.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "table.h"

#define hash_ptr Table_T

/* Types used to define a hash table. */
struct hash_ptr {
	int size;
	int (*cmp)(const datum *x, const datum *y);
	unsigned long (*hash)(const datum *key);
	int length;
	struct binding {
		struct binding *link;
		const datum *key;
		datum *value;
	}  **buckets;
};

/* Static functions (used by default unless specified). */
static int 
cmpatom(const datum *x, const datum *y)
{
	/* return x != y; */
	assert(x);
	assert(y);
	return (!(x->dsize == y->dsize) || bcmp(x->dptr, y->dptr, x->dsize));
}

static unsigned long
hashatom(const datum *key)
{
	return (unsigned long)key->dptr>>2;
}

hash_ptr 
hash_init(
	    OWPContext ctx,
	    int hint,
	    int cmp(const datum *x, const datum *y),
	    unsigned long hash(const datum *key)
)
{
	hash_ptr table;
	int i;
	static int primes[] = { 509, 509, 1021, 2053, 4093, 8191, 16381,
	32771, 65521, INT_MAX };
	
	assert(hint >= 0);
	for (i = 1; primes[i] < hint; i++)
		;
	table = (void *)malloc(sizeof(*table) + 
			       primes[i-1]*sizeof(table->buckets[0]));
	if (table == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: malloc for hash table");
		
		exit(1);
	}

	table->size = primes[i-1];
	table->cmp = cmp? cmp : cmpatom;
	table->hash = hash ? hash : hashatom;
	table->buckets = (struct binding **)(table + 1);
	for (i = 0; i < table->size; i++)
		table->buckets[i] = NULL;
	table->length = 0;
	return table;
}

void
hash_close(hash_ptr *table)
{
	assert(table && *table);
	if ((*table)->length > 0){
		int i;
		struct binding *p, *q;
		for (i = 0; i < (*table)->size; i++)
			for (p = (*table)->buckets[i]; p; p = q){
				q = p->link;
				if (p)
					free(p);
			}
	}
	if (*table)
		free(*table);
}

int 
hash_store(OWPContext ctx, hash_ptr table, const datum *key, datum *value)
{
	int i;
	struct binding *p;
	datum *prev;

	assert(table);
	assert(key);

	/* Search table for key. */
	i = (*table->hash)(key)%table->size;
	for (p = table->buckets[i]; p; p = p->link){
		if ((*table->cmp)(key, p->key) == 0)
			break;
	}

	if (p == NULL){ /* not found */
		p = (void *)malloc(sizeof(*p));
		if (p == NULL){
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "FATAL: malloc for hash table");
			return -1;
		}
	} else {
		p->key = key;
		p->link = table->buckets[i];
		table->buckets[i] = p;
		table->length++;
	}
}

datum *
hash_fetch(hash_ptr table, const datum *key){
	int i;
	struct binding *p;
	datum ret;
	ret.dsize = 0;
	ret.dptr = NULL;

	assert(table);
	assert(key);

	/* Search table for key. */
	i = (*table->hash)(key)%table->size;
	for (p = table->buckets[i]; p; p = p->link){
		if ((*table->cmp)(key, p->key) == 0)
			break;
	}
	
	return p ? (p->value) : NULL;
}

void
hash_print(hash_ptr table)
{
	int i;
	struct binding *p;
	
	assert(table);

	for (i = 0; i < table->size; i++)
		for (p = table->buckets[i]; p; p = p->link)
			fprintf(stderr, "DEBUG: the value of key %s is %s\n",
				p->key->dptr, p->value->dptr);
}
