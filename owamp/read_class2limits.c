/*! \file read_class2limits.c */

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
**	File:		read_class2limits.c
**
**	Author:		Anatoly Karp
**
**	Date:		Fri Jul 12 19:21:28  2002
**
**	Description:	Functions to parse class2limits config file.
*/

#ifndef OWP_READCLASS_H
#define OWP_READCLASS_H

#include <ctype.h>
#include <owamp/owamp.h>
#include "./access.h"

static char* lim_names[5] = {"bandwidth", "space", "expiry", "del_on_close", \
                             "del_on_fetch"};

/*
** Allocate a new tree node.
** Returns: valid owp_tree_node pointer on success;
**          NULL otherwise.
*/
static owp_tree_node_ptr
owp_tree_node_new()
{
	owp_tree_node_ptr ret;

	ret = (owp_tree_node_ptr)malloc(sizeof(*ret));
	if (!ret) {
		perror("malloc");
		return NULL;
	}

	ret->next_sibling = NULL;
	ret->first_child = NULL;
	ret->parent = NULL;

	return ret;
}

typedef struct owp_chunk_buf {
	char *data;             /* data */
	char *cur;              /* current location to be written */
	size_t alloc_size;      /* amount of memory allocated for data,
				   ignoring the sentinel */
	char *sentinel;         /* this location keeps the final '\0' and
				   cannot be overwritten */
} owp_chunk_buf, *owp_chunk_buf_ptr;

/*
** Initialize a dynamically allocated buffer for reading variable
** length fields. 
*/
static int
owp_buf_init(owp_chunk_buf_ptr bufptr, size_t len)
{
	assert(bufptr);

	bufptr->data = (char *)malloc(len + 1);
	if (!bufptr->data) {
		perror("malloc");
		return -1;
	}
	memset(bufptr->data, 0, len + 1); /* The last one is sentinel. */
	bufptr->cur = bufptr->data;
	bufptr->sentinel = bufptr->data + len;

	bufptr->alloc_size = len;
	return 0;
}

/*
** Empty the contents of the data buffer.
*/
static void
owp_buf_reset(owp_chunk_buf_ptr bufptr)
{
	assert(bufptr);

	bufptr->cur = bufptr->data;
	*(bufptr->cur) = '\0';
}

static void 
owp_buf_free(owp_chunk_buf_ptr buf)
{
	assert(buf); assert(buf->data);
	free(buf->data);
}

static int
owp_symbol_save(OWPContext ctx, owp_chunk_buf_ptr buf, int c)
{
	if (buf->cur == buf->sentinel) { /* reallocate memory */
		size_t newsize = buf->alloc_size + 20;
		buf->data = (char *)realloc(buf->data, newsize + 1);
		if (!buf->data) {
			OWPError(ctx, OWPErrFATAL, errno, 
				 "FATAL: owp_symbol_save: realloc failed"); 
			return -1;
		}
		buf->cur = buf->data + buf->alloc_size;
		buf->sentinel = buf->data + newsize;
		buf->alloc_size = newsize;
	}

	/* now save the symbol */
	*(buf->cur)++ = c;
	*(buf->cur) = '\0';

	return 0;
}

/*
** Print out contents of the buffer.
*/
static void
owp_buf_print(owp_chunk_buf_ptr buf)
{
	assert(buf);
	assert(buf->data);
	printf("%s\n", buf->data);
}

I2datum *
owp_node2datum(owp_tree_node_ptr node)
{
	
}

#define OWP_OK            0
#define OWP_ERR           1
#define OWP_EOF           2
#define OWP_LAST          3
#define OWP_END_DESCR     4

/*
** Skip blank lines. This function is assumed to only be called
** at the beginning of file, or immediately after a separator.
** Returns: OWP_OK on success.
**          OWP_ERR on physical error or if the separator is invalid
**          OWP_EOF if end of file is encountered
*/
static int
owp_skip_separators(OWPContext ctx, FILE *fp)
{
	int c;
	int newline = 1;           /* State variables. */
	int inside_comment = 0;

	while ((c = fgetc(fp)) != EOF) {
		/* While inside comment only need to watch for a newline. */
		if (inside_comment){
			if (c == '\n')
				inside_comment = 0;
			continue;
		}

		if (newline) {
			if (c == '\n')
				continue;
			if (c == '#') {
				inside_comment = 1;
				continue;
			}
			if (isspace(c)) {
				newline = 0;
				continue;
			}

			/* Reached iff c is the first non-whitespace 
			   since last newline. */
			return (ungetc(c, fp) != EOF)? OWP_OK : OWP_ERR;
		}

		/* Seen white-space since line start. */
		newline = (c == '\n')? 1 : 0;
		if (isspace(c))
			continue;
		
		/* Can't have whitespace preceding non-whitespace/ */
		return OWP_ERR;
	}

	return (feof(fp))? OWP_EOF : OWP_ERR;
}

/*
** Skip whitespaces before the start of next description chunk.
** Returns: OWP_OK on success (ready to read the next chunk)
**          OWP_END_DESCR - if descriptions has ended, and no
**                          new chunk has been found;
**          OWP_ERR on error (intended to be fatal)
*/
static int
owp_skip_whitespace(OWPContext ctx, 
		    FILE *fp, 
		    int *newline, 
		    unsigned int *line_num)
{
	int c;

	/* First skip whitespaces. */
	int inside_blank_line = *newline;
	while ((c = fgetc(fp)) != EOF) {
		if (*newline && (! isspace(c))) {
			ungetc(c, fp);
			return OWP_END_DESCR;
		}
		
		*newline = (c == '\n')? 1 : 0;
		if (isspace(c)){
			if (c == '\n') {
				(*line_num)++;
				if (inside_blank_line)
					return OWP_END_DESCR;
				inside_blank_line = 1;
			} 
			continue;
		}
		
		/* Found the first non-whitespace */
		return (ungetc(c, fp) != EOF)? OWP_OK : OWP_ERR;
	}
	return (ferror(fp))? OWP_ERR : OWP_END_DESCR;
}


/*
** Classname must consist of alhanumerics only, with the first 
** character being an alpha.
*/
static int
owp_is_valid_classname(char *class)
{
	char* ptr = class;
	assert(class);

	if (! isalpha(*ptr))
		return 0;

	while (*(++ptr) != '\0')
		if (! isalnum(*ptr))
			return 0;
	
	return 1;
}

/*
** Convert a string (with a possible SI unit) into a numeric value.
** Returns: 0 on success, 
**         -1 if invalid string, or overflow has occurred.
**
** NOTE: this function is destructive - you CANNOT use it twice on same string.
*/
static int
owp_str2num(char *str, owp_lim_t *val)
{
	char *tmp, *endptr;
	int t;
	
	unsigned long long ret, mult = 1;

	if ((!str) || isspace(*str) || (! isdigit(*str)))
		return -1;

	tmp = &str[strlen(str) - 1];
	if (! isdigit(*tmp)) {
		switch (*tmp) {
		case 'k':
		case 'K':
			mult = 1000ULL;                            /* 1e3 */
			break;
		case 'm':
		case 'M':
			mult = 1000000ULL;                         /* 1e6 */
			break;
		case 'g':
		case 'G':
			mult = 1000000000ULL;                      /* 1e9 */
			break;
		case 't':
		case 'T':
			mult = 1000000000000ULL;                   /* 1e12 */
			break;
		case 'p':
		case 'P':
			mult = 1000000000000000ULL;                /* 1e15 */
			break;
		case 'e':
		case 'E':
			mult = 1000000000000000000ULL;             /* 1e18 */
			break;
		case 'z':
		case 'Z':
			mult = 1000000000000000000000ULL;          /* 1e21 */
			break;
#if 0
		case 'y':
		case 'Y':
			mult = 1000000000000000000000000ULL;       /* 1e24 */
			break;
#endif
		default:
			return -1;
			/* UNREACHED */
		}
		*tmp = '\0';
	}
	ret = strtoull(str, &endptr, 10);
	if (*endptr != '\0')
		return -1;

	/* Check for overflow. */
	*val = ret * mult;
	return (*val < ret || *val < mult)? (-1) : 0;
}

#define OWP_ON(q) ((q)                       \
		   && (toupper(q[0]) == 'O') \
		   && (toupper(q[1]) == 'N') \
		   && (q[2] == '\0'))

#define OWP_OFF(q) ((q)                      \
		   && (toupper(q[0]) == 'O') \
		   && (toupper(q[1]) == 'F') \
		   && (toupper(q[2]) == 'F') \
		   && (q[3] == '\0'))

/*
** Given a class name return the address of the corresponding node
** on success, or NULL if not found.
*/
static owp_tree_node_ptr
owp_class2node(char *class, I2table hash)
{
	I2datum *key, *val;

	key = owp_raw2datum(class, strlen(class) + 1);
	val = I2hash_fetch(hash, key);
	return val? (owp_tree_node_ptr)(val->dptr) : NULL;
}

/*
** Read a logical line describing policy limits for a next class.
** Save the result in *new_node on success.
** Returns: OWP_OK on success
**          OWP_ERR on error
**          OWP_EOF on end of file

** Validity conditions:
** 1) both class name and parent name field (if any) are valid
** 2) all field names are valid
** 3) all field values, except for "parent", are valid. Validity of
**    the "parent" field is dealt with separately. 
**
** It is assumed that memory for <new_node> has been allocated by the caller.
*/
static int
owp_get_description(OWPContext ctx, 
		    FILE *fp, 
		    owp_tree_node_ptr new_node,
		    owp_tree_node_ptr *root,  /* NULL if hasn't been set yet */
		    unsigned int *line_num,
		    I2table class2node
		    )
{
	int c, t;
	owp_chunk_buf buf;
	char *p, *q, *brka;
	I2datum *key, *val;
	int newline = 1; /* set if the last character was '\n' */

	int parent_set = 0;

	assert(class2node);
	if ((t = owp_skip_separators(ctx, fp)) != OWP_OK)
		return t;

	if (owp_buf_init(&buf, 20) < 0)
		goto syntax_err;
	/* Process class - there MUST be one. Stop at first whitespace. */
	while ((c = fgetc(fp)) != EOF) {
		if (c == '\n')
			(*line_num)++;
		newline =  (c == '\n')? 1 : 0;
		if (isspace(c))
			break;
		if (owp_symbol_save(ctx, &buf, c) < 0)
			goto syntax_err;
	}
	if (ferror(fp)){
		OWPError(ctx, OWPErrFATAL, errno, "FATAL: fgetc() error"); 
		goto syntax_err;
	}
	if ((! owp_is_valid_classname(buf.data)) 
	    || (owp_class2node(buf.data, class2node)))
		goto syntax_err;
	if (!(new_node->data = strdup(buf.data))) {
		OWPError(ctx, OWPErrFATAL, errno, "FATAL: malloc() error"); 
		goto syntax_err;
	}

	while ((t = owp_skip_whitespace(ctx, fp, &newline, line_num))==OWP_OK){
		owp_lim_t numval;
		int i;
		/* Now process the chunk - look for first whitespace. */
		owp_buf_reset(&buf);
		while ((c = fgetc(fp)) != EOF) {
			newline = (c == '\n')? 1 : 0;
			if (c == '\n')
				(*line_num)++;
			if (isspace(c))
				break;
			if (owp_symbol_save(ctx, &buf, c) < 0)
				goto syntax_err;
		}
		if (ferror(fp)){
		    OWPError(ctx, OWPErrFATAL, errno, "FATAL: fgetc() error"); 
		    goto syntax_err;
		}

		/* Make sure there's exactly one '=' symbol. */
		if ((strchr(buf.data, '=') != strrchr(buf.data, '='))
		    || !(p = strtok_r(buf.data, "=", &brka))
		    || !(q = strtok_r(NULL, "=", &brka)))
			goto syntax_err;

		for (i = 0; i < 3; i++) {
			if (!strcmp(p, lim_names[i])) {
				if (owp_str2num(q, &numval) < 0)
					goto syntax_err;
				new_node->limits.values[i] = numval;
				goto next_chunk;
			}
		}
		for (i = 3; i < 5; i++) {
			if (!strcmp(p, lim_names[i])) {
				if (! (OWP_ON(q) || OWP_OFF(q)))
					goto syntax_err;
				new_node->limits.values[i] = (OWP_ON(q))? 1:0;
				goto next_chunk;
			}
		}
		if (!strcmp(p, "parent")) {
			owp_tree_node_ptr tmp;
			if (!(new_node->parent=owp_class2node(q,class2node)))
				goto syntax_err;
				
			tmp = new_node->parent->first_child;
			new_node->parent->first_child = new_node;
			new_node->next_sibling = tmp;
			continue;
		}
		goto syntax_err; /* No match. */
	next_chunk:
		continue;
	}
	if (t == OWP_ERR)
		goto syntax_err;

	/* Now inspect the description and check for any remaining errors. */
	/*
	  XXX
	*/

	if (!*root)  /* root has not been seet yet */
		*root = new_node;

	/* Save the new node in class2node hash */
	key = owp_raw2datum(new_node->data, strlen(new_node->data) + 1);
	val = owp_raw2datum(new_node, sizeof(*new_node));
	I2hash_store(class2node, key, val);
	
	/* Remember to free buffer at the end. */
	owp_buf_free(&buf);
	return OWP_OK;

 syntax_err:
	owp_buf_free(&buf); 
	OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
		 "FATAL: owp_get_description: bad syntax in config file"); 
	return OWP_ERR;
}


/*
** Read the config file <class2limits> and save the data in the hash
** for future lookups. 

** Description of the hash: key = class name [ASCII string]
** value = address of the owp_tree struct decribing the corresponding
** node.
*/
int
owp_read_class2limits2(OWPContext ctx, const char *class2limits, I2table hash)
{
	FILE* fp;
	int type, t;
	unsigned int line_num = 1;
	I2table class2node_hash;
	owp_tree_node_ptr last, cur_node, root = NULL;
	int is_first = 1; 
	fp = fopen(class2limits, "r");
	if (!fp) {
		OWPError(ctx, OWPErrFATAL, errno, 
			 "FATAL: fopen %s for reading", class2limits);
		return -1;
	}
	class2node_hash = I2hash_init(ctx, 0, NULL, NULL, 
				      owp_print_class2node_binding);
	if (!class2node_hash) {
		OWPError(ctx, OWPErrFATAL, errno, 
			 "FATAL: could not open class2node hash");
		return -1;
	}

	while (1) {
		cur_node = owp_tree_node_new(); /* XXX: err-check */
		t = owp_get_description(ctx, fp, cur_node, &root, &line_num,
					class2node_hash);
		switch (t) {
		case OWP_OK:
			/*
			  owp_merge_node(parent, cur_node);
			  XXX - merge cur_node into the tree 
			*/
			if (!root) {
				root = cur_node;
				continue;
			}
			break;
		case OWP_EOF:
			goto final;
			return 0;
			/* UNREACHED */
		case OWP_ERR:
			goto final;
			return -1;
			/* UNREACHED */
		default:
			/* XXX: Internal error. */
			break;
		}

	}
 final:
	printf("\nPrinting the class2node hash:\n");
	I2hash_print(class2node_hash, stdout);
	return 0;
}

#endif
