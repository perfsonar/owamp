/*! \file access2.c */

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
**	File:		access2.c
**
**	Author:		Anatoly Karp
**
**	Date:		Fri Jun 14 11:10:33  2002
**
**	Description:	
**	This file contains the OWAMP access policy functions.
*/

#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <owamp/owamp.h>
#include "./access.h"

/* Data for keeping the state */
static int new_line         = 1;
static char* filename       = NULL;
static unsigned int linenum = 1;

/* two flags to keep track of whether 0/0 and ::0/0 masks have been
   given a class */
static int ipv4_default_set = 0; 
static int ipv6_default_set = 0;

/*
** This function fills out a datum structure with the given string.
** When saving a string, <len> typically should be strlen(bytes) + 1.
** The memory is dynamically allocated, but normally will not be
** free()-ed because the key/value just gets saved in a hash.
*/
I2datum*
owp_raw2datum(const void *bytes, size_t len)
{
	I2datum *dat;

	if ( (dat = (void *)malloc(sizeof(*dat))) == NULL){
		return NULL;
	}
	memset(dat, 0, sizeof(*dat));

	if ( (dat->dptr = (void *)malloc(len)) == NULL) {
		free(dat);
		return NULL;
	}		

	memcpy(dat->dptr, bytes, len);
	dat->dsize = len;
	return dat;
}

/* Destructor function. */
void
owp_datum_free(I2datum *datum)
{
	assert(datum);
	if (datum->dptr) free(datum->dptr);
	free(datum);
}

/*
** Check if a given IPv6 netmask is legal - i.e. whether the (128 - offset)
** least significant bits in the 16-byte address are zero.
** Return 1 if yes, 0 otherwise.
*/
static int
is_valid_netmask6(struct sockaddr_in6 *addr, u_int8_t num_offset)
{
	int i;
	u_int8_t *ptr;
	u_int8_t nbytes, nbits;

	if (num_offset > 128)
		return 0;

	nbytes = num_offset/8;
	nbits = num_offset%8;
	if (nbits){     /* The last (8-nbits) bits must be zero. */
		if (addr->sin6_addr.s6_addr[nbytes++] 
		    & (((u_int8_t)1 << (8 - nbits)) - 1)) {
			fprintf(stderr, "found bad mask: *ptr = %u\n", *ptr);
			return 0;
		}
	}
	
	/* Make sure all subsequent bytes are zero. */
       for (i = nbytes; i < 16; i++) {
	       if (addr->sin6_addr.s6_addr[nbytes]) {
		       fprintf(stderr, "found bad mask: *ptr[%d] = %u\n", 
			       nbytes, ptr[nbytes]);

		       return 0;
	       }
       }

       return 1;
}

/*
** Mask out all but i first bits of the byte x.
*/
#define FIRST_BITS(x, i) ((x) & ((0xFF >> (8-(i))) << (8-(i))))

/*
** Return 0 if address belongs to a given netmask and both netmasks
** have the same offset, and non-zero otherwise.
**
** Assumes that AT LEAST one of the arguments is an actual legal
** netmask. This should be true since no illegal netmask should
** ever enter the hash in the first place (i.e. they should all
** be checked before being put in a hash).
**
** NOTE that when BOTH netmasks happen to be legal, the function
** behaves like a real honest comparison.
*/
static int
owp_cmp_netmask_match(const I2datum *address, const I2datum *netmask)
{
	owp_access_netmask *addr, *net;
	u_int8_t *ptra, *ptrb, nbytes, nbits;

	assert(addr); assert(net);
	addr = (owp_access_netmask *)(address->dptr);
	net = (owp_access_netmask *)(netmask->dptr);
	if (addr->af != net->af || addr->offset != net->offset)
		return 1;

	switch (addr->af) {
	case AF_INET:
		return (addr->addr4 != net->addr4);
		break;
#ifdef AF_INET6
	case AF_INET6:
		nbytes = net->offset/8;
		nbits = net->offset%8;
		ptra = addr->addr6;
		ptrb = net->addr6;
		
		if (nbytes)
			if (memcmp(ptra, ptrb, 16))
				return 1;
		
		ptra += nbytes;
		ptrb += nbytes;
		
		return (nbits)? 
			(FIRST_BITS(*ptra, nbits) != FIRST_BITS(*ptrb, nbits)) 
			: 0;
		break;
#endif
	default:
		break;
	}
	return 1;
}

/*
** Create a hash key out of a netmask.
*/
static I2datum *
owp_netmask2datum(owp_access_netmask *netmask)
{
	I2datum *ret = (void *)malloc(sizeof(*ret));
	if (!ret) {
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));
	
	ret->dptr = (void *)netmask;
	ret->dsize = sizeof(*netmask);

	return ret;
}

/*
** Given raw data describing a netmask, and a usage class,
** create a hash binding and save it in the hash. The raw
** data is as follows: in the IPv4 case <addr> points to
** a u_int32_t IP address in the HOST byte order. In the
** IPv6 case <addr> points to a struct sockaddr_in6
** (thus eventually keeping the address in the NETWORK byte
** order). Returns 0 on success, or -1 on failure.
*/
static int
owp_netmask2class_store(void *addr, 
			u_int8_t num_offset, 
			int family,         /* AF_INET, AF_INET6 */
			char *class,        /* name of the class */
			I2table id2class_hash)
{
	I2datum *key, *val;
	owp_access_netmask *ptr;

	if ((ptr = (owp_access_netmask *)malloc(sizeof(*ptr))) == NULL){
		return -1;
	}
	memset(ptr, 0, sizeof(*ptr));

	ptr->offset = num_offset;
	ptr->af = family;
	if ((key = owp_netmask2datum(ptr)) == NULL)
		return -1;
	
	switch (family) {
	case AF_INET:
		ptr->addr4 = *(u_int32_t *)addr;
		memset(ptr->addr6, 0, 16);
		break;
#ifdef AF_INET6
	case AF_INET6:
		ptr->addr4 = (u_int32_t)0;
		memcpy(ptr->addr6, 
		       ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr, 16);
		break;
#endif
	default:
		return 0;
		break;
	}
	if (((val = owp_raw2datum(class, strlen(class) + 1)) == NULL)
	    || (I2hash_store(id2class_hash, key, val) < 0))
		return -1;
	return 0;
}

static int
class_has_limits(char *class, owp_policy_data *policy)
{
	I2datum temp_dat, *val;
	I2table class2node = policy->class2node;

	temp_dat.dptr = class;
	temp_dat.dsize = strlen(class) + 1;
	val = I2hash_fetch(class2node, &temp_dat);

	return (val)? 1 : 0;
}

/*
** Read characters from <fp> until a white-space or EOF is encountered
** and save them in the provided buffer (the terminating whitespace
** is not saved). Return OWP_ERR if a physical read error has occurred
** or unable to save a char in the buffer, and OWP_OK otherwise.
*/
static int 
owp_getword(OWPContext ctx, FILE *fp, owp_chunk_buf *buf_ptr) 
{
	int c;

	while ((c = fgetc(fp)) != EOF) {
		if (isspace(c)) {
			if (c == '\n')
				linenum++;
			new_line = (c == '\n')? 1 : 0;
			return 0;
		}
		if (owp_symbol_save(ctx, buf_ptr, c) < 0) {
			OWPError(ctx, OWPErrFATAL, errno,
				 "FATAL: error saving char in a buffer");
			return OWP_ERR;
		}
		
	}

	/* Handle EOF here. */
	if (ferror(fp)) {
		OWPError(ctx, OWPErrFATAL, errno,
			 "FATAL: reading error");
		return OWP_ERR;
	}
	return OWP_OK;
}

/*
** Delimiter is a newline. But line length is not limited in advance.
** Key/value pairs are placed into the hash as they are read.
** Return OWP_OK on success, OWP_ERR on error, or OWP_EOF on end-of-file.
*/
static int
get_ip2class_line(OWPContext ctx, FILE *fp, owp_policy_data *policy)
{
	int c;
	owp_chunk_buf buf;
	struct addrinfo hints, *res;
	u_int8_t num_offset;
	u_int32_t addr;
	char *brkb, *netmask, *class, *slash, *nodename, *offset;
	unsigned int err_linenum = 0;      /* Impossible value. */
	I2table id2class_hash = policy->ip2class;

	if (owp_buf_init(&buf, 20) < 0) {
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: owp_buf_init:");
		return -1;
	}
	if ((c = fgetc(fp)) == EOF)
		goto got_eof;
	if (c == '#') { /* comment - skip till next line */
		while ((c = fgetc(fp)) != EOF) {
			if (c == '\n') {
				linenum++;
				return OWP_OK;
			}
		}
		goto got_eof;
	}

	if (isspace(c) || (c == '#')) { /* Expect empty line - else error*/
		while (c != '\n') {
			if ((c = fgetc(fp)) == EOF)
				goto got_eof;
			if (!isspace(c)) {
				OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
     "FATAL: get_ip2class_line: reading file %s: syntax error in line %u",
					 filename, linenum);
				return OWP_ERR;
			}
		}
		new_line = 1; /* Shouldn't be necessary but just in case. */
		linenum++;
		owp_buf_free(&buf);
		return OWP_OK;
	}

	/* Else expect a word - but remember to save the first char.*/
	if (owp_symbol_save(ctx, &buf, c) < 0)
		goto save_err;
	if (owp_getword(ctx, fp, &buf) == OWP_ERR) {
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
   "FATAL: get_ip2class_line: reading file %s: physical read error in line %u",
			 filename, linenum);
		return OWP_ERR;
	}

	if (new_line) {
		err_linenum = linenum - 1;
		goto syntax_err;
	}

	assert(buf.data);
	if ((netmask = strdup(buf.data)) == NULL)
		goto malloc_err;

	/* Skip white-spaces - newline disallowed. */
	while (1) {
		if ((c = fgetc(fp)) == EOF) {
			if (ferror(fp)) {
				free(netmask);
				OWPError(ctx, OWPErrFATAL, errno,
					 "FATAL: physical read error");
				return OWP_ERR;
			}
			err_linenum = linenum;
			goto syntax_err;
		}
		if (c == '\n') {
			free(netmask);
			err_linenum = linenum++;
			new_line = 1;
			goto syntax_err;
		}
		if (!isspace(c))
			break;
	}

#ifdef	VERBOSE
	owp_buf_print(stderr, &buf);
	fprintf(stderr, "%u\n", linenum);
#endif


	owp_buf_reset(&buf);
	if (owp_symbol_save(ctx, &buf, c) < 0) {
		free(netmask);
		goto save_err;
	}
	if (owp_getword(ctx, fp, &buf) == OWP_ERR) {
		free(netmask);
		owp_buf_free(&buf);
		return OWP_ERR;
	}


	err_linenum = (!new_line)? linenum : (linenum - 1); 
	if (!new_line) { /* Skip white-space till next newline */
		while (1) {
			c = fgetc(fp);
			if (c == EOF) {
				if (ferror(fp)){
					free(netmask);
					goto got_eof;
				}
				break;
			}
			if (c == '\n') {
				linenum++;
				new_line = 1;
				break;
			}
			if (!isspace(c)){
				free(netmask);
				goto syntax_err;
			}
		}
	}

	/* Found 2 tokens and nothing went wrong so far do more checking. */
	assert(buf.data);
	if ((class = strdup(buf.data)) == NULL) {
		free(netmask);
		goto malloc_err;
	}

#ifdef	VERBOSE
	owp_buf_print(stderr, &buf);
#endif

	if (!class_has_limits(class, policy)){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: class %s has not been assigned limits",
			 class); 
		owp_buf_free(&buf);
		return OWP_ERR;
	}

	/* Prepare the hints structure. */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	slash = strchr(netmask, '/');
	
	if (!slash) { /* Single IP address. */
		if (getaddrinfo(netmask, NULL, &hints, &res) != 0)
			goto bad_mask;
		
		/* Assume maximum offset by default.*/
		switch (res->ai_family) {
		case AF_INET:
			num_offset = 32;
			break;
#ifdef AF_INET6
		case AF_INET6:
			num_offset = 128;
			break;
#endif
		default: 
			free(class); free(netmask);
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN,
			      "FATAL: %s: line %lu: unknown protocol family");
			owp_buf_free(&buf);
			return OWP_ERR;
			/* UNREACHED */
		}
	} else { /* The IP netmask case. */
		nodename = strtok_r(netmask, "/", &brkb);
		if ( (!nodename) ||
		     (getaddrinfo(nodename, NULL, &hints, &res) < 0))
			    goto bad_mask;
		
		/* check if there is CIDR offset */
		offset = strtok_r(NULL, "/", &brkb);
		if (!offset)
			goto bad_mask;
		
		num_offset = (u_int8_t)strtol(offset, NULL, 10);
		if (num_offset == 0 && strcmp(offset, "0"))
			goto bad_mask;
	}
	
	/* At this point both addrinfo and num_offset are set. 
	   First check if netmask is correctly specified. */
	switch (res->ai_family) {
	case AF_INET:
		addr = 
		ntohl(((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr);
		
		/* Check if (addr, offset) combination is legal. */
		if ( (num_offset > 32) 
		     || (!num_offset && addr)
		     || (num_offset 
			 && (addr 
			     & (((u_int8_t)1<<(32-num_offset)) - 1)))
		     ) 
			goto bad_mask;
		/* If this is a 0/0 mask - set the flag. */
		if (!strcmp(nodename, "0") && !num_offset)
			ipv4_default_set = 1;
		owp_netmask2class_store(&addr, num_offset, 
					res->ai_family, class, id2class_hash);
		break;
#ifdef AF_INET6
	case AF_INET6:
		if (!is_valid_netmask6(
				       (struct sockaddr_in6 *)(res->ai_addr),
				       num_offset))
			goto bad_mask;
		/* If this is a ::0/0 mask - set the flag. */
		if (
		    (!strcmp(nodename, "::0")
		     || (!strcmp(nodename, "::")) 
		     || !strcmp(nodename, "0::0"))
		    && !num_offset
		    )
			ipv6_default_set = 1;
		owp_netmask2class_store(res->ai_addr, num_offset, 
					res->ai_family, class, id2class_hash);
		break;
#endif
	default:
		goto bad_family;
	}

	free(netmask);
	free(class);
	owp_buf_free(&buf);

	return OWP_OK;

 bad_family:
	free(netmask); free(class);
	OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
		 "FATAL: %s: line %lu: bad protocol family.",
		 filename, err_linenum);
	owp_buf_free(&buf);
	return OWP_ERR;

 bad_mask:
	owp_buf_free(&buf);
	free(netmask); free(class);
	OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
		 "FATAL: %s: line %lu: bad netmask.",
		 filename, err_linenum);
	return OWP_ERR;

 malloc_err:
	owp_buf_free(&buf);
	OWPError(ctx, OWPErrFATAL, errno, 
		 "FATAL: get_ip2class_line: reading file %s: malloc failed",
		 filename);
	return OWP_ERR;

 syntax_err:
	owp_buf_free(&buf);
	OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
	  "FATAL: get_ip2class_line: reading file %s: syntax error in line %u",
		 filename, err_linenum);
	return OWP_ERR;

 save_err:
	owp_buf_free(&buf);
	OWPError(ctx, OWPErrFATAL, errno,
		 "FATAL: error saving char in a buffer");
	return OWP_ERR;
	
 got_eof:
	owp_buf_free(&buf);
	if (ferror(fp)) {
		OWPError(ctx, OWPErrFATAL, errno,
			 "FATAL: reading error");
		return OWP_ERR;
	}
	return OWP_EOF;
}

/*
** Read the file containing the mapping of IP netmasks to classes,
** and save the key/value data in the given hash. Returns 0 on success,
** and -1 on failure.
*/
static int
owp_read_ip2class(OWPContext ctx,
		    const char *id2class, 
		    owp_policy_data *policy)
{
	FILE *fp;
	int t;

	if ( (fp = fopen(id2class, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: fopen %s for reading", id2class);
		return -1;
	}

	linenum = 1;
	new_line = 1;
	filename = (char *)id2class;

	while ((t = get_ip2class_line(ctx, fp, policy)) != OWP_EOF) {
		switch (t) {
		case OWP_OK:
			continue;
			/* UNREACHED */
		case OWP_ERR:
			return OWP_ERR;
			/* UNREACHED */
		default:              /* cannot happen */
			OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
				 "FATAL: internal error.");
			return OWP_ERR;
			/* UNREACHED */
		}
	}
	return 0;
}

/*
** Look up the class corresponding to a given KID.
** <len> typically should be strlen(kid) + 1.
*/
char *
owp_kid2class(const char *kid, int len, owp_policy_data* policy)
{
	I2table hash;
	I2datum *key, *val;
	owp_kid_data	*kdata;
	
	assert(kid); assert(policy);
	hash = policy->passwd;
	key = owp_raw2datum(kid, len);
	if(!key)
		return NULL;
	val = I2hash_fetch(hash, key);
	owp_datum_free(key);

	if(val){
		kdata = val->dptr;
		if(strlen(kdata->class))
			return kdata->class;
	}

	return NULL;
}

/*
** Look up the 32-byte hex-encoded password for a given KID.
** <len> typically should be strlen(kid) + 1.
*/
char *
owp_kid2passwd(const char *kid, int len, owp_policy_data* policy)
{
	I2table hash;
	I2datum *key, *val;
	
	if(!kid || !policy)
		return NULL;

	hash = policy->passwd;
	if(!hash)
		return NULL;
	key = owp_raw2datum(kid, len);
	if(!key)
		return NULL;
	val = I2hash_fetch(hash, key);

	owp_datum_free(key);
	return val? ((owp_kid_data *)(val->dptr))->passwd : NULL;
}

/*
** Given IPv4 or IPv6 address (the offset field is ignored)
** return the tightest class containing it (i.e. the class
** corresponding to the netmask with the largest offset).
** If no such class is found, NULL is returned.
*/
char *
owp_netmask2class(owp_access_netmask *netmask, owp_policy_data* policy)
{
	I2datum *key, *val;
	I2table hash;
	u_int32_t mask_template  = 0xFFFFFFFF;
	int offset;
	owp_access_netmask* cur_mask;

	if(!netmask || !policy)
		return NULL;

	if (!(cur_mask = malloc(sizeof(*cur_mask)))) {
		return NULL;
	}
	memset(cur_mask, 0, sizeof(*cur_mask));

	cur_mask->af = netmask->af;
	hash = policy->ip2class;
	switch (netmask->af) {
	case AF_INET:
		memset(cur_mask->addr6, 0, 16);
		for (offset = 32; offset >= 0; offset--){
			/* Prepare the netmask with the given offset. */
			int bits = 32 - offset;
			cur_mask->addr4 = (offset == 0)? 0 :
				((mask_template>>bits)<<bits) & netmask->addr4;
			cur_mask->offset = offset;

			key = owp_netmask2datum(cur_mask);
			if(!key)
				return NULL;
			val = I2hash_fetch(hash, key);
			free(key);
			if(val)
				return val->dptr;
		}
		break;
	case AF_INET6:
#ifdef AF_INET6
#ifdef ACCESS_DEBUG
		fprintf(stderr, "Original mask is:\n");
		owp_print_strnet(netmask, stderr);
#endif
		/* Prepare the address part of the mask */
		cur_mask->addr4 = 0;
		memcpy(cur_mask->addr6, netmask->addr6, 16);

		for (offset = 128; offset >= 0; offset--){
			u_int8_t nbytes, nbits, *ptr;
			int i;
			nbytes = offset/8;
			nbits = offset%8;
			ptr = (cur_mask->addr6) + nbytes;
			
			if (nbits){ /* The last (8-nbits) bits must be zero. */
				*ptr &= ~(((u_int8_t)1 << (8 - nbits)) - 1);
				nbytes++;
				ptr++;
			}
	
			/* Make sure all subsequent bytes are zero. */
			for (i = 0; i < 16 - nbytes; i++, ptr++)
				*ptr = (u_int8_t)0; 

			cur_mask->offset = offset;
			key = owp_netmask2datum(cur_mask);
			if(!key)
				return NULL;
#ifdef ACCESS_DEBUG
			fprintf(stderr, "netmask2datum, looking for mask\n");
			owp_print_netmask(key, stderr);
#endif
			val = I2hash_fetch(hash, key);
			free(key);
			if(val)
				return val->dptr;
		}
		break;
#endif /* AF_INET6 */
	default:
		break;
	}
	return NULL;
}

/*
** Given a sockaddr struct, return the tightest class containing 
** its IP address (i.e. corresponding to the netmask with the largest offset).
** If no such class is found, NULL is returned.
*/
char *
owp_sockaddr2class(struct sockaddr *addr, owp_policy_data* policy)
{
	owp_access_netmask mask;

	if(!addr || !policy)
		return NULL;

	mask.offset = (u_int8_t)0;

	switch (addr->sa_family) {
	case AF_INET:
		mask.addr4 
			= ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr);
		memset(mask.addr6, 0, 16);
		mask.af = AF_INET;
		return owp_netmask2class(&mask, policy);
		/* UNREACHED */
#ifdef AF_INET6
	case AF_INET6:
		/* Prepare the address part of the mask */
		mask.addr4 = 0;
		memcpy(mask.addr6, 
		       ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr, 16);
		mask.af = AF_INET6;
		return owp_netmask2class(&mask, policy);
		/* UNREACHED */
#endif /* AF_INET6 */
	default:
		break;
	}
	return NULL;
}

/*!
** Read the file given by the path <passwd_file>, parse it and save 
** results in <hash>. <password file> assigns to each KID its OWAMP 
** shared secret and usage class. Its format is: lines of the form 

** <KID> <shared_secret> <class>

** where <KID> is an ASCII string of length at most 16,
** <shared_secret> is a sequence of hex digits of length 32
** (corresponding to 16 bytes of binary data), and <class> is
** the usage class.
*/
static int
owp_read_passwd_file(OWPContext ctx, 
		     const char *passwd_file, 
		     owp_policy_data *policy)
{
	char line[OWPMAX_LINE];
	char *kid, *secret, *class;
	FILE *fp;
	owp_kid_data *kid_data;
	I2datum *key, *val;
	I2table hash = policy->passwd;

	if ( (fp = fopen(passwd_file, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, errno, 
			 "FATAL: fopen %s for reading", passwd_file);
		return -1;
	}

	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		line[strlen(line) - 1] = '\0';
		if (line[0] == '#') 
			continue;

		kid = strtok(line, " \t");
		if (!kid)
			continue;
		if (strlen(kid) > OWP_KID_LEN){
			kid[OWP_KID_LEN] = '\0';
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "warning: KID %s too long - truncating",
				 " to %d characters\n", kid, OWP_KID_LEN);
		}

		secret = strtok(NULL, " \t");
		if (!secret)
			continue;

		kid_data = (owp_kid_data *)malloc(sizeof(*kid_data));
		if (!kid_data) {
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "FATAL: malloc() failed");
			return -1;
		}
		memset(kid_data, 0, sizeof(*kid_data));

		strncpy(kid_data->passwd, secret, OWP_HEX_PASSWD_LEN);

		/* truncate if necessary */
		kid_data->passwd[OWP_HEX_PASSWD_LEN] = '\0';

		if( (class = strtok(NULL, " \t"))){
			strncpy(kid_data->class, class, OWP_MAX_CLASS_LEN);
			kid_data->class[OWP_MAX_CLASS_LEN] = '\0';
		}
		else
			kid_data->class[0] = '\0';

		/*
		 * If we are doing "full" policy and not just passwd
		 * Check if the class has been assigned limits.
		 */
		if((policy->class2node)&& (!class_has_limits(kid_data->class,
								policy))){
			OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
				"FATAL: class %s has not been assigned limits",
				 class); 
			return -1;
		}

		/* Now save the key/class pair in a hash. */
		if (!(key = owp_raw2datum(kid, strlen(kid) + 1))
		    || !(val = owp_raw2datum(kid_data, sizeof(*kid_data)))){
			OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
				 "FATAL: failure saving KID data in a hash");
			return -1;
		}

		if (I2hash_store(hash, key, val) != 0)
			continue;
	}

	if (fclose(fp) < 0){
		OWPError(ctx, OWPErrFATAL, errno, 
			 "FATAL: fclose(%d) failed\n", fp);
		return -1;
	}

	return 0;
}

/* 
** This function initializes policy database and returns the
** resulting handle (to be passed to any policy checks) on success,
** or NULL on error. It expects fulls paths to configuration files 
** (to be specified by application). Return policy handle on success,
** or NULL on failure.
*/
owp_policy_data *
OWPPolicyInit(
	   OWPContext ctx, 
	   char *ip2class_file,
	   char *class2limits_file,
	   char *passwd_file,
	   OWPErrSeverity *err_ret
	   )
{
	owp_policy_data *ret;
	
	if(!passwd_file)
		return NULL;

	ret = (void *)malloc(sizeof(*ret));
	if(!ret){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%M");
		return NULL;
	}
	memset(ret,0,sizeof(*ret));

	if(ip2class_file && class2limits_file){
		/* Initialize the hashes. */
		ret->ip2class = I2hash_init(ctx, 0, owp_cmp_netmask_match, NULL, 
					    owp_print_ip2class_binding);
		if(ret->ip2class == NULL){
			OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
				 "could not init ip2class hash");
			goto error;
		}

		ret->class2node = I2hash_init(ctx, 0, NULL, NULL, 
					      owp_print_class2node_binding);
		if (ret->class2node == NULL){
			OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
				 "could not init class2node hash");
			goto error;
		}

		if((owp_read_class2limits2(ctx, class2limits_file, ret) ==
								OWP_ERR) ||
			(owp_read_ip2class(ctx,ip2class_file, ret) == OWP_ERR))
			goto error;
	}

	ret->passwd = I2hash_init(ctx, 0, NULL, NULL, 
						  owp_print_kid2data_binding);
	if (ret->passwd == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
						 "could not init passwd hash");
		goto error;
	}
		
	if(owp_read_passwd_file(ctx, passwd_file, ret) == OWP_ERR)
			goto error;
	
	*err_ret = OWPErrOK;
	return ret;

error:
	*err_ret = OWPErrFATAL;
	if(ret){
		if(ret->ip2class)
			I2hash_close(ret->ip2class);
		if(ret->class2node)
			I2hash_close(ret->class2node);
		if(ret->passwd)
			I2hash_close(ret->passwd);
		free(ret);
	}
	return NULL;
}

unsigned long
OWAMPGetBandwidth(owp_lim *lim){
	return lim->values[0];
}

unsigned long
OWAMPGetSpace(owp_lim *lim){
	return lim->values[1];
}
