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

#ifndef OWP_ACCESS2_H
#define OWP_ACCESS2_H

#include <ctype.h>
#include <owamp/owamp.h>
#include "./access.h"

/*
** This function fills out a datum structure with the given string.
** When saving a string, <len> typically should be strlen(bytes) + 1.
*/
I2datum*
owp_raw2datum(const void *bytes, size_t len)
{
	I2datum *dat;

	if ( (dat = (void *)malloc(sizeof(*dat))) == NULL){
		perror("malloc");
		return NULL;
	}
	if ( (dat->dptr = (void *)malloc(len)) == NULL) {
		perror("malloc");
		return NULL;
	}		

	bcopy(bytes, dat->dptr, len);
	dat->dsize = len;
	return dat;
}

/*
** Check if a given IPv6 netmask is legal. Return 1 if yes, 0 otherwise.
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
	ptr = (addr->sin6_addr.s6_addr) + nbytes;

	if (nbits){     /* The last (8-nbits) bits must be zero. */
		if (*ptr++ && (((u_int8_t)1 << (8 - nbits)) - 1))
			return 0;
		nbytes++;
	}
	
	/* Make sure all subsequent bytes are zero. */
	for (i = 0; i < 16 - nbytes; i++) {
		if (*ptr++) 
			return 0;
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
		perror("malloc");
		return NULL;
	}
	
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
** order).
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

	key = (void *)malloc(sizeof(*key));
	if (!key) {
		perror("malloc");
		return -1;
		
	}
	key->dptr = (void *)malloc(sizeof(owp_access_netmask));
	ptr = (owp_access_netmask *)(key->dptr);
	ptr->offset = num_offset;
	ptr->af = family;
	key->dsize = sizeof(owp_access_netmask);

	switch (family) {
	case AF_INET:
		ptr->addr4 = *(u_int32_t *)addr;
		memset(ptr->addr6, 0, 16);
		break;
	case AF_INET6:
		ptr->addr4 = (u_int32_t)0;
		memcpy(ptr->addr6, 
		       ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr, 16);
		break;
	default:
		return 0;
		break;
	}
	val = owp_raw2datum(class, strlen(class) + 1);
	I2hash_store(id2class_hash, key, val);
	return 0;
}

/*
** Read the file containing the mapping of IP netmasks to classes,
** Then save the data in the given hash.
*/
static int
owp_read_ip2class(OWPContext ctx,
		    const char *id2class, 
		    I2table id2class_hash)
{
	FILE *fp;
	char line[MAX_LINE];
	unsigned long line_num = 0;

	printf("DEBUG: reading file %s...\n", id2class);

	if ( (fp = fopen(id2class, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: fopen %s for reading", id2class);
		return -1;
	}
	while (fgets(line, sizeof(line), fp) != NULL) {
		struct addrinfo hints, *res;
		u_int8_t num_offset;
		u_int32_t addr;
		char *brkt, *brkb, *netmask, *class, 
			*slash, *nodename, *offset;

		line_num++;
		if (line[0] == '#')
			continue;
		line[strlen(line) - 1] = '\0';

		netmask = strtok_r(line, " \t", &brkt);
		if (!netmask)             /* skip lines of whitespace */
			continue;

		class = strtok_r(NULL, " \t", &brkt);
		if (!class){
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN,
				 "warning: %s: line %lu: no classname given.",
				 id2class, line_num);
			continue;
		}
		/* Prepare the hints structure. */
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		slash = strchr(netmask, '/');

		if (!slash) { /* Single IP address. */
			if (getaddrinfo(netmask, NULL, &hints, &res) != 0)
				goto BAD_MASK;
			
			/* Assume maximum offset by default.*/
			switch (res->ai_family) {
			case AF_INET:
				num_offset = 32;
				break;
			case AF_INET6:
				num_offset = 128;
				break;
			default: 
				continue;
				break;
			}
		} else { /* The IP netmask case. */
			nodename = strtok_r(netmask, "/", &brkb);
			if (!nodename)           /* paranoia */
				continue;
			
			if (getaddrinfo(nodename, NULL, &hints, &res) < 0)
				goto BAD_MASK;
			
			/* check if there is CIDR offset */
			offset = strtok_r(NULL, "/", &brkb);
			
			if (!offset)
				goto BAD_MASK;
			
			num_offset = (u_int8_t)strtol(offset, NULL, 10);
			if (num_offset == 0 && strncmp(offset, "0", 2))
				goto BAD_MASK;
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
				goto BAD_MASK;
			owp_netmask2class_store(&addr, num_offset, 
					 res->ai_family, class, id2class_hash);
			break;
		case AF_INET6:
			if (!is_valid_netmask6(
					 (struct sockaddr_in6 *)(res->ai_addr),
					 num_offset))
				goto BAD_MASK;
		owp_netmask2class_store(res->ai_addr, num_offset, 
					res->ai_family, class, id2class_hash);
			break;
		default:
			continue; /* Should not happen. */
		}
		continue;

	BAD_MASK:
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN,
			 "warning: %s: line %lu: bad netmask.",
			 id2class, line_num);
		
	}
	return 0;
}

/*
** Look up the class corresponding to a given KID.
** <len> typically should be strlen(kid) + 1.
*/
char *
owp_kid2class(char *kid, int len, policy_data* policy)
{
	I2table hash;
	I2datum *key, *val;
	
	assert(kid); assert(policy);
	hash = policy->passwd;
	key = owp_raw2datum(kid, len);
	val = I2hash_fetch(hash, key);

	return val? val->dptr : NULL;
}


/*
** Look up the 32-byte hex-encoded password for a given KID.
** <len> typically should be strlen(kid) + 1.
*/
char *
owp_kid2passwd(const char *kid, int len, policy_data* policy)
{
	I2table hash;
	I2datum *key, *val;
	
	assert(kid); assert(policy);
	hash = policy->passwd;
	key = owp_raw2datum(kid, len);
	val = I2hash_fetch(hash, key);

	return val? ((owp_kid_data *)(val->dptr))->passwd : NULL;
}

/*
** Given IPv4 or IPv6 address (the offset field is ignored)
** return the tightest class containing it (i.e. the class
** corresponding to the netmask with the largest offset).
** If no such class is found, NULL is returned.
*/
char *
owp_netmask2class(owp_access_netmask *netmask, policy_data* policy)
{
	I2datum *key, *val;
	I2table hash;
	u_int32_t mask_template  = 0xFFFFFFFF;
	int offset;
	owp_access_netmask* cur_mask = (void *)malloc(sizeof(*cur_mask));
	if (!cur_mask) {
		perror("malloc");
		return NULL;
	}

	assert(netmask); assert(policy);
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
			val = I2hash_fetch(hash, key);
			if (val)
				return val->dptr;
		}
		break;
	case AF_INET6:
		/* Prepare the address part of the mask */
		cur_mask->addr4 = 0;
		memcpy(cur_mask->addr6, netmask->addr6, 16);

		for (offset = 128; offset >= 0; offset--){
			cur_mask->offset = offset;
			key = owp_netmask2datum(cur_mask);
			val = I2hash_fetch(hash, key);
			if (val)
				return val->dptr;
		}
		break;
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
owp_read_passwd_file(OWPContext ctx, const char *passwd_file, I2table hash)
{
	char line[MAX_LINE];
	char *kid, *secret, *class;
	FILE *fp;
	owp_kid_data *kid_data;
	
	I2datum *key, *val;

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

		strncpy(kid_data->passwd, secret, OWP_HEX_PASSWD_LEN + 1);

		/* truncate if necessary */
		kid_data->passwd[OWP_HEX_PASSWD_LEN] = '\0';

		class = strtok(NULL, " \t");
		if (!class)
			continue;
		strncpy(kid_data->class, class, OWP_MAX_CLASS_LEN + 1);
		kid_data->class[OWP_MAX_CLASS_LEN] = '\0';

		/* Now save the key/class pair in a hash. */
		key = owp_raw2datum(kid, strlen(kid) + 1);
		val = owp_raw2datum(kid_data, sizeof(*kid_data));

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
** (to be specified by application).
*/
policy_data *
PolicyInit(
	   OWPContext ctx, 
	   char *ip2class_file,
	   char *class2limits_file,
	   char *passwd_file,
	   OWPErrSeverity *err_ret
	   )
{
	policy_data *ret;
	
	ret = (void *)malloc(sizeof(*ret));
	if (ret == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, "malloc");
		return NULL;
	}

	/* Initialize the hashes. */
	ret->ip2class = I2hash_init(ctx, 0, owp_cmp_netmask_match, NULL, 
				    owp_print_ip2class_binding);
	if (ret->ip2class == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
			 "could not init ip2class hash");
		*err_ret = OWPErrFATAL;
		return ret;
	}

	ret->class2limits = I2hash_init(ctx, 0, NULL, NULL, NULL);
	if (ret->class2limits == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
			 "could not init class2limits hash");
		*err_ret = OWPErrFATAL;
		return ret;
	}

	ret->passwd = I2hash_init(ctx, 0, NULL, NULL, 
				  owp_print_kid2data_binding);
	if (ret->passwd == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
			 "could not init passwd hash");
		*err_ret = OWPErrFATAL;
		return ret;
	}
	
	/* Now read config files and save info in the hashes. */
	owp_read_ip2class(ctx, ip2class_file, ret->ip2class); 
	owp_read_passwd_file(ctx, passwd_file, ret->passwd);
	owp_read_class2limits2(ctx, class2limits_file, ret->class2limits);

	*err_ret = OWPErrOK;
	assert(ret->ip2class);
	return ret;
}

unsigned long
OWAMPGetBandwidth(owp_lim *lim){
	return lim->bandwidth;
}

unsigned long
OWAMPGetSpace(owp_lim *lim){
	return lim->space;
}

#endif
