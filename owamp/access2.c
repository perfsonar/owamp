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

#include <owamp/owamp.h>
#include "access.h"

/*
** This function fills out a datum structure with the given string.
** <len> typically should be strlen(bytes) + 1.
*/
static I2datum*
str2datum2(const char *bytes, size_t len)
{
	I2datum *dat;

	if ( (dat = (void *)malloc(sizeof(I2datum))) == NULL){
		perror("malloc");
		exit(1);
	}
	if ( (dat->dptr = (void *)malloc(len)) == NULL) {
		perror("malloc");
		exit(1);
	}		

	bcopy(bytes, dat->dptr, len);
	dat->dsize = len;
	return dat;
}

/*
** Check if a given IPv6 netmask is legal. Return 1 if yes, 0 otherwise.
*/
int
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


I2datum *
I2datum_new()
{
	I2datum *ret;
	ret = (void *)malloc(sizeof(*ret));
	if (!ret) {
		perror("malloc");
		exit(1);
	}

	return ret;
}

owp_access_id *
owp_access_id_new()
{
	owp_access_id *ret;
	ret = (void *)malloc(sizeof(*ret));
	if (!ret) {
		perror("malloc");
		exit(1);
	}
	return ret;
}

void
owp_id2class_store_netmask(void *addr, 
			   u_int8_t num_offset, 
			   u_int8_t family, 
			   char *class, 
			   I2table id2class_hash)
{
	I2datum *key, *val;
	owp_access_id *ptr;

	key = I2datum_new();
	key->dptr = (void *)owp_access_id_new();
	key->dsize = sizeof(owp_access_id);

	ptr = (owp_access_id *)(key->dptr);
	memset(ptr->kid, 0, KID_LEN + 1);
	ptr->offset = num_offset;

	switch (family) {
	case AF_INET:
		ptr->addr4 = *(u_int32_t *)addr;
		memset(ptr->addr6, 0, 16);
		ptr->type = OWP_IDTYPE_IPv4;
		break;
	case AF_INET6:
		ptr->addr4 = (u_int32_t)0;
		memcpy(ptr->addr6, addr, 16);
		ptr->type = OWP_IDTYPE_IPv6;
	default:
		return;
		break;
	}
	val = str2datum2(class, strlen(class) + 1);
	I2hash_store(id2class_hash, key, val);
}

void
owp_print_id(I2datum *key)
{
	owp_access_id *ptr;

	ptr = (owp_access_id *)(key->dptr);
	
	switch (ptr->type) {
	case OWP_IDTYPE_KID:
		printf("DEBUG: KID is %s\n", ptr->kid);
		break;
	default:
		printf("DEBUG: type = %d\n", ptr->type);
		break;
	}
}

/*
** Given a string representing a KID, save it in the hash.
*/ 
void
owp_id2class_store_kid(char *kid, char *class, I2table id2class_hash)
{
	I2datum *key, *val;
	owp_access_id *ptr;

	key = I2datum_new();

	key->dptr = (void *)owp_access_id_new();
	ptr = (owp_access_id *)(key->dptr);

	ptr->addr4 = 0;
	memset(ptr->addr6, 0, 16);
	ptr->offset = (u_int8_t)0;

	strncpy(ptr->kid, kid, KID_LEN);
	ptr->kid[KID_LEN] = '\0';

	ptr->type = OWP_IDTYPE_KID;
	key->dsize = sizeof(owp_access_id);

	val = str2datum2(class, strlen(class) + 1);

#if 0
	owp_print_id(key);
#endif
	I2hash_store(id2class_hash, key, val);
}

int
owamp_read_id2class(OWPContext ctx,
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
		char *brkt, *brkb, *id, *class, *slash, *nodename, *offset;

		line_num++;
		if (line[0] == '#')
			continue;
		line[strlen(line) - 1] = '\0';

		id = strtok_r(line, " \t", &brkt);
		if (!id)             /* skip lines of whitespace */
			continue;

		class = strtok_r(NULL, " \t", &brkt);
		if (!class){
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, "Warning: reading config file %s...\nLine %lu: no classname given\n", id2class, line_num);
			continue;
		}
		/* Prepare the hints structure. */
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		slash = strchr(id, '/');

		if (!slash) { /* Either KID or single IP address. */
			if (getaddrinfo(id, NULL, &hints, &res) != 0) {
				/* id is KID */
				owp_id2class_store_kid(id, class, 
						       id2class_hash);
				continue;
			}
			
			/* Otherwise this is a single IP address. 
			 Assume maximum offset by default.*/
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
			nodename = strtok_r(id, "/", &brkb);
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
			owp_id2class_store_netmask(&addr, num_offset, 
					 res->ai_family, class, id2class_hash);
			break;
		case AF_INET6:
			if (!is_valid_netmask6(
					 (struct sockaddr_in6 *)(res->ai_addr),
					 num_offset))
				goto BAD_MASK;
			owp_id2class_store_netmask(res->ai_addr, num_offset, 
					 res->ai_family, class, id2class_hash);
			break;
		default:
			continue; /* Should not happen. */
		}
		continue;

	BAD_MASK:
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
			 "Warning: reading config file %s...\nLine %lu: bad netmask.\n", id2class, line_num); 
		continue;		
		
	} /* while */

	return 0;
}

/*!
** This function reads the file given by the path <passwd_file>,
** parses it and saves results in <hash>. <password file> contains
** the mapping from KIDs to OWAMP shared secrets. Its format is the
** following: lines of the form 

** <KID> <shared_secret>

** where <KID> is an ASCII string of length at most 16,
** and <shared_secret> is a sequence of hex digits of length 32
** (corresponding to 16 bytes of binary data).
*/

#define HEX_SECRET_LEN  32 /* number of hex digits to encode a shared secret */
 
void
read_passwd_file2(OWPContext ctx, const char *passwd_file, I2table hash)
{
	char line[MAX_LINE];
	char *kid, *secret;
	FILE *fp;
	
	I2datum *key, *val;

	if ( (fp = fopen(passwd_file, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, errno, 
			 "FATAL: fopen %s for reading", passwd_file);
		exit(1);
	}

	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		line[strlen(line) - 1] = '\0';
		if (line[0] == '#') 
			continue;

		kid = strtok(line, " \t");
		if (!kid)
			continue;
		if (strlen(kid) > KID_LEN){
			kid[KID_LEN] = '\0';
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "Warning: KID %s too long - truncating",
				 " to %d characters\n", kid, KID_LEN);
		}

		secret = strtok(NULL, " \t");
		if (!secret)
			continue;
		
		/* truncate if necessary */
		secret[HEX_SECRET_LEN] = '\0';

		/* Now save the key/class pair in a hash. */
		key = str2datum2(kid, strlen(kid) + 1);
		val = str2datum2(secret, strlen(secret) + 1);

		if (I2hash_store(hash, key, val) != 0)
			continue;
	}

	if (fclose(fp) < 0)
		OWPError(ctx, OWPErrWARNING, errno, 
			 "Warning: fclose(%d)", fp);	;
}

void
owamp_read_class2limits2(OWPContext ctx, const char *class2limits,I2table hash)
{

}

/* 
** This function initializes policy database and returns the
** resulting handle (to be passed to any policy checks) on success,
** or NULL on error. It expects fulls paths to configuration files 
** (to be specified by application).
*/

policy_data *
PolicyInit2(
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
	ret->ip2class = I2hash_init(ctx, 0, NULL, NULL,print_id2class_binding);
	if (ret->ip2class == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
			 "could not init ip2class hash");
		*err_ret = OWPErrFATAL;
		return ret;
	}

	ret->class2limits = I2hash_init(ctx, 0, NULL, NULL, 
					print_class2limits_binding);
	if (ret->class2limits == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
			 "could not init class2limits hash");
		*err_ret = OWPErrFATAL;
		return ret;
	}

	ret->passwd = I2hash_init(ctx, 0, NULL, NULL, NULL);
	if (ret->passwd == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN,
			 "could not init passwd hash");
		*err_ret = OWPErrFATAL;
		return ret;
	}
	
	/* Now read config files and save info in the hashes. */
	owamp_read_id2class(ctx, ip2class_file, ret->ip2class); 
	owamp_read_class2limits2(ctx, class2limits_file, ret->class2limits);
	read_passwd_file2(ctx, passwd_file, ret->passwd);

	return ret;
}

#endif
