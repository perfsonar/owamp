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
** Create a datum struct out of a netmask and return a pointer.
*/
static I2datum*
netmask2datum(void *addr, long num_offset, int af)
{
	return NULL; /* XXX - TODO */
}

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
is_valid_netmask6(struct sockaddr_in6 *addr, long num_offset)
{
	int i;
	u_int8_t *ptr;
	long nbytes, nbits;

	if (num_offset < 0 || num_offset > 128)
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

int
owamp_read_id2class(OWPContext ctx,
		    const char *id2class, 
		    I2table id2class_hash)
{
	FILE *fp;
	char line[MAX_LINE];
	I2datum *key, *val;

	unsigned long line_num = 0;

	printf("DEBUG: reading file %s...\n", id2class);

	if ( (fp = fopen(id2class, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: fopen %s for reading", id2class);
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		struct addrinfo hints, *res;
		long num_offset;
		u_int32_t addr;
		int i;
		size_t len;
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
		len = strlen(class) + 1;
		val = str2datum2(class, len);

		/* Prepare the hints structure. */
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		slash = strchr(id, '/');

		if (!slash) { /* Either KID or single IP address. */
			if (getaddrinfo(nodename, NULL, &hints, &res) < 0) {
				/* id is KID */
				len = (strlen(nodename) > 8)?
					9 : strlen(nodename) + 1;
				nodename[len] = '\0';
				key = str2datum2(nodename, len);

				I2hash_store(id2class_hash, key, val);
				continue;
			}
			
			/* Otherwise this is a single IP address. */
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
			
			num_offset = strtol(offset, NULL, 10);
			if (num_offset == 0 && strncmp(offset, "0", 2))
				goto BAD_MASK;
		}

		/* At this point both addrinfo and num_offset are set. 
		   First check if netmask is correctly specified. */
		switch (res->ai_family) {
		case AF_INET:
			addr = 
		  ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);

			/* Check if (addr, offset) combination is legal. */
			if ( (num_offset > 32) 
			     || (num_offset < 0)
			     || (!num_offset && addr)
			     || (num_offset 
				 && (addr 
				     & (((u_int8_t)1<<(32-num_offset)) - 1)))
			     ) 
				goto BAD_MASK;
			break;
		case AF_INET6:
			if (!is_valid_netmask6(
					 (struct sockaddr_in6 *)(res->ai_addr),
					 num_offset))
				goto BAD_MASK;
			break;
		default:
			continue; /* Should not happen. */
		}

		/* Now netmask is known to be legal - save it in a hash. */
		key = netmask2datum(&addr, num_offset, res->ai_family);
#if 1
		if (!key)
			continue; /* XXX - fixit */
#endif
		I2hash_store(id2class_hash, key, val);
		continue;

	BAD_MASK:
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
			 "Warning: reading config file %s...\nLine %lu: bad netmask.\n", id2class, line_num); 
		continue;		
		
	} /* while */

	return 0;
}


void
read_passwd_file2(OWPContext ctx, const char *passwd_file, I2table hash)
{
	
}

void
owamp_read_class2limits2(OWPContext ctx, const char *class2limits, I2table hash)
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
	ret->ip2class = I2hash_init(ctx, 0, NULL, NULL,print_ip2class_binding);
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
