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
**	File:		access.c
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
		long num_offset, nbytes, nbits;
		u_int32_t addr;
		u_int8_t *ptr;
		int i;
		int bad_mask = 0;
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

		if (!slash) { 
			if (getaddrinfo(nodename, NULL, &hints, &res) < 0) {
			
			/* id is KID */

			/*
			  TODO: turn KID into a key, and add to the hash
			*/

			return 0;

			}
			
			/* Otherwise this is an IP address. */
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
			
		} else { /* The IP address case. */
			nodename = strtok_r(id, "/", &brkb);
			if (!nodename)           /* paranoia */
				continue;
			
			if (getaddrinfo(nodename, NULL, &hints, &res) < 0) {
			    OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, "Warning: reading config file %s...\nLine %lu: bad IP address\n", id2class, line_num);
			    continue;
			}
			
			/* check if there is CIDR offset */
			offset = strtok_r(NULL, "/", &brkb);
			
			if (!offset){
				OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				  "Warning: reading config file %s...\nLine %lu: netmask must have a numeric offset after the slash.\n", id2class, line_num); 
				continue;
			}
			
			num_offset = strtol(offset, NULL, 10);
			if (num_offset == 0 && strncmp(offset, "0", 2)) {
				OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
					 "Warning: reading config file %s...\nLine %lu: bad numeric offset after the slash.\n", id2class, line_num); 
				continue;
			}
		}

		/* At this point both addrinfo and num_offset are set. 
		   First check if netmask is correctly specified. */

		switch (res->ai_family) {
		case AF_INET:
			addr = 
		  ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
			
			if ((num_offset > 32) || (num_offset < 0)) {
				OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
			     "Warning: reading config file %s...\nLine %lu: numeric offset for IPv4 address must be between 0 and 32.\n", id2class, line_num); 
				continue;
			}
			
			if (!num_offset) {
				if (addr){
				  OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				    "Warning: reading config file %s...\nLine %lu: numeric offset 0 requires network address to be 0.\n", id2class, line_num); 
					continue;
					
				} else {
					/* 
					   TODO: handle 0/0 case here 
					*/
					continue;
				}
			}
			/* Now 1 <= num_offset <= 32. */
			if (addr & (((unsigned long)1<<(32-num_offset)) - 1)) {
				OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				    "Warning: reading config file %s...\nLine %lu: bad netmask.\n", id2class, line_num); 
				continue;
			}
			/* (addr, num_offset) pair is sane. */
			/* 
			   TODO: process it here
			*/
			
			continue;
			break;
		case AF_INET6:
			nbytes = num_offset / 8;
			nbits = num_offset%8;
			ptr = 
	  (((struct sockaddr_in6 *)res->ai_addr)->sin6_addr.s6_addr) + nbytes;
			if (nbits){
				if (*ptr++ 
				  && (((unsigned long)1 << (8 - nbits)) - 1)) {
				/*
				  bad netmask
				*/

					continue;
				}
				
				nbytes++;
			}

			/* Make sure all subsequent bytes are zero. */
			for (i = 0; i < 16 - nbytes; i++) {
				if (*ptr++) {
					/*
					  bad netmask
					*/
					bad_mask++;
					break;
				}
				
			}

			if (bad_mask)
				continue;
			
			/* If got this far: (addr, num_offset) pair is sane. */
			/* 
			   TODO: process it here
			*/
					
			continue;
			break;
			

		default:
			break;
		} /* switch */
		
		
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
** or NULL on error.
** It expects fulls paths to configuration files (to be specified
** by application).
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
