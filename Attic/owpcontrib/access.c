/*! \file access.c */

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
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Wed Mar 20 11:10:33  2002
**
**	Description:	
**	This file contains the OWAMP access policy functions.
*/

#ifndef OWP_ACCESS_H
#define OWP_ACCESS_H

#include <owamp/owamp.h>
#include "access.h"
#include "rijndael-api-fst.h"

#define DEBUG   0

struct subnet {
	u_int32_t address;
	u_int8_t offset;
};

u_int32_t
OWAMPGetBandwidth(OWAMPLimits * lim){
	return lim->bandwidth;
}

u_int32_t
OWAMPGetSpace(OWAMPLimits * lim){
	return lim->space;
}

u_int32_t
OWAMPGetNumSessions(OWAMPLimits * lim){
	return lim->test_sessions;
}

static void
OWAMPSetBandwidth(OWAMPLimits * lim, u_int32_t bw){
	lim->bandwidth = bw;
}

static void
OWAMPSetSpace(OWAMPLimits * lim, u_int32_t space){
	lim->space = space;
}

static void
OWAMPSetNumSessions(OWAMPLimits * lim, u_int32_t ns){
	lim->test_sessions = ns;
}

/*
** Turn an IP address in dotted decimal into
** a number.  This function also works  for
** partial addresses. Note that it basically
** views 255.255.255.255 as an illegal address.
*/

unsigned long
owamp_numberize(const char *addr)
{
        unsigned long sin_addr;
        int retval;

        retval = inet_pton(AF_INET, addr, &sin_addr);

        /* invalid address or error in inet_pton() */
        if(retval == 0 || retval == -1)
                return (unsigned long)(-1); 

        return ntohl(sin_addr); 
}

/*
** Converts an IP address into dotted decimal
** format.  Note that this function cannot be
** used twice in one instruction (e.g. printf
** ("%s%s",denumberize(x),denumberize(y)));
** because the return value is static.
*/

char *
owamp_denumberize(unsigned long addr)
{
	static char buffer[INET_ADDRSTRLEN];
	unsigned long addr_nl = htonl(addr);
	
	if(!inet_ntop(AF_INET, &addr_nl, buffer, sizeof(buffer)))
		return NULL;
	return buffer;
}


/*
** Compress subnet data into a subnet struct, and then datum,
** to be used as a database key.
*/

static I2datum *
subnet2datum(u_int32_t address, u_int8_t offset)
{
	I2datum *ret;

	if ( (ret = (void *)malloc(sizeof(I2datum))) == NULL) 
		return NULL;    
	if ( (ret->dptr = (void *)malloc(sizeof(struct subnet))) == NULL)     
		return NULL; 

	((struct subnet *)(ret->dptr))->address = address;
	((struct subnet *)(ret->dptr))->offset = offset;
	ret->dsize = sizeof(struct subnet);
	return ret;
}
/*
** Determines whether the given nework/offset combination
** is valid. Returns 1 if yes, and 0 otherwise.
*/

static int
is_valid_network(u_int32_t addr, u_int8_t offset)
{
	u_int32_t off_mask;

	if (offset > 32){
		fprintf(stderr, "offset > 32\n");
		return 0;
	}
	if ((offset == 0) && addr)
		return 1;
	off_mask = ((1<<(32-offset)) - 1);
	return (addr & off_mask)? 0 : 1; 
}

/*!
** This function takes a string of the form <address/netmask>
** where address is a dot-separated IP address, and netmask
** is a mask offset. The address and offset are returned through
** the last 2 argument pointers. The function returns 0 on success, 
** and -1 on failure.
*/

static int
owamp_parse_mask(const char *text, u_int32_t *addr, u_int8_t *off)
{
	
	char *addr_str = NULL;
	char *mask_str = NULL;

	if((addr_str = strdup(text)) == NULL)
		return -1;

	if( strchr(addr_str, '/'))
	{
		 /* IP and offset */
		addr_str = strtok(addr_str, "/");
		mask_str = strtok(NULL, "/");
		
		if(!mask_str)
			return -1;
		
		if((*addr = owamp_numberize(addr_str)) == (unsigned long)(-1))
			return -1;
	
		*off = atoi(mask_str);
		if(*off > 32)		  /* bad CIDR offset */
			return -1;

	} else {
		/* regular IP address */
		if((*addr = owamp_numberize(addr_str)) == (unsigned long)(-1))
			return -1;
		*off = 0;
	};
	
	if (!is_valid_network(*addr, *off))
		return -1;
	
	free(addr_str); 
	return 0;
}

/*
** This function fills out a datum structure with the given string.
*/

I2datum*
str2datum(const char *bytes, size_t len)
{
	I2datum *dat;

	if ( (dat = (void *)malloc(sizeof(I2datum))) == NULL)
		return NULL;
	if ( (dat->dptr = (void *)malloc(len)) == NULL) 
		return NULL;

	bcopy(bytes, dat->dptr, len);
	dat->dsize = len;
	return dat;
}

I2datum*
limits2datum(const OWAMPLimits * lim)
{
	I2datum* dat;
	size_t len = sizeof(*lim);

	if ( (dat = (void *)malloc(sizeof(I2datum))) == NULL)
		return NULL;
	if ( (dat->dptr = (void *)malloc(len)) == NULL) 
		return NULL;

	/* Later improve to: */
	/* dat->dptr = (char *)lim; */

	bcopy(lim, dat->dptr, len);
	dat->dsize = len;

	return dat;
}

u_int32_t
owp_get_ip(const I2datum * dat)
{
	return *(u_int32_t*)(dat->dptr);
}

u_int8_t
owp_get_offset(const I2datum * dat)
{
	return *(u_int8_t *)(((u_int8_t*)(dat->dptr)) + 4);
}

/*!
** This function reads the configuration file given by the path <ip2class>, 
** processes it and saves the results in <ip2class_hash>. 
** The format of the file is as follows: lines of the form 

** <network_address/offset> <class>

** where <network_address> is a dot-separated ASCII network address,
** <offset> is a CIDR style offset (integer from 0 to 32), and <class>
** is the (ASCII) name of the corresponding user class.
*/
void
owamp_read_ip2class(OWPContext ctx,
		    const char *ip2class, 
		    I2table ip2class_hash)
{
	char line[MAX_LINE], mask[MAX_LINE], class[MAX_LINE];
	FILE *fp;
	u_int32_t addr;
	u_int8_t off; 
	size_t len;
	
	I2datum *key, *val;

	if ( (fp = fopen(ip2class, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
			 "FATAL: fopen %s for reading", ip2class);
		exit(1);
	}

	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		int tmp;
			
		if (line[0] == '#') 
			continue;
		if (sscanf(line, "%s%s", mask, class) != 2) 
			continue;
		if ((tmp = owamp_parse_mask(mask, &addr, &off)) != 0){
			OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "Warning: bad network %s.", mask);
			continue;
		}
		
		/* Now save the key/class pair in a hash. */
		if ( (key = subnet2datum(addr, off)) == NULL)
			continue;

		len = strlen(class) + 1;
		if ( (val = str2datum(class, len)) == NULL )
			continue;

		if (I2hash_store(ip2class_hash, key, val) != 0)
			continue;
	}

	if (fclose(fp) < 0)
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "Warning: fclose %d. failed", fp);

	/* Assign OWP_DEFAULT_OPEN_CLASS for the widest mask. */
	if ( (key = subnet2datum(0, 0)) == NULL)
		goto CLOSE;
	len = strlen(OWP_DEFAULT_OPEN_CLASS) + 1;
	if ( (val = str2datum(OWP_DEFAULT_OPEN_CLASS, len)) == NULL)
		goto CLOSE;
	if (I2hash_store(ip2class_hash, key, val) != 0)
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
			 "WARNING: I2hash_store failed to insert all key");
 CLOSE:
	return;
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
read_passwd_file(OWPContext ctx, const char *passwd_file, I2table hash)
{
	char line[MAX_LINE];
	char *kid, *secret;
	FILE *fp;
	size_t len;
	
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
		len = strlen(kid) + 1;
		if ( (key = str2datum(kid, len)) == NULL)
			continue;

		len = strlen(secret) + 1;
		if ( (val = str2datum(secret, len)) == NULL )
			continue;

		if (I2hash_store(hash, key, val) != 0)
			continue;
	}

	if (fclose(fp) < 0)
		OWPError(ctx, OWPErrWARNING, errno, 
			 "Warning: fclose(%d)", fp);	;
}

char *
ipaddr2class(u_int32_t ip, I2table ip2class_hash)
{
	int offset;
	I2datum *key_dat_ptr, *val_dat;
	u_int32_t mask_template = 0xFFFFFFFF;
	
	for(offset=32; offset>0; offset--){
		int bits = 32 - offset;
		u_int32_t mask = (mask_template>>bits)<<bits;
		key_dat_ptr = subnet2datum(ip & mask, offset);
		val_dat = I2hash_fetch(ip2class_hash, key_dat_ptr);
		if (val_dat->dptr)
			return val_dat->dptr;
	}
	
	key_dat_ptr = subnet2datum(ip, 0);
	val_dat = I2hash_fetch(ip2class_hash, key_dat_ptr);
	if (val_dat->dptr)
		return val_dat->dptr;

	return OWP_DEFAULT_OPEN_CLASS;
}

/*! 
** This function reads the configuration file given by the path <ip2class>, 
** parses it and saves the results in <hash>. The format of <ip2class> is:
** lines of the form

** <class_name> [<param1>=<value1>] [<param2>=<value2>] ...

** where <class_name> is a user class name, each <param> is
** one of the following: "test_sessions", "bandwidth" or "space".
** Each <value> is a non-negative integer. 

** For each class, "test_sessions" is the maximal number of Test sessions
** that a single Control session is allowed to run altogether. 
** Moreover, "bandwidth" (bytes/sec) and "space" (bytes) limit 
** the resource consumption of each individual Test session.
*/

void
owamp_read_class2limits(OWPContext ctx, const char *class2limits, I2table hash)
{
	char line[MAX_LINE];
	char *key, *value, *class, *key_value, *brkt, *brkb;
	FILE *fp;
	long numval;
	size_t len;
	
	if ( (fp = fopen(class2limits, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, errno, 
			 "FATAL: fopen %s for reading", class2limits);
		exit(1);
	}

	fprintf(stderr, "\n");
	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		OWAMPLimits limits;

		if (line[0] == '#')
			continue;
		line[strlen(line) - 1] = '\0';
		class = strtok_r(line, " \t", &brkt);
		if (!class)
			continue;

		printf("DEBUG: class = %s\n", class);
		for (key_value=strtok_r(NULL, " \t", &brkt);
		     key_value;
		     key_value = strtok_r(NULL, " \t", &brkt)){
			key = strtok_r(key_value, "=", &brkb);
			if (!key)  
				continue; /* inner loop */
			value = strtok_r(NULL, "=", &brkb);
			if (!value)
				continue;
			numval = strtol(value, NULL, 10); /* XXX */
			
			/* Put the key/val pair in the limits struct */
			if (strcmp(key, "bandwidth") == 0)
				OWAMPSetBandwidth(&limits, numval);
			else if (strcmp(key, "space") == 0)
				OWAMPSetSpace(&limits, numval);
			else if (strcmp(key, "num_sessions") == 0)
				OWAMPSetNumSessions(&limits, numval);
			printf("DEBUG: key = %s value =  %ld\n", key, numval);
			} 
		/* Now save the limits structure in the hash. */
		len = strlen(class) + 1;
		I2hash_store(hash, str2datum(class, len), limits2datum(&limits));
	}
}

/* 
** This function initializes policy database and returns the
** resulting handle (to be passed to any policy checks) on success,
** or NULL on error.
** It expects fulls paths to configuration files (to be specified
** by application).
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
	owamp_read_ip2class(ctx, ip2class_file, ret->ip2class); 
	owamp_read_class2limits(ctx, class2limits_file, ret->class2limits);
	read_passwd_file(ctx, passwd_file, ret->passwd);

	return ret;
}

#endif
