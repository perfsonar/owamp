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

#include "../owamp/owampP.h"
#include "access.h"
#include "rijndael-api-fst.h"

#define DEBUG   0

#define SCRATCH 1

#if SCRATCH
FILE *scratch;
#endif

struct subnet {
	u_int32_t address;
	u_int8_t offset;
};

hash_ptr ip2class_hash, class2limits_hash, passwd_hash;
OWPContext ctx;

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

static u_int32_t
OWAMPSetSpace(OWAMPLimits * lim, u_int32_t space){
	lim->space = space;
}

static u_int32_t
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
                return -1; 

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

static datum *
subnet2datum(u_int32_t address, u_int8_t offset)
{
	datum *ret;

	if ( (ret = (void *)malloc(sizeof(datum))) == NULL) 
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
	unsigned long mask, host_bits;

	if((addr_str = strdup(text)) == NULL)
		return -1;

	if( strchr(addr_str, '/'))
	{
		 /* IP and offset */
		addr_str = strtok(addr_str, "/");
		mask_str = strtok(NULL, "/");
		
		if(!mask_str)
			return -1;
		
		if((*addr = owamp_numberize(addr_str)) == NULL)
			return -1;
	
		*off = atoi(mask_str);
		if(*off > 32)		  /* bad CIDR offset */
			return -1;

	} else {
		/* regular IP address */
		if((*addr = owamp_numberize(addr_str)) == NULL)
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

datum*
str2datum(const char *bytes)
{
	datum *dat;
	size_t len = strlen(bytes)+1;

	if ( (dat = (void *)malloc(sizeof(datum))) == NULL)
		return NULL;
	if ( (dat->dptr = (void *)malloc(len)) == NULL) 
		return NULL;

	bcopy(bytes, dat->dptr, len);
	dat->dsize = len;
	return dat;
}

u_int32_t
get_ip_addr(const datum * dat)
{
	return *(u_int32_t*)(dat->dptr);
}

u_int8_t
get_offset(const datum * dat)
{
	return *(u_int8_t*)((dat->dptr)+4);
}

hash_ptr
hash_init(const char *str)
{
	return (hash_ptr)dbm_open(str, O_CREAT|O_RDWR, 0660);
}

int
hash_store(hash_ptr hash, datum key, datum val, int flags)
{
	return dbm_store(hash, key, val, flags);
}

datum
hash_firstkey(hash_ptr hash)
{
	return dbm_firstkey(hash);
}

datum
hash_fetch(hash_ptr hash, datum key)
{
	return dbm_fetch(hash, key);
}

datum
hash_nextkey(hash_ptr hash)
{
	return dbm_nextkey(hash);
}

void
hash_close(hash_ptr hash)
{
	dbm_close(hash);
}

/*!
** This function reads the configuration file given by the path <ip2class>, 
** processes it and saves the results in <hash>. The format of the file
** is as follows: lines of the form 

** <network_address/offset> <class>

** where <network_address> is a dot-separated ASCII network address,
** <offset> is a CIDR style offset (integer from 0 to 32), and <class>
** is the (ASCII) name of the corresponding user class.
*/
void
owamp_read_ip2class(const char *ip2class, hash_ptr hash)
{
	char line[MAX_LINE], mask[MAX_LINE], class[MAX_LINE];
	char err_msg[1024];
	FILE *fp;
	u_int32_t addr;
	u_int8_t off; 
	
	datum *key, *val;

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

		if ( (val = str2datum(class)) == NULL )
			continue;

		if (hash_store(hash, *key, *val, DBM_REPLACE) != 0)
			continue;
	}

	if (fclose(fp) < 0)
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
				 "Warning: fclose %d. failed", fp);

	/* Assign DEFAULT_OPEN_CLASS for the widest mask. */
	if ( (key = subnet2datum(0, 0)) == NULL)
		goto CLOSE;
	if ( (val = str2datum(DEFAULT_OPEN_CLASS)) == NULL)
		goto CLOSE;
	if (hash_store(hash, *key, *val, DBM_INSERT) != 0)
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
			 "WARNING: hash_store failed to insert all key");
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
 
void
read_passwd_file(const char *passwd_file, hash_ptr hash)
{
	char line[MAX_LINE];
	char *kid, *secret;
	char err_msg[1024];
	FILE *fp;
	u_int32_t addr;
	u_int8_t off; 
	
	datum *key, *val;

	if ( (fp = fopen(passwd_file, "r")) == NULL){
		OWPError(ctx, OWPErrFATAL, OWPErrUNKNOWN, 
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
		if ( strlen(secret) != PASSWD_LEN_HEX ){
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
		   "Warning: shared_secret %s must consist of %d hex digits.", 
			 secret, PASSWD_LEN_HEX);
			continue;
		}

		/* Now save the key/class pair in a hash. */
		if ( (key = str2datum(kid)) == NULL)
			continue;

		if ( (val = str2datum(secret)) == NULL )
			continue;

		if (hash_store(hash, *key, *val, DBM_REPLACE) != 0)
			continue;
	}

	if (fclose(fp) < 0)
		OWPError(ctx, OWPErrWARNING, OWPErrUNKNOWN, 
			 "Warning: fclose(%d)", fp);	;
}

char *
ipaddr2class(u_int32_t ip)
{
	int offset;
	datum *key_dat_ptr, val_dat;
	u_int32_t mask_template = 0xFFFFFFFF;
	
	for(offset=32; offset>0; offset--){
		int bits = 32 - offset;
		u_int32_t mask = (mask_template>>bits)<<bits;
		key_dat_ptr = subnet2datum(ip & mask, offset);
		val_dat = hash_fetch(ip2class_hash, *key_dat_ptr);
		if (val_dat.dptr)
			return val_dat.dptr;
	}
	
	key_dat_ptr = subnet2datum(ip, 0);
	val_dat = hash_fetch(ip2class_hash, *key_dat_ptr);
	if (val_dat.dptr)
		return val_dat.dptr;

	return DEFAULT_OPEN_CLASS;
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
owamp_read_class2limits(const char *class2limits, hash_ptr hash)
{
	char line[MAX_LINE];
	char err_msg[1024];
	char *key, *value, *class, *key_value, *brkt, *brkb;
	FILE *fp;
	u_int32_t numval;
	
	datum key_dat, val_dat;

	if ( (fp = fopen(class2limits, "r")) == NULL){
		snprintf(err_msg, sizeof(err_msg),"fopen %s for reading", 
			class2limits);
		perror(err_msg);
		exit(1);
	}

	fprintf(stderr, "\n");
	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		OWAMPLimits limits;
		datum key_dat, val_dat;

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
			printf("DEBUG: key = %s value =  %lu\n", key, numval);
			} 
		printf("\n");                     /* DEBUG */

		/* Now save the limits structure in the hash. */
		key_dat = *(str2datum(class));
		val_dat.dptr = (char *)&limits;
		val_dat.dsize = sizeof(OWAMPLimits);
		hash_store(hash, key_dat, val_dat, DBM_REPLACE);
	}
}
