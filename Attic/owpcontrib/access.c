#include "access.h"

#define MAX_LINE 1024
#define DB_KEY_LEN 128

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;
const char *DefaultIPtoClassFile = DEFAULT_IP_TO_CLASS_FILE;
char *IPtoClassFile = NULL;
const char *DefaultClassToLimitsFile = DEFAULT_CLASS_TO_LIMITS_FILE;
char *ClassToLimitsFile = NULL;

static void usage(void);

static void
usage()
{
	return;
}

/*
** This function parses command line options.
*/

static void
parse_options(int argc, char *argv[])
{
    extern char *optarg;
    int c;
    ConfigFile = strdup(DefaultConfigFile);

    while ((c = getopt(argc, argv, "f:h")) != -1) {
	switch (c) {
	case 'f':
		ConfigFile = strdup(optarg);
		break;
	case 'h':
		usage();
		break;
	default:
		usage();
		break;
	}
    }
}


/*
** Turn an IP address in dotted decimal into
** a number.  This function also works  for
** partial addresses.
*/

unsigned long
numberize(const char *addr)
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

const char *
denumberize(unsigned long addr)
{
	static char buffer[INET_ADDRSTRLEN];
	unsigned long addr_nl = htonl(addr);
	
	if(!inet_ntop(AF_INET, &addr_nl, buffer, sizeof(buffer)))
		return NULL;
	return buffer;
}

/*
** This function takes a string of the form <address/netmask>
** where address is a dot-separated IP address, and netmask
** is a mask offset. On success it returns the key string of the form
** "netmask_lower_bound/offset" which uniquely identifies the
** netmask. Otherwise it returns NULL.
*/

char *
owamp_parse_mask(const char *text)
{
	char *addr_str = NULL;
	char *mask_str = NULL;
	unsigned int lb, off;
	unsigned long addr, mask, host_bits;
	char *key;

	key = (void *)malloc(DB_KEY_LEN);
	if (!key) return NULL;

	if((addr_str = strdup(text)) == NULL)
		return NULL;

	if( strchr(addr_str, '/'))
	{
		 /* IP and offset */
		addr_str = strtok(addr_str, "/");
		mask_str = strtok(NULL, "/");
		
		if(!mask_str)
			return NULL;
		
		if((addr = numberize(addr_str)) == -1)
			return NULL;
	
		/* CIDR */
		off = atoi(mask_str);
		
		if(off > 32)
			{
				/* bad CIDR offset */
				return NULL;
			};
		
		host_bits = 32 - off;
		lb = (addr >> host_bits) << host_bits;
	}
	else
	{
		/* regular IP address */
		if((addr = numberize(addr_str)) == -1)
			return NULL;
		lb = addr;
		off = 0;
	}

	snprintf(key, DB_KEY_LEN, "%lu/%lu", lb, off);
	free(addr_str); 
	return key;
}

int
datumify(const char *str, datum *dat)
{
	unsigned int len; 
	
	len = strlen(str) + 1;
	if ( (dat->dptr = (void *)malloc(len)) == NULL) {
		fprintf(stderr, "warning: malloc failed in datumify\n");
		return -1;
	}

	strcpy(dat->dptr, str);
	dat->dsize = len; /* counts the '\0' byte */
	return 0;
}

/* 
** This function reads the configuration file given by the path ip2class, 
** processes it and saves the results in Berkeley DB file, with the
** same base name, and extension ".db". The database can be printed by the
** companion function print_dbm().
*/

void
owamp_read_config(const char *ip2class)
{
	char line[MAX_LINE], mask[MAX_LINE], class[MAX_LINE];
	char err_msg[1024];
	char *key;
	FILE *fp;
	
	DBM *dbm;
	datum key_dat, val_dat;

	/* Open the database file for writing. */
	if ( (dbm = dbm_open(ip2class, O_CREAT|O_RDWR, 0660)) == NULL){
		perror("dbopen dbtest for read-write");
		exit(1);
	}

	if ( (fp = fopen(ip2class, "r")) == NULL){
		snprintf(err_msg, sizeof(err_msg),"fopen %s for reading", 
			ConfigFile);
		perror(err_msg);
		exit(1);
	}

	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		if (sscanf(line, "%s%s", mask, class) != 2) continue;
		if ( (key = owamp_parse_mask(mask)) == NULL) 
			continue;

		/* Now save the key/class pair in a hash. */
		if ( datumify(key, &key_dat) < 0 ) continue;
		if ( datumify(class, &val_dat) < 0 ) continue;
		if ( dbm_store(dbm, key_dat, val_dat, DBM_REPLACE) != 0){
			fprintf(stderr, 
				"dbm_store failed. key = %s, val = %s\n",
				key_dat.dptr, val_dat.dptr);
			continue;
		}
	}

	dbm_close(dbm);
	return;
}


/*
** This function prints out the database, given by the argument base.
** It is used mostly for debugging.
*/

void
print_dbm(char *base)
{
	DBM *dbm;
	datum key, val;

	dbm = dbm_open(base, O_RDWR | O_CREAT, 0660);
	for(key = dbm_firstkey(dbm); key.dptr != NULL; key = dbm_nextkey(dbm)){
		val = dbm_fetch(dbm, key);
		assert(val.dptr);
		fprintf(stderr, "the value of key %s is = %s\n",
			key.dptr, val.dptr);
	}
	dbm_close(dbm);
}

int
main(int argc, char *argv[])
{
	parse_options(argc, argv);
	if (!IPtoClassFile) {IPtoClassFile = strdup(DefaultIPtoClassFile);};
	owamp_read_config(IPtoClassFile);
	print_dbm(IPtoClassFile);
	exit(0);
}
