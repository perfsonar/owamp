#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>
#include <math.h>
#include <fcntl.h>
#include <ndbm.h>
#include <sys/stat.h>
#include <assert.h>

/* for inet_pton */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* for ntohl */
#include <sys/param.h>

#define MAX_LINE 1024

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

#define CLASS_NAME 1
#define LIMIT_NAME 2
#define NEITHER    3

#define DEBUG 0

struct subnet {
	u_int32_t network ;
	u_int8_t offset;
};

/*
** This structure is used to keep track of usage resources.
*/

typedef struct owamp_limits{
	u_int32_t bandwidth;   /* bytes/sec                          */
	u_int32_t space;       /* bytes                              */
	u_int8_t num_sessions; /* number of concurrent test sessions */
} OWAMPLimits;

const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;
const char *DefaultIPtoClassFile = DEFAULT_IP_TO_CLASS_FILE;
char *IPtoClassFile = NULL;
const char *DefaultClassToLimitsFile = DEFAULT_CLASS_TO_LIMITS_FILE;
char *ClassToLimitsFile = NULL;
DBM *ip2class_dbm;

static void usage(void);

static void
usage()
{
	return;
}

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
	return lim->num_sessions;
}

void
OWAMPSetBandwidth(OWAMPLimits * lim, u_int32_t bw){
	lim->bandwidth = bw;
}

u_int32_t
OWAMPSetSpace(OWAMPLimits * lim, u_int32_t space){
	lim->space = space;
}

u_int32_t
OWAMPSetNumSessions(OWAMPLimits * lim, u_int32_t ns){
	lim->num_sessions = ns;
}

/*
** This function parses command line options.
*/

static void
owamp_parse_options(int argc, char *argv[])
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


datum *
subnet2datum(u_int32_t addr, u_int8_t off)
{
	char *bytes;
	datum *ret;
	int num_bytes = sizeof(u_int32_t) + sizeof(u_int8_t);

	if ( (ret = (void *)malloc(sizeof(datum))) == NULL)
		return NULL;
	if ( (ret->dptr = (void *)malloc(num_bytes)) == NULL)
		return NULL;

	ret->dsize = num_bytes;
	*(u_int32_t*)(ret->dptr) = addr;
	*(u_int8_t*)((ret->dptr) + 4) = off;	
	return ret;
}

/*
** Determines whether the given nework/offset combination
** is valid. Returns 1 if yes, and 0 otherwise.
*/

int
is_valid_network(u_int32_t addr, u_int8_t offset)
{
	u_int32_t off_mask;

	if (offset > 32){
		fprintf(stderr, "offset > 32\n");
		return 0;
	}
	if ((offset == 0) && addr)
		return 0;
	off_mask = ((1<<(32-offset)) - 1);
	return (addr & off_mask)? 0 : 1; 
}

/*
** This function takes a string of the form <address/netmask>
** where address is a dot-separated IP address, and netmask
** is a mask offset. It fills in the location pointed to by dst 
** with 5 bytes of data: the first four bytes are network address 
** (host byte prder), and the last byte is the mask offset.
** It returns 0 on success, and -1 on failure.
*/


int
owamp_parse_mask(const char *text, u_int32_t *addr, u_int8_t *off)
{
	
	char *addr_str = NULL;
	char *mask_str = NULL;
	unsigned long mask, host_bits;

	if((addr_str = strdup(text)) == NULL)
		return -1;


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
owamp_datumify(const char *bytes, int dat_len)
{
	datum *dat;
	if ( (dat = (void *)malloc(sizeof(datum))) == NULL)
		return NULL;
	if ( (dat->dptr = (void *)malloc(dat_len)) == NULL) 
		return NULL;

	bcopy(bytes, dat->dptr, dat_len);
	dat->dsize = dat_len;
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

/* 
** This function reads the configuration file given by the path ip2class, 
** processes it and saves the results in Berkeley DB file, with the
** same base name, and extension ".db". The database can be printed by the
** companion function print_dbm(). This function should typically only
** be called once, outside of any application - to initialize the database.
*/

void
owamp_read_config(const char *ip2class)
{
	char line[MAX_LINE], mask[MAX_LINE], class[MAX_LINE];
	char err_msg[1024];
	FILE *fp;
	u_int32_t addr;
	u_int8_t off; 
	
	datum *key, *val;
	static const char all[] = "all";
	char tmp[5];

	/* Open the database file for writing. */
	if ((ip2class_dbm = dbm_open(ip2class, O_CREAT|O_RDWR, 0660)) == NULL){
		snprintf(err_msg, sizeof(err_msg),
			 "dbm_open %s.db for writing", ip2class);
		perror(err_msg);
		exit(1);
	}

	if ( (fp = fopen(ip2class, "r")) == NULL){
		snprintf(err_msg, sizeof(err_msg),"fopen %s for reading", 
			ip2class);
		perror(err_msg);
		exit(1);
	}

	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		int tmp;
			
		if (line[0] == '#') 
			continue;
		if (sscanf(line, "%s%s", mask, class) != 2) 
			continue;
		if ((tmp = owamp_parse_mask(mask, &addr, &off)) != 0){
			printf("bad network %s\n", mask);
			continue;
		}
		
		/* Now save the key/class pair in a hash. */
		if ( (key = subnet2datum(addr, off)) == NULL)
			continue;

		if ( (val = owamp_datumify(class, strlen(class)+1)) == NULL )
			continue;

		if (dbm_store(ip2class_dbm, *key, *val, DBM_REPLACE) != 0)
			continue;
	}

	/* In all cases make sure we have a class "all" for the widest mask. */
	bzero(tmp, 5);
	if ((key = owamp_datumify(tmp, 5)) == NULL)
		goto CLOSE;
	if ((val = owamp_datumify(all, strlen(all)+1)) == NULL)
		goto CLOSE;
	if (dbm_store(ip2class_dbm, *key, *val, DBM_INSERT) != 0)
		fprintf(stderr, "\ndbm_store failed to insert all key\n\n");
 CLOSE:
	dbm_close(ip2class_dbm);
	return;
}

/*
** This function prints out the database, given by the argument <base>.
** It is used mostly for debugging.
*/

void
owamp_print_dbm(char *base)
{
	DBM *dbm;
	datum key, val;

	dbm = dbm_open(base, O_RDWR | O_CREAT, 0660);
	for(key = dbm_firstkey(dbm); key.dptr != NULL; key = dbm_nextkey(dbm)){
		u_int32_t addr;
		u_int8_t off;
		char *valptr;

		val = dbm_fetch(dbm, key);
		assert(val.dptr);

		valptr = (void *)malloc(val.dsize + 1);
		bcopy(val.dptr, valptr, val.dsize);
		valptr[val.dsize] = '\0';

		fprintf(stderr, "the value of key %s/%u is = %s\n",
	       owamp_denumberize(get_ip_addr(&key)), get_offset(&key), valptr);
	}
	dbm_close(dbm);
}

/* 
** This function reads the configuration file given by the path ip2class, 
** processes it and saves the results in Berkeley DB file, with the
** same base name, and extension ".db". The database can be printed by the
** companion function print_dbm().
*/

void
owamp_read_limits(const char *class2limits)
{
	char line[MAX_LINE];
	char err_msg[1024];
	char *key;
	FILE *fp;
	char *cur_class;
	char *tok;
	
	DBM *dbm;
	datum key_dat, val_dat;

	/* Open the database file for writing. */
	if ( (dbm = dbm_open(class2limits, O_CREAT|O_RDWR, 0660)) == NULL){
		snprintf(err_msg, sizeof(err_msg),
			 "dbm_open %s.db for writing", class2limits);
		perror(err_msg);
		exit(1);
	}

	if ( (fp = fopen(class2limits, "r")) == NULL){
		snprintf(err_msg, sizeof(err_msg),"fopen %s for reading", 
			class2limits);
		perror(err_msg);
		exit(1);
	}

	fprintf(stderr, "\n");
	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		int len;
		tok = strtok(line, " \t\n");
		if (!tok)
			continue;
		if (tok[0] == '<'){ /* could be classname */
			len = strlen(tok);
			if (len <= 2 || tok[len-1] != '>') 
				continue;
			tok[len-1] = '\0'; /* now (line+1) points at class */
			fprintf(stderr, "DEBUG: class name = %s\n", (tok+1));
			cur_class = strdup(tok+1);
			continue;
		} else {
			if (!cur_class)
				continue;
			tok = strtok(NULL, " \t\n");
		}
		
	}
}


void
datum2string(const datum * dat, char *str)
{
	bcopy(dat->dptr, str, dat->dsize);
	str[dat->dsize] = '\0';
}

void
ipaddr2class(u_int32_t ip, char *class)
{
	char key_bytes[5];
	int offset;
	char *ascii;
	datum *key_dat, val_dat;
	u_int32_t mask_template = 0xFFFFFFFF;
	
	for(offset=32; offset>0; offset--){
		int bits = 32 - offset;
		u_int32_t mask = (mask_template>>bits)<<bits;
		key_dat = subnet2datum(ip & mask, offset);
		ascii = owamp_denumberize(ip & mask);
		val_dat = dbm_fetch(ip2class_dbm, *key_dat);
		if (val_dat.dptr){
			bcopy(val_dat.dptr, class, val_dat.dsize);
			class[val_dat.dsize] = '\0';
			return;
		}
	}

	/* If not found at this point, assign class "all" */
	strcpy(class, "all");
}

int
main(int argc, char *argv[])
{
	char line[MAX_LINE];
	u_int32_t ip;
	char key_bytes[5];
	datum * dat;
	char class[128];
	char err_msg[128];

	owamp_parse_options(argc, argv);
	if (!IPtoClassFile)
		IPtoClassFile = strdup(DefaultIPtoClassFile);
	if (!ClassToLimitsFile)
		ClassToLimitsFile = strdup(DefaultClassToLimitsFile);

	/* Uncomment if wish to read config file. Else will use db on disk */
	owamp_read_config(IPtoClassFile); 

	owamp_print_dbm(IPtoClassFile); 
	owamp_read_limits(ClassToLimitsFile);

	if ((ip2class_dbm = dbm_open(IPtoClassFile, O_CREAT|O_RDWR, 0660)) 
	    == NULL){
		snprintf(err_msg, sizeof(err_msg),
			 "dbm_open %s.db for writing", IPtoClassFile);
		perror(err_msg);
		exit(1);
	}
	while (1){
		printf("\nEnter a dotted IP address, or 'x' to exit:\n");
		fgets(line, sizeof(line), stdin);
		if (line[0] == 'x')
			exit(0);
		line[strlen(line)-1] = '\0';
		
		if ( (ip = owamp_numberize(line)) == -1){
			fprintf(stderr,"could not numberize IP = %s\n", line);
			exit(0);
		}

		ipaddr2class(ip, class);
#if 1
		printf("the class for ip = %lu is %s\n", ip, class);
#endif	
	}
	exit(0);
}
