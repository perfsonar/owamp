#include "access.h"

#define MAX_LINE 1024

const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;
const char *DefaultIPtoClassFile = DEFAULT_IP_TO_CLASS_FILE;
char *IPToClassFile = NULL;
const char *DefaultClassToLimitsFile = DEFAULT_CLASS_TO_LIMITS_FILE;
char *ClassToLimitsFile = NULL;

static void mainParseOptions(int, char **);
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
** is a mask offset. It returns 0 on successm and -1 on failure. 
** The lower limit of the netmask range, and mask offset are returned 
** through the pointers lb and off. This pair uniquely identifies the mask. 
*/

int
owamp_parse_mask(const char *text, unsigned int *lb, unsigned int *off)
{
	char *addr_str = NULL;
	char *mask_str = NULL;
	unsigned long addr, mask, host_bits;
	int offset;

	if((addr_str = strdup(text)) == NULL)
		return -1;

	if( strchr(addr_str, '/'))
	{
		 /* IP and mask or ip and offset */
		addr_str = strtok(addr_str, "/");
		mask_str = strtok(NULL, "/");
		
		if(!mask_str)
			return -1;
		
		if((addr = numberize(addr_str)) == -1)
			return -1;
	
		/* CIDR */
		offset = atoi(mask_str);
		
		if(offset > 32)
			{
				/* bad CIDR offset */
				return -1;
			};
		
		host_bits = 32 - offset;
		*lb = (addr >> host_bits) << host_bits;
		*off = offset;
	}
	else
	{
		/* regular IP address */
		if((addr = numberize(addr_str)) == -1)
			return -1;
		*lb = addr;
		*off = 0;
	}
	
	free(addr_str); 
	return 0;
}

/* 
** This function reads the configuration file, processes it
** and saves the results in a Berkeley DB file.
*/

void
owamp_read_config()
{
	char line[MAX_LINE], mask[MAX_LINE], class[MAX_LINE];
	char err_msg[1024];
	char key[128];
	unsigned int *lb, *offset;
	FILE *fp;
	
	if ( (lb = (void *)malloc(sizeof(int))) == NULL){
		perror("malloc");
		exit(1);
	}
	if ( (offset = (void *)malloc(sizeof(int))) == NULL){
		perror("malloc");
		exit(1);
	}

	if ( (fp = fopen(ConfigFile, "r")) == NULL){
		snprintf(err_msg, sizeof(err_msg),"fopen %s for reading", 
			ConfigFile);
		perror(err_msg);
		exit(1);
	}

	while ( (fgets(line, sizeof(line), fp)) != NULL) {
		if (sscanf(line, "%s%s", mask, class) != 2) continue;
		if (owamp_parse_mask(mask, lb, offset) == -1) continue;
		snprintf(key, sizeof(key), "%u/%u", *lb, *offset);

		/* Now save the key/class pair in a hash. */

	}
	return;
}

int
main(int argc, char *argv[])
{
	parse_options(argc, argv);
	owamp_read_config();

	exit(0);
}
