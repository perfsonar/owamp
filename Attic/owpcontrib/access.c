#include "access.h"

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
** The lower and upper limits of the netmask range are returned 
** through the pointers lb and ub. 
*/

int
owamp_parse_text(const char *text, unsigned int *lb, unsigned int *ub)
{
	char *addr_str = NULL;
	char *mask_str = NULL;
	unsigned int addr, mask, host_bits, host_max;
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
		
		if(offset < 1 || offset > 32)
			{
				/* bad CIDR offset */
				return -1;
			};
		
		host_bits = 32 - offset;
		host_max = pow(2, host_bits);
		*lb = (addr >> host_bits) << host_bits;
		*ub = *lb + host_max - 1;
		printf("DEBUG: lb = %s\n", denumberize(*lb));
		printf("DEBUG: ub = %s\n", denumberize(*ub));
	}
	else
	{
		/* regular IP address */
		if((addr = numberize(addr_str)) == -1)
			return -1;
		*lb = addr;
		*ub = addr;
		printf("DEBUG: lb = %s\n", denumberize(*lb));
		printf("DEBUG: ub = %s\n", denumberize(*ub));
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
	return;
}

int
main(int argc, char *argv[])
{
	unsigned int *lb, *ub;
	int i;
	char buf[1024];
	parse_options(argc, argv);

	lb = (void *)malloc(sizeof(int));
	if (!lb){
		perror("malloc");
		exit(1);
	}

	ub = (void *)malloc(sizeof(int));
	if (!lb){
		perror("malloc");
		exit(1);
	}

	while (1){
		printf("Enter an address/offset - CIDR style:\n");
		if ( fgets(buf, 1024, stdin) == NULL) exit(1);
		owamp_parse_text(buf, lb, ub);
		printf("\n*********************************\n");
	}
	exit(0);
}
