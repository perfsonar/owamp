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
**	
*/

#include "../libowamp/owampP.h"
#include "access.h"
#include "rijndael-api-fst.h"

#define DEBUG   0
#define LISTENQ 5
#define SERV_PORT_STR "5555"

#define MAX_MSG 60 /* XXX - currently 56 but KID to be extended by 4 bytes */
#define KID_LEN 16
#define PASSWD_LEN 16
#define PASSWD_LEN_HEX (PASSWD_LEN * 2)

#define DEFAULT_OPEN_CLASS "open"
#define AUTH_CLASS "authenticated"
#define BANNED_CLASS "banned"

#define SCRATCH 1

#if SCRATCH
FILE *scratch;
#endif

struct subnet {
	u_int32_t address;
	u_int8_t offset;
};

hash_ptr ip2class_hash, class2limits_hash, passwd_hash;

const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;
const char *DefaultIPtoClassFile = DEFAULT_IP_TO_CLASS_FILE;
char *IPtoClassFile = NULL;
const char *DefaultClassToLimitsFile = DEFAULT_CLASS_TO_LIMITS_FILE;
char *ClassToLimitsFile = NULL;
const char *DefaultPasswdFile = DEFAULT_PASSWD_FILE;
char *PasswdFile = NULL;
u_int32_t DefaultMode = OWP_MODE_OPEN;
OWPContext ctx;

/* Global variable - the total number of allowed Control connections. */
#define DEFAULT_NUM_CONN 100
int free_connections = DEFAULT_NUM_CONN;

static void
usage(char *name)
{
	printf("Usage: %s [-p port] [-a ip_address] [-n num] [-h]\n", name);
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
** is a mask offset. It fills in the location pointed to by dst 
** with 5 bytes of data: the first four bytes are network address 
** (host byte prder), and the last byte is the mask offset.
** It returns 0 on success, and -1 on failure.
*/

static int
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

static datum*
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
			fprintf(stderr, "Warning: bad network %s\n", mask);
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

	fclose(fp);

	/* Assign DEFAULT_OPEN_CLASS for the widest mask. */
	if ( (key = subnet2datum(0, 0)) == NULL)
		goto CLOSE;
	if ( (val = str2datum(DEFAULT_OPEN_CLASS)) == NULL)
		goto CLOSE;
	if (hash_store(hash, *key, *val, DBM_INSERT) != 0)
		fprintf(stderr, "\nhash_store failed to insert all key\n\n");
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
		snprintf(err_msg, sizeof(err_msg),"fopen %s for reading", 
			passwd_file);
		perror(err_msg);
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
			fprintf(stderr, "Warning: KID %s too long - ",
				"truncating to %d characters\n", kid, KID_LEN);
		}

		secret = strtok(NULL, " \t");
		if ( strlen(secret) != PASSWD_LEN_HEX ){
			fprintf(stderr, 
		"Warning: shared_secret %s must consist of %d hex digits.\n", 
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

	fclose(fp);
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

/*!
** This function runs an initial policy check on the remote host.
** Based only on the remote IP number, it determines if the client
** is a member of BANNED_CLASS. Additional diagnostics can be
** returned via err_ret.
** 
** Return values: 0 if the client is a member of BANNED_CLASS,
**                1 otherwise.
*/

OWPBoolean
owamp_first_check(void *app_data,
		       struct sockaddr *local,
		       struct sockaddr *remote,
		       OWPErrSeverity *err_ret
		       )
{
	u_int32_t ip_addr; 
	switch (remote->sa_family){
	case AF_INET:
	    ip_addr = ntohl((((struct sockaddr_in *)remote)->sin_addr).s_addr);
	    fprintf(stderr, "DEBUG: IP = %s\n", owamp_denumberize(ip_addr));
	    fprintf(stderr, "DEBUG: class = %s\n", ipaddr2class(ip_addr));

	    if (strcmp(ipaddr2class(ip_addr), BANNED_CLASS) == 0){
		    *err_ret = OWPErrFATAL; /* prohibit access */
		    return 0;
	    } else {
		    *err_ret = OWPErrOK;    /* allow access */
		    return 1;
	    };
	    break;
	    
	default:
		return 0;
		break;
	}
}

static int
tcp_listen(const char *host, const char *serv, socklen_t *addrlenp)
{
	int listenfd, n;
	const int on = 1;
	struct addrinfo	hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
		err_quit("tcp_listen error for %s, %s: %s",
				 host, serv, gai_strerror(n));
	ressave = res;

	do {
		listenfd = socket(res->ai_family, res->ai_socktype, 
				  res->ai_protocol);
		if (listenfd < 0)
			continue;		/* error, try next one */

		Setsockopt(listenfd, SOL_SOCKET,SO_REUSEADDR, &on, sizeof(on));
		if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0)
			break;			/* success */

		Close(listenfd);      /* bind error, close and try next one */
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL)	/* errno from final socket() or bind() */
		err_sys("tcp_listen error for %s, %s", host, serv);

	Listen(listenfd, LISTENQ);

	if (addrlenp)
		*addrlenp = res->ai_addrlen;/* return size of proto address */

	freeaddrinfo(ressave);

	return(listenfd);
}
/* end tcp_listen */

/* XXX - currently default. Make configurable later. */
u_int32_t
get_mode()
{
	return OWP_MODE_OPEN;
}

void
random_byte(char *ptr)
{
	*(u_int8_t *)ptr = random() / (RAND_MAX / 1<<8);
}

int
send_data(int sock, char *buf, size_t len, OWPBoolean encrypt)
{
	if (!encrypt){
		if (writen(sock, buf, len) < 0)
			return -1;
	}
	return 0;
}

void
doit(int connfd)
{
	char buf[MAX_MSG];
	char *cur;
	u_int32_t mode;
	int i, r, encrypt;
	u_int32_t mode_requested;
	u_int8_t challenge[16], token[32], session_key[16], client_iv[32];
	u_int8_t kid[8]; /* XXX - assuming Stas will extend KID to 8 bytes */

	/* Remove what's not needed. */
	BYTE cv[128/8];
	keyInstance keyInst;
	cipherInstance cipherInst;

	datum key;

	/* first generate server greeting */
	bzero(buf, sizeof(buf));
	mode = htonl(get_mode());
	*(int32_t *)(buf + 12) = mode; /* first 12 bytes unused */

	/* generate random data for the last 16 bytes.
	** We'll do it 16 times, one byte at a time, saving the result.
	*/
	for (i = 0; i < 16; i++)
		random_byte(challenge + i);
	bcopy(challenge, buf + 16, 16); /* the last 16 bytes */

	/* Send server greeting. */
	encrypt = 0;
	if (send_data(connfd, buf, 32, encrypt) < 0){
		fprintf(stderr, "Warning: send_data failed.\n");
		close(connfd);
		exit(1);
	}

	/* Read client greeting. */
	if (readn(connfd, buf, 60) != 60){
		fprintf(stderr, "Warning: client greeting too short.\n");
		exit(1);
	}

	mode_requested = htonl(*(u_int32_t *)buf);
	
	if (mode_requested & OWP_MODE_AUTHENTICATED){

		/* Save 8 bytes of kid */
		bcopy(buf + 4, kid, 8);

		/* Decrypt the token and compare the 16 bytes of challenge */
		bzero(client_iv, 16);

		key = hash_fetch(passwd_hash, *(str2datum((const char *)kid)));

		r = makeKey(&keyInst, DIR_DECRYPT, 128, key.dptr);
		if (TRUE != r) {
			fprintf(stderr,"makeKey error %d\n",r);
			exit(-1);
		}
		r = cipherInit(&cipherInst, MODE_CBC, NULL);
		if (TRUE != r) {
			fprintf(stderr,"cipherInit error %d\n",r);
			exit(-1);
		}

		/* Decrypt two 16-byte blocks */
		blockDecrypt(&cipherInst, &keyInst, buf + 12, 2*(16*8), token);

		/* Decrypted challenge is in the first 16 bytes */
		if (bcmp(challenge, token, 16)){
			fprintf(stderr, "Authentication failed.\n");
			close(connfd);
			exit(1);
		}

		/* Save 16 bytes of session key and 16 bytes of client IV*/
		bcopy(token + 16, session_key, 16);
		bcopy(buf + 44, client_iv, 16);
	}
	
}

/* 
** This function is called when the server doesn't even want
** to speak Control protocol with a particular host.
*/

void
do_ban(int fd)
{
	Close(fd);
}

/*
** Handler function for SIG_CHLD. It updates the number
** of available Control connections.
*/

void
sig_chld(int signo)
{
	pid_t pid;
	int stat;

	while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0)
		free_connections++;
	return;
}

/*
** This is a basic function to report errors on the server.
*/

int
owampd_err_func(
		void           *app_data,
		OWPErrSeverity severity,
		OWPErrType     etype,
		const char     *errmsg
)
{
	syslog(LOG_ERR, errmsg);
	return 0;
}

int
main(int argc, char *argv[])
{
	char key_bytes[5];
	datum * dat;
	char class[128];
	char err_msg[128];
	int listenfd, connfd;
	char buff[MAX_LINE];
	struct sockaddr *cliaddr;
	socklen_t addrlen, len;
	extern char *optarg;
	extern int optind;
	int c;
	char* port = NULL;
	char *host = NULL; 
	pid_t pid;
	OWPErrSeverity out;
	OWPContext ctx;
	OWPInitializeConfigRec cfg  = {
		0, 
		0,
		NULL,
		owampd_err_func, 
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

#if SCRATCH
	if ( (scratch = fopen("scratch.txt", "w")) == NULL){
		perror("fopen scratch.txt for writing.\n");
		exit(1);
	}
#endif

	/* Parse command line options. */
	while ((c = getopt(argc, argv, "f:a:p:n:h")) != -1) {
		switch (c) {
		case 'f':
			ConfigFile = strdup(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'a':
			host = strdup(optarg);
			break;
		case 'p':
			port = strdup(optarg);
			break;
		case 'n':
			free_connections = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
	if (argc != optind){
		usage(argv[0]);
		exit(1);
	}

	if (!port)
		port = strdup(SERV_PORT_STR);
	if (!IPtoClassFile)
		IPtoClassFile = strdup(DefaultIPtoClassFile);
	if (!ClassToLimitsFile)
		ClassToLimitsFile = strdup(DefaultClassToLimitsFile);
	if (!PasswdFile)
		PasswdFile = strdup(DefaultPasswdFile);

	ctx = OWPContextInitialize(&cfg);
	


	/* 
	   XXX - can't think of a better place to put it, but it doesn't
	   belong here. 
	*/
	openlog("owampd", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	
	/* Open the ip2class hash for writing. */
	if ((ip2class_hash = hash_init(IPtoClassFile)) == NULL){
		syslog(LOG_ERR, "Could not initialize hash for %s",
		       IPtoClassFile);
		exit(1);
	}
	owamp_read_ip2class(IPtoClassFile, ip2class_hash); 
	owamp_print_ip2class(ip2class_hash); 

	/* Open the class2limits hash for writing. */
	if ((class2limits_hash = hash_init(ClassToLimitsFile)) == NULL){
		syslog(LOG_ERR, "Could not initialize hash for %s",
		       ClassToLimitsFile);
		exit(1);
	}
	owamp_read_class2limits(ClassToLimitsFile, class2limits_hash);
	owamp_print_class2limits(class2limits_hash);

	/* Open the passwd hash for writing. */
	if ((passwd_hash = hash_init(PasswdFile)) == NULL){
		syslog(LOG_ERR, "Could not initialize hash for %s",
		       PasswdFile);
		exit(1);
	}
	read_passwd_file(PasswdFile, passwd_hash);

	listenfd = tcp_listen(host, port, &addrlen);
	Signal(SIGCHLD, sig_chld);

#if 0
	test_policy_check();
#endif

	cliaddr = (void*)Malloc(addrlen);

	for ( ; ; ) {
		len = addrlen;
#if 1
		break; /* XXX - remove */
#endif
		
		if ( (connfd = accept(listenfd, cliaddr, &len)) < 0){
			if (errno == EINTR)
				continue;
			else
				err_sys("accept error");
		}
		owamp_first_check(NULL, NULL, cliaddr, &out);
		switch (out) {
		case OWPErrFATAL:
			fprintf(stderr, "DEBUG: access prohibited\n");
			do_ban(connfd);
			continue;
			break;
		case OWPErrOK:
			fprintf(stderr, "DEBUG: access allowed\n");
			break;
		default:
			fprintf(stderr, "DEBUG: policy is confused\n");
			do_ban(connfd);
			continue;
			break;
		};

		if (free_connections == 0){
			do_ban(connfd);
			continue;
		}
		free_connections--;

		if ( (pid = fork()) < 0)
			sys_quit("fork");

		if (pid == 0) { /* child */
			doit(connfd);
			exit(0);
		}

		/* Parent */
		Close(connfd);
	}

	hash_close(ip2class_hash);
	hash_close(class2limits_hash);
	hash_close(passwd_hash);

#if SCRATCH
	fclose(scratch);
#endif

	exit(0);
}
