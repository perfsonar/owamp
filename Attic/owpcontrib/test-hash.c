#include "access.h"


void
test_ip2class()
{
	char line[MAX_LINE];
	u_int32_t ip;
	while (1){
		printf("\nEnter a dotted IP address, or 'x' to exit:\n");
		fgets(line, sizeof(line), stdin);
		if (line[0] == 'x')
			break;
		line[strlen(line)-1] = '\0';
		
		if ( (ip = owamp_numberize(line)) == -1){
			fprintf(stderr,"could not numberize IP = %s\n", line);
			continue;
		}
		printf("the class for ip = %lu is %s\n", ip, ipaddr2class(ip));
	}
}


void
print_limits(OWAMPLimits * limits)
{
	printf("bw = %lu, space = %lu, num_sessions = %u\n",
	       OWAMPGetBandwidth(limits),
	       OWAMPGetSpace(limits),
	       OWAMPGetNumSessions(limits)
	       );
}

void
owamp_print_class2limits(hash_ptr hash)
{
	datum key, val;

	for(key=hash_firstkey(hash);key.dptr != NULL;key = hash_nextkey(hash)){
		val = hash_fetch(hash, key);
		if (!val.dptr)
			continue;
		printf("the limits for class %s are: ", key.dptr);
		print_limits((OWAMPLimits *)val.dptr);
	}
}


/*
** This function prints out the hash, given by the argument <hash>.
** It is used mostly for debugging.
*/

void
owamp_print_ip2class(hash_ptr hash)
{
	datum key, val;

	for(key=hash_firstkey(hash);key.dptr != NULL;key = hash_nextkey(hash)){
		val = hash_fetch(hash, key);
		if (!val.dptr)
			continue;
		fprintf(stderr, "the value of key %s/%u is = %s\n",
	     owamp_denumberize(get_ip_addr(&key)), get_offset(&key), val.dptr);
	}
}


void
test_policy_check()
{
	int s, connfd;
	struct sockaddr_in sockaddr, cliaddr;
	OWPErrSeverity out;

	if ( (s = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("socket");
		exit(1);
	}

	bzero(&sockaddr, sizeof(sockaddr)); 
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(5555);
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(s, (struct sockaddr *)(&sockaddr), sizeof(sockaddr)) < 0){
		perror("bind");
		exit(1);
	}

	if (listen(s, 5) < 0){
		perror("listen");
		exit(1);
	}

	while (1){
		int len = sizeof(cliaddr);
		connfd = accept(s, (struct sockaddr *)(&cliaddr), &len);
		switch(owamp_first_check(NULL,NULL,
				     (struct sockaddr *)&cliaddr, &out)){
		case 0:
			fprintf(stderr, "DEBUG: access prohibited\n");
			break;
		case 1:
			fprintf(stderr, "DEBUG: access allowed\n");
			break;
		default:
			fprintf(stderr, "DEBUG: policy is confused\n");
			break;
		};
		close(connfd); 
	}
}
