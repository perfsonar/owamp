#include "access.h"
#include "table.h"

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
test_policy_check()
{
	;
}

/*
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
*/
