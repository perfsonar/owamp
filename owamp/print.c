/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		print.c
 *
 *	Author:		Anatoly Karp
 *			Internet2
 *
 *	Date:		Mon Jul 26 10:57:07 MDT 2002
 *
 *	Description:	
 */
#include <owamp/owampP.h>
#include <I2util/table.h>
#include "access.h"

/*
** Print the value (address + offset) of a given netmask.
*/
void
owp_print_strnet(owp_access_netmask *ptr, FILE* fp)
{
	struct in_addr addr4;
	struct in6_addr addr6;
	char buf[INET6_ADDRSTRLEN];

	switch (ptr->af) {
	case AF_INET:
		addr4.s_addr = htonl(ptr->addr4);
		if (inet_ntop(AF_INET, &addr4, buf, sizeof(buf)) == NULL) {
			fprintf(stderr, "DEBUG: inet_ntop failed\n");
			return;
		}
		break;
	case AF_INET6:
		memcpy(addr6.s6_addr, ptr->addr6, 16); 
		if (inet_ntop(AF_INET6, &addr6, buf, sizeof(buf)) == NULL) {
			fprintf(stderr, "DEBUG: inet_ntop failed\n");
			return;
		}
		break;
	default:
		fprintf(stderr,
			"DEBUG: warning: unusual type = %d...\n", ptr->af);
		return;
	}

	fprintf(fp, "DEBUG: netmask is %s/%d\n", buf, ptr->offset);
}


/*
** Print the value (address + offset) of a given netmask.
*/
void
owp_print_netmask(const I2datum *key, FILE* fp)
{
	owp_access_netmask *ptr;
	ptr = (owp_access_netmask *)(key->dptr);
	owp_print_strnet(ptr, fp);
}

/*
** Print the binding of a netmask and a corresponding usage class.
*/
void
owp_print_ip2class_binding(const struct I2binding *p, FILE* fp)
{
	owp_print_netmask(p->key, fp);
	fprintf(fp, "DEBUG: class is %s\n\n", (char *)(p->value->dptr));
}

/*
** Print the binding of a KID and its corresponding hex-encoded
** password and usage class.
*/
void
owp_print_kid2data_binding(const struct I2binding *p, FILE* fp)
{
	owp_kid_data* ptr = (owp_kid_data *)p->value->dptr;

	fprintf(fp, "KID %s has password %s and class %s.\n",
		(char *)p->key->dptr,
		ptr->passwd, ptr->class);
}

void
owp_print_class2node_binding(const struct I2binding *p, FILE* fp)
{
	int i;
	owp_tree_node_ptr node = (owp_tree_node_ptr)p->value->dptr;
	char *parent = (node->parent)? node->parent->data : "NO PARENT";
	static char* lim_names[6] = {"bandwidth", "space", "expiry", \
			       "del_on_close", "del_on_fetch", "open_mode_ok"};

	fprintf(fp, "Class %s has data = %s, parent = %s\n", 
		(char *)(p->key->dptr), node->data, parent);
	for (i = 0; i < 6; i++)
		printf("%s = %llu\n", lim_names[i], node->limits.values[i]);
}

/*
** Show the contents of a sockaddr_in struct.
*/
void
owp_print_sockaddr(struct sockaddr *sock)
{
	char host[128];
	unsigned short port;
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;

	switch (sock->sa_family) {
	case AF_INET:
		addr = (struct sockaddr_in *)sock;
		port = ntohs(addr->sin_port);
	
		if (inet_ntop(AF_INET, &(addr->sin_addr), host, 
			      sizeof(host))==NULL) {
			perror("inet_ntop");
			return;
		}
		
		break;
	case AF_INET6:
		addr6 = (struct sockaddr_in6 *)sock;
		port = ntohs(addr6->sin6_port);
		if (inet_ntop(AF_INET6, &(addr6->sin6_addr), host, 
			      sizeof(host))==NULL) {
			perror("inet_ntop");
			return;
		}

		break;
	default:
		return;
		/* UNREACHED */
	}

	fprintf(stderr, 
		"DEBUG: socket address is %s, port = %u \n", host, port);
}

void
owp_print_owpaddr(FILE *fp, OWPAddr addr)
{
	if (addr->node_set)
		fprintf(fp, "Node = %s\n", addr->node);

	if (addr->port_set)
		fprintf(fp, "Port = %s\n", addr->port);

	fprintf(fp, "addrlen = %d\n", addr->saddrlen);

	if (addr->saddr)
		owp_print_sockaddr(addr->saddr);
}
