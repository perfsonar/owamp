#include <owamp/owamp.h>
#include <I2util/table.h>
#include "access.h"

/*
** Print the value (address + offset) of a given netmask.
*/
void
owp_print_netmask(const I2datum *key, FILE* fp)
{
	owp_access_netmask *ptr;
	struct in_addr addr4;
	struct in6_addr addr6;
	char buf[INET6_ADDRSTRLEN];

	ptr = (owp_access_netmask *)(key->dptr);

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
		printf("DEBUG: warning: unusual type = %d...\n", ptr->af);
		return;
	}
	fprintf(fp, "DEBUG: netmask  is %s/%d\n", buf, ptr->offset);
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

#if 0
void
print_limits(OWAMPLimits * limits, FILE* fp)
{
	fprintf(fp, "bw = %lu, space = %lu, num_sessions = %lu\n",
	       OWAMPGetBandwidth(limits),
	       OWAMPGetSpace(limits),
	       OWAMPGetNumSessions(limits)
	       );
}

void
print_class2limits_binding(const struct I2binding *p, FILE* fp)
{
	fprintf(fp, "the limits for class %s are: ", (char *)(p->key->dptr));
	print_limits((OWAMPLimits *)(p->value->dptr), fp);
}
#endif

