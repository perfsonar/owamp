#include <owamp/owamp.h>
#include <I2util/table.h>
#include "access.h"

/*
** Basic function to print out ip2class.
*/

void
print_ip2class_binding(const struct I2binding *p, FILE* fp)
{
	fprintf(fp, "DEBUG: the value of key %s/%u is = %s\n",
	       owamp_denumberize(owp_get_ip(p->key)), 
	       owp_get_offset(p->key), (char *)(p->value->dptr));
}

void
print_id2class_binding(const struct I2binding *p, FILE* fp)
{
	idtype type;
	owp_access_id *ptr;
	char *class;
	struct in_addr addr4;
	struct in6_addr addr6;
	char buf[INET6_ADDRSTRLEN];
	char *ret;

	ptr = (owp_access_id *)(p->key->dptr);
	class = (char *)(p->value->dptr);
	type = ptr->type;

	switch (type) {
	case OWP_IDTYPE_KID:
		fprintf(fp, "DEBUG: class of KID `%s' is `%s'\n", 
			ptr->kid, class);
		return;
	case OWP_IDTYPE_IPv4:
		addr4.s_addr = htonl(ptr->addr4); 
		if (inet_ntop(AF_INET, &addr4, buf, sizeof(buf)) == NULL) {
			fprintf(stderr, "DEBUG: inet_ntop failed\n");
			return;
		}
		break;
	case OWP_IDTYPE_IPv6:
		memcpy(addr6.s6_addr, ptr->addr6, 16); 
		if (inet_ntop(AF_INET6, &addr6, buf, sizeof(buf)) == NULL) {
			fprintf(stderr, "DEBUG: inet_ntop failed\n");
			return;
		}
		break;
	default:
		return;
	}
	fprintf(fp, "DEBUG class of %s/%d is %s\n", buf, ptr->offset, class);
}


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

