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
	u_int8_t type;

	type = ((owp_access_id *)(p->key->dptr))->type;
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

