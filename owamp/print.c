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
	       owamp_denumberize(get_ip_addr(p->key)), 
	       get_offset(p->key), p->value->dptr);
}

void
print_limits(OWAMPLimits * limits, FILE* fp)
{
	fprintf(fp, "bw = %lu, space = %lu, num_sessions = %u\n",
	       OWAMPGetBandwidth(limits),
	       OWAMPGetSpace(limits),
	       OWAMPGetNumSessions(limits)
	       );
}

void
print_class2limits_binding(const struct I2binding *p, FILE* fp)
{
	fprintf(fp, "the limits for class %s are: ", p->key->dptr);
	print_limits((OWAMPLimits *)(p->value->dptr), fp);
}

