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
**	File:		defaults.c
**
**	Author:		Anatoly Karp
**
**	Date:		Mon Jul 15:10:33  2002
**
**	Description:	
**      Hook functions used by OWAMP applications.
*/
#include <owamp/owamp.h>
#include <owamp/owampP.h>
#include <owamp/access.h>
#include <owamp/conndata.h>

/*
** Fetch 16-byte binary AES key for a given KID and return it
** via key_ret (memory must be allocated by the caller).
** Returns: 0 on success,
**         -1 on failure 
*/
OWPBoolean
owp_get_aes_key(void *app_data, 
		const char	*kid,
		u_int8_t	*key_ret,
		OWPErrSeverity	*err_ret)
{
	int i;
	policy_data* policy = ((OWPPerConnDataRec *)app_data)->policy;

	/* First fetch 32-byte hex-encoded key. */
	char* secr = owp_kid2passwd(kid, strlen(kid) + 1, policy);

	*err_ret = OWPErrOK;
	if (!secr)
		return False;

	/* Now do hex decoding. */
	for (i = 0; i < 128/8; i++) {
		int t, v;

		t = *secr++;
		if ((t >= '0') && (t <= '9')) v = (t - '0') << 4;
		else if ((t >= 'a') && (t <= 'f')) v = (t - 'a' + 10) << 4;
		else if ((t >= 'A') && (t <= 'F')) v = (t - 'A' + 10) << 4;
		else return False;
		
		t = *secr++;
		if ((t >= '0') && (t <= '9')) v ^= (t - '0');
		else if ((t >= 'a') && (t <= 'f')) v ^= (t - 'a' + 10);
		else if ((t >= 'A') && (t <= 'F')) v ^= (t - 'A' + 10);
		else return False;
		
		key_ret[i] = (u_int8_t)v;
	}

	return True;
}

#define OWP_DEFAULTS_DEBUG

/*
** Returns False if the class of the <remote_sa_addr> has "open_mode_ok"
** flag turned OFF, or on error, and True in all other cases. Also
** sets up the usage class associated with this Control connection.
** KID, if valid, takes precedence over the ip address.
*/
OWPBoolean
owp_check_control(
		void *          app_data,        /* policy data         */
		OWPSessionMode	mode,	         /* requested mode      */
		const char	*kid,	         /* key identity       	*/
		struct sockaddr	*local_sa_addr,	 /* local addr or NULL	*/
		struct sockaddr	*remote_sa_addr, /* remote addr		*/
		OWPErrSeverity	*err_ret	 /* error - return     	*/
)
{
	policy_data* policy;
	char *class;
	owp_tree_node_ptr node;
	*err_ret = OWPErrOK;
	policy = ((OWPPerConnDataRec *)app_data)->policy;

	/* 
	   This implementation assumes that the KID has already
	   been authenticated, and is valid.
	*/

	if (mode & _OWP_DO_CIPHER) { /* Look up class of the KID. */
		if (!kid)  /* Paranoia */
			return False;
		class = owp_kid2class(kid, strlen(class) + 1, policy);
	} else {
		if (!remote_sa_addr)
			return False;
		class = owp_sockaddr2class(remote_sa_addr, policy);
	}

	if (!class)  /*Internal error - every KID must have a class.*/{
#ifdef	VERBOSE
		fprintf(stderr, "DEBUG: no class for the connection\n");
#endif
		goto error;
	}
#ifdef	VERBOSE
	fprintf(stderr, "DEBUG: class = %s\n", class);
#endif

	node = owp_class2node(class, policy->class2node);
	if (!node)  /* Internal error - every class must have a node. */
		goto error;
	
	/* If request open mode which is forbidden for class, deny. */
	if (!(mode & (OWPSessionMode)_OWP_DO_CIPHER) 
	    && !node->limits.values[5])
		return False;

	((OWPPerConnDataRec *)app_data)->node = node;
	
	return True;
	
 error:
	*err_ret = OWPErrFATAL;
	return False;
}

OWPBoolean
owp_check_test(
	void		*app_data,
	OWPSessionMode	mode,
	const char	*kid,
	OWPBoolean	local_sender,
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	OWPTestSpec	*test_spec,
	OWPErrSeverity	*err_ret
)
{
	u_int64_t packets_per_sec, total_octets, octets_on_disk, bw;
	u_int32_t octs_per_pack;
	OWPTestSpecPoisson *poisson_test;
	policy_data* policy = ((OWPPerConnDataRec *)app_data)->policy;
	owp_tree_node_ptr node = ((OWPPerConnDataRec *)app_data)->node;
	
	switch (test_spec->test_type) {
	case OWPTestPoisson:
		poisson_test = (OWPTestSpecPoisson *)test_spec;
		switch (mode) {
		case OWP_MODE_OPEN:
			total_octets = 12 + poisson_test->packet_size_padding;
			break;
		case OWP_MODE_AUTHENTICATED:
			total_octets = 24 + poisson_test->packet_size_padding;
			break;
		case OWP_MODE_ENCRYPTED:
			total_octets = 16 + poisson_test->packet_size_padding;
			break;
		default:
			return False;
			/* UNREACHED */
		}
		bw = (total_octets*1000000)/poisson_test->InvLambda;
		total_octets *= poisson_test->npackets;
		octets_on_disk = (u_int64_t)20 * poisson_test->npackets;
		
#ifdef	VERBOSE
		fprintf(stderr, "DEBUG: request parsed ok\n");
#endif

		/* fetch class limits and check restrictions */
		if (bw > node->limits.values[OWP_LIM_BANDWIDTH])
			return False;
		if (!local_sender &&
		    (octets_on_disk > node->limits.values[OWP_LIM_SPACE]))
			return False;
		return True;
		/* UNREACHED */
	case OWPTestUnspecified:
		return False;
		/* UNREACHED */
	default:
		return False;
		/* UNREACHED */
	}

	return False;
}
