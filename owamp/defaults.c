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
	owp_policy_data* policy = ((OWPPerConnDataRec *)app_data)->policy;

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


/*
** Create a path and directory using base prefix <datadir>
** and position of <node> in the class policy tree. The path
** is dynamically allocated. <add_chars> specifies the additional
** number of chars to be allocated.
*/
static char *
make_data_dir(
	      char		 *datadir,
	      owp_tree_node_ptr	 node,
	      unsigned int	 add_chars
	      )
{
	char		*path;
	int		len;

	if(node){
		path = make_data_dir(datadir, node->parent, strlen(node->data) 
				     + OWP_PATH_SEPARATOR_LEN + add_chars);
		if(!path)
			return NULL;
		strcat(path,OWP_PATH_SEPARATOR);
		strcat(path,node->data);
	} 
	else {
		len = strlen(datadir) + OWP_PATH_SEPARATOR_LEN
			+ strlen(OWP_NODES_DIR) + add_chars;
		if(len > FILENAME_MAX){
			fprintf(stderr, "Datapath length too long.");
			return NULL;
		}
		path = malloc(len+1);
		if(!path)
			return NULL;
		
		strcpy(path,datadir);
		strcat(path,OWP_PATH_SEPARATOR);
		strcat(path, OWP_NODES_DIR);
	}
	
	if((mkdir(path,0755) != 0) && (errno != EEXIST)){
		fprintf(stderr,"Unable to mkdir(%s):%s",path,strerror(errno));
		free(path);
		return NULL;
	}
	return path;
}

#define OWP_DEFAULTS_DEBUG

/*
** Returns False if the class of the <remote_sa_addr> has "open_mode_ok"
** flag turned OFF, or on error, and True in all other cases. Also
** sets up the usage class associated with this Control connection.
** KID, if valid, takes precedence over the ip address. Finally,
** set up paths for data directories (both real and symlink). Return
** True on success, or False on failure.
*/
OWPBoolean
owp_check_control(
	void *          app_data,        /* policy data         */
	OWPSessionMode	mode,	         /* requested mode      */
	const char	*kid,	         /* key identity       	*/
	struct sockaddr	*local_sa_addr __attribute__((unused)),
					/* local addr or NULL	*/
	struct sockaddr	*remote_sa_addr, /* remote addr		*/
	OWPErrSeverity	*err_ret	 /* error - return     	*/
)
{
	owp_policy_data* policy;
	char *class;
	owp_tree_node_ptr node;
	OWPPerConnDataRec *conndata = (OWPPerConnDataRec *)app_data;

	assert(conndata);

	*err_ret = OWPErrOK;
	policy = ((OWPPerConnDataRec *)app_data)->policy;

	/* 
	   This implementation assumes that the KID has already
	   been authenticated, and is valid.
	*/

	if (mode & _OWP_DO_CIPHER) { /* Look up class of the KID. */
		if (!kid)  /* Paranoia */
			return False;
		class = owp_kid2class(kid, strlen(kid) + 1, policy);
	} else {
		if (!remote_sa_addr)
			return False;
		class = owp_sockaddr2class(remote_sa_addr, policy);
	}

	if (!class)  /*Internal error - every KID must have a class.*/{
		fprintf(stderr, "DEBUG: no class for the connection\n");
		goto error;
	}
	fprintf(stderr, "DEBUG: class = %s\n", class);

	node = owp_class2node(class, policy->class2node);
	if (!node)  /* Internal error - every class must have a node. */
		goto error;
	
	/* If request open mode which is forbidden for class, deny. */
	if (!(mode & (OWPSessionMode)_OWP_DO_CIPHER) 
	    && !node->limits.values[5])
		return False;

	conndata->node = node;

	/* 
	   Set up key data directories.
	*/
	if ((conndata->real_data_dir 
	     = make_data_dir(conndata->datadir, node, 0)) == NULL) {
		fprintf(stderr, "FATAL: Could not make data path");
		goto error;
	}
	/* 1 for '\0' at the end */
	if (!(conndata->link_data_dir 
	      = (char *)malloc(strlen(conndata->datadir) 
			       + OWP_PATH_SEPARATOR_LEN
			       + strlen(OWP_SESSIONS_DIR) + 1))) {
		free(conndata->real_data_dir);
		fprintf(stderr, "FATAL: malloc failed");
		goto error;
	} 
	strcpy(conndata->link_data_dir, conndata->datadir);
	strcat(conndata->link_data_dir, OWP_PATH_SEPARATOR);
	strcat(conndata->link_data_dir, OWP_SESSIONS_DIR);

	return True;
	
 error:
	*err_ret = OWPErrFATAL;
	return False;
}

OWPBoolean
owp_check_test(
	void		*app_data,
	OWPSessionMode	mode,
	const char	*kid	__attribute__((unused)),
	OWPBoolean	local_sender,
	struct sockaddr	*local_sa_addr	__attribute__((unused)),
	struct sockaddr	*remote_sa_addr	__attribute__((unused)),
	OWPTestSpec	*test_spec,
	OWPErrSeverity	*err_ret
)
{
	u_int64_t total_octets, octets_on_disk, bw;
	OWPTestSpecPoisson *poisson_test;
	owp_tree_node_ptr node = ((OWPPerConnDataRec *)app_data)->node;

	*err_ret = OWPErrOK;

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
		
		fprintf(stderr, "DEBUG: request parsed ok\n");

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
