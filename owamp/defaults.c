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
#include <owpcontrib/access.h>
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
