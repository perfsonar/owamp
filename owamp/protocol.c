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
**	File:		protocol.c
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Tue Apr  2 10:42:12  2002
**
**	Description:	This file contains the private functions that
**			actually speak the owamp protocol directly.
**			(i.e. read and write the data and save it
**			to structures for the rest of the api to deal
**			with.)
**
**			The idea is to basically keep all network ordering
**			architecture dependant things in this file.
*/
#include <owampP.h>

/*
 * Function: _OWPReadServerGreeting
 *
 * Description:
 * 	This function is used to read the server's greeting message and
 * 	return the mode's available. It saves the "challenge" in the cntrl
 * 	structure for later use by the _OWPInitClientEncryptionValues
 * 	function if the cntrl->mode requires encryption.
 *
 * 	returns 0 on success - non-0 on failure.
 */
int
_OWPReadServerGreeting(
	OWPControl	cntrl,		/* cntrl state structure	*/
	u_int32_t	*mode,		/* modes available - returned	*/
	OWPErrSeverity	*err_ret	/* error - returned		*/
)
{
	mode = 0;
	*err_ret = OWPErrOK;

	return 0;
}

/*
 * Function: _OWPInitClientEncryptionValues
 *
 * Description:
 * 	Given the cntrl->mode setting, and the cntrl->challenge this function
 * 	creates the clientIV and the session token.
 *
 * 	returns 0 on success - non-0 on failure.
 */
int
_OWPInitClientEncryptionValues(
	OWPControl	cntrl,		/* cntrl state structure	*/
	OWPErrSeverity	*err_ret	/* error - returned		*/
)
{
	*err_ret = OWPErrOK;

	return 0;
}
