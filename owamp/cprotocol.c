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
**	File:		cprotocol.c
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Tue Apr  2 10:42:12  2002
**
**	Description:	This file contains the private functions that
**			speak the owamp protocol directly from the
**			client point of view.
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
_OWPClientReadServerGreeting(
	OWPControl	cntrl,		/* cntrl state structure	*/
	u_int32_t	*mode,		/* modes available - returned	*/
	OWPByte		*challenge,	/* challenge - returned		*/
	OWPErrSeverity	*err_ret	/* error - returned		*/
)
{
	char	buf[32];

	*err_ret = OWPErrOK;

	if(_OWPReadn(cntrl->sockfd,buf,32) != 32){
		*err_ret = OWPErrFATAL;
		return 1;
	}

	/*
	 * First 12 octets ignored...
	 * (0-11)
	 */

	/*
	 * Next 4 octets represent a 4 byte integer indicating mode.
	 * (12-15)
	 */
	*mode = ntohl(*((u_int32_t *)&buf[12]));

	/*
	 * Next 16 octets are the challenge - binary byte data so
	 * no byte reordering is necessary.
	 * (16-31)
	 */
	memcpy(challenge,&buf[16],16);

	return 0;
}

/*
 * Function:	_OWPClientRequestModeReadResponse
 *
 * Description:	
 * 		Called to requst the control communication mode. To do this
 * 		the client sends a token (challenge from server concatenated
 * 		with a client chosen session key) and the client-IV if needed
 * 		by the mode chosen. This function returns after it reads
 * 		the server response.
 *
 * Returns:	
 */
int
_OWPClientRequestModeReadResponse(
	OWPControl	cntrl,
	OWPByte		*token,
	OWPErrSeverity	*err_ret
)
{
	/*
	 * TODO:Ensure Stas actually changed KID to 8 octets - otherwise this
	 * buffer is the wrong size!
	 */
	char	buf[60];
	OWPByte	accept_session;

	*err_ret = OWPErrOK;

	*(u_int32_t *)&buf[0] = htonl(cntrl->mode);

	if(cntrl->kid)
		memcpy(&buf[4],cntrl->kid,8);
	else
		random_bytes(&buf[4],8);

	memcpy(&buf[12],token,32);
	memcpy(&buf[44],cntrl->writeIV,16);

	if(_OWPWriten(cntrl->sockfd,buf,60) != 60){
		*err_ret = OWPErrFATAL;
		return -1;
	}

	/*
	 * Now - read response...
	 */
	if(_OWPReadn(cntrl->sockfd,buf,32) != 32){
		*err_ret = OWPErrFATAL;
		return -1;
	}

	accept_session = *((OWPByte *)&buf[15]);

	if(accept_session){
		OWPError(cntrl->ctx,OWPErrFATAL,accept_session,
				"Server denied session:%M");
		return -1;
	}

	memcpy(cntrl->readIV,&buf[16],16);

	return 0;
}
