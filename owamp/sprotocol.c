
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
**	Date:		Wed Apr  24 10:42:12  2002
**
**	Description:	This file contains the private functions that
**			speak the owamp protocol directly from the
**			server point of view.
**			(i.e. read and write the data and save it
**			to structures for the rest of the api to deal
**			with.)
**
**			The idea is to basically keep all network ordering
**			architecture dependant things in this file.
*/
#include <owampP.h>

int
_OWPServerSendServerGreeting(
       OWPControl cntrl,          /* cntrl state structure  */
       u_int32_t	mode,	  /* modes available        */
       OWPErrSeverity	*err_ret  /* error - returned       */
)
{
	char buf[MAX_MSG];
	memset(buf, 0, sizeof(buf));
	*(int32_t *)(buf + 12) = htonl(mode); /* first 12 bytes unused */

	/* generate 16 random bytes and save them away. */
	random_bytes(cntrl->challenge, 16);
	memcpy(buf + 16, cntrl->challenge, 16); /* the last 16 bytes */

	return 0;
}
