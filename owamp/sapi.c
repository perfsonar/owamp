/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		sapi.c
 *
 *	Author:		Anatoly Karp
 *			Jeff W. Boote
 *			Internet2
 *
 *	Date:		Sun Jun 02 11:40:27 MDT 2002
 *
 *	Description:	
 *
 *	This file contains the api functions typically called from an
 *	owamp server application.
 */
#include "./owampP.h"

#define IS_LEGAL_MODE(x) ((x) == OWP_MODE_OPEN | (x) == OWP_MODE_AUTHENTICATED | (x) == OWP_MODE_ENCRYPTED)

/*
 * Function:	OWPControlAccept
 *
 * Description:	
 * 		Used by the server to talk the protocol until
 *              a Control Connection has been established, or
 *              rejected, or error occurs.
 *           
 * In Args:	
 *
 * Returns:	Valid OWPControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
OWPControl
OWPControlAccept(
		 OWPContext     ctx,       /* control context               */
		 u_int32_t      mode_offered,/* advertised server mode      */
		 int            connfd,    /* connected socket              */
		 void*          app_data,  /* policy                        */
		 OWPErrSeverity *err_ret   /* err - return                  */
)
{
	char challenge[16];

	char buf[MAX_MSG]; /* used to send and receive messages */
	char token[32];
	char *class;
	OWPControl cntrl;
	*err_ret = OWPErrOK;
	if ( !(cntrl = _OWPControlAlloc(ctx, err_ret)))
		return NULL;

	cntrl->sockfd = connfd;
	cntrl->server = True;
	/* XXX TODO:
	   OWPAddr			remote_addr;
	   OWPAddr			local_addr;
	*/

	/* Compose Server greeting. */
	memset(buf, 0, sizeof(buf));
	*(u_int32_t *)(buf + 12) = htonl(mode_offered);

	/* generate 16 random bytes of challenge and save them away. */
	I2RandomBytes(challenge, 16);
	memcpy(buf + 16, challenge, 16); /* the last 16 bytes */
	
	if (_OWPSendBlocks(cntrl, buf, 2) < 0){
		*err_ret = OWPErrFATAL;
		OWPControlClose(cntrl);
		return NULL;
	}

	/* Read client greeting */
	if (_OWPReadn(cntrl->sockfd, buf, 60) != 60){
		*err_ret = OWPErrFATAL;
		OWPControlClose(cntrl);
		return NULL;
	}

	cntrl->mode = ntohl(*(u_int32_t *)buf); /* requested mode */
	
	/* insure that exactly one is chosen */
	if ( ! IS_LEGAL_MODE(cntrl->mode)){
		*err_ret = OWPErrFATAL;
		OWPControlClose(cntrl);
		return NULL;
	}

	if (cntrl->mode & ~mode_offered){ /* can't provide requested mode */
		if (_OWPServerOK(cntrl, CTRL_REJECT) < 0)
			*err_ret = OWPErrFATAL;
		OWPControlClose(cntrl);
		return NULL;
	}
	
	if (cntrl->mode & (OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)){
		OWPByte binKey[16];
		
		memcpy(cntrl->kid_buffer, buf + 4, 8); /* 8 bytes of kid */
		cntrl->kid = cntrl->kid_buffer;
		
		/* Fetch the encryption key into binKey */
		if(!_OWPCallGetAESKey(cntrl->ctx, buf + 4, binKey, err_ret)){
			if(*err_ret != OWPErrOK){
				*err_ret = OWPErrFATAL;
				OWPControlClose(cntrl);
				return NULL;
			}
		}
		
		if (OWPDecryptToken(binKey, buf + 12, token) < 0){
			OWPControlClose(cntrl);
			return NULL;
		}
		
		/* Decrypted challenge is in the first 16 bytes */
		if (memcmp(challenge, token, 16) != 0){
			_OWPServerOK(cntrl, CTRL_REJECT);
			OWPControlClose(cntrl);
			return NULL;
		}
		
		/* Authentication ok - determine usage class now.*/
		if (_OWPCallCheckControlPolicy(
			   cntrl->ctx, cntrl->mode, cntrl->kid, 
			   /* cntrl->local_addr, cntrl->remote_addr, */
			   NULL, NULL,
			   err_ret) == False){
			_OWPServerOK(cntrl, CTRL_REJECT);
			OWPControlClose(cntrl);
			return NULL;
		}	
			
		I2RandomBytes(cntrl->writeIV, 16);

		/* Save 16 bytes of session key and 16 bytes of client IV*/
		memcpy(cntrl->session_key, token + 16, 16);
		memcpy(cntrl->readIV, buf + 44, 16);
		_OWPMakeKey(cntrl, cntrl->session_key); 
	} else { /* mode_req == OPEN */
		if (_OWPCallCheckControlPolicy(
			   cntrl->ctx, cntrl->mode, cntrl->kid, 
			   /* cntrl->local_addr, cntrl->remote_addr, */
			   NULL, NULL,
			   err_ret) == False){
			_OWPServerOK(cntrl, CTRL_REJECT);
			OWPControlClose(cntrl);
			return NULL;		
		}
	}
	
	/* Apparently everything is ok. Accept the Control session. */
	_OWPServerOK(cntrl, CTRL_ACCEPT);

	cntrl->state = _OWPStateRequest;
	return cntrl;
}
