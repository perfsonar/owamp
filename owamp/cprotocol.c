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
#include <sys/socket.h>
#include <netinet/in.h>

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

/*
 * Function:	_OWPClientRequestTestReadResponse
 *
 * Description:	
 * 		Called to requst a specific test. Returns accept value.
 *
 * 		The format of a TestRequest message is as follows:
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      1        |IPVN-S | IPVN-R| Conf-Sender   | Conf-Receiver |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                        Sender Address                         |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|              Sender Address (cont.) or Unused                 |
 *	12|                                                               |
 *	16|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	20|                        Receiver Address                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	24|              Receiver Address (cont.) or Unused               |
 *	28|                                                               |
 *	32|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	36|          Sender Port          |         Receiver Port         |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	40|                                                               |
 *	44|                        SID (16 octets)                        |
 *	48|                                                               |
 *	52|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	56|                          Inv-Lambda                           |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	60|                            Packets                            |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	64|                          Padding Length                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	68|                            Start Time                         |
 *	72|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	76|                         Type-P Descriptor                     |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	80|                                                               |
 *	84|                      Zero Padding (16 octets)                 |
 *	88|                                                               |
 *	92|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 		The format of an Accept-Session messages is as follows:
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|    Accept     |  Unused       |            Port               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                                                               |
 *	08|                        SID (16 octets)                        |
 *	12|                                                               |
 *	16|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	20|                                                               |
 *	24|                      Zero Padding (12 octets)                 |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *	 Returns:	negative number on error,
 *	 		value of "Accept" from server otherwise.
 *
 *	 		if server_conf_sender && !server_conf_receiver
 *	 			sets sender->saddr_in[6]->sin[6]_port
 *	 		if server_conf_receiver && !server_conf_sender
 *	 			sets receiver->saddr_in[6]->sin[6]_port
 *
 * 			if server_conf_receiver
 *	 			sets sid
 */
int
_OWPClientRequestTestReadResponse(
	OWPControl	cntrl,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec,
	OWPSID		sid,		/* ret iff conf_receiver else set */
	OWPErrSeverity	*err_ret
)
{
	unsigned char		zero[16] = {0};
	unsigned char		buf[96];
	unsigned char		version;
	OWPTestSpecPoisson	*ptest;
	struct sockaddr_in6	*saddr6;
	struct sockaddr_in	*saddr4;
	int			accept;

	/*
	 * Figure out what style of addresses we are using.
	 */
	switch (sender->saddr->sa_family){
		case AF_INET:
			version = 4;
			break;
		case AF_INET6:
			version = 6;
			break;
		default:
			OWPError(cntrl->ctx,OWPErrWARNING,OWPErrINVALID,
					"Invalid IP Address Family");
			return -1;
	}

	if(test_spec->test_type != OWPTestPoisson){
		OWPError(cntrl->ctx,OWPErrWARNING,OWPErrINVALID,
				"Invalid test distribution function");
		return -1;
	}
	ptest = (OWPTestSpecPoisson*)test_spec;

	*(u_int8_t*)&buf[0] = 1;	/* Request-Session message # */
	*(u_int8_t*)&buf[1] = (version<<4) | version;
	*(u_int8_t*)&buf[2] = (server_conf_sender)?1:0;
	*(u_int8_t*)&buf[3] = (server_conf_receiver)?1:0;

	switch(version){
		case 6:
			/* sender address  and port */
			saddr6 = (struct sockaddr_in6*)sender->saddr;
			memcpy(&buf[4],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[36] = saddr6->sin6_port;

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver->saddr;
			memcpy(&buf[20],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[38] = saddr6->sin6_port;

			break;
		case 4:
			/* sender address and port  */
			saddr4 = (struct sockaddr_in*)sender->saddr;
			*(u_int32_t*)&buf[4] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[36] = saddr4->sin_port;

			/* receiver address and port  */
			saddr4 = (struct sockaddr_in*)receiver->saddr;
			*(u_int32_t*)&buf[20] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[38] = saddr4->sin_port;

			break;
	}

	memcpy(&buf[40],sid,16);
	*(u_int32_t*)&buf[56] = htonl(ptest->InvLambda);
	*(u_int32_t*)&buf[60] = htonl(ptest->npackets);
	*(u_int32_t*)&buf[64] = htonl(ptest->packet_size_padding);

	/*
	 * timestamp...
	 */
	OWPEncodeTimeStamp(&buf[68],&ptest->start_time);

	*(u_int32_t*)&buf[76] = htonl(ptest->typeP);

	memset(&buf[80],0,16);

	/*
	 * Now - send the request!
	 */
	if(_OWPSendBlocks(cntrl,buf,6) != 0)
		return -1;
	
	/*
	 * Get the servers response.
	 */
	if(_OWPReceiveBlocks(cntrl,buf,2) != 0)
		return -1;

	/*
	 * Check zero padding first.
	 */
	if(memcmp(&buf[20],zero,12)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"Invalid Accept-Session message received");
		return -1;
	}

	accept = *(u_int8_t*)&buf[0];

	switch(version){
		case 6:
			if(server_conf_sender && server_conf_receiver)
				break;
			if(server_conf_sender)
				saddr6 = (struct sockaddr_in6*)sender->saddr;
			else
				saddr6 = (struct sockaddr_in6*)receiver->saddr;
			saddr6->sin6_port = *(u_int16_t*)&buf[2];

			break;
		case 4:
			if(server_conf_sender && server_conf_receiver)
				break;
			if(server_conf_sender)
				saddr4 = (struct sockaddr_in*)sender->saddr;
			else
				saddr4 = (struct sockaddr_in*)receiver->saddr;
			saddr4->sin_port = *(u_int16_t*)&buf[2];

			break;
	}

	if(server_conf_receiver)
		memcpy(sid,&buf[4],16);

	return accept;
}

