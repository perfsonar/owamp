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
**			speak the owamp protocol directly.
**			(i.e. read and write the data and save it
**			to structures for the rest of the api to deal
**			with.)
**
**			The idea is to basically keep all network ordering
**			architecture dependant things in this file. And
**			hopefully to minimize the impact of any changes
**			to the actual protocol message formats.
**
**			The message templates are here for convienent
**			reference for byte offsets in the code - for
**			explainations of the fields please see the
**			relevant specification document.
**			(currently draft-ietf-ippm-owdp-03.txt)
**
**			(ease of referenceing byte offsets is also why
**			the &buf[BYTE] notation is being used.)
*/

#include <I2util/util.h>

#include <owampP.h>

/*
 * 	ServerGreeting message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                                                               |
 *	04|                      Unused (12 octets)                       |
 *	08|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|                            Modes                              |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                     Challenge (16 octets)                     |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
_OWPWriteServerGreeting(
	OWPControl	cntrl,
	u_int32_t	avail_modes,
	u_int8_t	*challenge	/* [16] */
	)
{
	/*
	 * buf_aligned it to ensure u_int32_t alignment, but I use
	 * buf for actuall assignments to make the array offsets agree with
	 * the byte offsets shown above.
	 */
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	/*
	 * Set unused bits to 0.
	 */
	memset(buf,0,12);

	*((u_int32_t *)&buf[12]) = htonl(avail_modes);
	memcpy(&buf[16],challenge,16);
	if(_OWPWriten(cntrl->sockfd,buf,32) != 32)
		return OWPErrFATAL;

	return OWPErrOK;
}

int
_OWPReadServerGreeting(
	OWPControl	cntrl,
	u_int32_t	*mode,		/* modes available - returned	*/
	u_int8_t	*challenge	/* [16] : challenge - returned	*/
)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;


	if(_OWPReadn(cntrl->sockfd,buf,32) != 32){
		return (int)OWPErrFATAL;
	}

	*mode = ntohl(*((u_int32_t *)&buf[12]));
	memcpy(challenge,&buf[16],16);

	return OWPErrOK;
}

/*
	 * TODO:Ensure Stas actually changed KID to 8 octets - otherwise this
	 * message is the wrong size!
 *
 *
 * 	ClientGreeting message format:
 *
 * 	size: 60 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                             Mode                              |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                              KID                              |
 *	08|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|                                                               |
 *	16|                                                               |
 *	20|                                                               |
 *	24|                       Token (32 octets)                       |
 *	28|                                                               |
 *	32|                                                               |
 *	36|                                                               |
 *	40|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	44|                                                               |
 *	48|                     Client-IV (16 octets)                     |
 *	52|                                                               |
 *	56|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
_OWPWriteClientGreeting(
	OWPControl	cntrl,
	u_int8_t	*token	/* [32]	*/
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	*(u_int32_t *)&buf[0] = htonl(cntrl->mode);

	if(cntrl->kid)
		memcpy(&buf[4],cntrl->kid,8);
	else
		I2RandomBytes(&buf[4],8);

	memcpy(&buf[12],token,32);
	memcpy(&buf[44],cntrl->writeIV,16);

	if(_OWPWriten(cntrl->sockfd,buf,60) != 60)
		return OWPErrFATAL;

	return OWPErrOK;
}

int
_OWPReadClientGreeting(
	OWPControl	cntrl,
	u_int32_t	*mode,
	u_int8_t	*token,		/* [32] - return	*/
	u_int8_t	*clientIV	/* [16] - return	*/
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(_OWPReadn(cntrl->sockfd,buf,60) != 60)
		return OWPErrFATAL;

	*mode = ntohl(*(u_int32_t *)&buf[0]);
	memcpy(cntrl->kid_buffer,&buf[4],8);
	memcpy(token,&buf[12],32);
	memcpy(clientIV,&buf[44],16);

	return OWPErrOK;
}

static OWPAcceptType
GetAcceptType(
	OWPControl	cntrl,
	u_int8_t	val
	)
{
	switch(val){
		case _OWP_CNTRL_ACCEPT:
			return _OWP_CNTRL_ACCEPT;
		case _OWP_CNTRL_REJECT:
			return _OWP_CNTRL_REJECT;
		default:
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
							"GetAcceptType");
			return _OWP_CNTRL_INVALID;
	}
}

/*
 * 	ServerOK message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                                                               |
 *	04|                      Unused (15 octets)                       |
 *	08|                                                               |
 *	  +                                               +-+-+-+-+-+-+-+-+
 *	12|                                               |   Accept      |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                     Server-IV (16 octets)                     |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
_OWPWriteServerOK(
	OWPControl	cntrl,
	OWPAcceptType	code
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	memset(&buf[0],0,15);
	*(u_int8_t *)&buf[15] = code & 0x0ff;
	memcpy(&buf[16],cntrl->writeIV,16);
	if(_OWPSendBlocks(cntrl, buf, 2) == 0)
		return OWPErrOK;
	return OWPErrFATAL;
}
int
_OWPReadServerOK(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval	/* ret	*/
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(_OWPReadn(cntrl->sockfd,buf,32) != 32)
		return OWPErrFATAL;

	*acceptval = GetAcceptType(cntrl,buf[15]);
	if(*acceptval == _OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	memcpy(cntrl->readIV,&buf[16],16);

	return OWPErrOK;
}

/*
 * This function is called on the server side to read the first block
 * of client requests. The remaining read request messages MUST be called
 * next!.
 */
u_int8_t
OWPReadRequestType(
	OWPControl	cntrl
	)
{
	int	msgtype;

	if(!_OWPStateIsRequest(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"OWPReadRequestType:called in wrong state.");
		return 0;
	}

	/* Read one block so we can peek at the message type */
	if (_OWPReceiveBlocks(cntrl, (u_int8_t*)cntrl->msg, 1) != 0)
		return 0;	

	msgtype = *(u_int8_t*)cntrl->msg;

	/*
	 * Not all requests are allowed during a test.
	 */
	if(_OWPStateIs(_OWPStateTest,cntrl) && (msgtype < 3)){
		cntrl->state = _OWPStateInvalid;
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"OWPReadRequestType:Invalid request from client.");
		return 0;
	}

	switch(msgtype){
		/*
		 * TestRequest
		 */
		case	1:
			cntrl->state |= _OWPStateReadingTestRequest;
			break;
		case	2:
			cntrl->state |= _OWPStateReadingStartSessions;
			break;
		case	3:
			cntrl->state |= _OWPStateReadingStopSessions;
			break;
		case	4:
			cntrl->state |= _OWPStateReadingRetrieveSession;
			break;
		default:
			cntrl->state = _OWPStateInvalid;
			return 0;
	}

	return *(u_int8_t *)(cntrl->msg);
}

/*
 * 	TestRequest message format:
 *
 * 	size: 96 octets
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
 */
int
_OWPWriteTestRequest(
	OWPControl	cntrl,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	OWPBoolean	server_conf_sender,
	OWPBoolean	server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*test_spec
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;
	u_int8_t		version;
	OWPTestSpecPoisson	*ptest;

	if(!server_conf_sender && !server_conf_receiver){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPWriteTestRequest:Request for empty config?");
		return OWPErrFATAL;
	}

	if(sender->sa_family != receiver->sa_family){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
					"Address Family mismatch");
		return OWPErrFATAL;
	}

	/*
	 * Figure out what style of addresses we are using.
	 */
	switch (sender->sa_family){
		case AF_INET:
			version = 4;
			break;
#ifdef	AF_INET6
		case AF_INET6:
			version = 6;
			break;
#endif
		default:
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
					"Invalid IP Address Family");
			return OWPErrFATAL;
	}

	if(test_spec->test_type != OWPTestPoisson){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"Invalid test distribution function");
		return OWPErrFATAL;
	}
	ptest = (OWPTestSpecPoisson*)test_spec;

	*(u_int8_t*)&buf[0] = 1;	/* Request-Session message # */
	*(u_int8_t*)&buf[1] = (version<<4) | version;
	*(u_int8_t*)&buf[2] = (server_conf_sender)?1:0;
	*(u_int8_t*)&buf[3] = (server_conf_receiver)?1:0;

	switch(version){
	struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
	struct sockaddr_in6	*saddr6;
		case 6:
			/* sender address  and port */
			saddr6 = (struct sockaddr_in6*)sender;
			memcpy(&buf[4],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[36] = saddr6->sin6_port;

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver;
			memcpy(&buf[20],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[38] = saddr6->sin6_port;

			break;
#endif
		case 4:
			/* sender address and port  */
			saddr4 = (struct sockaddr_in*)sender;
			*(u_int32_t*)&buf[4] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[36] = saddr4->sin_port;

			/* receiver address and port  */
			saddr4 = (struct sockaddr_in*)receiver;
			*(u_int32_t*)&buf[20] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[38] = saddr4->sin_port;

			break;
		default:
			/*
			 * This can't happen, but default keeps compiler
			 * warnings away.
			 */
			break;
	}

	if(sid)
		memcpy(&buf[40],sid,16);

	*(u_int32_t*)&buf[56] = htonl(ptest->InvLambda);
	*(u_int32_t*)&buf[60] = htonl(ptest->npackets);
	*(u_int32_t*)&buf[64] = htonl(ptest->packet_size_padding);

	/*
	 * timestamp...
	 */
	OWPEncodeTimeStamp((u_int32_t*)&buf[68],&ptest->start_time);

	*(u_int32_t*)&buf[76] = htonl(ptest->typeP);

	memset(&buf[80],0,16);

	/*
	 * Now - send the request!
	 */
	if(_OWPSendBlocks(cntrl,buf,6) != 0)
		return OWPErrFATAL;

	return OWPErrOK;
}

int
_OWPReadTestRequest(
	OWPControl	cntrl,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	socklen_t	*socklen,
	u_int8_t	*ipvn,
	OWPBoolean	*server_conf_sender,
	OWPBoolean	*server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*test_spec
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;
	OWPTestSpecPoisson	*ptest;

	if(!_OWPStateIs(_OWPStateReadingTestRequest,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadTestRequest called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_TEST_REQUEST_BLK_LEN-1) != 0){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[80],16)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadTestRequest:Invalid zero padding");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_OWPStateReadingTestRequest;
	cntrl->state |= _OWPStateTestAccept;

	*ipvn = buf[1] >> 4;
	if(*ipvn != (buf[1] & 0x0f)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"Test request has incompatible address versions...");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	switch(buf[2]){
		case 0:
			*server_conf_sender = False;
			break;
		case 1:
			*server_conf_sender = True;
			break;
		default:
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadTestRequest:Invalid Conf-Sender (%d)",buf[1]);
			cntrl->state = _OWPStateInvalid;
			return OWPErrFATAL;
	}
	switch(buf[3]){
		case 0:
			*server_conf_receiver = False;
			break;
		case 1:
			*server_conf_receiver = True;
			break;
		default:
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadTestRequest:Invalid Conf-Sender (%d)",buf[1]);
			cntrl->state = _OWPStateInvalid;
			return OWPErrFATAL;
	}

	switch(*ipvn){
	struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
	struct sockaddr_in6	*saddr6;
		case 6:
			if(*socklen < sizeof(struct sockaddr_in6)){
				OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadTestRequest:socklen not big enough (%d < %d)",
					*socklen,sizeof(struct sockaddr_in6));
				*socklen = 0;
				return OWPErrFATAL;
			}
			*socklen = sizeof(struct sockaddr_in6);

			/* sender address  and port */
			saddr6 = (struct sockaddr_in6*)sender;
			memcpy(saddr6->sin6_addr.s6_addr,&buf[4],16);
			saddr6->sin6_port = *(u_int16_t*)&buf[36];

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver;
			memcpy(saddr6->sin6_addr.s6_addr,&buf[20],16);
			saddr6->sin6_port = *(u_int16_t*)&buf[38];

			break;
#endif
		case 4:
			if(*socklen < sizeof(struct sockaddr_in)){
				*socklen = 0;
				OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadTestRequest:socklen not big enough (%d < %d)",
					*socklen,sizeof(struct sockaddr_in));
				return OWPErrFATAL;
			}
			*socklen = sizeof(struct sockaddr_in);

			/* sender address and port  */
			saddr4 = (struct sockaddr_in*)sender;
			*(u_int32_t*)&buf[4] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[36] = saddr4->sin_port;

			/* receiver address and port  */
			saddr4 = (struct sockaddr_in*)receiver;
			*(u_int32_t*)&buf[20] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[38] = saddr4->sin_port;

			break;
		default:
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadTestRequest:Unsupported IP version (%d)",
									*ipvn);
			return OWPErrFATAL;
	}

	memcpy(sid,&buf[40],16);

	/*
	 * We currently only support the poisson test... so this is easy.
	 */
	ptest = (OWPTestSpecPoisson*)test_spec;
	ptest->test_type = OWPTestPoisson;
	ptest->InvLambda = ntohl(*(u_int32_t*)&buf[56]);
	ptest->npackets = ntohl(*(u_int32_t*)&buf[60]);
	ptest->packet_size_padding = ntohl(*(u_int32_t*)&buf[64]);

	/*
	 * timestamp...
	 */
	OWPDecodeTimeStamp(&ptest->start_time,(u_int32_t*)&buf[68]);

	ptest->typeP = ntohl(*(u_int32_t*)&buf[76]);

	return OWPErrOK;
}

/*
 *
 * 	TestAccept message format:
 *
 * 	size: 32 octets
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
 */
int
_OWPWriteTestAccept(
	OWPControl	cntrl,
	OWPAcceptType	acceptval,
	u_int16_t	port,
	OWPSID		sid
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	buf[0] = acceptval & 0xff;
	*(u_int16_t *)&buf[2] = port;
	if(sid)
		memcpy(&buf[4],sid,16);
	memset(&buf[20],0,12);

	if(_OWPSendBlocks(cntrl,buf,3) != 0)
		return OWPErrFATAL;
	return OWPErrOK;
}

int
_OWPReadTestAccept(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval,
	u_int16_t	*port,
	OWPSID		sid
	)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	/*
	 * Get the servers response.
	 */
	if(_OWPReceiveBlocks(cntrl,buf,2) != 0)
		return OWPErrFATAL;

	/*
	 * Check zero padding first.
	 */
	if(memcmp(&buf[20],cntrl->zero,12)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"Invalid Accept-Session message received");
		return OWPErrFATAL;
	}

	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == _OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(port)
		*port = *(u_int16_t*)&buf[2];

	if(sid)
		memcpy(sid,&buf[4],16);

	return OWPErrOK;
}

/*
 *
 * 	StartSessions message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      2        |                                               |
 *	  +-+-+-+-+-+-+-+-+                                               +
 *	04|                      Unused (15 octets)                       |
 *	08|                                                               |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                    Zero Padding (16 octets)                   |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
_OWPWriteStartSessions(
	OWPControl	cntrl
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	buf[0] = 2;
#ifndef	NDEBUG
	memset(&buf[1],0,15);	/* Unused	*/
#endif
	memset(&buf[16],0,16);	/* Zero padding */

	if(_OWPSendBlocks(cntrl,buf,2) != 0)
		return OWPErrFATAL;
	return OWPErrOK;
}

int
_OWPReadStartSessions(
	OWPControl	cntrl
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	if(!_OWPStateIs(_OWPStateReadingStartSessions,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadStartSessions called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_STOP_SESSIONS_BLK_LEN-1) != 0){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadTestRequest:Invalid zero padding");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(buf[0] != 2){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadStartSessions:Not a StartSessions message...");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_OWPStateReadingStartSessions;
	cntrl->state |= _OWPStateControlAck;

	return OWPErrOK;
}

/*
 *
 * 	StopSessions message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      3        |    Accept     |                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *	04|                       Unused (14 octets)                      |
 *	08|                                                               |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                    Zero Padding (16 octets)                   |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
_OWPWriteStopSessions(
	OWPControl	cntrl,
	OWPAcceptType	acceptval
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!(_OWPStateIs(_OWPStateRequest,cntrl) &&
					_OWPStateIs(_OWPStateTest,cntrl))){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPWriteStopSessions called in wrong state.");
		return OWPErrFATAL;
	}

	buf[0] = 3;
	buf[1] = acceptval & 0xff;
#ifndef	NDEBUG
	memset(&buf[2],0,14);	/* Unused	*/
#endif
	memset(&buf[16],0,16);	/* Zero padding */

	if(_OWPSendBlocks(cntrl,buf,_OWP_STOP_SESSIONS_BLK_LEN) != 0)
		return OWPErrFATAL;
	return OWPErrOK;
}

int
_OWPReadStopSessions(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	if(!(_OWPStateIs(_OWPStateRequest,cntrl) &&
					_OWPStateIs(_OWPStateTest,cntrl))){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadStopSessions called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_STOP_SESSIONS_BLK_LEN-1) != 0){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadControlAck:Invalid zero padding");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}
	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == _OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_OWPStateControlAck;
	cntrl->state |= _OWPStateRequest;

	return OWPErrOK;
}

/*
 * TODO: Make sure the format of this message is correct - it was not
 * 	clear in the first version of the spec - (I modified it to be
 * 	a multiple of 16 octets - a requirement for AES). In the spec,
 * 	Unused was shown as 17 - but that made no sense.)
 *
 * 	RetrieveSession message format:
 *
 * 	size: 48 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      4        |                                               |
 *	  +-+-+-+-+-+-+-+-+                                               +
 *	04|                      Unused (7 octets)                        |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                         Begin Seq                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|                          End Seq                              |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                        SID (16 octets)                        |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	32|                                                               |
 *	36|                    Zero Padding (16 octets)                   |
 *	40|                                                               |
 *	44|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
_OWPWriteRetrieveSession(
	OWPControl	cntrl,
	u_int32_t	begin,
	u_int32_t	end,
	OWPSID		sid
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_OWPStateIs(_OWPStateRequest,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPWriteRetrieveSession called in wrong state.");
		return OWPErrFATAL;
	}

	buf[0] = 4;
#ifndef	NDEBUG
	memset(&buf[1],0,7);	/* Unused	*/
#endif
	*(u_int32_t*)&buf[8] = begin;
	*(u_int32_t*)&buf[12] = end;
	memcpy(&buf[16],sid,16);
	memset(&buf[32],0,16);	/* Zero padding */

	if(_OWPSendBlocks(cntrl,buf,_OWP_RETRIEVE_SESSION_BLK_LEN) != 0)
		return OWPErrFATAL;
	return OWPErrOK;
}

int
_OWPReadRetrieveSession(
	OWPControl	cntrl,
	u_int32_t	*begin,
	u_int32_t	*end,
	OWPSID		sid
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	if(!_OWPStateIs(_OWPStateReadingRetrieveSession,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadRetrieveSession called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_RETRIEVE_SESSION_BLK_LEN-1)
									!= 0){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[32],16)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadRetrieveSession:Invalid zero padding");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}
	if(buf[0] != 4){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadRetrieveSession:Invalid message...");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	*begin = *(u_int32_t*)&buf[8];
	*end = *(u_int32_t*)&buf[12];
	memcpy(sid,&buf[16],16);

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_OWPStateReadingRetrieveSession;
	cntrl->state |= _OWPStateControlAck;

	return OWPErrOK;
}

/*
 *
 * 	ControlAck message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|     Accept    |                                               |
 *	  +-+-+-+-+-+-+-+-+                                               +
 *	04|                      Unused (15 octets)                       |
 *	08|                                                               |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                    Zero Padding (16 octets)                   |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
_OWPWriteControlAck(
	OWPControl	cntrl,
	OWPAcceptType	acceptval
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_OWPStateIs(_OWPStateControlAck,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPWriteControlAck called in wrong state.");
		return OWPErrFATAL;
	}

	buf[0] = acceptval & 0xff;
#ifndef	NDEBUG
	memset(&buf[1],0,15);	/* Unused	*/
#endif
	memset(&buf[16],0,16);	/* Zero padding */

	if(_OWPSendBlocks(cntrl,buf,_OWP_CONTROL_ACK_BLK_LEN) != 0)
		return OWPErrFATAL;
	return OWPErrOK;
}

int
_OWPReadControlAck(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	if(!_OWPStateIs(_OWPStateControlAck,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadControlAck called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_CONTROL_ACK_BLK_LEN-1) != 0){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadControlAck:Invalid zero padding");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}
	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == _OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_OWPStateControlAck;
	cntrl->state |= _OWPStateRequest;

	return OWPErrOK;
}

/*
 * TODO:Send session data functions...
 */
