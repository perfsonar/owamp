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

	if(!_OWPStateIsInitial(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPWriteServerGreeting:called in wrong state.");
		return OWPErrFATAL;
	}
	/*
	 * Set unused bits to 0.
	 */
	memset(buf,0,12);

	*((u_int32_t *)&buf[12]) = htonl(avail_modes);
	memcpy(&buf[16],challenge,16);
	if(OWPWriten(cntrl->sockfd,buf,32) != 32)
		return OWPErrFATAL;

	cntrl->state = _OWPStateSetup;

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

	if(!_OWPStateIsInitial(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadServerGreeting:called in wrong state.");
		return OWPErrFATAL;
	}

	if(OWPReadn(cntrl->sockfd,buf,32) != 32){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Read failed:(%s)",strerror(errno));
		return (int)OWPErrFATAL;
	}

	*mode = ntohl(*((u_int32_t *)&buf[12]));
	memcpy(challenge,&buf[16],16);

	cntrl->state = _OWPStateSetup;

	return OWPErrOK;
}

/*
	 * TODO:Ensure Stas actually changed KID to 8 octets - otherwise this
	 * message is the wrong size!
 *
 *
 * 	ClientGreeting message format:
 *
 * 	size: 68 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                             Mode                              |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                              KID                              |
 *	08|                                                               |
 *	12|                                                               |
 *	16|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	20|                                                               |
 *	24|                       Token (32 octets)                       |
 *	28|                                                               |
 *	32|                                                               |
 *	36|                                                               |
 *	40|                                                               |
 *	44|                                                               |
 *	48|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	52|                                                               |
 *	56|                     Client-IV (16 octets)                     |
 *	60|                                                               |
 *	64|                                                               |
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

	if(!_OWPStateIsSetup(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPWriteClientGreeting:called in wrong state.");
		return OWPErrFATAL;
	}

	*(u_int32_t *)&buf[0] = htonl(cntrl->mode);

	if(cntrl->kid)
		memcpy(&buf[4],cntrl->kid,16);
	else
		I2RandomBytes(&buf[4],16);

	memcpy(&buf[20],token,32);
	memcpy(&buf[52],cntrl->writeIV,16);

	if(OWPWriten(cntrl->sockfd, buf, 68) != 68)
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

	if(!_OWPStateIsSetup(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadClientGreeting:called in wrong state.");
		return OWPErrFATAL;
	}

	if(OWPReadn(cntrl->sockfd,buf,68) != 68){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Read failed:(%s)",strerror(errno));
		return OWPErrFATAL;
	}

	*mode = ntohl(*(u_int32_t *)&buf[0]);
	memcpy(cntrl->kid_buffer,&buf[4],16);
	memcpy(token,&buf[20],32);
	memcpy(clientIV,&buf[52],16);

	return OWPErrOK;
}

static OWPAcceptType
GetAcceptType(
	OWPControl	cntrl,
	u_int8_t	val
	)
{
	switch(val){
		case OWP_CNTRL_ACCEPT:
			return OWP_CNTRL_ACCEPT;
		case OWP_CNTRL_REJECT:
			return OWP_CNTRL_REJECT;
		case OWP_CNTRL_FAILURE:
			return OWP_CNTRL_FAILURE;
		case OWP_CNTRL_UNSUPPORTED:
			return OWP_CNTRL_UNSUPPORTED;
		default:
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
					"GetAcceptType:Invalid val %u",val);
			return OWP_CNTRL_INVALID;
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

	if(!_OWPStateIsSetup(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPWriteServerOK:called in wrong state.");
		return OWPErrFATAL;
	}

	memset(&buf[0],0,15);
	*(u_int8_t *)&buf[15] = code & 0x0ff;
	memcpy(&buf[16],cntrl->writeIV,16);
	if(OWPWriten(cntrl->sockfd,buf,32) != 32)
		return OWPErrFATAL;

	cntrl->state = _OWPStateRequest;

	return OWPErrOK;
}
int
_OWPReadServerOK(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval	/* ret	*/
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_OWPStateIsSetup(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadServerOK:called in wrong state.");
		return OWPErrFATAL;
	}

	if(OWPReadn(cntrl->sockfd,buf,32) != 32){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Read failed:(%s)",strerror(errno));
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	*acceptval = GetAcceptType(cntrl,buf[15]);
	if(*acceptval == OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	memcpy(cntrl->readIV,&buf[16],16);

	cntrl->state = _OWPStateRequest;

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
	u_int8_t	msgtype;
	int		n;

	if(!_OWPStateIsRequest(cntrl) || _OWPStateIsReading(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"OWPReadRequestType:called in wrong state.");
		return 0;
	}

	/* Read one block so we can peek at the message type */
	if((n = _OWPReceiveBlocks(cntrl, (u_int8_t*)cntrl->msg, 1)) != 1)
		return n;	

	msgtype = *(u_int8_t*)cntrl->msg;

	/*
	 * StopSessions(3) message is only allowed during active tests,
	 * and it is the only message allowed during active tests.
	 */
	if((_OWPStateIs(_OWPStateTest,cntrl) && (msgtype != 3)) ||
			(_OWPStateIs(_OWPStateTest,cntrl) && (msgtype == 3))){
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
			cntrl->state |= _OWPStateTestRequest;
			break;
		case	2:
			cntrl->state |= _OWPStateStartSessions;
			break;
		case	3:
			cntrl->state |= _OWPStateStopSessions;
			break;
		case	4:
			cntrl->state |= _OWPStateRetrieveSession;
			break;
		default:
			cntrl->state = _OWPStateInvalid;
			return 0;
	}

	return msgtype;
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

	if(!_OWPStateIsRequest(cntrl) || _OWPStateIsPending(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPWriteTestRequest:called in wrong state.");
		return OWPErrFATAL;
	}

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
	if(_OWPSendBlocks(cntrl,buf,6) != 6){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	cntrl->state |= _OWPStateTestAccept;

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

	if(!_OWPStateIs(_OWPStateTestRequest,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadTestRequest called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_TEST_REQUEST_BLK_LEN-1) != 
			(_OWP_TEST_REQUEST_BLK_LEN-1)){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[80],16)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadTestRequest:Invalid zero padding");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

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
			"_OWPReadTestRequest:Invalid Conf-Sender (%d)",buf[2]);
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
			"_OWPReadTestRequest:Invalid Conf-Receiver (%d)",
					buf[3]);
			cntrl->state = _OWPStateInvalid;
			return OWPErrFATAL;
	}

	if(!*server_conf_sender && !*server_conf_receiver){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadTestRequest:Invalid null request");
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
			saddr6->sin6_family = AF_INET6;
			memcpy(saddr6->sin6_addr.s6_addr,&buf[4],16);
			if(*server_conf_sender)
				saddr6->sin6_port = 0;
			else
				saddr6->sin6_port = *(u_int16_t*)&buf[36];

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver;
			saddr6->sin6_family = AF_INET6;
			memcpy(saddr6->sin6_addr.s6_addr,&buf[20],16);
			if(*server_conf_receiver)
				saddr6->sin6_port = 0;
			else
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
			saddr4->sin_family = AF_INET;
			saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[4];
			if(*server_conf_sender)
				saddr4->sin_port = 0;
			else
				saddr4->sin_port = *(u_int16_t*)&buf[36];

			/* receiver address and port  */
			saddr4 = (struct sockaddr_in*)receiver;
			saddr4->sin_family = AF_INET;
			saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[20];
			if(*server_conf_receiver)
				saddr4->sin_port = 0;
			else
				saddr4->sin_port = *(u_int16_t*)&buf[38];

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

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_OWPStateTestRequest;
	cntrl->state |= _OWPStateTestAccept;

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

	if(!_OWPStateIs(_OWPStateTestAccept,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPWriteTestAccept called in wrong state.");
		return OWPErrFATAL;
	}

	buf[0] = acceptval & 0xff;
	*(u_int16_t *)&buf[2] = port;
	if(sid)
		memcpy(&buf[4],sid,16);
	memset(&buf[20],0,12);

	if(_OWPSendBlocks(cntrl,buf,2) != 2){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	cntrl->state &= ~_OWPStateTestAccept;

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

	if(!_OWPStateIs(_OWPStateTestAccept,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadTestAccept called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Get the servers response.
	 */
	if(_OWPReceiveBlocks(cntrl,buf,2) != 2){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/*
	 * Check zero padding first.
	 */
	if(memcmp(&buf[20],cntrl->zero,12)){
		cntrl->state = _OWPStateInvalid;
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"Invalid Accept-Session message received");
		return OWPErrFATAL;
	}

	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(port)
		*port = *(u_int16_t*)&buf[2];

	if(sid)
		memcpy(sid,&buf[4],16);

	cntrl->state &= ~_OWPStateTestAccept;

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

	if(!_OWPStateIsRequest(cntrl) || _OWPStateIsPending(cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPWriteStartSessions:called in wrong state.");
		return OWPErrFATAL;
	}

	buf[0] = 2;	/* start-session identifier	*/
#ifndef	NDEBUG
	memset(&buf[1],0,15);	/* Unused	*/
#endif
	memset(&buf[16],0,16);	/* Zero padding */

	if(_OWPSendBlocks(cntrl,buf,2) != 2){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	cntrl->state |= _OWPStateControlAck;
	return OWPErrOK;
}

int
_OWPReadStartSessions(
	OWPControl	cntrl
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	if(!_OWPStateIs(_OWPStateStartSessions,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadStartSessions called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_STOP_SESSIONS_BLK_LEN-1) !=
					(_OWP_STOP_SESSIONS_BLK_LEN-1) ){
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
	cntrl->state &= ~_OWPStateStartSessions;
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

	if(_OWPSendBlocks(cntrl,buf,2) != 2)
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
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_STOP_SESSIONS_BLK_LEN-1) !=
				(_OWP_STOP_SESSIONS_BLK_LEN-1)){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPReadStopSessions:Invalid zero padding");
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}
	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_OWPStateStopSessions;
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

	if(_OWPSendBlocks(cntrl,buf,3) != 3)
		return OWPErrFATAL;

	cntrl->state |= (_OWPStateControlAck | _OWPStateFetch);
	cntrl->state &= ~(_OWPStateRequest);
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

	if(!_OWPStateIs(_OWPStateRetrieveSession,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			"_OWPReadRetrieveSession called in wrong state.");
		return OWPErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_RETRIEVE_SESSION_BLK_LEN-1)
					!= (_OWP_RETRIEVE_SESSION_BLK_LEN-1)){
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
	cntrl->state &= ~_OWPStateRetrieveSession;
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

	if(_OWPSendBlocks(cntrl,buf,2) != 2)
		return OWPErrFATAL;

	cntrl->state &= ~_OWPStateControlAck;
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
	if(_OWPReceiveBlocks(cntrl,&buf[16],_OWP_CONTROL_ACK_BLK_LEN-1) != 
					(_OWP_CONTROL_ACK_BLK_LEN-1)){
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
	if(*acceptval == OWP_CNTRL_INVALID){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/* If FetchRequest was rejected get back into StateRequest */
	if (_OWPStateIsFetch(cntrl) && (*acceptval != OWP_CNTRL_ACCEPT)){
		cntrl->state &= ~(_OWPStateFetch);
		cntrl->state |= _OWPStateRequest;
	}

	cntrl->state &= ~_OWPStateControlAck;

	return OWPErrOK;
}

/*
** During Fetch session, read the first 16 bytes of data transmission.
** Save the promised number of records into *num_rec.
*/
int
_OWPReadDataHeader(OWPControl cntrl, u_int32_t *num_rec)
{
	u_int8_t *buf = (u_int8_t*)cntrl->msg;
	u_int8_t *tmp;
	int i;

	if(!_OWPStateIs(_OWPStateFetch,cntrl)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			 "_OWPReadDataHeader called in wrong state.");
		return OWPErrFATAL;
	};

	if(_OWPReceiveBlocks(cntrl, buf, 1) != 1){
		cntrl->state = _OWPStateInvalid;
		return OWPErrFATAL;
	}

	/* Check for 8 bytes of zero padding. */
	tmp = &buf[8];
	for (i = 0; i < 8; i++) {
		if (*tmp) {
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
			    "Non-zero padding in data header sent by server.");
			return OWPErrFATAL;
		}
	}

	*num_rec = ntohl(*(u_int32_t *)buf);
	
	/*
	  XXX - Type-P descriptor (octets 8-11)
	*/
	
	return OWPErrOK;
}

/*
 * TODO:Send session data functions...
 */
