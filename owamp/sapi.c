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


static OWPAddr
AddrByWildcard(
	OWPContext	ctx
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	OWPAddr		addr;
	int		ai_err;


	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if( (ai_err = getaddrinfo(NULL,OWP_CONTROL_SERVICE_NAME,&hints,&ai)!=0)
								|| !ai){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"getaddrinfo():%s",
							strerror(errno));
		return NULL;
	}

	if( !(addr = _OWPAddrAlloc(ctx))){
		freeaddrinfo(ai);
		return NULL;
	}

	addr->ai = ai;

	return addr;
}

static OWPBoolean
SetServerAddrInfo(
	OWPContext	ctx,
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	int		ai_err;
	char		*port=NULL;

	if(!addr || (addr->fd > -1)){
		*err_ret = OWPErrFATAL;
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,"Invalid address");
		return False;
	}

	if(addr->ai)
		return True;

	if(!addr->node_set){
		*err_ret = OWPErrFATAL;
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,"Invalid address");
		return False;
	}

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(addr->port_set)
		port = addr->port;
	else
		port = OWP_CONTROL_SERVICE_NAME;

	if( (ai_err = getaddrinfo(addr->node,port,&hints,&ai)!=0) || !ai){
		*err_ret = OWPErrFATAL;
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"getaddrinfo():%s",
							strerror(errno));
		return False;
	}
	addr->ai = ai;

	return True;
}

/*
 * This function should only be called on an OWPAddr that already has
 * a fd associated with it.
 */
static OWPBoolean
AddrSetSAddr(
	OWPAddr		addr,
	struct sockaddr	*fromaddr,
	socklen_t	fromaddrlen,
	OWPErrSeverity	*err_ret
	)
{
	int		so_type;
	socklen_t	so_typesize = sizeof(so_type);
	struct sockaddr	*saddr=NULL;
	struct addrinfo	*ai=NULL;

	*err_ret = OWPErrOK;

	if(!addr || (addr->fd < 0)){
		OWPError(addr->ctx,OWPErrFATAL,OWPErrINVALID,"Invalid address");
		goto error;
	}

	if(addr->saddr && addr->saddrlen)
		return True;

	if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
		OWPErrorLine(addr->ctx,OWPLine,OWPErrFATAL,errno,
				"getsockopt():%s",strerror(errno));
		goto error;
	}

	if( !(saddr = malloc(fromaddrlen)) ||
				!(ai = malloc(sizeof(struct addrinfo)))){
		OWPErrorLine(addr->ctx,OWPLine,OWPErrFATAL,errno,"malloc():%s",
				strerror(errno));
		goto error;
	}

	memcpy((void*)saddr,(void*)fromaddr,fromaddrlen);
	ai->ai_flags = 0;
	ai->ai_family = saddr->sa_family;
	ai->ai_socktype = so_type;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default.	*/
	ai->ai_addrlen = fromaddrlen;
	ai->ai_canonname = NULL;
	ai->ai_addr = saddr;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->saddr = saddr;
	addr->saddrlen = fromaddrlen;

	if(getnameinfo(addr->saddr,addr->saddrlen,
				addr->node,sizeof(addr->node),
				addr->port,sizeof(addr->port),
				NI_NUMERICHOST | NI_NUMERICSERV) != 0){
		strncpy(addr->node,"unknown",sizeof(addr->node));
		strncpy(addr->port,"unknown",sizeof(addr->port));
	}
	addr->node_set = True;
	addr->port_set = True;

	return True;

error:
	if(saddr) free(saddr);
	if(ai) free(ai);
	*err_ret = OWPErrFATAL;
	return False;
}

/*
 * This function should only be called on an OWPAddr that already has
 * a fd associated with it.
 */
static OWPBoolean
AddrSetSockName(
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
	)
{
	u_int8_t	sbuff[SOCK_MAXADDRLEN];
	socklen_t	so_size = sizeof(sbuff);

	if(!addr || (addr->fd < 0)){
		OWPError(addr->ctx,OWPErrFATAL,OWPErrINVALID,"Invalid address");
		goto error;
	}

	if(getsockname(addr->fd,(void*)sbuff,&so_size) != 0){
		OWPErrorLine(addr->ctx,OWPLine,OWPErrFATAL,errno,
				"getsockname():%s",strerror(errno));
		goto error;
	}

	return AddrSetSAddr(addr,(struct sockaddr *)sbuff,so_size,err_ret);

error:
	*err_ret = OWPErrFATAL;
	return False;
}



static int
OpenSocket(
	int	family,
	OWPAddr	addr
	)
{
	struct addrinfo	*ai;
	const int	on=1;

	for(ai = addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != family)
			continue;

		addr->fd =socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);

		if(addr->fd < 0)
			continue;

		if((setsockopt(addr->fd,SOL_SOCKET,SO_REUSEADDR,&on,
							sizeof(on)) == 0) &&
			(bind(addr->fd,ai->ai_addr,ai->ai_addrlen) == 0)){

			addr->saddr = ai->ai_addr;
			addr->saddrlen = ai->ai_addrlen;

			break;
		}

		while((close(addr->fd) < 0) && (errno == EINTR));
		addr->fd = -1;
	}

	return addr->fd;
}

/*
 * Function:	OWPServerSockCreate
 *
 * Description:	
 * 		Used by server to create the initial listening socket.
 * 		(It is not required that the server use this interface,
 * 		but it will be kept up-to-date and in sync with the
 * 		client OWPControlOpen function. For example, both of
 * 		these functions currently give priority to IPV6 addresses
 * 		over IPV4.)
 *
 * 		The addr should be NULL for a wildcard socket, or bound to
 * 		a specific interface using OWPAddrByNode or OWPAddrByAddrInfo.
 *
 * 		This function will create the socket, bind it, and set the
 * 		"listen" backlog length.
 *
 * 		If addr is set using OWPAddrByFD, it will cause an error.
 * 		(It doesn't really make much sense to call this function at
 * 		all if you are going to	create and bind your own socket -
 * 		the only thing left is to call "listen"...)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
OWPAddr
OWPServerSockCreate(
	OWPContext	ctx,
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
	)
{
	int		fd = -1;

	*err_ret = OWPErrOK;

	/*
	 * AddrByFD is invalid.
	 */
	if(addr && (addr->fd > -1)){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
			"Invalid OWPAddr record - fd already specified.");
		goto error;
	}

	/*
	 * If no addr specified, then use wildcard address.
	 */
	if((!addr) && !(addr = AddrByWildcard(ctx)))
		goto error;


	if(!SetServerAddrInfo(ctx,addr,err_ret))
		goto error;

#ifdef	AF_INET6
	/*
	 * First try IPv6 addrs only
	 */
	fd = OpenSocket(AF_INET6,addr);

	/*
	 * Fall back to IPv4 addrs if necessary.
	 */
	if(fd < 0)
#endif
		fd = OpenSocket(AF_INET,addr);

	/*
	 * if we failed to find any IPv6 or IPv4 addresses... punt.
	 */
	if(fd < 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"OWPServerSockCreate:No valid addresses");
		goto error;
	}

	/*
	 * We have a bound socket - set the listen backlog.
	 */
	if(listen(addr->fd,OWP_LISTEN_BACKLOG) < 0){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"listen(%d,%d):%s",
				addr->fd,OWP_LISTEN_BACKLOG,strerror(errno));
		goto error;
	}

	return addr;

error:
	OWPAddrFree(addr);
	*err_ret = OWPErrFATAL;
	return NULL;

}

/*
 * Function:	OWPControlAccept
 *
 * Description:	
 * 		This function is used to initialiize the communication
 * 		to the peer.
 *           
 * In Args:	
 * 		connfd,connsaddr, and connsaddrlen are all returned
 * 		from "accept".
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
	OWPContext	ctx,		/* library context		*/
	int		connfd,		/* connected socket		*/
	struct sockaddr	*connsaddr,	/* connected socket addr	*/
	socklen_t	connsaddrlen,	/* connected socket addr len	*/
	u_int32_t	mode_offered,	/* advertised server mode	*/
	OWPErrSeverity	*err_ret	/* err - return			*/
)
{
	OWPControl	cntrl;
	u_int8_t	challenge[16];
	u_int8_t	rawtoken[32];
	u_int8_t	token[32];
	int		rc;

	*err_ret = OWPErrOK;

	if ( !(cntrl = _OWPControlAlloc(ctx, err_ret)))
		goto error;

	cntrl->sockfd = connfd;
	cntrl->server = True;

	/*
	 * set up remote_addr for policy decisions, and log reporting.
	 *
	 * set fd_user false to make OWPAddrFree of remote_addr close the
	 * socket. (This will happen from OWPControlClose.)
	 */
	if(!(cntrl->remote_addr = OWPAddrBySockFD(ctx,connfd)))
		goto error;
	cntrl->remote_addr->fd_user = False;
	if(!AddrSetSAddr(cntrl->remote_addr,connsaddr,connsaddrlen,err_ret))
		goto error;


	/*
	 * set up local_addr for policy decisions, and log reporting.
	 */
	if( !(cntrl->local_addr = OWPAddrBySockFD(ctx,connfd))){
		*err_ret = OWPErrFATAL;
		goto error;
	}
	if(!AddrSetSockName(cntrl->local_addr,err_ret))
		goto error;

	OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
			"Connection to (%s:%s) from (%s:%s)",
				cntrl->local_addr->node,cntrl->local_addr->port,
				cntrl->remote_addr->node,
				cntrl->remote_addr->port);

	/* generate 16 random bytes of challenge and save them away. */
	I2RandomBytes(challenge, 16);
	if( (rc = _OWPWriteServerGreeting(cntrl,mode_offered,
						challenge)) < 0){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	if( (rc=_OWPReadClientGreeting(cntrl,&cntrl->mode,rawtoken,
								cntrl->readIV))
									< 0){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	/* insure that exactly one mode is chosen */
	if(	(cntrl->mode != OWP_MODE_OPEN) &&
			(cntrl->mode != OWP_MODE_AUTHENTICATED) &&
			(cntrl->mode != OWP_MODE_ENCRYPTED)){
		*err_ret = OWPErrFATAL;
		goto error;
	}

	if(!(cntrl->mode | mode_offered)){ /* can't provide requested mode */
		OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
			"Control request to (%s:%s) denied from (%s:%s):mode not offered (%u)",
				cntrl->local_addr->node,cntrl->local_addr->port,
				cntrl->remote_addr->node,
				cntrl->remote_addr->port,cntrl->mode);
		if( (rc = _OWPWriteServerOK(cntrl, OWP_CNTRL_REJECT)) < 0)
			*err_ret = (OWPErrSeverity)rc;
		goto error;
	}
	
	if(cntrl->mode & (OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)){
		u_int8_t binKey[16];
		
		/* Fetch the encryption key into binKey */
		if(!_OWPCallGetAESKey(cntrl->ctx,cntrl->kid_buffer,binKey,
								err_ret)){
			if(*err_ret == OWPErrOK){
				OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
					"Unknown kid (%s)",cntrl->kid_buffer);
				(void)_OWPWriteServerOK(cntrl,
							OWP_CNTRL_REJECT);
			}else{
				(void)_OWPWriteServerOK(cntrl,
						OWP_CNTRL_FAILURE);
			}
			goto error;
		}
		
		if (OWPDecryptToken(binKey,rawtoken,token) < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					OWPErrUNKNOWN,
					"Encryption state problem?!?!");
			(void)_OWPWriteServerOK(cntrl,
						OWP_CNTRL_FAILURE);
			*err_ret = OWPErrFATAL;
			goto error;
		}
		
		/* Decrypted challenge is in the first 16 bytes */
		if (memcmp(challenge,token,16) != 0){
			OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
				"Control request to (%s:%s) denied from (%s:%s):Invalid challenge encryption",
				cntrl->local_addr->node,cntrl->local_addr->port,
				cntrl->remote_addr->node,
				cntrl->remote_addr->port);
			(void)_OWPWriteServerOK(cntrl,OWP_CNTRL_REJECT);
			goto error;
		}
		
		/* Authentication ok - set encryption fields */
		cntrl->kid = cntrl->kid_buffer;
		I2RandomBytes(cntrl->writeIV, 16);
		memcpy(cntrl->session_key,&token[16],16);
		_OWPMakeKey(cntrl,cntrl->session_key); 
	}

	if(!_OWPCallCheckControlPolicy(cntrl->ctx,cntrl->mode,cntrl->kid, 
		   cntrl->local_addr->saddr,cntrl->remote_addr->saddr,err_ret)){
		if(*err_ret > OWPErrWARNING){
			OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
		"ControlSession request to (%s:%s) denied from kid(%s):(%s:%s)",
				cntrl->local_addr->node,cntrl->local_addr->port,
				(cntrl->kid)?cntrl->kid:"nil",
				cntrl->remote_addr->node,
				cntrl->remote_addr->port);
			/*
			 * send mode of 0 to client, and then close.
			 */
			(void)_OWPWriteServerOK(cntrl,OWP_CNTRL_REJECT);
		}
		else{
			OWPErrorLine(ctx,OWPLine,*err_ret,OWPErrUNKNOWN,
						"Policy function failed.");
			(void)_OWPWriteServerOK(cntrl,
						OWP_CNTRL_FAILURE);
		}
		goto error;
	}

	/*
	 * Made it through the gauntlet - accept the control session!
	 */
	if( (rc = _OWPWriteServerOK(cntrl,OWP_CNTRL_ACCEPT)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}
	OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
		"ControlSession to (%s:%s) accepted from kid(%s):(%s:%s)",
		cntrl->local_addr->node,cntrl->local_addr->port,
		(cntrl->kid)?cntrl->kid:"nil",
		cntrl->remote_addr->node,
		cntrl->remote_addr->port);
	
	return cntrl;

error:
	OWPControlClose(cntrl);
	return NULL;
}

static OWPAddr
AddrBySAddrRef(
	OWPContext	ctx,
	struct sockaddr	*saddr,
	socklen_t	saddrlen
	)
{
	OWPAddr		addr;
	struct addrinfo	*ai=NULL;

	if(!saddr){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
				"AddrBySAddrRef:Invalid saddr");
		return NULL;
	}

	if(!(addr = _OWPAddrAlloc(ctx)))
		return NULL;

	if(!(ai = malloc(sizeof(struct addrinfo)))){
		OWPErrorLine(addr->ctx,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"malloc():%s",strerror(errno));
		(void)OWPAddrFree(addr);
		return NULL;
	}

	ai->ai_flags = 0;
	ai->ai_family = saddr->sa_family;
	ai->ai_socktype = SOCK_DGRAM;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default.	*/
	ai->ai_addrlen = saddrlen;
	ai->ai_canonname = NULL;
	ai->ai_addr = saddr;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->saddr = saddr;
	addr->saddrlen = saddrlen;

	if(getnameinfo(addr->saddr,addr->saddrlen,
				addr->node,sizeof(addr->node),
				addr->port,sizeof(addr->port),
				NI_NUMERICHOST | NI_NUMERICSERV) != 0){
		strncpy(addr->node,"unknown",sizeof(addr->node));
		strncpy(addr->port,"unknown",sizeof(addr->port));
	}
	addr->node_set = True;
	addr->port_set = True;

	return addr;
}

OWPErrSeverity
OWPProcessTestRequest(
	OWPControl	cntrl
		)
{
	socklen_t	addrlen = SOCK_MAXADDRLEN;
	struct sockaddr	*sendaddr;
	struct sockaddr	*recvaddr;
	OWPAddr		SendAddr=NULL;
	OWPAddr		RecvAddr=NULL;
	int		af_family;
	u_int8_t	ipvn;
	OWPBoolean	conf_sender;
	OWPBoolean	conf_receiver;
	OWPSID		sid;
	OWPTestSpec	tspec;
	OWPTestSession	tsession = NULL;
	OWPErrSeverity	err_ret=OWPErrOK;
	u_int16_t	*sendport;
	u_int16_t	*recvport;
	u_int16_t	port;
	int		rc;
	OWPAcceptType	acceptval = OWP_CNTRL_FAILURE;

	/*
	 * Use dynamic memory to ensure memory alignment will work for
	 * all sockaddr types.
	 */
	sendaddr = malloc(addrlen);
	recvaddr = malloc(addrlen);
	if(!sendaddr || !recvaddr){
		OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"malloc():%s",strerror(errno));
		goto error;
	}

	if( (rc = _OWPReadTestRequest(cntrl,sendaddr,recvaddr,&addrlen,
			&ipvn,&conf_sender,&conf_receiver,sid,&tspec)) < 0){
		err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	switch (ipvn){
		struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
		struct sockaddr_in6	*saddr6;

		case 6:
			af_family = AF_INET6;
			saddr6 = (struct sockaddr_in6*)sendaddr;
			sendport = &saddr6->sin6_port;
			saddr6 = (struct sockaddr_in6*)recvaddr;
			recvport = &saddr6->sin6_port;
			break;
#endif
		case 4:
			af_family = AF_INET;
			saddr4 = (struct sockaddr_in*)sendaddr;
			sendport = &saddr4->sin_port;
			saddr4 = (struct sockaddr_in*)recvaddr;
			recvport = &saddr4->sin_port;
			break;
		default:
			af_family = AF_UNSPEC;
			break;
	}

	if((af_family == AF_UNSPEC) || (sendaddr->sa_family != af_family)
			|| (recvaddr->sa_family != af_family)){
		OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
				"Test Denied:unsupported ipvn %d",ipvn);
		err_ret = OWPErrINFO;
		acceptval = OWP_CNTRL_UNSUPPORTED;
		goto error;
	}

	SendAddr = AddrBySAddrRef(cntrl->ctx,sendaddr,addrlen);
	RecvAddr = AddrBySAddrRef(cntrl->ctx,recvaddr,addrlen);
	if( !(tsession = _OWPTestSessionAlloc(cntrl,SendAddr,conf_sender,
					RecvAddr,conf_receiver,&tspec)))
		goto error;

	/*
	 * if conf_receiver - open port and get SID.
	 */
	if(conf_receiver){
		if(!_OWPCallCheckTestPolicy(cntrl,False,recvaddr,sendaddr,
						&tspec,&err_ret)){
			if(err_ret < OWPErrOK)
				goto error;
			OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
							"Test not allowed");
			acceptval = OWP_CNTRL_REJECT;
			err_ret = OWPErrINFO;
			goto error;
		}
		/* receiver first (sid comes from there) */
		if(!_OWPCallEndpointInit(cntrl,&tsession->recv_end_data,
				False,tsession->receiver,&tsession->test_spec,
				tsession->sid,&err_ret)){
			goto error;
		}
	}else{
		/* if !conf_receiver, sid comes from TestRequest message */
		memcpy(tsession->sid,sid,sizeof(sid));
	}


	if(conf_sender){
		/*
		 * TODO: Check for a local sender being used for DOS?
		 *  -or can we rely on TestPolicy function?
		 *
		 * if(!conf_receiver && (receiver_address != control_address))
		 * 	deny test
		 */
		if(!_OWPCallCheckTestPolicy(cntrl,True,sendaddr,
						recvaddr,&tspec,&err_ret)){
			if(err_ret < OWPErrOK)
				goto error;
			OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
							"Test not allowed");
			acceptval = OWP_CNTRL_REJECT;
			err_ret = OWPErrINFO;
			goto error;
		}
		if(!_OWPCallEndpointInit(cntrl, &tsession->send_end_data,
					True,tsession->sender,
					&tsession->test_spec,
					tsession->sid,&err_ret)){
			goto error;
		}
		if(!_OWPCallEndpointInitHook(cntrl,tsession->send_end_data,
						tsession->receiver,
						tsession->sid,&err_ret)){
			goto error;
		}
		port = *sendport;
	}

	if(conf_receiver){
		if(!_OWPCallEndpointInitHook(cntrl,
					tsession->recv_end_data,
					tsession->sender,
					tsession->sid,&err_ret)){
			goto error;
		}
		port = *recvport;
	}

	if( (rc = _OWPWriteTestAccept(cntrl,OWP_CNTRL_ACCEPT,
						port,tsession->sid)) < 0){
		err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	/*
	 * Add tsession to list of tests managed by this control connection.
	 */
	tsession->next = cntrl->tests;
	cntrl->tests = tsession;

	return OWPErrOK;

error:
	/*
	 * If it is a non-fatal error, communication should continue, so
	 * send negative accept.
	 */
	if(err_ret >= OWPErrWARNING)
		(void)_OWPWriteTestAccept(cntrl,acceptval,0,NULL);

	if(tsession)
		_OWPTestSessionFree(tsession,OWP_CNTRL_FAILURE);
	else{
		if(SendAddr)
			OWPAddrFree(SendAddr);
		else
			free(sendaddr);
		if(RecvAddr)
			OWPAddrFree(RecvAddr);
		else
			free(recvaddr);
	}
	return err_ret;
}

OWPErrSeverity
OWPProcessStartSessions(
	OWPControl	cntrl
	)
{
	int		rc;
	OWPTestSession	tsession;
	OWPErrSeverity	err,err2=OWPErrOK;

	if( (rc = _OWPReadStartSessions(cntrl)) < 0)
		return _OWPFailControlSession(cntrl,(OWPErrSeverity)rc,
							OWPErrUNKNOWN,NULL);

	if( (rc = _OWPWriteControlAck(cntrl,OWP_CNTRL_ACCEPT)) < 0)
		return _OWPFailControlSession(cntrl,(OWPErrSeverity)rc,
							OWPErrUNKNOWN,NULL);

	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->recv_end_data){
			if(!_OWPCallEndpointStart(tsession,
						tsession->recv_end_data,&err)){
				(void)_OWPWriteStopSessions(cntrl,
							    OWP_CNTRL_FAILURE);
				return _OWPFailControlSession(cntrl,err,
							OWPErrUNKNOWN,NULL);
			}
			err2 = MIN(err,err2);
		}
		if(tsession->send_end_data){
			if(!_OWPCallEndpointStart(tsession,
						tsession->send_end_data,&err)){
				(void)_OWPWriteStopSessions(cntrl,
							    OWP_CNTRL_FAILURE);
				return _OWPFailControlSession(cntrl,err,
							OWPErrUNKNOWN,NULL);
			}
			err2 = MIN(err,err2);
		}
	}

	return err2;
}

OWPErrSeverity
OWPProcessStopSessions(
	OWPControl	cntrl
	)
{
	int		rc;
	OWPTestSession	tsession;
	OWPAcceptType	acceptval;
	OWPErrSeverity	err,err2=OWPErrOK;

	if( (rc = _OWPReadStopSessions(cntrl,&acceptval)) < 0)
		return _OWPFailControlSession(cntrl,(OWPErrSeverity)rc,
							OWPErrUNKNOWN,NULL);

	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->recv_end_data){
			_OWPCallEndpointStop(tsession,tsession->recv_end_data,
					acceptval,&err);
			err2 = MIN(err,err2);
		}
		if(tsession->send_end_data){
			_OWPCallEndpointStop(tsession,tsession->send_end_data,
					acceptval,&err);
			err2 = MIN(err,err2);
		}
	}

	if(err2 < OWPErrWARNING)
		acceptval = OWP_CNTRL_FAILURE;
	else
		acceptval = OWP_CNTRL_ACCEPT;

	if( (rc = _OWPWriteStopSessions(cntrl,acceptval)) < 0)
		return _OWPFailControlSession(cntrl,(OWPErrSeverity)rc,
							OWPErrUNKNOWN,NULL);


	return err2;
}

OWPErrSeverity
OWPProcessRetrieveSession(
	OWPControl	cntrl
	)
{
	int		rc;
	OWPSID		sid;
	u_int32_t	begin;
	u_int32_t	end;

	if( (rc = _OWPReadRetrieveSession(cntrl,&begin,&end,sid)) < 0)
		return _OWPFailControlSession(cntrl,(OWPErrSeverity)rc,
							OWPErrUNKNOWN,NULL);

	/*
	 * TODO: setup something to actually retrieve the data.
	 * for now just return negative.
	err = _OWPCallRetrieveSession(cntrl,begin,end,sid);
	 */

	if( (rc = _OWPWriteControlAck(cntrl,OWP_CNTRL_UNSUPPORTED)) < 0)
		return _OWPFailControlSession(cntrl,(OWPErrSeverity)rc,
							OWPErrUNKNOWN,NULL);

	return OWPErrOK;
}

/*
 * TODO: Add timeout so ProcessRequests can break out if no request
 * comes in some configurable fixed time. (Necessary to have the server
 * process exit when test sessions are done, if the client doesn't send
 * the StopSessions.)
 */
OWPErrSeverity
OWPProcessRequests(
	OWPControl	cntrl
		)
{
	OWPErrSeverity	rc;
	int		msgtype;

	while((msgtype = OWPReadRequestType(cntrl)) > 0){

		switch (msgtype){
				/* TestRequest */
			case 1:
				rc = OWPProcessTestRequest(cntrl);
				break;
			case 2:
				rc = OWPProcessStartSessions(cntrl);
				break;
			case 3:
				rc = OWPProcessStopSessions(cntrl);
				break;
			case 4:
				rc = OWPProcessRetrieveSession(cntrl);
				break;
			default:
				OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
		"Invalid msgtype (%d) returned from OWPReadRequesttype",
					msgtype);
				rc = OWPErrFATAL;
		}

		if(rc > OWPErrFATAL)
			continue;
		return rc;
	}

	/*
	 * Normal socket close
	 */
	if(msgtype == 0)
		return OWPErrOK;

	return OWPErrFATAL;
}
