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
#include <owamp/owampP.h>
/*
 * TODO: conndata shouldn't be accessed here - need to take the
 * conndata out of FetchSession and create an endpoint_open_session_file
 * function that returns the fd.
 */
#include <owamp/conndata.h>
#include <sys/stat.h>
#include <fcntl.h>

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
		OWPError(ctx,OWPErrFATAL,errno,"getaddrinfo():%s",
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
		OWPError(ctx,OWPErrFATAL,errno,"getaddrinfo():%s",
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
		OWPError(addr->ctx,OWPErrFATAL,errno,
				"getsockopt():%s",strerror(errno));
		goto error;
	}

	if( !(saddr = malloc(fromaddrlen)) ||
				!(ai = malloc(sizeof(struct addrinfo)))){
		OWPError(addr->ctx,OWPErrFATAL,errno,"malloc():%s",
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
	addr->so_type = so_type;

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
	struct sockaddr_storage	sbuff;
	socklen_t		so_size = sizeof(sbuff);

	if(!addr || (addr->fd < 0)){
		OWPError(addr->ctx,OWPErrFATAL,OWPErrINVALID,"Invalid address");
		goto error;
	}

	if(getsockname(addr->fd,(void*)&sbuff,&so_size) != 0){
		OWPError(addr->ctx,OWPErrFATAL,errno,
				"getsockname():%s",strerror(errno));
		goto error;
	}

	return AddrSetSAddr(addr,(struct sockaddr *)&sbuff,so_size,err_ret);

error:
	*err_ret = OWPErrFATAL;
	return False;
}

static int
OpenSocket(
	OWPContext	ctx	__attribute__((unused)),
	int		family,
	OWPAddr		addr
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

		if(setsockopt(addr->fd,SOL_SOCKET,SO_REUSEADDR,&on,
							sizeof(on)) != 0)
			goto failsock;

		if(bind(addr->fd,ai->ai_addr,ai->ai_addrlen) == 0){

			addr->saddr = ai->ai_addr;
			addr->saddrlen = ai->ai_addrlen;
			addr->so_type = ai->ai_socktype;

			break;
		}

		if(errno == EADDRINUSE)
			return -2;

failsock:
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
	fd = OpenSocket(ctx,AF_INET6,addr);

	/*
	 * Fall back to IPv4 addrs if necessary.
	 */
	if(fd == -1)
#endif
		fd = OpenSocket(ctx,AF_INET,addr);

	/*
	 * if we failed to find any IPv6 or IPv4 addresses... punt.
	 */
	if(fd < 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"OWPServerSockCreate:%M");
		goto error;
	}

	/*
	 * We have a bound socket - set the listen backlog.
	 */
	if(listen(addr->fd,OWP_LISTEN_BACKLOG) < 0){
		OWPError(ctx,OWPErrFATAL,errno,"listen(%d,%d):%s",
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
	void		*app_data,	/* set app_data for this conn	*/
	OWPErrSeverity	*err_ret	/* err - return			*/
)
{
	OWPControl	cntrl;
	u_int8_t	challenge[16];
	u_int8_t	rawtoken[32];
	u_int8_t	token[32];
	int		rc;

	*err_ret = OWPErrOK;

	if ( !(cntrl = _OWPControlAlloc(ctx, app_data, err_ret)))
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
		 cntrl->remote_addr->node, cntrl->remote_addr->port);

	/* generate 16 random bytes of challenge and save them away. */
	if(I2RandomBytes(ctx->rand_src,challenge, 16) != 0){
		*err_ret = OWPErrFATAL;
		goto error;
	}
	if( (rc = _OWPWriteServerGreeting(cntrl,mode_offered,
						challenge)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	if( (rc=_OWPReadClientGreeting(cntrl,&cntrl->mode,rawtoken,
				       cntrl->readIV)) < OWPErrOK){
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
		if( (rc = _OWPWriteServerOK(cntrl, OWP_CNTRL_REJECT))<OWPErrOK)
			*err_ret = (OWPErrSeverity)rc;
		goto error;
	}
	
	if(cntrl->mode & (OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)){
		u_int8_t binKey[16];
		
		/* Fetch the encryption key into binKey */
		if(!_OWPCallGetAESKey(cntrl,cntrl->kid_buffer,binKey,err_ret)){
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
			OWPError(cntrl->ctx,OWPErrFATAL,
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
		if(I2RandomBytes(cntrl->ctx->rand_src,cntrl->writeIV,16) != 0){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to fetch randomness...");
			(void)_OWPWriteServerOK(cntrl,OWP_CNTRL_FAILURE);
			goto error;
		}
		memcpy(cntrl->session_key,&token[16],16);
		_OWPMakeKey(cntrl,cntrl->session_key); 
	}

	if(!_OWPCallCheckControlPolicy(cntrl,cntrl->mode,cntrl->kid, 
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
			OWPError(ctx,*err_ret,OWPErrUNKNOWN,
						"Policy function failed.");
			(void)_OWPWriteServerOK(cntrl, OWP_CNTRL_FAILURE);
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
		OWPError(addr->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"malloc():%s",strerror(errno));
		(void)OWPAddrFree(addr);
		return NULL;
	}

	if(!(addr->saddr = malloc(saddrlen))){
		OWPError(addr->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"malloc():%s",strerror(errno));
		(void)OWPAddrFree(addr);
		(void)free(ai);
		return NULL;
	}
	memcpy(addr->saddr,saddr,saddrlen);
	ai->ai_addr = addr->saddr;
	addr->saddrlen = saddrlen;
	ai->ai_addrlen = saddrlen;

	ai->ai_flags = 0;
	ai->ai_family = saddr->sa_family;
	ai->ai_socktype = SOCK_DGRAM;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default.	*/
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->so_type = SOCK_DGRAM;
	addr->so_protocol = IPPROTO_IP;

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
	struct sockaddr_storage	sendaddr_rec;
	struct sockaddr_storage	recvaddr_rec;
	struct sockaddr	*sendaddr = (struct sockaddr*)&sendaddr_rec;
	struct sockaddr *recvaddr = (struct sockaddr*)&recvaddr_rec;
	socklen_t	addrlen = sizeof(sendaddr_rec);
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
	u_int32_t	offset;
	u_int16_t	*sendport;
	u_int16_t	*recvport;
	u_int16_t	port;
	int		rc;
	OWPAcceptType	acceptval = OWP_CNTRL_FAILURE;

	memset(sendaddr,0,sizeof(struct sockaddr_storage));
	memset(recvaddr,0,sizeof(struct sockaddr_storage));

	if( (rc = _OWPReadTestRequest(cntrl,sendaddr,recvaddr,&addrlen,
			&ipvn,&conf_sender,&conf_receiver,sid,&tspec)) < OWPErrOK){
		err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	switch (ipvn){
#ifdef	AF_INET6

		case 6:
			af_family = AF_INET6;
			/* compute offset of port field */
			offset =
			(((char*)&(((struct sockaddr_in6*)NULL)->sin6_port)) -
				((char*)NULL));

			break;
#endif
		case 4:
			af_family = AF_INET;
			/* compute offset of port field */
			offset =
			(((char*)&(((struct sockaddr_in*)NULL)->sin_port)) -
				((char*)NULL));
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
	sendport = (u_int16_t *)((u_int8_t*)SendAddr->saddr + offset);
	RecvAddr = AddrBySAddrRef(cntrl->ctx,recvaddr,addrlen);
	recvport = (u_int16_t *)((u_int8_t*)RecvAddr->saddr + offset);

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
		if(!_OWPCallEndpointInitHook(cntrl,&tsession->send_end_data,
						tsession->receiver,
						tsession->sid,&err_ret)){
			goto error;
		}
		port = *sendport;
	}

	if(conf_receiver){
		if(!_OWPCallEndpointInitHook(cntrl,
					&tsession->recv_end_data,
					tsession->sender,
					tsession->sid,&err_ret)){
			goto error;
		}
		port = *recvport;
	}

	if( (rc = _OWPWriteTestAccept(cntrl,OWP_CNTRL_ACCEPT,
						port,tsession->sid)) < OWPErrOK){
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

	if( (rc = _OWPReadStartSessions(cntrl)) < OWPErrOK)
		return _OWPFailControlSession(cntrl,rc);

	if( (rc = _OWPWriteControlAck(cntrl,OWP_CNTRL_ACCEPT)) < OWPErrOK)
		return _OWPFailControlSession(cntrl,rc);

	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->recv_end_data){
			if(!_OWPCallEndpointStart(tsession,
						&tsession->recv_end_data,&err)){
				(void)_OWPWriteStopSessions(cntrl,
							    OWP_CNTRL_FAILURE);
				return _OWPFailControlSession(cntrl,err);
			}
			err2 = MIN(err,err2);
		}
		if(tsession->send_end_data){
			if(!_OWPCallEndpointStart(tsession,
						&tsession->send_end_data,&err)){
				(void)_OWPWriteStopSessions(cntrl,
							    OWP_CNTRL_FAILURE);
				return _OWPFailControlSession(cntrl,err);
			}
			err2 = MIN(err,err2);
		}
	}

	return err2;
}

/*
** Read records from the given descriptor and send it to the OWPControl socket.
*/
static OWPErrSeverity
OWPSendFullDataFile(OWPControl cntrl, int fd, u_int32_t blksize,off_t filesize)
{
	u_int8_t    *p, *q, *r;
	u_int32_t    num_records, i;
	off_t        bytes_left, saved_bytes;

	if ((p = (u_int8_t *)malloc(blksize + (4*_OWP_TS_REC_SIZE))) == NULL) {
		OWPError(cntrl->ctx, OWPErrFATAL, errno, 
			 "OWPSendDataFile: malloc(%d) failed: ", 
			 blksize);	
		return OWPErrFATAL;
	}

	q = &p[(4*_OWP_TS_REC_SIZE)];

	/* 
	   Compute the number of records. 
	   '4' for Type-P descriptor at file start.
	*/
	num_records = (filesize - 4) / _OWP_TS_REC_SIZE; 
	*(u_int32_t *)p = htonl(num_records);
	if (I2Readn(fd, &p[4], 4) == -1) {
		OWPError(cntrl->ctx, OWPErrFATAL, errno, 
			 "OWPSendDataFile: read failure");
		free(p);
		return OWPErrFATAL;
	}
	memset(&p[8], 0, 8);
	if (_OWPSendBlocks(cntrl, p, 1) != 1)
		goto send_err;

	saved_bytes = 0;
	bytes_left = (filesize - 4);
	while (bytes_left >= blksize) {

		if (I2Readn(fd, q, blksize) == -1) {
			OWPError(cntrl->ctx, OWPErrFATAL, errno, 
				 "OWPSendDataFile: read failure");
			free(p);
			return OWPErrFATAL;
		}
		bytes_left -= blksize;
		r = p + ((4*_OWP_TS_REC_SIZE) - saved_bytes);
		for (i = 0; i<(blksize + saved_bytes)/(4*_OWP_TS_REC_SIZE);i++){
			if (_OWPSendBlocks(cntrl, r, 5) != 5)
				goto send_err;
			r += (4*_OWP_TS_REC_SIZE);
		}
		saved_bytes = (blksize + saved_bytes)%(4*_OWP_TS_REC_SIZE);
		memcpy(p + ((4*_OWP_TS_REC_SIZE) - saved_bytes), r,saved_bytes);
	}

	/* Read any remaining bytes from file. */
	if (bytes_left) {
			if (I2Readn(fd, q, bytes_left) == -1) {
				OWPError(cntrl->ctx, OWPErrFATAL, errno, 
					 "OWPSendDataFile: read failure");
				free(p);
				return OWPErrFATAL;
			}
	}

	r = p + ((4*_OWP_TS_REC_SIZE) - saved_bytes);
	for (i = 0; i < (bytes_left + saved_bytes) / (4*_OWP_TS_REC_SIZE); i++){
		if (_OWPSendBlocks(cntrl, r, 5) != 5)
			goto send_err;
		r += (4*_OWP_TS_REC_SIZE);
	}

	/* At most 79 bytes remain now */
	bytes_left = (bytes_left + saved_bytes)%(4*_OWP_TS_REC_SIZE);
	if (bytes_left) {
		u_int32_t nblocks, padding_bytes;
		nblocks       =  bytes_left / 16;
		padding_bytes =  16 -  (bytes_left%16);
		memset(&r[bytes_left], 0, padding_bytes + 16);
		if (_OWPSendBlocks(cntrl, r, nblocks + 2) < 0)
			goto send_err;	
	} else {
		memset(r, 0, 16);
		if (_OWPSendBlocks(cntrl, r, 1) != 1)
			goto send_err;	
	}

	free(p);
	return OWPErrOK;

 send_err:
	free(p);
	OWPError(cntrl->ctx, OWPErrFATAL, errno, 
		 "OWPSendDataFile: _OWPSendBlocks failure");
	return OWPErrFATAL;
}


/*
** Check if the 20-byte timestamp data record has sequence number
** between the given boundaries. Return 1 if yes, 0 otherwise.
** <begin> and <end> are in host byte order.
*/
static int
_OWPRecordIsInRange(u_int8_t *record, u_int32_t begin, u_int32_t end)
{
	u_int32_t seq_no = ntohl(*(u_int32_t *)record);
	
	return ((seq_no >= begin) && (seq_no <= end))? 1 : 0;
}

#define OWP_COUNT 0
#define OWP_SEND  1

/*
** Read timestamp data records from the descriptor and count or send them
** to Control socket depending on <type>. Error code is returned via 
** <*err_ret> and must be checked by caller. When <type> is OWP_COUNT,
** returns the number of records within the given range (and when
** <type> is OWP_SEND the return value can be ignored).
*/
static u_int32_t
OWPProcessRecordsInRange(OWPControl      cntrl, 
			 int             fd, 
			 u_int32_t       begin,
			 u_int32_t       end,
			 u_int32_t       blksize,
			 off_t           rem_bytes,
			 int             type,       /* OWP_COUNT, OWP_SEND */
			 OWPErrSeverity* err_ret
)
{
	u_int32_t    m = 0;      /* number of unprocessed bytes in buffer */
	off_t        bytes_left = rem_bytes;     /* unread bytes from file */
	u_int8_t     send_buf[4*_OWP_TS_REC_SIZE];
	u_int8_t     *p, *q, *r;

	u_int32_t    bytes_to_read, ret = 0;
	int          k; /* from 0 to 3 - index of current record in
			   send_buf */
	int did_send = 0; /* flag */


	if (!(p = (u_int8_t *)malloc(blksize + _OWP_TS_REC_SIZE))) {
		OWPError(cntrl->ctx, OWPErrFATAL, errno, 
		     "OWPProcessRecordsInRange: malloc(%d) failed: ", blksize);
		*err_ret = OWPErrFATAL;
		return 0;
	}

	q = &p[_OWP_TS_REC_SIZE];
	r = q;

	while (bytes_left > 0) { /* try read 4 records at a time */
		int nblocks, padbytes;

		for (k = 0; k < 4; ) {
			if (m < _OWP_TS_REC_SIZE) { /* refill */
				/* Save away remaining odd bytes if any */
				if (m) {
					memcpy(p +(_OWP_TS_REC_SIZE - m), r, m);
					r = p + (_OWP_TS_REC_SIZE - m);
				}

				bytes_to_read = MIN(bytes_left, blksize);
				if (I2Readn(fd, q, bytes_to_read) == -1) {
					OWPError(cntrl->ctx,OWPErrFATAL,errno, 
					"OWPSendRecordsInRange: read failure");
					return 0;
				}
				m +=  bytes_to_read;
				bytes_left -= bytes_to_read;
			}
			if (m < _OWP_TS_REC_SIZE)
				break;
			m -= _OWP_TS_REC_SIZE;
			if (_OWPRecordIsInRange(r, begin, end)) {
				memcpy(&send_buf[k*_OWP_TS_REC_SIZE], r, 
				       _OWP_TS_REC_SIZE);
				r += _OWP_TS_REC_SIZE;
				k++;
			}
		}

		if (type == OWP_COUNT) {
			ret += k;
			continue;
		}

		/* 2 possible reasons: no more bytes, or got 4 records. */
		switch (k) {
		case 4: 
			if (_OWPSendBlocks(cntrl, send_buf, 5) != 5)
				goto send_err;
			did_send = 1;
			break;
		case 0:
			break;
		default:      /* add odd zero padding */
			nblocks = (k * 20) / 16 + 1;
			padbytes = 16 - (k * 20) % 16;
			memset(&send_buf[k*20], 0, padbytes);
			if (_OWPSendBlocks(cntrl, send_buf,nblocks) != nblocks)
				goto send_err;
			did_send = 1;
			break;
		}
	}

	if (type == OWP_COUNT) {
		*err_ret = OWPErrOK;
		return ret;
	}

	if (did_send) {
		memset(send_buf, 0, 16);
		if (_OWPSendBlocks(cntrl, send_buf, 1) != 1)
				goto send_err;
	}

	*err_ret = OWPErrOK;
	return 0;

 send_err:
	OWPError(cntrl->ctx, OWPErrFATAL, errno, 
		 "OWPSendRecordsInRange: _OWPSendBlocks failure");
	*err_ret = OWPErrFATAL;
	return 0;
}


OWPErrSeverity
OWPProcessRetrieveSession(
	OWPControl	cntrl
	)
{
	int		rc;
	OWPSID		sid;
	u_int32_t	begin; /* both in network byte order */
	u_int32_t	end;
	struct stat     stat_buf;

	char            path[PATH_MAX];  /* path for data file */
	char		sid_name[(sizeof(OWPSID)*2)+1];
	int             fd;
	char*           datadir;
	OWPErrSeverity  err;

	if( (rc = _OWPReadRetrieveSession(cntrl,&begin,&end,sid)) < OWPErrOK)
		return _OWPFailControlSession(cntrl,rc);

	/*
	  XXX - TODO: check for path length overflow
	*/

	/* Construct the base pathname */
	datadir = ((OWPPerConnData)(cntrl->app_data))->link_data_dir;
	assert(datadir);

	strcpy(path, datadir);
	strcat(path, OWP_PATH_SEPARATOR);
	OWPHexEncode(sid_name,sid,sizeof(OWPSID));
	strcat(path, sid_name);

	/* First look for incomplete file */
	strcat(path, OWP_INCOMPLETE_EXT);

 try_incomplete_file:
	if ((fd = open(path, O_RDONLY)) < 0) {
		if (errno == EINTR )
			goto try_incomplete_file;
	}

	/* If not found - look for the completed one. */
	path[strlen(path) - strlen(OWP_INCOMPLETE_EXT)] = '\0';

 try_complete_file:
	if ((fd = open(path, O_RDONLY )) < 0) {
		if (errno == EINTR )
			goto try_complete_file;
		OWPError(cntrl->ctx, OWPErrFATAL, errno, 
              "WARNING: OWPProcessRetrieveSession: open(%s) failed: %M", path);
		goto fail;
	}

	if (fstat(fd, &stat_buf) < 0) {
		OWPError(cntrl->ctx, OWPErrFATAL, errno, 
			 "OWPCountRecordsInRange: fstat() failed: ");	
		return OWPErrFATAL;
	}

	if ((begin == 0) && (end == 0xFFFFFFFF)) /* complete session  */ {
		if((rc = _OWPWriteControlAck(cntrl,OWP_CNTRL_ACCEPT))<OWPErrOK)
			return _OWPFailControlSession(cntrl,rc);
		return OWPSendFullDataFile(cntrl, fd, stat_buf.st_blksize,
					   stat_buf.st_size);
	} else {                        /* range of sequence numbers */
		u_int8_t buf[16];
		u_int32_t numrec; 

		begin = ntohl(begin);
		end = ntohl(end);

		/* First pass - start at offset 4. */
		if (lseek(fd, 4, SEEK_SET) < 0)
			goto lseek_err;
		
		numrec = OWPProcessRecordsInRange(cntrl, fd, begin, end,
						stat_buf.st_blksize,
						stat_buf.st_size - 4, 
						OWP_COUNT, &err);
		if (err != OWPErrOK)
			goto fail;

		/* Ready to start the second pass through the file. */
		if (lseek(fd, 0, SEEK_SET) < 0)
			goto lseek_err;

		/* Prepare first 16 bytes for transmission. */
		*(u_int32_t *)buf = htonl(numrec);
		if (I2Readn(fd, &buf[4], 4) == -1) {
			OWPError(cntrl->ctx, OWPErrFATAL, errno, 
				 "OWPSendDataFile: read failure");
			return OWPErrFATAL;
		}
		memset(&buf[8], 0, 8);

		/* 
		   Can't wait any longer - send ACCEPT, can't predict
		   any errors down the road.
		*/
		if( (rc = _OWPWriteControlAck(cntrl, OWP_CNTRL_ACCEPT)) < OWPErrOK) {
			return _OWPFailControlSession(cntrl,rc);
		}
		
		if (_OWPSendBlocks(cntrl, buf, 1) != 1){ /* First 16 bytes */
			OWPError(cntrl->ctx, OWPErrFATAL, errno, 
			"OWPProcessRetrieveSession: _OWPSendBlocks failure");
			return OWPErrFATAL;
		}
		OWPProcessRecordsInRange(cntrl, fd, begin, end,
					 stat_buf.st_blksize,
					 stat_buf.st_size - 4, OWP_SEND, &err);
		return err;
		
	lseek_err:
		OWPError(cntrl->ctx, OWPErrFATAL, errno, 
			 "OWPProcessRetrieveSession: lseek failure");
		goto fail;
	}
	return OWPErrOK;

 fail:
	if( (rc = _OWPWriteControlAck(cntrl,
				      OWP_CNTRL_FAILURE)) < OWPErrOK)
		return _OWPFailControlSession(cntrl,rc);
	return OWPErrOK;

}

/*
 * TODO: Add timeout so ProcessRequests can break out if no request
 * comes in some configurable fixed time.
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
				if(rc <= OWPErrFATAL)
					break;

				/* rc gives us all the return info we need */
				rc = OWPErrOK;
				(void)OWPStopSessionsWait(cntrl,NULL,NULL,&rc);
				break;
			case 4:
				rc = OWPProcessRetrieveSession(cntrl);
				break;
			default:
				OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
		"Invalid msgtype (%d) returned from OWPReadRequestType",
					msgtype);
				rc = OWPErrFATAL;
		}

		if(rc <= OWPErrFATAL)
			return rc;
	}

	/*
	 * Normal socket close
	 */
	if(msgtype == 0)
		return OWPErrOK;

	return OWPErrFATAL;
}
