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

		if(close(addr->fd) < 0)
			OWPError(addr->ctx,OWPErrWARNING,errno,"close():%s",
							strerror(errno));
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
#endif
	/*
	 * Fall back to IPv4 addrs if necessary.
	 */
	if(fd < 0)
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


	/*
	 * Check address policy.
	 *
	 * TODO: OWPErrINFO is being used for "logging" informatino.
	 * we may want to make a specific "log" level for OWPErrSeverity
	 * eventually...
	 */
	if(!_OWPCallCheckAddrPolicy(ctx,cntrl->local_addr->saddr,
					cntrl->remote_addr->saddr,err_ret)){
		if(*err_ret > OWPErrWARNING){
			OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
			"Connect request to (%s:%s) denied from (%s:%s)",
				cntrl->local_addr->node,cntrl->local_addr->port,
				cntrl->remote_addr->node,
				cntrl->remote_addr->port);
			/*
			 * send mode of 0 to client, and then close.
			 */
			rc = _OWPWriteServerGreeting(cntrl,0,challenge);
			if(rc < 0)
				*err_ret = (OWPErrSeverity)rc;
			goto error;
		}
		else
			OWPErrorLine(ctx,OWPLine,*err_ret,OWPErrUNKNOWN,
						"Policy function failed.");
		goto error;
	}
	OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
			"Connect request to (%s:%s) accepted from (%s:%s)",
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
		if( (rc = _OWPWriteServerOK(cntrl, _OWP_CNTRL_REJECT)) < 0)
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
							_OWP_CNTRL_REJECT);
			}else{
				(void)_OWPWriteServerOK(cntrl,
						_OWP_CNTRL_SERVER_FAILURE);
			}
			goto error;
		}
		
		if (OWPDecryptToken(binKey,rawtoken,token) < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					OWPErrUNKNOWN,
					"Encryption state problem?!?!");
			(void)_OWPWriteServerOK(cntrl,
						_OWP_CNTRL_SERVER_FAILURE);
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
			(void)_OWPWriteServerOK(cntrl,_OWP_CNTRL_REJECT);
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
			(void)_OWPWriteServerOK(cntrl,_OWP_CNTRL_REJECT);
		}
		else{
			OWPErrorLine(ctx,OWPLine,*err_ret,OWPErrUNKNOWN,
						"Policy function failed.");
			(void)_OWPWriteServerOK(cntrl,
						_OWP_CNTRL_SERVER_FAILURE);
		}
		goto error;
	}

	/*
	 * Made it through the gauntlet - accept the control session!
	 */
	if( (rc = _OWPWriteServerOK(cntrl,_OWP_CNTRL_ACCEPT)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}
	OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
		"ControlSession to (%s:%s) accepted from kid(%s):(%s:%s)",
		cntrl->local_addr->node,cntrl->local_addr->port,
		(cntrl->kid)?cntrl->kid:"nil",
		cntrl->remote_addr->node,
		cntrl->remote_addr->port);
	
	/*
	 * TODO: Figure out where the state stuff is going to be done - api
	 * files or protocol.c...
	 */
	cntrl->state = _OWPStateRequest;

	return cntrl;

error:
	OWPControlClose(cntrl);
	return NULL;
}
