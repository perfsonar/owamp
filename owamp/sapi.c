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
#include <unistd.h>
#include <netinet/in.h>
#include "./owampP.h"

#define IS_LEGAL_MODE(x) ((x) == OWP_MODE_OPEN | (x) == OWP_MODE_AUTHENTICATED | (x) == OWP_MODE_ENCRYPTED)

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
SetServerSockInfo(
	OWPContext	ctx,
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
	)
{
	OWPByte		sbuff[SOCK_MAXADDRLEN];
	socklen_t	so_size = sizeof(sbuff);
	int		so_type;
	socklen_t	so_typesize = sizeof(so_type);
	struct sockaddr	*saddr=NULL;
	struct addrinfo	*ai=NULL;

	*err_ret = OWPErrOK;

	if(!addr || (addr->fd < 0)){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,"Invalid address");
		goto error;
	}

	if(addr->saddr && addr->saddrlen)
		return True;

	if(getsockname(addr->fd,(void*)&sbuff,&so_size) != 0){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"getsockname():%s",
							strerror(errno));
		goto error;
	}
	if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"getsockopt():%s",
				strerror(errno));
		goto error;
	}

	if( !(saddr = malloc(so_size)) ||
				!(ai = malloc(sizeof(struct addrinfo)))){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"malloc():%s",
				strerror(errno));
		goto error;
	}

	memcpy((void*)saddr,(void*)sbuff,so_size);
	ai->ai_flags = 0;
	ai->ai_family = saddr->sa_family;
	ai->ai_socktype = so_type;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default.	*/
	ai->ai_addrlen = so_size;
	ai->ai_canonname = NULL;
	ai->ai_addr = saddr;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->saddr = saddr;
	addr->saddrlen = so_size;

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
SetPeerSockInfo(
	OWPContext	ctx,
	OWPAddr		addr,
	struct sockaddr	*peeraddr,
	socklen_t	peeraddrlen,
	OWPErrSeverity	*err_ret
	)
{
	int		so_type;
	socklen_t	so_typesize = sizeof(so_type);
	struct sockaddr	*saddr=NULL;
	struct addrinfo	*ai=NULL;

	*err_ret = OWPErrOK;

	if(!addr || (addr->fd < 0)){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,"Invalid address");
		goto error;
	}

	if(addr->saddr && addr->saddrlen)
		return True;

	if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"getsockopt():%s",
				strerror(errno));
		goto error;
	}

	if( !(saddr = malloc(peeraddrlen)) ||
				!(ai = malloc(sizeof(struct addrinfo)))){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"malloc():%s",
				strerror(errno));
		goto error;
	}

	memcpy((void*)saddr,(void*)peeraddr,peeraddrlen);
	ai->ai_flags = 0;
	ai->ai_family = saddr->sa_family;
	ai->ai_socktype = so_type;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default.	*/
	ai->ai_addrlen = peeraddrlen;
	ai->ai_canonname = NULL;
	ai->ai_addr = saddr;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->saddr = saddr;
	addr->saddrlen = peeraddrlen;

	return True;

error:
	if(saddr) free(saddr);
	if(ai) free(ai);
	*err_ret = OWPErrFATAL;
	return False;
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
 * 		If addr is set using ByNode or ByAddrInfo, then this function
 * 		will create the socket, bind it, and set the "listen" backlog
 * 		length. If it is set using ByFD, then it is assumed the
 * 		calling function already called bind - and this function
 * 		just initializes the OWPAddr structure as best it can, and
 * 		sets the "listen" backlog. (It doesn't really make much
 * 		sense to call this function at all if you are going to
 * 		create and bind your own socket - just call listen too.)
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
	struct addrinfo	*ai;
	int		fd;
	const int	on=1;

	*err_ret = OWPErrOK;

	/*
	 * If no addr specified, then use wildcard address.
	 */
	if((!addr) && !(addr = AddrByWildcard(ctx)))
		goto error;

	/*
	 * If addr was set by fd, we only need to prepare the sockaddr stuff,
	 * and call listen.
	 * (Most likely, this function won't even be called in this case...)
	 */
	if(addr->fd > -1){
		if(SetServerSockInfo(ctx,addr,err_ret))
			goto success;
		goto error;
	}

	if(!SetServerAddrInfo(ctx,addr,err_ret))
		goto error;

#ifdef	AF_INET6
	/*
	 * Only try IPv6 addrs in this loop.
	 */
	for(ai = addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != AF_INET6)
			continue;

		fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);

		if(fd < 0)
			continue;

		if((setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) == 0)
				&& (bind(fd,ai->ai_addr,ai->ai_addrlen) == 0)){
			addr->fd = fd;
			addr->saddr = ai->ai_addr;
			addr->saddrlen = ai->ai_addrlen;

			goto success;
		}

		if(close(fd) < 0)
			OWPError(ctx,OWPErrWARNING,errno,"close():%s",
							strerror(errno));
	}
#endif
	/*
	 * We didn't find a v6 addr, try IPv4
	 */
	for(ai = addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != AF_INET)
			continue;

		fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);

		if(fd < 0)
			continue;

		if((setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) == 0)
				&& (bind(fd,ai->ai_addr,ai->ai_addrlen) == 0)){
			addr->fd = fd;
			addr->saddr = ai->ai_addr;
			addr->saddrlen = ai->ai_addrlen;

			goto success;
		}

		if(close(fd) < 0)
			OWPError(ctx,OWPErrWARNING,errno,"close():%s",
							strerror(errno));
	}

	/*
	 * Failed to find any IPv6 or IPv4 addresses... punt.
	 */
	OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
				"OWPServerSockCreate:No valid addresses");
	goto error;

success:
	/*
	 * We have a bound socket - set the listen backlog.
	 */
	if(listen(addr->fd,OWP_LISTEN_BACKLOG) < 0){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,"listen(%d,%d):%s",
					fd,OWP_LISTEN_BACKLOG,strerror(errno));
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
 * 		listenaddr should be null unless the listen socket
 * 		was created using the OWPServerSockCreate function,
 * 		then pass in the return'ed OWPAddr from that function.
 * 		(It will optimize the policy check.)
 *
 * Returns:	Valid OWPControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 * 	*note: If the listenaddr is passed in - the caller is still
 * 	responsible for free'ing the listenaddr using OWPAddrFree.
 * 	(That is how the listen socket should be closed if OWPCreateServerSock
 * 	is used to create the listening socket.) This is
 * 	in contrast to virtually every other OWPAddr arguement in this API.
 */
OWPControl
OWPControlAccept(
	OWPContext	ctx,		/* library context		*/
	int		connfd,		/* connected socket		*/
	struct sockaddr	*connsaddr,	/* connected socket addr	*/
	socklen_t	connsaddrlen,	/* connected socket addr len	*/
	OWPAddr		listenaddr,	/* listenaddr or NULL		*/
	u_int32_t	mode_offered,	/* advertised server mode	*/
	OWPErrSeverity	*err_ret	/* err - return			*/
)
{
	OWPByte		challenge[16];
	OWPByte		buf[MAX_MSG];
	OWPByte		token[32];
	OWPControl	cntrl;

	*err_ret = OWPErrOK;

	if ( !(cntrl = _OWPControlAlloc(ctx, err_ret)))
		goto error;

	/*
	 * set up remote_addr for policy decisions.
	 */
	if(!(cntrl->remote_addr = OWPAddrBySockFD(ctx,connfd)))
		goto error;
	if(!SetPeerSockInfo(ctx,cntrl->remote_addr,connsaddr,connsaddrlen,
								err_ret))
		goto error;

	/*
	 * set up local_addr for policy decisions.
	 */
	if(listenaddr)
		cntrl->local_addr = _OWPAddrCopy(listenaddr);
	else
		cntrl->local_addr = OWPAddrBySockFD(ctx,connfd);
	if(!cntrl->local_addr ||
			!SetServerSockInfo(ctx,cntrl->local_addr,err_ret))
		goto error;

	cntrl->sockfd = connfd;
	cntrl->server = True;

	/*
	 * Check address policy.
	 */
	if(!_OWPCallCheckAddrPolicy(ctx,cntrl->local_addr->saddr,
					cntrl->remote_addr->saddr,err_ret)){
		char	lnodename[NI_MAXHOST];
		char	lservname[NI_MAXSERV];
		char	rnodename[NI_MAXHOST];
		char	rservname[NI_MAXSERV];

		(void)getnameinfo(cntrl->local_addr->saddr,
					cntrl->local_addr->saddrlen,
					lnodename,sizeof(lnodename),
					lservname,sizeof(lservname),
					NI_NUMERICHOST | NI_NUMERICSERV);
		(void)getnameinfo(cntrl->remote_addr->saddr,
					cntrl->remote_addr->saddrlen,
					rnodename,sizeof(rnodename),
					rservname,sizeof(rservname),
					NI_NUMERICHOST | NI_NUMERICSERV);
		OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
			"Connect request to (%s:%s) denied from (%s:%s)",
				lnodename,lservname,rnodename,rservname);
				goto error;
	}

#if	NOTYET
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
#endif	NOTYET
	return cntrl;

error:
	OWPControlClose(cntrl);
	return NULL;
}
