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
#include <sys/stat.h>
#include <fcntl.h>

#include <owamp/owampP.h>
/*
 * TODO: conndata shouldn't be accessed here - need to take the
 * conndata out of FetchSession and create an endpoint_open_session_file
 * function that returns the fd.
 */
#include "conndata.h"

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
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"getaddrinfo(): %s",gai_strerror(ai_err));
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
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"getaddrinfo(): %s",
							gai_strerror(ai_err));
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
	int		gai;

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

	if( (gai = getnameinfo(addr->saddr,addr->saddrlen,
				addr->node,sizeof(addr->node),
				addr->port,sizeof(addr->port),
				NI_NUMERICHOST | NI_NUMERICSERV)) != 0){
		OWPError(addr->ctx,OWPErrWARNING,OWPErrUNKNOWN,
				"getnameinfo(): %s",gai_strerror(gai));
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
	struct timeval	tval;

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

	if(gettimeofday(&tval,NULL)!=0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"gettimeofday():%M");
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
	if(gettimeofday(&cntrl->delay_bound,NULL)!=0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"gettimeofday():%M");
		*err_ret = OWPErrFATAL;
		goto error;
	}
	tvalsub(&cntrl->delay_bound,&tval);

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
		"ControlSession to ([%s]:%s) accepted from kid(%s):([%s]:%s)",
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
	int		gai;

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

	if( (gai = getnameinfo(addr->saddr,addr->saddrlen,
				addr->node,sizeof(addr->node),
				addr->port,sizeof(addr->port),
				NI_NUMERICHOST | NI_NUMERICSERV)) != 0){
		OWPError(addr->ctx,OWPErrWARNING,OWPErrUNKNOWN,
				"getnameinfo(): %s",gai_strerror(gai));
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

	/*
	 * TODO: In v5 this will just read the TestRequest header - then
	 * another function will have to read the slots and compute the
	 * schedule.
	 */
	if( (rc = _OWPReadTestRequest(cntrl,sendaddr,recvaddr,&addrlen,
				      &ipvn,&conf_sender,&conf_receiver,sid,
				      &tspec)) < OWPErrOK){
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
					RecvAddr,conf_receiver,&tspec))){
		err_ret = OWPErrWARNING;
		acceptval = OWP_CNTRL_FAILURE;
		goto error;
	}

	if(conf_receiver){
		if(_OWPCreateSID(tsession) != 0){
			err_ret = OWPErrWARNING;
			acceptval = OWP_CNTRL_FAILURE;
			goto error;
		}
	}else{
		memcpy(tsession->sid,sid,sizeof(sid));
	}

	/*
	 * TODO: In v5, alloc space for slots and read them in, then use
	 * them to compute the schedule.
	 */

	if(_OWPTestSessionCreateSchedule(tsession) != 0){
		err_ret = OWPErrWARNING;
		acceptval = OWP_CNTRL_FAILURE;
		goto error;
	}

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
		if(!_OWPCallEndpointInit(cntrl,tsession,tsession->receiver,NULL,
					&tsession->recv_end_data,&err_ret)){
			err_ret = OWPErrWARNING;
			acceptval = OWP_CNTRL_FAILURE;
			goto error;
		}
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
					    recvaddr, &tspec, &err_ret)){
			if(err_ret < OWPErrOK)
				goto error;
			OWPError(cntrl->ctx, OWPErrINFO, OWPErrPOLICY,
				 "Test not allowed");
			acceptval = OWP_CNTRL_REJECT;
			err_ret = OWPErrINFO;
			goto error;
		}
		if(!_OWPCallEndpointInit(cntrl,tsession,tsession->sender,NULL,
					&tsession->send_end_data,&err_ret)){
			err_ret = OWPErrWARNING;
			acceptval = OWP_CNTRL_FAILURE;
			goto error;
		}
		if(!_OWPCallEndpointInitHook(cntrl,tsession,
					&tsession->send_end_data,&err_ret)){
			err_ret = OWPErrWARNING;
			acceptval = OWP_CNTRL_FAILURE;
			goto error;
		}
		port = *sendport;
	}

	if(conf_receiver){
		if(!_OWPCallEndpointInitHook(cntrl,tsession,
					&tsession->recv_end_data,&err_ret)){
			err_ret = OWPErrWARNING;
			acceptval = OWP_CNTRL_FAILURE;
			goto error;
		}
		port = *recvport;
	}

	if( (rc = _OWPWriteTestAccept(cntrl,OWP_CNTRL_ACCEPT,
				      port,tsession->sid)) < OWPErrOK){
		err_ret = (OWPErrSeverity)rc;
		goto done;
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

done:
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

static
OWPErrSeverity
_OWPSendDataHeader(
	OWPControl	cntrl,
	u_int32_t	num_records
	)
{
	u_int8_t	buf[_OWP_RIJNDAEL_BLOCK_SIZE];

	/*
	 * Send data header information.
	 * TODO: v5 - need to send the original Test-Request record.
	 */
	memset(buf,0,sizeof(buf));
	*(u_int32_t*)&buf[0] = htonl(num_records);
	*(u_int32_t*)&buf[4] = htonl(0);	/* bogus typeP */
	if (_OWPSendBlocks(cntrl,buf,1) != 1)
		return OWPErrFATAL;
	return OWPErrOK;
}

/*
** Read records from the given descriptor and send it to the OWPControl socket.
*/
static OWPErrSeverity
OWPSendFullDataFile(
	OWPControl	cntrl,
	FILE		*fp,
	u_int32_t	nrecs
	)
{
	/*
	 * buf is 80 because:
	 * (80) == (_OWP_RIJNDAEL_BLOCK_SIZE*5) == (_OWP_TS_REC_SIZE*4)
	 */
#if	(80 != (_OWP_RIJNDAEL_BLOCK_SIZE*5))
#error "Block-sizes have changed! Fix this function."
#endif
#if	(80 != (_OWP_TS_REC_SIZE*4))
#error "Record sizes have changed! Fix this function."
#endif
	u_int8_t	buf[80];
	u_int32_t	num_records;
	int		blks;

	memset(buf,0,sizeof(buf));

	/*
	 * Now start sending data blocks. (4 records at a time)
	 */
	for(num_records=nrecs;num_records >= 4;num_records-=4){
		if(fread(buf,_OWP_TS_REC_SIZE,4,fp) < 4)
			return _OWPFailControlSession(cntrl,OWPErrFATAL);
		if(_OWPSendBlocks(cntrl,buf,5) != 5)
			return _OWPFailControlSession(cntrl,OWPErrFATAL);
	}

	memset(buf,0,sizeof(buf)); /* ensure zero padding */

	if(num_records){
		/*
		 * Now do remaining records if necessary - less than 4 left.
		 */
		if(fread(buf,_OWP_TS_REC_SIZE,num_records,fp) < num_records)
			return _OWPFailControlSession(cntrl,OWPErrFATAL);
		/*
		 * Determine number of AES blocks needed to hold remaining
		 * records. (earlier memset ensures zero padding for
		 * the remainder of the last block)
		 */
		blks = num_records*_OWP_TS_REC_SIZE/_OWP_RIJNDAEL_BLOCK_SIZE+1;
		if(_OWPSendBlocks(cntrl,buf,blks) != blks)
			return _OWPFailControlSession(cntrl,OWPErrFATAL);
	}

	/*
	 * Send 1 block of complete zero pad to finalize transaction.
	 */
	if(_OWPSendBlocks(cntrl,&buf[64],1) != 1)
		return _OWPFailControlSession(cntrl,OWPErrFATAL);

	return OWPErrOK;
}


/*
** Check if the 20-byte timestamp data record has sequence number
** between the given boundaries. Return 1 if yes, 0 otherwise.
** <begin> and <end> are in host byte order.
*/
static int
_OWPRecordIsInRange(u_int8_t *record, u_int32_t begin, u_int32_t end)
{
	u_int32_t seq_no;

	/*
	 * Must memcpy because record memory is not aligned for
	 * "long" access.
	 */
	memcpy(&seq_no,record,sizeof(u_int32_t));
	seq_no = ntohl(seq_no);
	
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
OWPProcessRecordsInRange(OWPControl	cntrl, 
			 FILE		*fp,
			 u_int32_t	nrecs,
			 u_int32_t	begin,
			 u_int32_t	end,
			 int		type,       /* OWP_COUNT, OWP_SEND */
			 OWPErrSeverity	*err_ret
)
{
	/*
	 * sbuf is 80 because:
	 * 80 == (_OWP_RIJNDAEL_BLOCK_SIZE*5) == (_OWP_TS_REC_SIZE*4)
	 * Make sure record sizes have not changed since 80 was figured.
	 */
#if	(80 != (_OWP_RIJNDAEL_BLOCK_SIZE*5))
#error "Block-sizes have changed! Fix this function."
#endif
#if	(80 != (_OWP_TS_REC_SIZE*4))
#error "Record sizes have changed! Fix this function."
#endif
	u_int8_t	rbuf[_OWP_TS_REC_SIZE];
	u_int8_t	sbuf[80];
	int		sbufi=0;
	u_int32_t	num_records;
	u_int32_t	count=0;

	for(num_records = nrecs;num_records > 0; num_records--){
		if(fread(rbuf,_OWP_TS_REC_SIZE,1,fp) < 1)
			goto readerr;
		if(!_OWPRecordIsInRange(rbuf,begin,end))
			continue;
		count++;
		if(type != OWP_SEND)
			continue;
		/*
		 * copy this record to the send buffer
		 */
		memcpy(&sbuf[_OWP_TS_REC_SIZE*sbufi++],rbuf,_OWP_TS_REC_SIZE);

		/*
		 * If the send buffer is full, send it and reset sbufi
		 */
		if(sbufi < 4)
			continue;
		if(_OWPSendBlocks(cntrl,sbuf,5) != 5)
			goto senderr;
		sbufi = 0;
	}

	/*
	 * If there are any remaining records in the send buffer - send them.
	 */
	if((type == OWP_SEND) && sbufi){
		int blks;

		/* fill remainder of buffer with 0's */
		memset(&sbuf[_OWP_TS_REC_SIZE*sbufi],0,
					sizeof(sbuf)-_OWP_TS_REC_SIZE*sbufi);
		/*
		 * Send as many blocks as is necessary to send remaining
		 * records - incomplete blocks are padded with 0's.
		 * (+2 - 1: round up incomplete block
		 * 	 1: full AES block of MBZ
		 */
		blks = sbufi*_OWP_TS_REC_SIZE/_OWP_RIJNDAEL_BLOCK_SIZE+2;
		if(_OWPSendBlocks(cntrl,sbuf,blks) != blks)
			goto senderr;
	}

	return count;

readerr:
	OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"OWPSendRecordsInRange:fread():%M");
	*err_ret = OWPErrFATAL;
	return 0;

senderr:
	OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN, 
		 "OWPSendRecordsInRange: _OWPSendBlocks failure");
	*err_ret = _OWPFailControlSession(cntrl,OWPErrFATAL);
	return 0;
}


OWPErrSeverity
OWPProcessRetrieveSession(
	OWPControl	cntrl
	)
{
	int		rc;
	OWPSID		sid;
	u_int32_t	filerecs;
	u_int32_t	begin;
	u_int32_t	end;

	char            path[PATH_MAX];  /* path for data file */
	char		sid_name[(sizeof(OWPSID)*2)+1];
	FILE		*fp;
	char*           datadir;
	OWPErrSeverity  err;
	u_int32_t	hdr_len;

	if( (rc = _OWPReadRetrieveSession(cntrl, &begin, &end,sid)) < OWPErrOK)
		return _OWPFailControlSession(cntrl, rc);

	/*
	 * TODO: All this path/file opening code should be combined
	 * with the similar code in endpoint.c (receiver) somehow.
	 */

	/* Construct the base pathname */
	datadir = ((OWPPerConnData)(cntrl->app_data))->link_data_dir;
	if(!datadir)
		goto denied;

	strcpy(path, datadir);
	strcat(path, OWP_PATH_SEPARATOR);
	OWPHexEncode(sid_name, sid, sizeof(OWPSID));
	strcat(path, sid_name);

	/* First look for incomplete file */
	strcat(path, OWP_INCOMPLETE_EXT);

try_incomplete_file:
	if( !(fp = fopen(path,"r"))){
		if(errno == EINTR )
			goto try_incomplete_file;
		if(errno != ENOENT){
			OWPError(cntrl->ctx,OWPErrFATAL,errno,"fopen(%s):%M",
					path);
			goto failed;
		}

		/* If not found - look for the completed one. */
		path[strlen(path) - strlen(OWP_INCOMPLETE_EXT)] = '\0';
		
try_complete_file:
		if( !(fp = fopen(path,"r"))){
			if (errno == EINTR )
				goto try_complete_file;
			if(errno != ENOENT){
				OWPError(cntrl->ctx,OWPErrFATAL,errno,
						"fopen(%s):%M",path);
				goto failed;
			}
			OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
		              "FetchRequest for non-existant SID:%s",sid_name);
			goto denied;
		}
	}

	/*
	 * TODO:v5 - the fourth arg to ReadDataHeader will read the
	 * header info so we can send it on to the client here.
	 */
	if( !(filerecs = OWPReadDataHeader(cntrl->ctx,fp,&hdr_len,NULL))){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"OWPReadDataHeader():%M");
		goto failed;
	}

	if ((begin == 0) && (end == 0xFFFFFFFF)) /* complete session  */ {
		if((rc = _OWPWriteControlAck(cntrl,OWP_CNTRL_ACCEPT))<OWPErrOK)
			return _OWPFailControlSession(cntrl,rc);
		if((rc = _OWPSendDataHeader(cntrl,filerecs)) < OWPErrOK)
			return _OWPFailControlSession(cntrl,rc);
		return OWPSendFullDataFile(cntrl,fp,filerecs);
	} else {                        /* range of sequence numbers */
		u_int32_t numrec; 

		/*
		 * First pass - OWPReadDataHeader has the fp positioned,
		 * find out how many records are in range.
		 */
		numrec = OWPProcessRecordsInRange(cntrl,fp,filerecs,begin,end,
								OWP_COUNT,&err);
		if (err != OWPErrOK)
			goto failed;

		/* 
		 * Ready to start the second pass through the file
		 * to actually send records.
		 * Start right at the offset
		 */
		if(fseek(fp,hdr_len,SEEK_SET) != 0){
			OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseek():%M");
			goto failed;
		}

		if( (rc=_OWPWriteControlAck(cntrl,OWP_CNTRL_ACCEPT))<OWPErrOK)
			return _OWPFailControlSession(cntrl,rc);
		if( (rc = _OWPSendDataHeader(cntrl,numrec)) < OWPErrOK)
			return _OWPFailControlSession(cntrl,rc);
		
		(void)OWPProcessRecordsInRange(cntrl,fp,filerecs,begin,end,
								OWP_SEND,&err);
		return err;
		
	}

denied:
	if( (rc = _OWPWriteControlAck(cntrl,OWP_CNTRL_REJECT)) < OWPErrOK)
		return _OWPFailControlSession(cntrl,rc);
	return OWPErrOK;

failed:
	if( (rc = _OWPWriteControlAck(cntrl, OWP_CNTRL_FAILURE)) < OWPErrOK)
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
