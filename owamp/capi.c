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
 *	File:		capi.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Sun Jun 02 11:37:38 MDT 2002
 *
 *	Description:	
 *
 *	This file contains the api functions that are typically called from
 *	an owamp client application.
 */
#include <I2util/util.h>
#include <owamp/owampP.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>



static OWPBoolean
_OWPClientBind(
	OWPControl	cntrl,
	int		fd,
	OWPAddr		local_addr,
	struct addrinfo	*remote_addrinfo,
	OWPErrSeverity	*err_ret
)
{
	struct addrinfo	*ai;

	if(local_addr->fd > -1){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"Invalid local_addr - ByFD");
		*err_ret = OWPErrFATAL;
		return False;
	}

	if(!local_addr->ai){
		/*
		 * Call getaddrinfo to find useful addresses
		 */
		struct addrinfo	hints, *airet;
		const char	*port=NULL;
		int		gai;

		if(!local_addr->node_set){
			OWPError(cntrl->ctx,OWPErrFATAL,
				OWPErrUNKNOWN,"Invalid localaddr specified");
			*err_ret = OWPErrFATAL;
			return False;
		}

		if(local_addr->port_set)
			port = local_addr->port;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if(((gai = getaddrinfo(local_addr->node,port,&hints,&airet))!=0)
							|| !airet){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"getaddrinfo(): %s",gai_strerror(gai));
			*err_ret = OWPErrFATAL;
			return False;
		}

		local_addr->ai = airet;
	}

	for(ai=local_addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != remote_addrinfo->ai_family)
			continue;
		if(ai->ai_socktype != remote_addrinfo->ai_socktype)
			continue;

		if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
			local_addr->saddr = ai->ai_addr;
			local_addr->saddrlen = ai->ai_addrlen;
			return True;
		}

	}

	/*
	 * None found.
	 */
	return False;
}

static OWPBoolean
SetClientAddrInfo(
	OWPControl	cntrl,
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	const char	*node=NULL;
	const char	*port=NULL;
	int		gai;

	if(!addr){
		*err_ret = OWPErrFATAL;
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
							"Invalid address");
		return False;
	}

	if(addr->ai)
		return True;

	/*
	 * Call getaddrinfo to find useful addresses
	 */

	if(addr->node_set)
		node = addr->node;
	if(addr->port_set)
		port = addr->port;
	else
		port = OWP_CONTROL_SERVICE_NAME;

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if(((gai = getaddrinfo(node,port,&hints,&ai))!=0) || !ai){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"getaddrinfo(): %s",gai_strerror(gai));
		return False;
	}

	addr->ai = ai;
	return True;
}

/*
 * -1: error
 *  0: success
 *  1: keep trying
 */
static int
TryAddr(
	OWPControl	cntrl,
	struct addrinfo	*ai,
	OWPAddr		local_addr,
	OWPAddr		server_addr
	)
{
	OWPErrSeverity	addr_ok=OWPErrOK;
	int		fd;

	fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
	if(fd < 0)
		return 1;

	if(local_addr){
		if(!_OWPClientBind(cntrl,fd,local_addr,ai,&addr_ok)){
			if(addr_ok != OWPErrOK){
				return -1;
			}
			goto cleanup;
		}
	}

	/*
	 * Call connect - if it succeeds, return else try again.
	 */
	if(_OWPConnect(fd,ai->ai_addr,ai->ai_addrlen,&cntrl->ctx->cfg.tm_out)
									== 0){
		server_addr->fd = fd;
		server_addr->saddr = ai->ai_addr;
		server_addr->saddrlen = ai->ai_addrlen;
		server_addr->so_type = ai->ai_socktype;
		server_addr->so_protocol = ai->ai_protocol;
		cntrl->remote_addr = server_addr;
		cntrl->local_addr = local_addr;
		cntrl->sockfd = fd;

		return 0;
	}

cleanup:
	while((close(fd) < 0) && (errno == EINTR));
	return 1;
}

static int
_OWPClientConnect(
	OWPControl	cntrl,
	OWPAddr		local_addr,
	OWPAddr		server_addr,
	OWPErrSeverity	*err_ret
)
{
	int		rc;
	struct addrinfo	*ai=NULL;
	char		*tstr;

	if(!server_addr)
		goto error;

	/*
	 * Easy case - application provided socket directly.
	 */
	if(server_addr->fd > -1){
		cntrl->remote_addr = server_addr;
		cntrl->sockfd = server_addr->fd;
		return 0;
	}

	if(!SetClientAddrInfo(cntrl,server_addr,err_ret))
		goto error;

	/*
	 * Now that we have addresses - see if it is valid by attempting
	 * to create a socket of that type, and binding(if wanted).
	 * Also check policy for allowed connection before calling
	 * connect.
	 * (Binding will call the policy function internally.)
	 */
#ifdef	AF_INET6
	for(ai=server_addr->ai;ai;ai=ai->ai_next){

		if(ai->ai_family != AF_INET6) continue;

		if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
			return 0;
		if(rc < 0)
			goto error;
	}
#endif
	/*
	 * Now try IPv4 addresses.
	 */
	for(ai=server_addr->ai;ai;ai=ai->ai_next){

		if(ai->ai_family != AF_INET) continue;

		if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
			return 0;
		if(rc < 0)
			goto error;
	}

	if(server_addr->node_set)
		tstr = server_addr->node;
	else
		tstr = "Server";

	OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"Unable to connect to %s",tstr);

error:
	*err_ret = OWPErrFATAL;

	return -1;
}

/*
 * Function:	OWPControlOpen
 *
 * Description:	
 * 		Opens a connection to an owamp server. Returns after complete
 * 		control connection setup is complete. This means that encrytion
 * 		has been intialized, and the client is authenticated to the
 * 		server if that is necessary. However, the client has not
 * 		verified the server at this point.
 *
 * Returns:	
 * Side Effect:	
 */
OWPControl
OWPControlOpen(
	OWPContext	ctx,		/* control context	*/
	OWPAddr		local_addr,	/* local addr or null	*/
	OWPAddr		server_addr,	/* server addr		*/
	u_int32_t	mode_req_mask,	/* requested modes	*/
	const char	*kid,		/* kid or NULL		*/
	void		*app_data,	/* set app_data for this conn	*/
	OWPErrSeverity	*err_ret	/* err - return		*/
)
{
	int		rc;
	OWPControl	cntrl;
	u_int32_t	mode_avail;
	u_int8_t	key_value[16];
	u_int8_t	challenge[16];
	u_int8_t	token[32];
	u_int8_t	*key=NULL;
	OWPAcceptType	acceptval;
	struct timeval	tval;

	*err_ret = OWPErrOK;

	if( !(cntrl = _OWPControlAlloc(ctx,app_data,err_ret)))
		goto error;

	if((!server_addr) &&
		!(server_addr = OWPAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

	/*
	 * Address policy check happens in here.
	 */
	if(_OWPClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
		goto error;

	if( (rc=_OWPReadServerGreeting(cntrl,&mode_avail,challenge)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	/*
	 * Select mode wanted...
	 */
	mode_avail &= mode_req_mask;	/* mask out unwanted modes */

	/*
	 * retrieve key if needed
	 */
	if(kid &&
		(mode_avail & _OWP_DO_CIPHER)){
		strncpy(cntrl->kid_buffer,kid,sizeof(cntrl->kid_buffer)-1);
		if(_OWPCallGetAESKey(cntrl,cntrl->kid_buffer,key_value,
								err_ret)){
			key = key_value;
			cntrl->kid = cntrl->kid_buffer;
		}
		else{
			if(*err_ret != OWPErrOK)
				goto error;
		}
	}
	/*
	 * If no key, then remove auth/crypt modes
	 */
	if(!key)
		mode_avail &= ~_OWP_DO_CIPHER;

	/*
	 * Pick "highest" level mode still available to this server.
	 */
	if((mode_avail & OWP_MODE_ENCRYPTED) &&
			_OWPCallCheckControlPolicy(cntrl,OWP_MODE_ENCRYPTED,
				cntrl->kid,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_ENCRYPTED;
	}
	else if((*err_ret == OWPErrOK) &&
			(mode_avail & OWP_MODE_AUTHENTICATED) &&
			_OWPCallCheckControlPolicy(cntrl,OWP_MODE_AUTHENTICATED,
				cntrl->kid,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_AUTHENTICATED;
	}
	else if((*err_ret == OWPErrOK) &&
			(mode_avail & OWP_MODE_OPEN) &&
			_OWPCallCheckControlPolicy(cntrl,OWP_MODE_OPEN,
				NULL,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_OPEN;
	}
	else if(*err_ret != OWPErrOK){
		goto error;
	}
	else{
		OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
				"OWPControlOpen:No Common Modes");
		goto denied;
	}

	/*
	 * Initialize all the encryption values as necessary.
	 */
	if(cntrl->mode & _OWP_DO_CIPHER){
		unsigned char	buf[32];

		memcpy(buf,challenge,16);
		if(I2RandomBytes(ctx->rand_src,cntrl->session_key,16) != 0)
			goto error;

		memcpy(&buf[16],cntrl->session_key,16);

		_OWPMakeKey(cntrl,cntrl->session_key);


		if(OWPEncryptToken(key,buf,token) != 0)
			goto error;
	}
	else{
		if(I2RandomBytes(ctx->rand_src,token,32) != 0)
			goto error;
	}
	if(I2RandomBytes(ctx->rand_src,cntrl->writeIV,16) != 0)
		goto error;

	if(gettimeofday(&tval,NULL)!=0)
		goto error;
	/*
	 * Write the client greeting, and see if the Server agree's to it.
	 */
	if( ((rc=_OWPWriteClientGreeting(cntrl,token)) < OWPErrOK) ||
			((rc=_OWPReadServerOK(cntrl,&acceptval)) < OWPErrOK)){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	if(acceptval != OWP_CNTRL_ACCEPT){
		OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
							"Server denied access");
		goto denied;
	}

	if(gettimeofday(&cntrl->delay_bound,NULL)!=0)
		goto error;
	tvalsub(&cntrl->delay_bound,&tval);

	return cntrl;

error:
	*err_ret = OWPErrFATAL;
denied:
	if(cntrl->local_addr != local_addr)
		OWPAddrFree(local_addr);
	if(cntrl->remote_addr != server_addr)
		OWPAddrFree(server_addr);
	OWPControlClose(cntrl);
	return NULL;
}

static OWPBoolean
SetEndpointAddrInfo(
	OWPControl	cntrl,
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
)
{
	int			so_type;
	socklen_t		so_typesize = sizeof(so_type);
	struct sockaddr_storage	sbuff;
	socklen_t		so_size = sizeof(sbuff);
	struct sockaddr		*saddr=NULL;
	struct addrinfo		*ai=NULL;
	struct addrinfo		hints;
	char			*port=NULL;
	int			rc;

	if(!addr){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
						"Invalid test address");
		return False;
	}

	if(addr->ai)
		return True;

	if(addr->fd > -1){

		/*
		 * Get an saddr to describe the fd...
		 */
		if(getsockname(addr->fd,(void*)&sbuff,&so_size) != 0){
			OWPError(cntrl->ctx,OWPErrFATAL,
				errno,"getsockname():%s",
				strerror(errno));
			goto error;
		}

		/*
		 * Determine "type" of socket.
		 */
		if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
			OWPError(cntrl->ctx,OWPErrFATAL,
				errno,"getsockopt():%s",
				strerror(errno));
			goto error;
		}

		if(! (saddr = malloc(so_size))){
			OWPError(cntrl->ctx,OWPErrFATAL,
				errno,"malloc():%s",strerror(errno));
			goto error;
		}
		memcpy((void*)saddr,(void*)&sbuff,so_size);
		
		/*
		 * create an addrinfo to describe this sockaddr
		 */
		if(! (ai = malloc(sizeof(struct addrinfo)))){
			OWPError(cntrl->ctx,OWPErrFATAL,
				errno,"malloc():%s",strerror(errno));
			goto error;
		}

		ai->ai_flags = 0;
		ai->ai_family = saddr->sa_family;
		ai->ai_socktype = so_type;
		/*
		 * all necessary info encapsalated by family/socktype,
		 * so default proto to IPPROTO_IP(0).
		 * (Could probably set this to IPPROTO_UDP/IPPROTO_TCP
		 * based upon the socktype, but the 0 default fits
		 * the model for most "socket" calls.)
		 */
		ai->ai_protocol = IPPROTO_IP;
		ai->ai_addrlen = so_size;
		ai->ai_canonname = NULL;
		ai->ai_addr = saddr;
		ai->ai_next = NULL;

		/*
		 * Set OWPAddr ai
		 */
		addr->ai = ai;
		addr->ai_free = True;
	}
	else if(addr->node_set){
		/*
		 * Hey - do the normal thing, call getaddrinfo
		 * to get an addrinfo, how novel!
		 */
		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;

		if(addr->port_set)
			port = addr->port;
		if(((rc = getaddrinfo(addr->node,port,&hints,&ai))!=0) || !ai){
			OWPError(cntrl->ctx,OWPErrFATAL,
				errno,"getaddrinfo(): %s", gai_strerror(rc));
			goto error;
		}
		addr->ai = ai;

	}else{
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
						"Invalid test address");
		goto error;
	}

	return True;

error:
	if(saddr) free(saddr);
	if(ai) free(ai);
	*err_ret = OWPErrFATAL;
	return FALSE;
}

static int
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
	int		rc;
	OWPAcceptType	acceptval;
	struct sockaddr	*set_addr=NULL;
	u_int16_t	*port_ret=NULL;
	u_int8_t	*sid_ret=NULL;

	if((rc = _OWPWriteTestRequest(cntrl, sender->saddr, receiver->saddr,
				      server_conf_sender, server_conf_receiver,
				      sid, test_spec)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		return -1;
	}

	/*
	 * Figure out if the server will be returning Port field.
	 * If so - set set_addr to the sockaddr that needs to be set.
	 */
	if(server_conf_sender && !server_conf_receiver)
		set_addr = sender->saddr;
	else if(!server_conf_sender && server_conf_receiver)
		set_addr = receiver->saddr;

	/*
	 * If it was determined that the server will be returning port,
	 * figure out the correct offset into set_addr for they type
	 * of sockaddr, and set port_ret to that address.
	 * (Don't you just love the joy's of supporting multiple AF's?)
	 */
	if(set_addr){
		switch(set_addr->sa_family){
			struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
			struct sockaddr_in6	*saddr6;

			case AF_INET6:
				saddr6 = (struct sockaddr_in6*)set_addr;
				port_ret = &saddr6->sin6_port;
				break;
#endif
			case AF_INET:
				saddr4 = (struct sockaddr_in*)set_addr;
				port_ret = &saddr4->sin_port;
				break;
			default:
				OWPError(cntrl->ctx,
						OWPErrFATAL,OWPErrINVALID,
						"Invalid address family");
				return 1;
		}
	}

	if(server_conf_receiver)
		sid_ret = sid;

	if((rc = _OWPReadTestAccept(cntrl,&acceptval,port_ret,sid_ret)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		return -1;
	}

	if(acceptval == OWP_CNTRL_ACCEPT)
		return 0;

	/*
	 * TODO: report addresses for test here.
	 */
	OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,"Server denied test:");
	*err_ret = OWPErrOK;
	return 1;
}

OWPAddr
OWPAddrByLocalControl(
		   OWPControl	cntrl
		   )
{
	struct addrinfo		*ai=NULL;
	OWPAddr			addr;
	struct sockaddr_storage	saddr_rec;
	struct sockaddr		*oaddr=NULL;
	socklen_t		len;
	u_int16_t		*port=NULL;

	if(cntrl->local_addr && cntrl->local_addr->saddr){
		oaddr = cntrl->local_addr->saddr;
		len = cntrl->local_addr->saddrlen;
	}else{
		memset(&saddr_rec,0,sizeof(saddr_rec));
		oaddr = (struct sockaddr*)&saddr_rec;
		len = sizeof(saddr_rec);
		if(getsockname(cntrl->sockfd,oaddr,&len) != 0){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"getsockname():%M");
			return NULL;
		}
	}

	if(!len)
		return NULL;

	switch(oaddr->sa_family){
		struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
		struct sockaddr_in6	*saddr6;

		case AF_INET6:
			saddr6 = (struct sockaddr_in6*)oaddr;
			port = &saddr6->sin6_port;
			break;
#endif
		case AF_INET:
			saddr4 = (struct sockaddr_in*)oaddr;
			port = &saddr4->sin_port;
			break;
		default:
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
						"Invalid address family");
			return NULL;
	}
	*port = 0;

	if( !(addr = _OWPAddrAlloc(cntrl->ctx)))
		return NULL;

	if( !(ai = calloc(1,sizeof(struct addrinfo))) ||
					!(addr->saddr = calloc(1,len))){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%M");
		goto error;
	}

	memcpy(addr->saddr,oaddr,len);
	ai->ai_addr = addr->saddr;
	addr->saddrlen = len;
	ai->ai_addrlen = len;

	ai->ai_flags = 0;
	ai->ai_family = oaddr->sa_family;
	ai->ai_socktype = SOCK_DGRAM;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default */
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->so_type = SOCK_DGRAM;
	addr->so_protocol = IPPROTO_IP;

	return addr;

error:
	if(addr)
		OWPAddrFree(addr);
	if(ai)
		free(ai);

	return NULL;
}

OWPBoolean
OWPSessionRequest(
	OWPControl	cntrl,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec,
	OWPSID		sid_ret,
	FILE		*fp,
	OWPErrSeverity	*err_ret
)
{
	struct addrinfo		*rai=NULL;
	struct addrinfo		*sai=NULL;
	OWPTestSession		tsession = NULL;
	int			rc=0;

	*err_ret = OWPErrOK;

	/*
	 * Check cntrl state is appropriate for this call.
	 * (this would happen as soon as we tried to call the protocol
	 * function - but it saves a lot of misplaced work to check now.)
	 */
	if(!cntrl || !_OWPStateIsRequest(cntrl)){
		*err_ret = OWPErrFATAL;
		OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
		"OWPSessionRequest called with invalid cntrl record");
		goto error;
	}

	if(!receiver){
		if(server_conf_receiver)
			receiver = OWPAddrByNode(cntrl->ctx,"localhost");
		else
			receiver = OWPAddrByLocalControl(cntrl);
		if(!receiver)
			goto error;
	}

	if(!sender){
		if(server_conf_sender)
			sender = OWPAddrByNode(cntrl->ctx,"localhost");
		else
			sender = OWPAddrByLocalControl(cntrl);
		if(!sender)
			goto error;
	}

	/*
	 * Get addrinfo for address spec's so we can choose between
	 * the different address possiblities in the next step. (These
	 * ai will be SOCK_DGRAM unless an fd was passed in directly, in
	 * which case we trust the application knows what it is doing...)
	 */
	if(!SetEndpointAddrInfo(cntrl,receiver,err_ret) ||
				!SetEndpointAddrInfo(cntrl,sender,err_ret))
		goto error;
	/*
	 * Determine proper address specifications for send/recv.
	 * Loop on ai values to find a match and use that.
	 * (We prefer IPV6 over others, so loop over IPv6 addrs first...)
	 * We only support AF_INET and AF_INET6.
	 */
#ifdef	AF_INET6
	for(rai = receiver->ai;rai;rai = rai->ai_next){
		if(rai->ai_family != AF_INET6) continue;
		for(sai = sender->ai;sai;sai = sai->ai_next){
			if(rai->ai_family != sai->ai_family) continue;
			if(rai->ai_socktype != sai->ai_socktype) continue;
			goto foundaddr;
		}
	}
#endif
	for(rai = receiver->ai;rai;rai = rai->ai_next){
		if(rai->ai_family != AF_INET) continue;
		for(sai = sender->ai;sai;sai = sai->ai_next){
			if(rai->ai_family != sai->ai_family) continue;
			if(rai->ai_socktype != sai->ai_socktype) continue;
			goto foundaddr;
		}
	}

	/*
	 * Didn't find compatible addrs - return error.
	 */
	*err_ret = OWPErrWARNING;
	OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
		"OWPSessionRequest called with incompatible addresses");
	goto error;

foundaddr:
	receiver->saddr = rai->ai_addr;
	receiver->saddrlen = rai->ai_addrlen;
	receiver->so_type = rai->ai_socktype;
	receiver->so_protocol = rai->ai_protocol;
	sender->saddr = sai->ai_addr;
	sender->saddrlen = sai->ai_addrlen;
	sender->so_type = sai->ai_socktype;
	sender->so_protocol = sai->ai_protocol;

	/*
	 * Create a structure to store the stuff we need to keep for
	 * later calls.
	 */
	if( !(tsession = _OWPTestSessionAlloc(cntrl,sender,!server_conf_sender,
				receiver,!server_conf_receiver,test_spec)))
		goto error;

	/*
	 * Configure receiver first since the sid comes from there.
	 */
	if(server_conf_receiver){
		/*
		 * If send local, check local policy for sender
		 */
		if(!server_conf_sender){
			/*
			 * create the local sender
			 */
			if(!_OWPCallEndpointInit(cntrl,tsession,sender,NULL,
					&tsession->send_end_data,err_ret))
				goto error;
		}
		/*
		 * Request the server create the receiver & possibly the
		 * sender.
		 */
		if((rc = _OWPClientRequestTestReadResponse(cntrl,
					sender,server_conf_sender,
					receiver,server_conf_receiver,
					test_spec,tsession->sid,err_ret)) != 0){
			goto error;
		}

		/*
		 * Now that we know the SID we can create the schedule.
		 */
		if(_OWPTestSessionCreateSchedule(tsession) != 0)
			goto error;

		/*
		 * If sender is local, complete it's initialization now that
		 * we know the receiver port number.
		 */
		if(!server_conf_sender){
			/*
			 * check local policy for this sender
			 * (had to call policy check after initialize
			 * because schedule couldn't be computed until
			 * we got the SID from the server.)
			 */
			if(!_OWPCallCheckTestPolicy(cntrl,True,
					sender->saddr,receiver->saddr,
					test_spec,err_ret)){
				OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
				goto error;
			}

			if(!_OWPCallEndpointInitHook(cntrl,tsession,
					&tsession->send_end_data,err_ret))
				goto error;
		}
	}
	else{
		/*
		 * local receiver - create SID and compute schedule.
		 */
		if(_OWPCreateSID(tsession) ||
				_OWPTestSessionCreateSchedule(tsession))
			goto error;

		/*
		 * Local receiver - first check policy, then create.
		 */
		if(!_OWPCallCheckTestPolicy(cntrl,False,receiver->saddr,
					sender->saddr,test_spec,err_ret)){
			OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
			goto error;
		}
		if(!_OWPCallEndpointInit(cntrl,tsession,receiver,fp,
					&tsession->recv_end_data,err_ret))
			goto error;


		/*
		 * If conf_sender - make request to server
		 */
		if(server_conf_sender){
			if((rc = _OWPClientRequestTestReadResponse(cntrl,
					sender,server_conf_sender,
					receiver,server_conf_receiver,
					test_spec,tsession->sid,err_ret)) != 0){
				goto error;
			}
		}else{
			/*
			 * Otherwise create sender: check policy,then init.
			 *
			 * btw - this is a VERY strange situation - the
			 * client is setting up a test session without
			 * making a request to the server...
			 *
			 * Should almost just return an error here...
			 */
			if(!_OWPCallCheckTestPolicy(cntrl,True,sender->saddr,
					receiver->saddr,test_spec,err_ret)){
				OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
				goto error;
			}
			if(!_OWPCallEndpointInit(cntrl,tsession,sender,NULL,
						&tsession->send_end_data,
						err_ret))
				goto error;
			if(!_OWPCallEndpointInitHook(cntrl,tsession,
					&tsession->send_end_data,err_ret))
				goto error;
		}
		if(!_OWPCallEndpointInitHook(cntrl,tsession,
					&tsession->recv_end_data,err_ret))
			goto error;
	}

	tsession->next = cntrl->tests;
	cntrl->tests = tsession;

	memcpy(sid_ret,tsession->sid,sizeof(OWPSID));

	return True;

error:
	if(tsession)
		_OWPTestSessionFree(tsession,OWP_CNTRL_FAILURE);
	else{
		/*
		 * If tsession exists - the addr's will be free'd as part
		 * of it - otherwise, do it here.
		 */
		OWPAddrFree(receiver);
		OWPAddrFree(sender);
	}

	return False;
}

OWPErrSeverity
OWPStartSessions(
	OWPControl	cntrl
)
{
	int		rc;
	OWPErrSeverity	err,err2=OWPErrOK;
	OWPTestSession	tsession;
	OWPAcceptType	acceptval;

	if(!cntrl){
		OWPError(NULL,OWPErrFATAL,OWPErrINVALID,
		"OWPStartSessions called with invalid cntrl record");
		return OWPErrFATAL;
	}

	if((rc = _OWPWriteStartSessions(cntrl)) < OWPErrOK)
		return _OWPFailControlSession(cntrl,rc);

	/*
	 * Small optimization... - start local receivers while waiting for
	 * the server to respond. (should not start senders - don't want
	 * to send packets unless control-ack comes back positive.)
	 */
	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->recv_end_data){
			if(!_OWPCallEndpointStart(tsession,
						&tsession->recv_end_data,&err))
				return _OWPFailControlSession(cntrl,err);
			err2 = MIN(err,err2);
		}
	}

	if(((rc = _OWPReadControlAck(cntrl,&acceptval)) < OWPErrOK) ||
					(acceptval != OWP_CNTRL_ACCEPT))
		return _OWPFailControlSession(cntrl,OWPErrFATAL);

	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->send_end_data){
			if(!_OWPCallEndpointStart(tsession,
						&tsession->send_end_data,&err))
				return _OWPFailControlSession(cntrl,err);
			err2 = MIN(err,err2);
		}
	}

	return err2;
}

/*
** Compute delay in seconds
*/
double
owp_delay(OWPTimeStamp *send_time, OWPTimeStamp *recv_time)
{
	/*
	 * num64 is encoded as 32.32 (sec.frac) - so divide by 2^32
	 * to return scaled to "seconds".
	 * (Do subtraction in u_int64_t space to maintain precision.)
	 */
	static double scale = ((u_int64_t)1<<32);
	OWPnum64 t1, t2;

	assert(send_time);
	assert(recv_time);
	t1 = OWPTimeStamp2num64(send_time);
	t2 = OWPTimeStamp2num64(recv_time);

	/* Return negative quantity if send_time is before recv_time. 
	   Yes weird, -  but possible with bad clocks. */
	return (t2 > t1)? (double)(t2 - t1)/scale : (double)(t1 - t2)/(-scale);
}

/*
 * Returns the number of data records in the file. If < 1, check err_ret to
 * find out if it was an error condition: ErrOK just means the request
 * was denied by the server.
 *
 * (If the caller doesn't really want to save the information, they can
 * open a file to /dev/null so everything gets thrown away. We need to
 * download the entire session in any case, so it doesn't make sense
 * to split the api.)
 *
 * TODO: In v5 OWPSessionHeader should be filled in with the SessionRequest
 * information. For now, if hdr_ret is passed in, set hdr_ret->header = False.
 */
int
OWPFetchSession(
	OWPControl		cntrl,
	FILE			*fp,
	u_int32_t		begin,
	u_int32_t		end,
	OWPSID			sid,
	OWPSessionHeader	hdr_ret,
	OWPErrSeverity		*err_ret
	)
{
	/*
	 * buf is 80 because:
	 * 80 == (_OWP_RIJNDAEL_BLOCK_SIZE*5) == (_OWP_TS_REC_SIZE*4)
	 * if this changes, this routine must change.
	 */
#if	(80 != (_OWP_RIJNDAEL_BLOCK_SIZE*5))
#error "Block-sizes have changed! Fix this function."
#endif
#if     (80 != (_OWP_TS_REC_SIZE*4))
#error "Record sizes have changed! Fix this function."
#endif
	OWPAcceptType	acc_type;
	u_int32_t	num_rec,n;
	u_int8_t	buf[80];
	int		i;

	/*
	 * Make the request of the server.
	 */
	if((*err_ret = _OWPWriteRetrieveSession(cntrl,begin,end,sid)) <
								OWPErrWARNING)
		goto failure;

	/*
	 * Read the response
	 */
	if((*err_ret = _OWPReadControlAck(cntrl, &acc_type)) < OWPErrWARNING)
		goto failure;
	
	/*
	 * If the server didn't accept, we are done.
	 */
	if(acc_type != OWP_CNTRL_ACCEPT)
		return 0;

	/*
	 * Read the DataHeader from the server.
	 * (Currently the only useful info is num_rec - in v5 this will
	 * return full session info on this sid's session.)
	 */
	if((*err_ret=_OWPReadFetchHeader(cntrl,&num_rec,NULL)) < OWPErrWARNING)
		goto failure;

	if(hdr_ret)
		hdr_ret->header = False;

	/*
	 * Currently write boring header - again, in v5 this will
	 * need to save more interesting information. (Basically we fill
	 * in an OWPSessionHeader structure with the ReadFetchHeader function,
	 * and pass that into this function. (And set hdr_ret with it.)
	 */
	if(OWPWriteDataHeader(cntrl->ctx,fp,NULL) != 0){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"OWPWriteDataHeader():%M");
		goto failure;
	}

	for(n=num_rec;n>=4;n-=4){
		if(_OWPReceiveBlocks(cntrl,buf,5) != 5)
			goto failure;
		if(fwrite(buf,_OWP_TS_REC_SIZE,4,fp) < 4){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"OWPFetchSession:fwrite():%M");
			goto failure;
		}
	}

	if(n){
		/*
		 * Read enough AES blocks to get remaining records.
		 */
		int	blks = n*_OWP_TS_REC_SIZE/_OWP_RIJNDAEL_BLOCK_SIZE + 1;

		if(_OWPReceiveBlocks(cntrl,buf,blks) != blks)
			goto failure;
		if(fwrite(buf,_OWP_TS_REC_SIZE,n,fp) < n){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"OWPFetchSession:fwrite():%M");
			goto failure;
		}
		/* check MBZ padding */
		for(i=(n*_OWP_TS_REC_SIZE);
					i < (blks*_OWP_RIJNDAEL_BLOCK_SIZE);i++)
			if(buf[i] != 0){
				OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"OWPFetchSession:MBZ padding corrupt");
			}
	}

	fflush(fp);

	/*
	 * Read final MBZ AES block to finalize transaction.
	 */
	if(_OWPReceiveBlocks(cntrl,buf,1) != 1)
		goto failure;
	if(memcmp(cntrl->zero,buf,_OWP_RIJNDAEL_BLOCK_SIZE)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"OWPFetchSession:Final MBZ block corrupt");
		*err_ret = OWPErrFATAL;
		goto failure;
	}


	return num_rec;

failure:
	(void)_OWPFailControlSession(cntrl,*err_ret);
	return 0;
}
