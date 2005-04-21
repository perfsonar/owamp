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

/*
 * Function:	_OWPClientBind
 *
 * Description:	
 * 	This function attempts to bind the fd to a local address allowing
 * 	the client socket to have the source addr bound.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 	True if successful, False if unsuccessful.
 * 	Additionally err_ret will be set to OWPErrFATAL if there was a
 * 	problem with the local_addr.
 * Side Effect:	
 */
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

	*err_ret = OWPErrOK;

	/*
	 * Ensure local_addr is not from a fd.
	 */
	if(local_addr->fd > -1){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"Invalid local_addr - ByFD");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * if getaddrinfo has not been called for this OWPAddr, then call
	 * it.
	 */
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
					"getaddrinfo([%s]:%s): %s",
                                        local_addr->node,port,
                                        gai_strerror(gai));
			*err_ret = OWPErrFATAL;
			return False;
		}

		local_addr->ai = airet;
	}

	/*
	 * Now that we have a valid addrinfo list for this address, go
	 * through each of those addresses and try to bind the first
	 * one that matches addr family and socktype.
	 */
	for(ai=local_addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != remote_addrinfo->ai_family)
			continue;
		if(ai->ai_socktype != remote_addrinfo->ai_socktype)
			continue;

		if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
			local_addr->saddr = ai->ai_addr;
			local_addr->saddrlen = ai->ai_addrlen;
			return True;
		}else{
			switch(errno){
				/* report these errors */
				case EAGAIN:
				case EBADF:
				case ENOTSOCK:
				case EADDRNOTAVAIL:
				case EADDRINUSE:
				case EACCES:
				case EFAULT:
					OWPError(cntrl->ctx,OWPErrFATAL,errno,
							"bind(): %M");
					break;
				/* ignore all others */
				default:
					break;
			}
			return False;
		}

	}

	/*
	 * None found.
	 */
	return False;
}

/*
 * Function:	SetClientAddrInfo
 *
 * Description:	
 * 	PRIVATE function for initializing the addrinfo portion of
 * 	the given OWPAddr.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
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
 * Function:	TryAddr
 *
 * Description:	
 * 	This function attempts to connect to the given ai description of
 * 	the "server" addr possibly binding to "local" addr.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 *	-1: error - future trys are unlikely to succeed - terminate upward.
 *	 0: success - wahoo!
 *	 1: keep trying - this one didn't work, probably addr mismatch.
 * Side Effect:	
 */
/*
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
	if(connect(fd,ai->ai_addr,ai->ai_addrlen) == 0){
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

/*
 * Function:	_OWPClientConnect
 *
 * Description:	
 * 	This function attempts to create a socket connection between
 * 	the local client and the server. Each specified with OWPAddr
 * 	records. If the local_addr is not specified, then the source
 * 	addr is not bound. The server_addr is used to get a valid list
 * 	of addrinfo records and each addrinfo description record is
 * 	tried until one succeeds. (IPV6 is prefered over IPV4)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
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

	/*
	 * Initialize addrinfo portion of server_addr record.
	 */
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

	/*
	 * Unable to connect! If we have a server name report it in
	 * the error message.
	 */
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
 * 		A valid OWPControl pointer or NULL.
 * Side Effect:	
 */
OWPControl
OWPControlOpen(
	OWPContext	ctx,		/* control context	*/
	OWPAddr		local_addr,	/* local addr or null	*/
	OWPAddr		server_addr,	/* server addr		*/
	u_int32_t	mode_req_mask,	/* requested modes	*/
	OWPUserID	userid,		/* userid or NULL	*/
	OWPNum64	*uptime_ret,	/* server uptime - ret	*/
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
	struct timeval	tvalstart,tvalend;
	OWPNum64	uptime;

	*err_ret = OWPErrOK;

	/*
	 * First allocate memory for the control state.
	 */
	if( !(cntrl = _OWPControlAlloc(ctx,err_ret)))
		goto error;

	/*
	 * Initialize server record for address we are connecting to.
	 */
	if((!server_addr) &&
		!(server_addr = OWPAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

	/*
	 * Connect to the server.
	 * Address policy check happens in here.
	 */
	if(_OWPClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
		goto error;

	/*
	 * Read the server greating.
	 */
	if((rc=_OWPReadServerGreeting(cntrl,&mode_avail,challenge)) < OWPErrOK){
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
	if(userid &&
		(mode_avail & OWP_MODE_DOCIPHER)){
		strncpy(cntrl->userid_buffer,userid,
					sizeof(cntrl->userid_buffer)-1);
		if(_OWPCallGetAESKey(cntrl->ctx,cntrl->userid_buffer,key_value,
								err_ret)){
			key = key_value;
			cntrl->userid = cntrl->userid_buffer;
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
		mode_avail &= ~OWP_MODE_DOCIPHER;

	/*
	 * Pick "highest" level mode still available to this server.
	 */
	if((mode_avail & OWP_MODE_ENCRYPTED) &&
			_OWPCallCheckControlPolicy(cntrl,OWP_MODE_ENCRYPTED,
				cntrl->userid,
				(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_ENCRYPTED;
	}
	else if((*err_ret == OWPErrOK) &&
			(mode_avail & OWP_MODE_AUTHENTICATED) &&
			_OWPCallCheckControlPolicy(cntrl,OWP_MODE_AUTHENTICATED,
				cntrl->userid,
				(local_addr)?local_addr->saddr:NULL,
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
	if(cntrl->mode & OWP_MODE_DOCIPHER){
		/*
		 * Create "token" for ClientGreeting message.
		 * Section 4.1 of owamp spec:
		 * 	AES(concat(challenge(16),sessionkey(16)))
		 */
		unsigned char	buf[32];

		/*
		 * copy challenge
		 */
		memcpy(buf,challenge,16);

		/*
		 * Create random session key
		 */
		if(I2RandomBytes(ctx->rand_src,cntrl->session_key,16) != 0)
			goto error;
		/*
		 * concat session key to buffer
		 */
		memcpy(&buf[16],cntrl->session_key,16);

		/*
		 * Initialize AES structures for use with this
		 * key. (ReadBlock/WriteBlock functions will automatically
		 * use this key for this cntrl connection.
		 */
		_OWPMakeKey(cntrl,cntrl->session_key);

		/*
		 * Encrypt the token as specified by Section 4.1
		 */
		if(OWPEncryptToken(key,buf,token) != 0)
			goto error;

		/*
		 * Create random writeIV
		 */
		if(I2RandomBytes(ctx->rand_src,cntrl->writeIV,16) != 0)
			goto error;
	}

	/*
	 * Get current time before sending client greeting - used
	 * for very rough estimate of RTT. (upper bound)
	 */
	if(gettimeofday(&tvalstart,NULL)!=0)
		goto error;

	/*
	 * Write the client greeting, and see if the Server agree's to it.
	 */
	if( ((rc=_OWPWriteClientGreeting(cntrl,token)) < OWPErrOK) ||
			((rc=_OWPReadServerOK(cntrl,&acceptval)) < OWPErrOK)){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}

        /*
         * TODO: enumerate reason for rejection
         */
	if(acceptval != OWP_CNTRL_ACCEPT){
		OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,
							"Server denied access");
		goto denied;
	}

	/*
	 * Get current time after response from server and set the RTT
	 * in the "rtt_bound" field of cntrl.
	 */
	if(gettimeofday(&tvalend,NULL)!=0)
		goto error;
	tvalsub(&tvalend,&tvalstart);
	OWPTimevalToNum64(&cntrl->rtt_bound,&tvalend);

	if((rc=_OWPReadServerUptime(cntrl,&uptime)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		goto error;
	}

	if(uptime_ret){
		*uptime_ret = uptime;
	}

	/*
	 * Done - return!
	 */
	return cntrl;

	/*
	 * If there was an error - set err_ret, then cleanup memory and return.
	 */
error:
	*err_ret = OWPErrFATAL;

	/*
	 * If access was denied - cleanup memory and return.
	 */
denied:
	if(cntrl->local_addr != local_addr)
		OWPAddrFree(local_addr);
	if(cntrl->remote_addr != server_addr)
		OWPAddrFree(server_addr);
	OWPControlClose(cntrl);
	return NULL;
}

/*
 * Function:	SetEndpointAddrInfo
 *
 * Description:	
 * 	Initialize the OWPAddr record's addrinfo section for an Endpoint
 * 	of a test. (UDP test with no fixed port number.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
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

	/*
	 * Must specify an addr record to this function.
	 */
	if(!addr){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
						"Invalid test address");
		return False;
	}

	/*
	 * Already done!
	 */
	if(addr->ai)
		return True;

	/*
	 * Addr was passed in as a fd so application created the
	 * socket itself - determine as much information about the
	 * socket as we can.
	 */
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
		/*
		 * Empty OWPAddr record - report error.
		 */
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
						"Invalid test address");
		goto error;
	}

	/*
	 * success!
	 */
	return True;

error:
	/*
	 * Failed - free memory and return negative.
	 */
	if(saddr) free(saddr);
	if(ai) free(ai);
	*err_ret = OWPErrFATAL;
	return FALSE;
}

/*
 * Function:	_OWPClientRequestTestReadResponse
 *
 * Description:	
 * 	This function is used to request a test from the server and
 * 	return the response.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 	0 on success
 * Side Effect:	
 */
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
	u_int16_t	port_ret=0;
	u_int8_t	*sid_ret=NULL;

	if((rc = _OWPWriteTestRequest(cntrl, sender->saddr, receiver->saddr,
				      server_conf_sender, server_conf_receiver,
				      sid, test_spec)) < OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		return 1;
	}

	/*
	 * Figure out if the server will be returning Port field.
	 * If so - set set_addr to the sockaddr that needs to be set.
	 */
	if(server_conf_sender && !server_conf_receiver)
		set_addr = sender->saddr;
	else if(!server_conf_sender && server_conf_receiver)
		set_addr = receiver->saddr;

	if(server_conf_receiver)
		sid_ret = sid;

	if((rc = _OWPReadTestAccept(cntrl,&acceptval,&port_ret,sid_ret)) <
								OWPErrOK){
		*err_ret = (OWPErrSeverity)rc;
		return 1;
	}

	/*
	 * If it was determined that the server returned a port,
	 * figure out the correct offset into set_addr for the type
	 * of sockaddr, and set  the port in the saddr to the
	 * port_ret value.
	 * (Don't you just love the joy's of supporting multiple AF's?)
	 */
	if(set_addr){
		switch(set_addr->sa_family){
			struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
			struct sockaddr_in6	*saddr6;

			case AF_INET6:
				saddr6 = (struct sockaddr_in6*)set_addr;
				saddr6->sin6_port = htons(port_ret);
				break;
#endif
			case AF_INET:
				saddr4 = (struct sockaddr_in*)set_addr;
				saddr4->sin_port = htons(port_ret);
				break;
			default:
				OWPError(cntrl->ctx,
						OWPErrFATAL,OWPErrINVALID,
						"Invalid address family");
				return 1;
		}
	}


	if(acceptval == OWP_CNTRL_ACCEPT)
		return 0;

        /*
         * TODO: enumerate failure reasons
         */
	OWPError(cntrl->ctx,OWPErrINFO,OWPErrPOLICY,"Server denied test");

	*err_ret = OWPErrOK;
	return 1;
}

/*
 * Function:	OWPAddrByLocalControl
 *
 * Description:	
 * 	Create an OWPAddr record for the local address based upon the
 * 	control socket connection. (This is used to make a test request
 * 	to to the same address that the control connection is coming from -
 * 	it is very useful when you allow the local connection to wildcard
 * 	since the test connection cannot wildcard.
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
OWPAddrByLocalControl(
		   OWPControl	cntrl
		   )
{
	struct addrinfo		*ai=NULL;
	OWPAddr			addr;
	struct sockaddr_storage	saddr_rec;
	struct sockaddr		*oaddr=(struct sockaddr*)&saddr_rec;
	socklen_t		len;
	u_int16_t		*port=NULL;

	/*
	 * copy current socketaddr into saddr_rec
	 */
	if(cntrl->local_addr && cntrl->local_addr->saddr){
		len = cntrl->local_addr->saddrlen;
		memcpy(&saddr_rec,cntrl->local_addr->saddr,len);
	}else{
		memset(&saddr_rec,0,sizeof(saddr_rec));
		len = sizeof(saddr_rec);
		if(getsockname(cntrl->sockfd,oaddr,&len) != 0){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"getsockname():%M");
			return NULL;
		}
	}

	/*
	 * If copy was unsuccessful return error.
	 */
	if(!len)
		return NULL;

	/*
	 * decode v4 and v6 sockaddrs.
	 */
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

	/*
	 * Allocate an OWPAddr record to assign the data into.
	 */
	if( !(addr = _OWPAddrAlloc(cntrl->ctx)))
		return NULL;

	if( !(ai = calloc(1,sizeof(struct addrinfo))) ||
					!(addr->saddr = calloc(1,len))){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%M");
		goto error;
	}

	/*
	 * Assign all the fields.
	 */
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

/*
 * Function:	OWPSessionRequest
 *
 * Description:	
 * 	Public function used to request a test from the server.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 	True/False based upon acceptance from server. If False is returned
 * 	check err_ret to see if an error condition exists. (If err_ret is
 * 	not OWPErrOK, the control connection is probably no longer valid.)
 * Side Effect:	
 */
OWPBoolean
OWPSessionRequest(
	OWPControl	cntrl,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec,
	FILE		*fp,
	OWPSID		sid_ret,
	OWPErrSeverity	*err_ret
)
{
	struct addrinfo		*rai=NULL;
	struct addrinfo		*sai=NULL;
	OWPTestSession		tsession = NULL;
	int			rc=0;
        OWPAcceptType           aval = OWP_CNTRL_ACCEPT;

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

	/*
	 * If NULL passed in for recv address - fill it in with local
	 */
	if(!receiver){
		if(server_conf_receiver)
			receiver = OWPAddrByNode(cntrl->ctx,"localhost");
		else
			receiver = OWPAddrByLocalControl(cntrl);
		if(!receiver)
			goto error;
	}

	/*
	 * If NULL passed in for send address - fill it in with local
	 */
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
	/*
	 * Fill OWPAddr records with "selected" addresses for test.
	 */
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
	if( !(tsession = _OWPTestSessionAlloc(cntrl,sender,server_conf_sender,
				receiver,server_conf_receiver,test_spec)))
		goto error;

	/*
	 * This section initializes the two endpoints for the test.
	 * EndpointInit is used to create a local socket and allocate
	 * a port for the local side of the test.
	 *
	 * EndpointInitHook is used to set the information for the
	 * remote side of the test and then the Endpoint process
	 * is forked off.
	 *
	 * The request to the server is interwoven in based upon which
	 * side needs to happen first. (The receiver needs to be initialized
	 * first because the SID comes from there - so, if conf_receiver
	 * then the request is sent to the server, and then other work
	 * happens. If the client is the receiver, then the local
	 * initialization needs to happen before sending the request.)
	 */

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
			if(!_OWPEndpointInit(cntrl,tsession,sender,NULL,
							&aval,err_ret)){
				goto error;
			}
		}
		else{
			/*
			 * This request will fail with the sample implementation
			 * owampd. owampd is not prepared to configure both
			 * endpoints - but let the test request go through
			 * here anyway.  It will allow a client of the
			 * sample implementation to be used with a possibly
			 * more robust server.
			 */
			;
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
		 * Now that we know the SID we can create the schedule
		 * context.
		 */
		if(!(tsession->sctx = OWPScheduleContextCreate(cntrl->ctx,
					tsession->sid,&tsession->test_spec))){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to init schedule generator");
			goto error;
		}

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
					sender->saddrlen,
					test_spec,&tsession->closure,err_ret)){
				OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
				goto error;
			}

			if(!_OWPEndpointInitHook(cntrl,tsession,&aval,err_ret)){
				goto error;
			}
		}
	}
	else{
		/*
		 * local receiver - create SID and compute schedule.
		 */
		if(_OWPCreateSID(tsession) != 0){
			goto error;
		}

		/*
		 * Now that we know the SID we can create the schedule
		 * context.
		 */
		if(!(tsession->sctx = OWPScheduleContextCreate(cntrl->ctx,
					tsession->sid,&tsession->test_spec))){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to init schedule generator");
			goto error;
		}

		/*
		 * Local receiver - first check policy, then create.
		 */
		if(!_OWPCallCheckTestPolicy(cntrl,False,receiver->saddr,
					sender->saddr,sender->saddrlen,
					test_spec,
					&tsession->closure,err_ret)){
			OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
			goto error;
		}
		if(!_OWPEndpointInit(cntrl,tsession,receiver,fp,&aval,err_ret)){
			goto error;
		}


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
		}
		else{
			/*
			 * This is a VERY strange situation - the
			 * client is setting up a test session without
			 * making a request to the server...
			 *
			 * Just return an error here...
			 */
			OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
			goto error;
		}
		if(!_OWPEndpointInitHook(cntrl,tsession,&aval,err_ret)){
			goto error;
		}
	}

	/*
	 * Server accepted our request, and we were able to initialize our
	 * side of the test. Add this "session" to the tests list for this
	 * control connection.
	 */
	tsession->next = cntrl->tests;
	cntrl->tests = tsession;

	/*
	 * return the SID for this session to the caller.
	 */
	memcpy(sid_ret,tsession->sid,sizeof(OWPSID));

	return True;

error:
        switch(aval){
            case OWP_CNTRL_ACCEPT:
                break;
            case OWP_CNTRL_REJECT:
		OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,"Test not allowed");
                break;
            case OWP_CNTRL_UNSUPPORTED:
		OWPError(cntrl->ctx,*err_ret,OWPErrUNKNOWN,
                        "Test type unsupported");
                break;
            case OWP_CNTRL_UNAVAILABLE_PERM:
                OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
                        "Test denied: resources unavailable");
                break;
            case OWP_CNTRL_UNAVAILABLE_TEMP:
                OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
                        "Test denied: resource temporarily unavailable");
                break;
            case OWP_CNTRL_FAILURE:
            default:
		OWPError(cntrl->ctx,*err_ret,OWPErrUNKNOWN,"Test failed");
                break;
        }

	if(tsession){
		_OWPTestSessionFree(tsession,OWP_CNTRL_FAILURE);
	}
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

/*
 * Function:	OWPStartSessions
 *
 * Description:	
 * 	This function is used by applications to send the StartSessions
 * 	message to the server and to kick of it's side of all sessions.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
OWPErrSeverity
OWPStartSessions(
	OWPControl	cntrl
)
{
	int		rc;
	OWPErrSeverity	err,err2=OWPErrOK;
	OWPTestSession	tsession;
	OWPAcceptType	acceptval;

	/*
	 * Must pass valid cntrl record.
	 */
	if(!cntrl){
		OWPError(NULL,OWPErrFATAL,OWPErrINVALID,
		"OWPStartSessions called with invalid cntrl record");
		return OWPErrFATAL;
	}

	/*
	 * Send the StartSessions message to the server
	 */
	if((rc = _OWPWriteStartSessions(cntrl)) < OWPErrOK){
		return _OWPFailControlSession(cntrl,rc);
	}

	/*
	 * Small optimization... - start local receivers while waiting for
	 * the server to respond. (should not start senders - don't want
	 * to send packets unless control-ack comes back positive.)
	 */
	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->endpoint && !tsession->endpoint->send){
			if(!_OWPEndpointStart(tsession->endpoint,&err)){
				return _OWPFailControlSession(cntrl,err);
			}
			err2 = MIN(err,err2);
		}
	}

	/*
	 * Read the server response.
	 */
	if(((rc = _OWPReadStartAck(cntrl,&acceptval)) < OWPErrOK) ||
					(acceptval != OWP_CNTRL_ACCEPT)){
		return _OWPFailControlSession(cntrl,OWPErrFATAL);
	}

	/*
	 * Now start local senders.
	 */
	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->endpoint && tsession->endpoint->send){
			if(!_OWPEndpointStart(tsession->endpoint,&err)){
				return _OWPFailControlSession(cntrl,err);
			}
			err2 = MIN(err,err2);
		}
	}

	return err2;
}

/*
 * Function:	OWPDelay
 *
 * Description:	
 * 	Compute delay between two timestamps.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
double
OWPDelay(
	OWPTimeStamp	*send_time,
	OWPTimeStamp	*recv_time
	)
{
	return OWPNum64ToDouble(recv_time->owptime) -
			OWPNum64ToDouble(send_time->owptime);
}

/*
 * Function:	OWPFetchSession
 *
 * Description:	
 *	This function is used to request that the data for the TestSession
 *	identified by sid be fetched from the server and copied to the
 *	file pointed at by fp. This function assumes fp is currently pointing
 *	at an open file, and that fp is ready to write at the begining of the
 *	file.
 *
 *	To request an entire session set begin = 0, and end = 0xFFFFFFFF.
 *	(This is only valid if the session is complete - otherwise the server
 *	should deny this request.)
 *	Otherwise, "begin" and "end" refer to sequence numbers in the test
 *	session.
 *	The number of records returned will not necessarily be end-begin due
 *	to possible loss and/or duplication.
 *
 *      There is a full description of the owp file format in the comments
 *      in api.c.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 *	The number of data records in the file. If < 1, check err_ret to
 *	find out if it was an error condition: ErrOK just means the request
 *	was denied by the server. ErrWARNING means there was a local
 *	problem (fp not writeable etc...) and the control connection is
 *	still valid.
 * Side Effect:	
 */
u_int32_t
OWPFetchSession(
	OWPControl	cntrl,
	FILE		*fp,
	u_int32_t	begin,
	u_int32_t	end,
	OWPSID		sid,
	OWPErrSeverity  *err_ret
	)
{
    OWPAcceptType	acceptval;
    u_int8_t            finished;
    u_int32_t           n;
    OWPTestSession	tsession = NULL;
    OWPSessionHeaderRec	hdr;
    off_t               toff;
    u_int8_t		buf[_OWP_FETCH_BUFFSIZE];
    OWPBoolean		dowrite = True;


    *err_ret = OWPErrOK;

    if(!fp){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPFetchSession: Invalid fp");
        *err_ret = OWPErrFATAL;
        return 0;
    }

    /*
     * Initialize file header record.
     */
    memset(&hdr,0,sizeof(hdr));

    /*
     * Make the request of the server.
     */
    if((*err_ret = _OWPWriteFetchSession(cntrl,begin,end,sid)) < OWPErrWARNING){
        goto failure;
    }

    /*
     * Read the response
     */
    if((*err_ret = _OWPReadFetchAck(cntrl,&acceptval,&finished,&hdr.next_seqno,
                    &hdr.num_skiprecs,&hdr.num_datarecs)) < OWPErrWARNING){
        goto failure;
    }
    /* store 8 bit finished in 32 bit hdr.finished field. */
    hdr.finished = finished;

    /*
     * If the server didn't accept, the fetch response is complete.
     */
    if(acceptval != OWP_CNTRL_ACCEPT){
        return 0;
    }

    /*
     * Representation of original TestReq is first.
     */
    if((*err_ret = _OWPReadTestRequest(cntrl,NULL,&tsession,NULL)) != OWPErrOK){
        goto failure;
    }

    /*
     * Write the file header now. First encode the tsession into
     * a SessionHeader.
     */
    assert(sizeof(hdr.addr_sender) >= tsession->sender->saddrlen);
    memcpy(&hdr.addr_sender,tsession->sender->saddr,tsession->sender->saddrlen);
    memcpy(&hdr.addr_receiver,tsession->receiver->saddr,
            tsession->receiver->saddrlen);

    hdr.conf_sender = tsession->conf_sender;
    hdr.conf_receiver = tsession->conf_receiver;

    memcpy(hdr.sid,tsession->sid,sizeof(hdr.sid));
    /* hdr.test_spec will now point at same slots memory. */
    hdr.test_spec = tsession->test_spec;

    /*
     * Now, actually write the header
     */
    if( !OWPWriteDataHeader(cntrl->ctx,fp,&hdr)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPFetchSession: OWPWriteDataHeader(): %M");
        *err_ret = OWPErrWARNING;
        (void)_OWPTestSessionFree(tsession,OWP_CNTRL_INVALID);
        dowrite = False;
    }

    /*
     * Skip records:
     *
     * How many octets of skip records?
     */
    toff = hdr.num_skiprecs * _OWP_SKIPREC_SIZE;

    /*
     * Read even AES blocks of skips first
     */
    while(toff > _OWP_RIJNDAEL_BLOCK_SIZE){
        if(_OWPReceiveBlocks(cntrl,buf,1) != 1){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        if(dowrite && ( fwrite(buf,1,_OWP_RIJNDAEL_BLOCK_SIZE,fp) !=
                    _OWP_RIJNDAEL_BLOCK_SIZE)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
        toff -= _OWP_RIJNDAEL_BLOCK_SIZE;
    }
    /*
     * Finish incomplete block
     */
    if(toff){
        if(_OWPReceiveBlocks(cntrl,buf,1) != 1){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        if(dowrite && ( fwrite(buf,1,toff,fp) != toff)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
    }

    /*
     * Read one block of IZP
     */
    if(_OWPReceiveBlocks(cntrl,buf,1) != 1){
        *err_ret = OWPErrFATAL;
        goto failure;
    }
    if(memcmp(cntrl->zero,buf,_OWP_RIJNDAEL_BLOCK_SIZE)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPFetchSession: IZP block corrupt");
        *err_ret = OWPErrFATAL;
        goto failure;
    }

    /*
     * Data records are next
     *
     */

    /*
     * File pointer should now be positioned for data.
     * (verify)
     */
    if( (toff = ftello(fp)) < 0){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "OWPFetchSession: ftello(): %M");
        dowrite = False;
    }
    else if(toff != hdr.oset_skiprecs){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPFetchSession: Invalid datarec offset!");
        dowrite = False;
    }

    for(n=hdr.num_datarecs;
            n >= _OWP_FETCH_DATAREC_BLOCKS;
            n -= _OWP_FETCH_DATAREC_BLOCKS){
        if(_OWPReceiveBlocks(cntrl,buf,_OWP_FETCH_AES_BLOCKS) !=
                _OWP_FETCH_AES_BLOCKS){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        if(dowrite && (fwrite(buf,_OWP_DATAREC_SIZE,
                        _OWP_FETCH_DATAREC_BLOCKS,fp) !=
                    _OWP_FETCH_DATAREC_BLOCKS)){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
    }

    if(n){
        /*
         * Read enough AES blocks to get remaining records.
         */
        int	blks = n*_OWP_DATAREC_SIZE/_OWP_RIJNDAEL_BLOCK_SIZE + 1;

        if(_OWPReceiveBlocks(cntrl,buf,blks) != blks){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        if(dowrite && (fwrite(buf,_OWP_DATAREC_SIZE,n,fp) != n)){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
    }

    fflush(fp);

    /*
     * Read final block of IZP
     */
    if(_OWPReceiveBlocks(cntrl,buf,1) != 1){
        *err_ret = OWPErrFATAL;
        goto failure;
    }
    if(memcmp(cntrl->zero,buf,_OWP_RIJNDAEL_BLOCK_SIZE)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPFetchSession: IZP block corrupt");
        *err_ret = OWPErrFATAL;
        goto failure;
    }

    /*
     * reset state to request.
     */
    cntrl->state &= ~_OWPStateFetching;
    cntrl->state |= _OWPStateRequest;

    if(!dowrite){
        *err_ret = OWPErrWARNING;
        hdr.num_datarecs = 0;
    }

    return hdr.num_datarecs;

failure:
    (void)_OWPFailControlSession(cntrl,*err_ret);
    return 0;
}
