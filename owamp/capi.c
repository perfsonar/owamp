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
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>

#include "./owampP.h"

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
	OWPErrSeverity	local_err=OWPErrOK;

	if(local_addr->fd > -1){
		OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
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

		if(!local_addr->node_set){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
				OWPErrUNKNOWN,"Invalid localaddr specified");
			*err_ret = OWPErrFATAL;
			return False;
		}

		if(local_addr->port_set)
			port = local_addr->port;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if((getaddrinfo(local_addr->node,port,&hints,&airet)!=0) ||
									!airet){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
					":getaddrinfo()");
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
		if(!_OWPCallCheckAddrPolicy(cntrl->ctx,ai->ai_addr,
				remote_addrinfo->ai_addr,&local_err)){
			if(local_err != OWPErrOK){
				*err_ret = local_err;
				return False;
			}
			continue;
		}

		if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
			local_addr->saddr = ai->ai_addr;
			local_addr->saddrlen = ai->ai_addrlen;
			return True;
		}

	}

	/*
	 * None found.
	 */
	*err_ret = OWPErrFATAL;
	return False;
}

static int
_OWPClientConnect(
	OWPControl	cntrl,
	OWPAddr		local_addr,
	OWPAddr		server_addr,
	OWPErrSeverity	*err_ret
)
{
	int		fd=-1;
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
	 * Do we have an "address" for the connection yet?
	 */
	if(!server_addr->ai){
		/*
		 * Call getaddrinfo to find useful addresses
		 */
		struct addrinfo	hints, *airet;
		const char	*node=NULL;
		const char	*port=NULL;

		if(server_addr->node_set)
			node = server_addr->node;
		if(server_addr->port_set)
			port = server_addr->port;
		else
			port = OWP_CONTROL_SERVICE_NAME;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if((getaddrinfo(node,port,&hints,&airet)!=0) || !airet){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
					":getaddrinfo()");
			goto error;
		}

		server_addr->ai = airet;
	}

	/*
	 * Now that we have addresses - see if it is valid by attempting
	 * to create a socket of that type, and binding(if wanted).
	 * Also check policy for allowed connection before calling
	 * connect.
	 * (Binding will call the policy function internally.)
	 */
	for(ai=server_addr->ai;ai;ai=ai->ai_next){
		OWPErrSeverity	addr_ok=OWPErrOK;
		fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
		if(fd < 0)
			continue;

		if(local_addr){
			/*
			 * ClientBind will check Addr policy for possible
			 * combinations before binding.
			 */
			if(!_OWPClientBind(cntrl,fd,local_addr,ai,&addr_ok)){
				if(addr_ok != OWPErrOK){
					goto error;
				}
				goto next;
			}
			/*
			 * local_addr bound ok - fall through to connect.
			 */
		}
		else{
			/*
			 * Verify address is ok to talk to in policy.
			 */
			if(!_OWPCallCheckAddrPolicy(cntrl->ctx,NULL,
						server_addr->saddr,&addr_ok)){
				if(addr_ok != OWPErrOK){
					goto error;
				}
				goto next;
			}
			/*
			 * Policy ok - fall through to connect.
			 */
		}

		/*
		 * Call connect - we ignore error values from here for now...
		 */
		if(_OWPConnect(fd,ai->ai_addr,ai->ai_addrlen,&cntrl->ctx->cfg.tm_out) == 0){
			server_addr->fd = fd;
			server_addr->saddr = ai->ai_addr;
			server_addr->saddrlen = ai->ai_addrlen;
			cntrl->remote_addr = server_addr;
			cntrl->local_addr = local_addr;
			cntrl->sockfd = fd;

			return 0;
		}

next:
		if(close(fd) !=0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrWARNING,
						errno,":close(%d)",fd);
			*err_ret = OWPErrWARNING;
		}
	}

	if(server_addr->node_set)
		tstr = server_addr->node;
	else
		tstr = "Server";

	OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
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
	OWPErrSeverity	*err_ret	/* err - return		*/
)
{
	int		fd;
	OWPControl	cntrl;
	u_int32_t	mode_avail;
	OWPByte         key_value[16];
	OWPByte		challenge[16];
	OWPByte		token[32];
	OWPByte         *key=NULL;
	struct sockaddr	*local=NULL, *remote;

	*err_ret = OWPErrOK;

	if( !(cntrl = _OWPControlAlloc(ctx,err_ret)))
		goto error;

	if((!server_addr) &&
		!(server_addr = OWPAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

	if(_OWPClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
		goto error;

	if(_OWPClientReadServerGreeting(cntrl,&mode_avail,challenge,err_ret)
			!= 0)
		goto error;

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
		if(_OWPCallGetAESKey(ctx,cntrl->kid_buffer,key_value,err_ret)){
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
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_ENCRYPTED,
				cntrl->kid,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_ENCRYPTED;
	}
	else if((mode_avail & OWP_MODE_AUTHENTICATED) &&
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_AUTHENTICATED,
				cntrl->kid,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_AUTHENTICATED;
	}
	else if((mode_avail & OWP_MODE_OPEN) &&
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_OPEN,
				NULL,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_OPEN;
	}
	else{
		OWPError(ctx,*err_ret,OWPErrPOLICY,"No Common Modes");
		goto error;
	}

	/*
	 * Initialize all the encryption values as necessary.
	 */
	if(cntrl->mode & _OWP_DO_CIPHER){
		char	buf[32];

		memcpy(buf,challenge,16);
		I2RandomBytes(cntrl->session_key,16);
		memcpy(&buf[16],cntrl->session_key,16);

		_OWPMakeKey(cntrl,cntrl->session_key);


		if(OWPEncryptToken(key,buf,token) != 0)
			goto error;
	}
	else{
		I2RandomBytes(token,32);
	}
	I2RandomBytes(cntrl->writeIV,32);

	/*
	 * This function requests the cntrl->mode communication from the
	 * server, and validates the kid/key with the server. If the
	 * server accepts this, it will return 0 - otherwise it will
	 * return with an error.
	 */
	if(_OWPClientRequestModeReadResponse(cntrl,token,err_ret) != 0)
		goto error;

	cntrl->state = _OWPStateRequest;
	return cntrl;

error:
	*err_ret = OWPErrFATAL;
	if(cntrl->local_addr != local_addr)
		OWPAddrFree(local_addr);
	if(cntrl->remote_addr != server_addr)
		OWPAddrFree(server_addr);
	OWPControlClose(cntrl);
	return NULL;
}

static OWPBoolean
SetEndAddrInfo(
	OWPControl	cntrl,
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
)
{
	int		so_type;
	socklen_t	so_typesize = sizeof(int);
	OWPByte		sbuff[SOCK_MAXADDRLEN];
	socklen_t	so_size = sizeof(sbuff);
	struct sockaddr	*saddr=NULL;
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	char		*port=NULL;

	if(!addr->ai){
		if(addr->fd > -1){

			/*
			 * Get an saddr to describe the fd...
			 */
			if(getsockname(addr->fd,(void*)&sbuff,&so_size) != 0){
				OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					errno,"getsockname():%s",
					strerror(errno));
				goto error;
			}

			if(! (saddr = malloc(so_size))){
				OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					errno,"malloc():%s",strerror(errno));
				goto error;
			}
			memcpy((void*)saddr,(void*)sbuff,so_size);
			
			/*
			 * Determine "type" of socket.
			 */
			so_size = sizeof(so_type);
			if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
					(void*)&so_type,&so_typesize) != 0){
				OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					errno,"getsockopt():%s",
					strerror(errno));
				goto error;
			}

			/*
			 * create an addrinfo to describe this sockaddr
			 */
			if(! (ai = malloc(sizeof(struct addrinfo)))){
				OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
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
			if((getaddrinfo(addr->node,port,&hints,&ai)!=0) || !ai){
				OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					errno,"getaddrinfo():%s",
					strerror(errno));
				goto error;
			}
			addr->ai = ai;

		}else{
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
							"Invalid test address");
			goto error;
		}
	}

	return True;

error:
	if(saddr) free(saddr);
	if(ai) free(ai);
	*err_ret = OWPErrFATAL;
	return FALSE;
}


OWPBoolean
OWPRequestTestSession(
	OWPControl	cntrl,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec,
	OWPSID		sid_ret,
	OWPErrSeverity	*err_ret
)
{
	struct addrinfo		*rai=NULL;
	struct addrinfo		*sai=NULL;
	void			*send_endpoint = NULL;
	void			*recv_endpoint = NULL;
	OWPTestSession		tsession = NULL;

	*err_ret = OWPErrOK;

	/*
	 * Check cntrl state is appropriate for this call.
	 */
	if(!cntrl || !_OWPStateIsRequest(cntrl)){
		*err_ret = OWPErrFATAL;
		OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
		"OWPRequestTestSession called with invalid cntrl record");
		goto error;
	}

	if((!receiver) &&
		!(receiver = OWPAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

	if((!sender) &&
		!(sender = OWPAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

	/*
	 * Get addrinfo for address spec's so we can choose between
	 * the different address possiblities in the next step. (These
	 * ai will be SOCK_DGRAM unless an fd was passed in directly, in
	 * which case we trust the application knows what it is doing...)
	 */
	if(!SetEndAddrInfo(cntrl,receiver,err_ret) ||
					!SetEndAddrInfo(cntrl,sender,err_ret))
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
		"OWPRequestTestSession called with incompatible addresses");
	goto error;

foundaddr:
	receiver->saddr = rai->ai_addr;
	receiver->saddrlen = rai->ai_addrlen;
	sender->saddr = sai->ai_addr;
	sender->saddrlen = sai->ai_addrlen;

	/*
	 * Create a structure to store the stuff we need to keep for
	 * later calls.
	 */
	if( !(tsession = _OWPTestSessionAlloc(cntrl,sender,server_conf_sender,
				receiver,server_conf_receiver,test_spec)))
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
			 * check local policy for this sender
			 */
			if(!_OWPCallCheckTestPolicy(cntrl,True,
					sender->saddr,receiver->saddr,
					test_spec,err_ret)){
				OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
				goto error;
			}
			/*
			 * create the local sender
			 */
			if(!_OWPCallEndpointInit(cntrl,&tsession->send_end_data,
							True,sender,test_spec,
							tsession->sid,err_ret))
				goto error;
		}
		/*
		 * Request the server create the receiver & possibly the
		 * sender.
		 */
		if(_OWPClientRequestTestReadResponse(cntrl,
					sender,server_conf_sender,
					receiver,server_conf_receiver,
					test_spec,sid_ret,err_ret) != 0){
			goto error;
		}

		/*
		 * If sender is local, complete it's initialization now that
		 * we know the receiver port number.
		 */
		if(!server_conf_sender){
			if(!_OWPCallEndpointInitHook(cntrl,
					tsession->send_end_data,receiver,
					tsession->sid,err_ret))
				goto error;
		}
	}
	else{
		/*
		 * Local receiver - first check policy, then create.
		 */
		if(!_OWPCallCheckTestPolicy(cntrl,False,receiver->saddr,
					sender->saddr,test_spec,err_ret)){
			OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
					"Test not allowed");
			goto error;
		}
		if(!_OWPCallEndpointInit(cntrl,&tsession->recv_end_data,
					False,receiver,test_spec,tsession->sid,
					err_ret))
			goto error;


		/*
		 * If conf_sender - make request to server
		 */
		if(server_conf_sender){
			if(_OWPClientRequestTestReadResponse(cntrl,
					sender,server_conf_sender,
					receiver,server_conf_receiver,
					test_spec,tsession->sid,err_ret) != 0){
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
			if(!_OWPCallEndpointInit(cntrl,&tsession->send_end_data,
					True,sender,test_spec,tsession->sid,
					err_ret))
				goto error;
			if(!_OWPCallEndpointInitHook(cntrl,
					tsession->send_end_data,receiver,
					tsession->sid,err_ret))
				goto error;
		}
		if(!_OWPCallEndpointInitHook(cntrl,
					tsession->recv_end_data,sender,
					tsession->sid,err_ret))
			goto error;
	}

	tsession->next = cntrl->tests;
	cntrl->tests = tsession;

	memcpy(sid_ret,tsession->sid,sizeof(OWPSID));

	return True;

error:
	if(send_endpoint){
		/* TODO: stop send endpoint */
	}
	if(recv_endpoint){
		/* TODO: stop recv endpoint */
	}
	_OWPTestSessionFree(tsession);
	OWPAddrFree(receiver);
	OWPAddrFree(sender);
	return False;
}

OWPErrSeverity
OWPStartTestSessions(
	OWPControl	cntrl
)
{
	return OWPErrFATAL;
}
