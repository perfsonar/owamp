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
**	File:		api.c
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Fri Mar 29 15:36:44  2002
**
**	Description:	
*/
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>

#include "./owampP.h"
#include "./rijndael-api-fst.h"

static OWPInitializeConfigRec	def_cfg = {
	/* tm_out.tv_sec		*/	0,
	/* tm_out.tv_usec		*/	0,
	/* app_data			*/	NULL,
	/* err_func			*/	NULL,
	/* check_control_func		*/	NULL,
	/* check_test_func		*/	NULL,
	/* get_aes_key			*/	NULL,
	/* get_timestamp_func		*/	NULL,
	/* endpoint_init_func		*/	NULL,
	/* endpoint_init_hook_func	*/	NULL,
	/* endpoint_start_func		*/	NULL,
	/* endpoint_stop_func		*/	NULL
};

OWPContext
OWPContextInitialize(
	OWPInitializeConfig	config
)
{
	OWPContext	ctx = malloc(sizeof(OWPContextRec));

	if(!ctx){
		OWPErrorLine(NULL,OWPLine,
			OWPErrFATAL,ENOMEM,":malloc(%d)",
			sizeof(OWPContextRec));
		return NULL;
	}

	if(config)
		ctx->cfg = *config;
	else
		ctx->cfg = def_cfg;

	ctx->cntrl_list = NULL;

	return ctx;
}

void
OWPContextFree(
	OWPContext	ctx
)
{
	free(ctx);

	return;
}

static OWPAddr
_OWPAddrAlloc(
	OWPContext	ctx
)
{
	OWPAddr	addr = malloc(sizeof(struct OWPAddrRec));

	if(!addr){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
				":malloc(%d)",sizeof(struct OWPAddrRec));
		return NULL;
	}

	addr->ctx = ctx;

	addr->node_set = 0;
	addr->node[0] = '\0';
	addr->ai_free = 0;
	addr->ai = NULL;

	addr->saddr = NULL;
	addr->saddrlen = 0;

	addr->fd_user = 0;
	addr->fd= -1;

	return addr;
}

OWPErrSeverity
OWPAddrFree(
	OWPAddr	addr
)
{
	OWPErrSeverity	err = OWPErrOK;

	if(!addr)
		return;

	if(addr->ai){
		if(!addr->ai_free){
			freeaddrinfo(addr->ai);
		}else{
			struct addrinfo	*ai, *next;

			ai = addr->ai;
			while(ai){
				next = ai->ai_next;

				if(ai->ai_addr) free(ai->ai_addr);
				if(ai->ai_canonname) free(ai->ai_canonname);
				free(ai);

				ai = next;
			}
		}
		addr->ai = NULL;
		addr->saddr = NULL;
	}

	if((addr->fd >= 0) && !addr->fd_user){
		if(close(addr->fd) < 0){
			OWPErrorLine(addr->ctx,OWPLine,OWPErrWARNING,
					errno,":close(%d)",addr->fd);
			err = OWPErrWARNING;
		}
	}

	free(addr);

	return err;
}

OWPAddr
OWPAddrByNode(
	OWPContext	ctx,
	const char	*node
)
{
	OWPAddr	addr;
	char		buff[MAXHOSTNAMELEN];
	const char	*nptr=node;
	char		*pptr=NULL;
	char		*s1,*s2,*s3;

	if(!node)
		return NULL;

	if(!(addr=_OWPAddrAlloc(ctx)))
		return NULL;

	strncpy(buff,node,MAXHOSTNAMELEN);

	/*
	 * Pull off port if specified. If syntax doesn't match URL like
	 * node:port - ipv6( [node]:port) - then just assume whole string
	 * is nodename and let getaddrinfo report problems later.
	 * (This service syntax is specified by rfc2396 and rfc2732.)
	 */

	/*
	 * First try ipv6 syntax since it is more restrictive.
	 */
	if(s1 = strchr(buff,'[')){
		s1++;
		if(strchr(s1,'[')) goto NOPORT;
		if(!(s2 = strchr(s1,']'))) goto NOPORT;
		*s2++='\0';
		if(strchr(s2,']')) goto NOPORT;
		if(*s2++ != ':') goto NOPORT;
		nptr = s1;
		pptr = s2;
	}
	/*
	 * Now try ipv4 style.
	 */
	else if(s1 = strchr(buff,':')){
		*s1++='\0';
		if(strchr(s1,':')) goto NOPORT;
		nptr = buff;
		pptr = s1;
	}


NOPORT:
	strncpy(addr->node,nptr,MAXHOSTNAMELEN);
	addr->node_set = 1;

	if(pptr){
		strncpy(addr->port,pptr,MAXHOSTNAMELEN);
		addr->port_set = 1;
	}

	return addr;
}

static struct addrinfo*
_OWPCopyAddrRec(
	OWPContext		ctx,
	const struct addrinfo	*src
)
{
	struct addrinfo	*dst = malloc(sizeof(struct addrinfo));

	if(!dst){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
				":malloc(sizeof(struct addrinfo))");
		return NULL;
	}

	*dst = *src;

	if(src->ai_addr){
		dst->ai_addr = malloc(sizeof(struct sockaddr));
		if(!dst->ai_addr){
			OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
				":malloc(sizeof(struct sockaddr))");
			free(dst);
			return NULL;
		}
		*dst->ai_addr = *src->ai_addr;
	}

	if(src->ai_canonname){
		int	len = strlen(src->ai_canonname);

		if(len > MAXHOSTNAMELEN){
			OWPErrorLine(ctx,OWPLine,OWPErrWARNING,
					OWPErrUNKNOWN,
					":Invalid canonname!");
			dst->ai_canonname = NULL;
		}else{
			dst->ai_canonname = malloc(sizeof(char)*(len+1));
			if(!dst->ai_canonname){
				OWPErrorLine(ctx,OWPLine,OWPErrWARNING,
					errno,":malloc(sizeof(%d)",len+1);
				dst->ai_canonname = NULL;
			}else
				strcpy(dst->ai_canonname,src->ai_canonname);
		}
	}

	dst->ai_next = NULL;

	return dst;
}

OWPAddr
OWPAddrByAddrInfo(
	OWPContext		ctx,
	const struct addrinfo	*ai
)
{
	OWPAddr	addr = _OWPAddrAlloc(ctx);
	struct addrinfo	**aip;

	if(!addr)
		return NULL;

	addr->ai_free = 1;
	aip = &addr->ai;

	while(ai){
		*aip = _OWPCopyAddrRec(ctx,ai);
		if(!*aip){
			free(addr);
			return NULL;
		}
		aip = &(*aip)->ai_next;
		ai = ai->ai_next;
	}

	return addr;
}

OWPAddr
OWPAddrBySockFD(
	OWPContext	ctx,
	int		fd
)
{
	OWPAddr	addr = _OWPAddrAlloc(ctx);

	if(!addr)
		return NULL;

	addr->fd_user = 1;
	addr->fd = fd;

	return addr;
}

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

static OWPControl
_OWPControlAlloc(
	OWPContext		ctx,
	OWPErrSeverity		*err_ret
)
{
	OWPControl	cntrl;
	
	if( !(cntrl = malloc(sizeof(OWPControlRec)))){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
				":malloc(%d)",sizeof(OWPControlRec));
		*err_ret = OWPErrFATAL;
		return NULL;
	}

	/*
	 * Init state fields
	 */
	cntrl->ctx = ctx;

	cntrl->server = 0;
	cntrl->state = 0;
	cntrl->mode = 0;

	/*
	 * Init addr fields
	 */
	cntrl->remote_addr = cntrl->local_addr = NULL;
	cntrl->sockfd = -1;

	/*
	 * Init encryption fields
	 */
	cntrl->kid = NULL;
	cntrl->kid_buffer[sizeof(cntrl->kid_buffer)-1] = '\0';
	memset(cntrl->session_key,0,sizeof(cntrl->session_key));
	memset(cntrl->readIV,0,sizeof(cntrl->readIV));
	memset(cntrl->writeIV,0,sizeof(cntrl->writeIV));

	/*
	 * Init test sessions list.
	 */
	cntrl->tests = NULL;

	/*
	 * Put this control record on the ctx list.
	 */
	cntrl->next = ctx->cntrl_list;
	ctx->cntrl_list = cntrl;

	return cntrl;
}

OWPErrSeverity
OWPControlClose(OWPControl cntrl)
{
	OWPErrSeverity	err = OWPErrOK;
	OWPErrSeverity	lerr = OWPErrOK;
	OWPControl	*list = &cntrl->ctx->cntrl_list;

	/*
	 * TODO: remove all test sessions if necessary - send stop session
	 * if needed.
	 */

	/*
	 * Remove cntrl from ctx list.
	 */
	while(*list && (*list != cntrl))
		list = &(*list)->next;
	if(*list == cntrl)
		*list = cntrl->next;

	/*
	 * this function will close the control socket if it is open.
	 */
	lerr = OWPAddrFree(cntrl->remote_addr);
	err = MIN(err,lerr);
	lerr = OWPAddrFree(cntrl->local_addr);
	err = MIN(err,lerr);

	free(cntrl);

	return err;
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
		random_bytes(cntrl->session_key,16);
		memcpy(&buf[16],cntrl->session_key,16);

		_OWPMakeKey(cntrl,cntrl->session_key);


		if(OWPEncryptToken(key,buf,token) != 0)
			goto error;
	}
	else{
		random_bytes(token,32);
	}
	random_bytes(cntrl->writeIV,32);

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

static OWPTestSession
TestSessionAlloc(
	OWPControl	cntrl,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec
)
{
	OWPTestSession	test = malloc(sizeof(OWPTestSessionRec));

	if(!test){
		OWPError(cntrl->ctx,OWPErrFATAL,errno,
						"malloc(OWPTestSessionRec)");
		return NULL;
	}

	test->cntrl = cntrl;
	memset(test->sid,0,sizeof(OWPSID));
	test->sender = sender;
	test->server_conf_sender = server_conf_sender;
	test->receiver = receiver;
	test->server_conf_receiver = server_conf_receiver;
	test->send_end_data = test->recv_end_data = NULL;
	memcpy(&test->test_spec,test_spec,sizeof(OWPTestSpec));
	test->next = NULL;

	return test;
}

static void
TestSessionFree(
	OWPTestSession	tsession
)
{
	/*
	 * TODO: call stop on the endpoints.
	 */
	/*
	 * TODO: remove this tsession from the cntrl->tests lists.
	 */
	free(tsession);
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
	if( !(tsession = TestSessionAlloc(cntrl,sender,server_conf_sender,
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
	TestSessionFree(tsession);
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

#define IS_LEGAL_MODE(x) ((x) == OWP_MODE_OPEN | (x) == OWP_MODE_AUTHENTICATED | (x) == OWP_MODE_ENCRYPTED)

/*
 * Function:	OWPControlAccept
 *
 * Description:	
 * 		Used by the server to talk the protocol until
 *              a Control Connection has been established, or
 *              rejected, or error occurs.
 *           
 * In Args:	
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
		 OWPContext     ctx,       /* control context               */
		 u_int32_t      mode_offered,/* advertised server mode      */
		 int            connfd,    /* connected socket              */
		 void*          app_data,  /* policy                        */
		 OWPErrSeverity *err_ret   /* err - return                  */
)
{
	char challenge[16];

	char buf[MAX_MSG]; /* used to send and receive messages */
	char token[32];
	char *class;
	OWPControl cntrl;
	*err_ret = OWPErrOK;
	if ( !(cntrl = _OWPControlAlloc(ctx, err_ret)))
		return NULL;

	cntrl->sockfd = connfd;
	cntrl->server = True;
	/* XXX TODO:
	   OWPAddr			remote_addr;
	   OWPAddr			local_addr;
	*/

	/* Compose Server greeting. */
	memset(buf, 0, sizeof(buf));
	*(u_int32_t *)(buf + 12) = htonl(mode_offered);

	/* generate 16 random bytes of challenge and save them away. */
	random_bytes(challenge, 16);
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
			
		random_bytes(cntrl->writeIV, 16);

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
	return cntrl;
}
