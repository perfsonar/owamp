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
AllocAddr(
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

	addr->saddr_set = 0;

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

	if(!(addr=AllocAddr(ctx)))
		return NULL;

	strncpy(buff,node,MAXHOSTNAMELEN);

	/*
	 * Pull off port if specified. If syntax doesn't match URL like
	 * node:port - ipv6( [node]:port) - then just assume whole string
	 * is nodename, and let getaddrinfo report problems later.
	 * (This service syntax is specified by rfc2732.)
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
	OWPAddr	addr = AllocAddr(ctx);
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
	OWPAddr	addr = AllocAddr(ctx);

	if(!addr)
		return NULL;

	addr->fd_user = 1;
	addr->fd = fd;

	return addr;
}

/*
 * This function just ensure's that there is a valid addr_info pointer in
 * the addr OWPAddr pointer.
 * Returns OWPErrOK on success.
 */
static OWPErrSeverity
_OWPAddrInfo(
	OWPContext	ctx,
	OWPAddr		addr
)
{
	struct addrinfo	hints, *airet;
	const char	*node=NULL;

	/*
	 * Don't need addr_info if we already have a fd.
	 */
	if(addr->fd > -1)
		return OWPErrOK;

	if(addr->ai)
		return OWPErrOK;
	/*
	 * Call getaddrinfo to find useful addresses
	 */

	if(addr->node_set)
		node = addr->node;

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if((getaddrinfo(node,OWP_CONTROL_SERVICE_NAME,&hints,&airet)!=0)
								|| !airet){
		OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,":getaddrinfo()");
		return OWPErrFATAL;
	}

	addr->ai = airet;
	return OWPErrOK;
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

	if(!local_addr->ai &&
		(_OWPAddrInfo(cntrl->ctx,local_addr) < OWPErrWARNING)){
		*err_ret = OWPErrFATAL;
		return False;
	}

	for(ai=local_addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != remote_addrinfo->ai_family)
			continue;
		if(ai->ai_socktype != remote_addrinfo->ai_socktype)
			continue;
		if(ai->ai_protocol != remote_addrinfo->ai_protocol)
			continue;
		if(!_OWPCallCheckAddrPolicy(cntrl->ctx,ai->ai_addr,
				&remote_addrinfo->ai_addr,&local_err)){
			if(local_err != OWPErrOK){
				*err_ret = local_err;
				return False;
			}
			continue;
		}

		if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
			local_addr->saddr = *ai->ai_addr;
			local_addr->saddr_set = True;
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

	if((!server_addr) &&
		!(server_addr = OWPAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

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
						&server_addr->saddr,&addr_ok)){
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
			server_addr->saddr = *ai->ai_addr;
			server_addr->saddr_set = True;
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

	if(_OWPClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
		goto error;

	if(_OWPClientReadServerGreeting(cntrl,&mode_avail,challenge,err_ret) != 0)
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
						cntrl->kid,&local_addr->saddr,
						&server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_ENCRYPTED;
	}
	else if((mode_avail & OWP_MODE_AUTHENTICATED) &&
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_AUTHENTICATED,
						cntrl->kid,&local_addr->saddr,
						&server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_AUTHENTICATED;
	}
	else if((mode_avail & OWP_MODE_OPEN) &&
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_OPEN,
						NULL,&local_addr->saddr,
						&server_addr->saddr,err_ret)){
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
	/* XXX TODO: set cntrl->state 
	   cntrl->mode ???
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
			    cntrl->local_addr, cntrl->remote_addr, 
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
			    cntrl->local_addr, cntrl->remote_addr, 
			   err_ret) == False){
			_OWPServerOK(cntrl, CTRL_REJECT);
			OWPControlClose(cntrl);
			return NULL;		
		}
	}
	
	/* Apparently everything is ok. Accept the Control session. */
	_OWPServerOK(cntrl, CTRL_ACCEPT);
	return cntrl;
}
