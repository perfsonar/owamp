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
#include <owampP.h>
#include <rijndael-api-fst.h>
#include "../contrib/table.h"

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
	OWPAddr	addr = AllocAddr(ctx);

	if(!addr)
		return NULL;

	strncpy(addr->node,node,MAXHOSTNAMELEN);
	addr->node_set = 1;

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

		OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
							"bind(,,):%m");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * None found.
	 */
	*err_ret = OWPErrOK;
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

	if((!server_addr) &&
		!(server_addr = OWPAddrByNode(cntrl->ctx,"localhost"))){
		return -1;
	}

	if(server_addr->fd > -1){
		cntrl->remote_addr = server_addr;
		cntrl->sockfd = server_addr->fd;

		return 0;
	}

	if(!server_addr->ai){
		/*
		 * Call getaddrinfo to find useful addresses
		 */
		struct addrinfo	hints, *airet;
		const char	*node=NULL;

		if(server_addr->node_set)
			node = server_addr->node;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if((getaddrinfo(node,OWP_CONTROL_SERVICE_NAME,&hints,&airet)!=0)
								|| !airet){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
					":getaddrinfo()");
			*err_ret = OWPErrFATAL;
			return -1;
		}

		server_addr->ai = airet;
	}

	for(ai=server_addr->ai;ai;ai->ai_next){
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
					*err_ret = addr_ok;
					return -1;
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
					*err_ret = addr_ok;
					return -1;
				}
				goto next;
			}
			/*
			 * Policy ok - fall through to connect.
			 */
		}

		/*
		 * TODO:Add timeout (non-block connect, then select...)
		 */
		if(connect(fd,ai->ai_addr,ai->ai_addrlen) == 0){
			server_addr->fd = fd;
			server_addr->saddr = *ai->ai_addr;
			server_addr->saddr_set = True;
			cntrl->remote_addr = server_addr;
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

	OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
			"No Valid Addr's");
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
	memset(&cntrl->kid,0,sizeof(OWPKID));
	memset(&cntrl->key,0,sizeof(&cntrl->key));
	memset(cntrl->challenge,0,sizeof(cntrl->challenge));
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

static void
_OWPControlFree(OWPControl cntrl)
{
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
	OWPAddrFree(cntrl->remote_addr);
	OWPAddrFree(cntrl->local_addr);

	free(cntrl);

	return;
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
	const OWPKID	*kid,		/* kid or NULL		*/
	OWPErrSeverity	*err_ret	/* err - return		*/
)
{
	int		fd;
	OWPControl	cntrl = _OWPControlAlloc(ctx,err_ret);
	u_int32_t	mode_avail;
	OWPByte		key_value[16];
	OWPByte		*key=NULL;
	struct sockaddr	*local=NULL, *remote;

	*err_ret = OWPErrOK;

	if( !(cntrl = _OWPControlAlloc(ctx,err_ret))){
		OWPAddrFree(server_addr);
		return NULL;
	}

	if(_OWPClientConnect(cntrl,local_addr,server_addr,err_ret) != 0){
		_OWPControlFree(cntrl);
		return NULL;
	}

	if(_OWPClientReadServerGreeting(cntrl,&mode_avail,err_ret) != 0){
		_OWPControlFree(cntrl);
		return NULL;
	}

	/*
	 * Select mode wanted...
	 */
	mode_avail &= mode_req_mask;	/* mask out unwanted modes */
	/*
	 * retrieve key if needed
	 */
	if(kid &&
		(mode_avail & (OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED))){
		if(!_OWPCallGetAESKey(ctx,kid,&key_value,err_ret)){
			if(*err_ret != OWPErrOK){
				_OWPControlFree(cntrl);
				return NULL;
			}
		}
		else
			key = key_value;
	}
	/*
	 * If no key, then remove auth/crypt modes
	 */
	if(!key)
		mode_avail &= ~(OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED);

	/*
	 * Pick "highest" level mode still available.
	 */
	if(mode_avail & OWP_MODE_ENCRYPTED){
		cntrl->mode = OWP_MODE_ENCRYPTED;
	}else if(mode_avail & OWP_MODE_AUTHENTICATED){
		cntrl->mode = OWP_MODE_AUTHENTICATED;
	}else if(mode_avail & OWP_MODE_OPEN){
		cntrl->mode = OWP_MODE_OPEN;
	}else{
		OWPError(ctx,OWPErrFATAL,OWPErrPOLICY,"No Common Modes");
		*err_ret = OWPErrFATAL;
		_OWPControlFree(cntrl);
		return NULL;
	}

	/*
	 * Now determine if client side is willing to actually talk control
	 * given the kid/addr combinations.
	 */
	if(!_OWPCallCheckControlPolicy(ctx,cntrl->mode,kid,cntrl->key,
			&local_addr->saddr,&server_addr->saddr,err_ret)){
		_OWPControlFree(cntrl);
		return NULL;
	}

	/*
	 * cntrl->mode MUST be set before calling this!
	 * This function simply prepares the token from a generated
	 * session key and the challenge from the server. It also generates
	 * the ClientIV for encryption.
	 */
	if(_OWPClientInitEncryptionValues(cntrl,err_ret)!=0){
		_OWPControlFree(cntrl);
		return NULL;
	}

	/*
	 * This function requests the cntrl->mode communication from the
	 * server, and validates the kid/key with the server. If the
	 * server accepts this, it will return 0 - otherwise it will
	 * return with an error.
	 */
	if(_OWPClientRequestModeReadResponse(cntrl,err_ret) != 0){
		_OWPControlFree(cntrl);
		return NULL;
	}

	return cntrl;
}

/*
 * Function:	OWPDefineEndpoint
 *
 * Description:	
 * 		Used to define an endpoint for a test session.
 *
 * In Args:	
 * 	send_or_recv	defines if endpoint is a send or recv endpoint
 * 	server_request	if True server is asked to configure the endpoint
 * 			otherwise it will be up to the current process to
 * 			configure the endpoint using the endpoint func's
 * 			defined in the ctx record.
 *
 * Returns:	
 * Side Effect:	
 */
OWPEndpoint
OWPDefineEndpoint(
	OWPAddr		addr,
	OWPEndpointType	send_or_recv,
	OWPBoolean	server_request
)
{

}

#if	NOT
/*
** This function sets WriteIV to the contents of the buffer ptr (16 bytes).
*/
void
OWPSetWriteIV(OWPControl ctrl, char* ptr)
{
	bcopy(ptr, ctrl->writeIV, 16);
}

/*
** This function sets ReadIV to the contents of the buffer ptr (16 bytes).
*/
void
OWPSetReadIV(OWPControl ctrl, char* ptr)
{
	bcopy(ptr, ctrl->readIV, 16);
}

/*
** This function sets SessionKey to the contents of the buffer ptr (16 bytes).
*/
void
OWPSetSessionKey(OWPControl ctrl, char* ptr)
{
	bcopy(ptr, ctrl->session_key, 16);
}
#endif

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
 *
 * Side Effect:	
 */

OWPControl
OWPControlAccept(
		 OWPContext     ctx,       /* control context               */
		 int            connfd,    /* connected socket              */
		 void*          app_data,  /* policy                        */
		 OWPErrSeverity *err_ret   /* err - return                  */
)
{
	OWPControl cntrl;
	char buf[MAX_MSG]; 

	char *cur;
	u_int32_t mode = 4; /* XXX - fix later */
	int i, r, encrypt;
	u_int32_t mode_requested;
	u_int8_t challenge[16], token[32], read_iv[16], write_iv[16];
	u_int8_t kid[8]; /* XXX - assuming Stas will extend KID to 8 bytes */

	/* Remove what's not needed. */
	datum *key;
	keyInstance keyInst;
	cipherInstance cipherInst;

	/* 
	   XXX - need to hide this
	   hash_ptr passwd_hash = ((struct data *)app_data)->passwd; 
	*/

	*err_ret = OWPErrOK;
	if ( !(cntrl = _OWPControlAlloc(ctx, err_ret)))
		return NULL;

	_OWPServerSendServerGreeting(cntrl, mode, err_ret);

	/* first generate server greeting */
	memset(buf, 0, sizeof(buf));
	mode = htonl(get_mode());
	*(int32_t *)(buf + 12) = mode; /* first 12 bytes unused */

	/* generate 16 random bytes and save them away. */
	random_bytes(challenge, 16);
	bcopy(challenge, buf + 16, 16); /* the last 16 bytes */

	/* Send server greeting. */
	encrypt = 0;
	if (send_data(connfd, buf, 32, encrypt) < 0){
		fprintf(stderr, "Warning: send_data failed.\n");
		close(connfd);
		exit(1);
	}

	/* Read client greeting. */
	if (readn(connfd, buf, 60) != 60){
		fprintf(stderr, "Warning: client greeting too short.\n");
		exit(1);
	}

	mode_requested = htonl(*(u_int32_t *)buf);
	if (mode_requested & ~mode){ /* can't provide requested mode */
		OWPServerOK(cntrl, connfd, CTRL_REJECT, buf);
		close(connfd);
		exit(0);
	}
	if (mode_requested & OWP_MODE_AUTHENTICATED){

		/* Save 8 bytes of kid */
		bcopy(buf + 4, kid, 8);

		/* Fetch the shared secret and initialize the cipher. */
		/* XXX - this needs to be redone to respect abstraction 
		key = hash_fetch(passwd_hash, 
				 (const datum *)str2datum((const char *)kid));
		r = makeKey(&keyInst, DIR_DECRYPT, 128, key->dptr);
		*/

		if (TRUE != r) {
			fprintf(stderr,"makeKey error %d\n",r);
			exit(-1);
		}
		r = cipherInit(&cipherInst, MODE_CBC, NULL);
		if (TRUE != r) {
			fprintf(stderr,"cipherInit error %d\n",r);
			exit(-1);
		}

		/* Decrypt two 16-byte blocks - save the result into token.*/
		blockDecrypt(&cipherInst, &keyInst, buf + 12, 2*(16*8), token);

		/* Decrypted challenge is in the first 16 bytes */
		if (bcmp(challenge, token, 16)){
			OWPServerOK(cntrl, connfd, CTRL_REJECT, buf);
			close(connfd);
			exit(0);
		}

		/* Save 16 bytes of session key and 16 bytes of client IV*/
		/* OWPSetSessionKey(cntrl, token + 16); */
		bcopy(buf + 44, read_iv, 16);

		/* Apparently everything is ok. Accept the Control session. */
		OWPServerOK(cntrl, connfd, CTRL_ACCEPT, buf);

	}

	return cntrl;
}

/*
** This function does the initial policy check on the remote host.
** It returns True if it is ok to start Control protocol converstion,
** and False otherwise.
*/
OWPBoolean
OWPAddrCheck(
	     OWPContext ctx,
	     void *app_data, 
	     struct sockaddr *local, 
	     struct sockaddr *remote, 
	     OWPErrSeverity *err_ret)
{
	*err_ret = OWPErrOK;
	
	if(!ctx){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
			     "OWPAddrCheck:No Context!");
		*err_ret = OWPErrFATAL;
		return False;
	}


	/*
	 * Default action is deny access.
	 */
	if(!ctx->cfg.check_addr_func)
		return False;

	return (*ctx->cfg.check_addr_func)(app_data, local, remote, err_ret);
}

