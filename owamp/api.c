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
connect_tmout(
	int		fd,
	struct sockaddr	*ai_addr,
	size_t		ai_addr_len,
	struct timeval	*tm_out
)
{
	int		flags;
	int		rc;
	fd_set		rset,wset;
	int		len;
	/*
	 * Some versions of select modify the timeval values - so create
	 * a local copy before calling select.
	 */
	struct timeval	ltm = *tm_out;

	flags = fcntl(fd, F_GETFL,0);
	fcntl(fd,F_SETFL,flags|O_NONBLOCK);

	rc = connect(fd,ai_addr,ai_addr_len);

	if(rc==0)
		goto DONE;

	if(errno != EINPROGRESS){
		return -1;
	}
	
AGAIN:
	FD_ZERO(&rset);
	FD_SET(fd,&rset);
	wset = rset;

	rc = select(fd+1,&rset,&wset,NULL,&ltm);
	if(rc == 0){
		errno = ETIMEDOUT;
		return -1;
	}
	if(rc < 0){
		if(errno == EINTR)
			goto AGAIN;
		return -1;
	}

	if(FD_ISSET(fd,&rset) || FD_ISSET(fd,&wset)){
		len = sizeof(rc);
		if(getsockopt(fd,SOL_SOCKET,SO_ERROR,(void*)&rc,&len) < 0){
			return -1;
		}
		if(rc != 0){
			errno = rc;
			return -1;
		}
	}else
		return -1;

DONE:
	fcntl(fd,F_SETFL,flags);
	return fd;
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

		if(server_addr->node_set)
			node = server_addr->node;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if((getaddrinfo(node,OWP_CONTROL_SERVICE_NAME,&hints,&airet)!=0)
								|| !airet){
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
		if(connect_tmout(fd,ai->ai_addr,ai->ai_addrlen,&cntrl->ctx->cfg.tm_out) == 0){
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

	OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
			"No Valid Addr's");
error:
	*err_ret = OWPErrFATAL;
	OWPAddrFree(local_addr);
	OWPAddrFree(server_addr);

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
	memset(&cntrl->encrypt_key,0,sizeof(cntrl->encrypt_key));
	memset(&cntrl->decrypt_key,0,sizeof(cntrl->decrypt_key));
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
	OWPByte         *key=NULL;
	struct sockaddr	*local=NULL, *remote;

	*err_ret = OWPErrOK;

	if( !(cntrl = _OWPControlAlloc(ctx,err_ret)))
		goto error;

	if(_OWPClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
		goto error;

	if(_OWPClientReadServerGreeting(cntrl,&mode_avail,err_ret) != 0)
		goto error;

	/*
	 * Select mode wanted...
	 */
	mode_avail &= mode_req_mask;	/* mask out unwanted modes */

	/*
	 * retrieve key if needed
	 */
	if(kid &&
		(mode_avail & (OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED))){
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
		mode_avail &= ~(OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED);

	/*
	 * Pick "highest" level mode still available to this server.
	 */
	if((mode_avail & OWP_MODE_ENCRYPTED) &&
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_ENCRYPTED,
						cntrl->kid,&local_addr->saddr,
						&server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_ENCRYPTED;
	}else if((mode_avail & OWP_MODE_AUTHENTICATED) &&
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_AUTHENTICATED,
						cntrl->kid,&local_addr->saddr,
						&server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_AUTHENTICATED;
	}else if((mode_avail & OWP_MODE_OPEN) &&
			_OWPCallCheckControlPolicy(ctx,OWP_MODE_OPEN,
						NULL,&local_addr->saddr,
						&server_addr->saddr,err_ret)){
		cntrl->mode = OWP_MODE_OPEN;
	}else{
		OWPError(ctx,*err_ret,OWPErrPOLICY,"No Common Modes");
		goto error;
	}

	/*
	 * cntrl->mode MUST be set before calling this!
	 * This function simply prepares the token from a generated
	 * session key and the challenge from the server. It also generates
	 * the ClientIV for encryption.
	 */
	if(_OWPClientInitEncryptionValues(cntrl,err_ret)!=0)
		goto error;

	/*
	 * This function requests the cntrl->mode communication from the
	 * server, and validates the kid/key with the server. If the
	 * server accepts this, it will return 0 - otherwise it will
	 * return with an error.
	 */
	if(_OWPClientRequestModeReadResponse(cntrl,err_ret) != 0)
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
		 u_int32_t      mode_offered,/* advertised server mode      */
		 int            connfd,    /* connected socket              */
		 void*          app_data,  /* policy                        */
		 OWPErrSeverity *err_ret   /* err - return                  */
)
{
	u_int32_t mode_requested;
	char challenge[16];

	char buf[MAX_MSG]; /* used to send and receive messages */
	char token[32];
	char *class;
	OWPControl cntrl;
	*err_ret = OWPErrOK;
	if ( !(cntrl = _OWPControlAlloc(ctx, err_ret)))
		return NULL;

	/* XXX - setc cntrl fields, - say,
	   cntrl->sockfd = connfd, etc
	*/
	cntrl->sockfd = connfd;

	/* Compose Server greeting. */
	memset(buf, 0, sizeof(buf));
	*(u_int32_t *)(buf + 12) = htonl(mode_offered);

	/* generate 16 random bytes of challenge and save them away. */
	random_bytes(challenge, 16);
	memcpy(buf + 16, challenge, 16); /* the last 16 bytes */
	
	if (_OWPSendBlocks(cntrl, buf, 2) < 0)
		return NULL;

	if (readn(cntrl->sockfd, buf, 60) != 60){
		return NULL;
	}

	mode_requested = ntohl(*(u_int32_t *)buf);
	
	/* insure that exactly one is chosen */
	if ( !(mode_requested == OWP_MODE_OPEN 
	       | mode_requested == OWP_MODE_AUTHENTICATED
	       | mode_requested == OWP_MODE_ENCRYPTED ))
		{
			*err_ret = OWPErrFATAL;
			return cntrl;
				}

	if (mode_requested & ~mode_offered){ /* can't provide requested mode */
		_OWPServerOK(cntrl, CTRL_REJECT);
		return NULL;
	}
	
	if (mode_requested & (OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)){
		OWPByte binKey[16];

		memcpy(cntrl->kid, buf + 4, 8); /* Save 8 bytes of kid */

		if(!_OWPCallGetAESKey(cntrl->ctx, buf + 4, binKey, err_ret)){
			if(*err_ret != OWPErrOK){
				*err_ret = OWPErrFATAL;
				return NULL;
			}
		}


		if (OWPDecryptToken(binKey, buf + 12, token) < 0)
			return NULL;

		/* Decrypted challenge is in the first 16 bytes */
		if (memcmp(cntrl->challenge, token, 16) != 0){
			_OWPServerOK(cntrl, CTRL_REJECT);
			return NULL;
		}

		/* XXX - Authentication ok - determine usage class now. 
		   BUT: libowamp doesn't know about policy!!!
		   Must make use of hook function here.
		if (class = (GetClass(cntrl->kid)) == NULL)
			class = OWP_MODE_AUTHENTICATED;
		
		if ((GetMode(class) & mode_requested) == 0){
			_OWPServerOK(cntrl, CTRL_REJECT);
			return NULL;
		}
		*/
			
		random_bytes(cntrl->writeIV, 16);

		/* Save 16 bytes of session key and 16 bytes of client IV*/
		memcpy(cntrl->session_key, token + 16, 16);
		memcpy(cntrl->readIV, buf + 44, 16);
		_OWPMakeKey(cntrl, cntrl->session_key); 
	} else { /* mode_req == OPEN */
		/* XXX - Authentication ok - determine usage class now. 
		   BUT: libowamp doesn't know about policy!!!
		   Must make use of hook function here.
		if (class = (GetClass(cntrl->remote)) == NULL)
			class = OWP_OPEN;

		if ((GetMode(class) & mode_requested) == 0){
			_OWPServerOK(cntrl, CTRL_REJECT);
			return NULL;
		}
		*/
	}

	/* Apparently everything is ok. Accept the Control session. */
	cntrl->mode = mode_requested;
	_OWPServerOK(cntrl, CTRL_ACCEPT);
	return cntrl;
}

/*
** This function sets up the key field of a OWPControl structure,
** using the binary key located in <binKey>.
*/

_OWPMakeKey(OWPControl cntrl, OWPByte *binKey)
{
	cntrl->encrypt_key.Nr
		= rijndaelKeySetupEnc(cntrl->encrypt_key.rk, binKey, 128);
	cntrl->decrypt_key.Nr 
		= rijndaelKeySetupDec(cntrl->decrypt_key.rk, binKey, 128);
}


/* 
** The next two functions perform a single encryption/decryption
** of Token in Control protocol, using a given (binary) key and the IV of 0.
*/

#define TOKEN_BITS_LEN (2*16*8)

int
OWPEncryptToken(char *binKey, char *token_in, char *token_out)
{
	int r;
	char IV[16];
	keyInstance key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupEnc(key.rk, binKey, 128);
	r = blockEncrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}

int
OWPDecryptToken(char *binKey, char *token_in, char *token_out)
{
	int r;
	char IV[16];
	keyInstance key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupDec(key.rk, binKey, 128);
	r = blockDecrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}
