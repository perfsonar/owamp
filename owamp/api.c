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

static OWPInitializeConfigRec	def_cfg = {
	/* tm_out			*/	0,
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
			OWPErrFatal,ENOMEM,":malloc(%d)",
			sizeof(OWPContextRec));
		return NULL;
	}

	if(config)
		ctx->cfg = *config;
	else
		ctx->cfg = def_cfg;

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
		OWPErrorLine(ctx,OWPLine,OWPErrFatal,errno,
				":malloc(%d)",sizeof(struct OWPAddrRec));
		return NULL;
	}

	addr->ctx = ctx;

	addr->node_set = 0;
	addr->node[0] = '\0';
	addr->ai_free = 0;
	addr->ai = NULL;

	addr->fd_set = -1;

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
		if(close(fd) < 0){
			OWPErrorLine(addr->ctx,OWPLine,OWPErrWARNING,
					errno,":close(%d)",fd);
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

struct addrinfo*
_OWPCopyAddrRec(
	OWPContext	ctx,
	struct addrinfo	*src
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
					OWPErrUNDEFINED,
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

OWPControl
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

	cntrl->ctx = ctx;

	cntrl->server = 0;
	cntrl->state = 0;
	cntrl->mode = 0;
	cntrl->addr = NULL;
	cntrl->next = NULL;

	return cntrl;
}

void
_OWPClientBind(
	OWPControl	cntrl,
	int		fd,
	struct addrinfo	*local_addrinfo,
	struct addrinfo	*remote_addrinfo,
	OWPErrSeverity	*err_ret
)
{
	struct addrinfo	*ai;

	for(ai=local_addrinfo;ai;ai = ai_next){
		if(ai->ai_family != remote_addrinfo->ai_family)
			continue;
		if(ai->ai_socktype != remote_addrinfo->ai_socktype)
			continue;
		if(ai->ai_protocol != remote_addrinfo->ai_protocol)
			continue;

		if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0)
			return;
		OWPErrorLine(cntrl->ctx,OWPLine,errno,"bind(,,):%m");
		*err_ret = OWPErrFATAL;
		return;
	}

	OWPErrorLine(cntrl->ctx,OWPLine,errno,"Invalid local addr spec's");
	err_ret = OWPErrFATAL;
	return;
}

int
_OWPClientConnect(
	OWPControl	cntrl,
	OWPAddr		local_addr,
	OWPAddr		server_addr,
	OWPErrSeverity	*err_ret
)
{
	int		fd=-1;
	struct sockaddr	*local_saddr=NULL;

	if((!server_addr) &&
		!(server_addr = OWPAddrByNode("localhost"))){
		return -1;
	}

	if(server_addr->fd > -1){
		cntrl->remote_addr = server_addr;
		return _OWPClientSetSock(cntrl,err_ret);
	}

	if(!server_addr->ai){
		/*
		 * Call getaddrinfo to find useful addresses
		 */
		struct addrinfo	hints, *ret;
		const char	*node=NULL;

		if(server_addr->node_set)
			node = server_addr->node;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if((getaddrinfo(node,OWP_CONTROL_SERVICE_NAME,&hints,&ret)!=0)
								|| !ret){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
					":getaddrinfo()");
			*err_ret = OWPErrFATAL;
			return -1;
		}

		server_addr->ai = ret;
	}

	for(ai=server_addr->ai;ai;ai->ai_next){
		OWPErrSeverity	addr_ok;

		fd = socket(ret->ai_family,ret->ai_socktype,ret->ai_protocol);
		if(fd < 0)
			continue;

		if(local_addr){
			addr_ok = OWPErrOK;
			_OWPClientBind(cntrl,fd,local_addr,ret,&addr_ok);
			if(addr_ok != OWPErrOK)
				goto next;
		}

		_OWPCheckAddr(cntrl->ctx,local_addr,ret->ai_addr,
				&addr_ok);
		if(addr_ok != OWPErrOK)
			goto next;

		/*
		 * TODO:Add timeout (non-block connect, then select...)
		 */
		if(connect(fd,ai->ai_addr,ai->ai_addrlen) == 0){
			server_addr->fd = fd;
			server_addr->saddr = ai->ai_addr;
			cntrl->remote_addr = server_addr;
			return _OWPClientSetSock(cntrl,local_addr,err_ret);
		}

next:
		if(close(fd) !=0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrWARNING,
						errno,":close(%d)",fd);
			*err_ret = OWPErrWARNING;
		}
	}

	OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,OWPErrUNDEFINED,
			"No Valid Addr's");
	*err_ret = OWPErrFATAL;
	return NULL;
}

OWPControl
OWPControlOpen(
	OWPContext	ctx,
	OWPAddr		local_addr,
	OWPAddr		server_addr,
	u_int32_t	mode_req_mask,
	const OWPKID	*kid,
	const OWPKey	*key,
	OWPErrSeverity	*err_ret
)
{
	int		fd;
	OWPControl	cntrl = _OWPControlAlloc(ctx,err_ret);
	u_int32_t	mode_avail;
	u_int32_t	challenge[4];


	if( !(cntrl = _OWPControlAlloc(ctx,err_ret))){
		OWPAddrFree(server_addr);
		return NULL;
	}

	if(_OWPClientConnect(cntrl,server_addr,err_ret) != 0){
		_OWPControlFree(cntrl);
		return NULL;
	}


	if(_OWPClientReadServerGreeting(cntrl,&mode_avail,challenge,err_ret)
									!= 0){
		_OWPControlFree(cntrl);
		return NULL;
	}

	/*
	 * Select mode wanted...
	 * Remove auth bits, if they were set with no kid or key.
	 */
	if(!kid || !key)
		mode_req_mask &= ~OWP_DO_ENCRYPT;
	mode_avail &= mode_req_mask;

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

	if((cntrl->mode & _OWP_DO_ENCRYPT) &&
		(_OWPInitClientEncryptionValues(cntrl,challenge,err_ret)!=0)){

		_OWPControlFree(cntrl);
		return NULL;
	}

	if(_OWPClientRequestModeReadResponse(cntrl,&mode_avail,challenge,err_ret) != 0){
		_OWPControlFree(cntrl);
		return NULL;
	}

}
