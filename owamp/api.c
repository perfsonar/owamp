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
	OWPContext		ctx
)
{
	OWPControl	cntrl = malloc(sizeof(OWPControlRec));

	if(!cntrl){
		OWPErrorLine(ctx,OWPLine,OWPErrFatal,errno,
				":malloc(%d)",sizeof(OWPControlRec));
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

OWPAddr
_OWPConnect(
	OWPContext	ctx,
	OWPAddr		server_addr
)
{
	int	fd=-1;

	if(server_addr->fd > -1)
		return server_addr;

	if(!server_addr->ai){
		/*
		 * Call getaddrinfo to find useful addresses
		 */
		struct addrinfo	hints, *ret;
		const char	*node="localhost";

		if(server_addr->node_set)
			node = server_addr->node;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if((getaddrinfo(node,OWP_CONTROL_SERVICE_NAME,&hints,&ret)!=0)
								|| !ret){
			OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
					":getaddrinfo()");
			return NULL;
		}

		server_addr->ai = ret;
	}

	for(ai=server_addr->ai;ai;ai->ai_next){
		fd = socket(ret->ai_family,ret->ai_socktype,ret->ai_protocol);
		if(fd < 0)
			continue;

		if(connect(fd,ret->ai_addr,ret->ai_addrlen) == 0){
			server_addr->fd = fd;
			return server_addr;
		}

		if(close(fd) !=0){
			OWPErrorLine(ctx,OWPLine,OWPErrFATAL,errno,
					":close(%d)",fd);
			return NULL;
		}
	}

	OWPErrorLine(ctx,OWPLine,OWPErrFATAL,OWPErrUNDEFINED,"No Valid Addr's");
	return NULL;
}

OWPControl
OWPControlOpen(
	OWPContext	ctx,
	OWPAddr		server_addr,
	int		mode_mask,
	const OWPKID	*kid,
	const OWPKey	*key,
	OWPErrSeverity	*err_ret
)
{
	int		fd;
	OWPControl	cntrl = _OWPControlAlloc(ctx);

	if(!cntrl)
		return NULL;

	if( !(cntrl->addr = _OWPConnect(ctx,server_addr))){
		_OWPControlFree(cntrl);
		OWPAddrFree(server_addr);
		return NULL;
	}

}
