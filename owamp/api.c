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

OWPAddr
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
	 * these functions will close the control socket if it is open.
	 */
	lerr = OWPAddrFree(cntrl->remote_addr);
	err = MIN(err,lerr);
	lerr = OWPAddrFree(cntrl->local_addr);
	err = MIN(err,lerr);

	free(cntrl);

	return err;
}

OWPTestSession
_OWPTestSessionAlloc(
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

void
_OWPTestSessionFree(
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

