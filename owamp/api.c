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
	/* tm_out.tv_sec		*/	{0,
	/* tm_out.tv_usec		*/	0},
	/* eh				*/	NULL,
	/* get_aes_key			*/	NULL,
	/* check_control_func		*/	NULL,
	/* check_test_func		*/	NULL,
	/* endpoint_init_func		*/	NULL,
	/* endpoint_init_hook_func	*/	NULL,
	/* endpoint_start_func		*/	NULL,
	/* endpoint_status_func		*/	NULL,
	/* endpoint_stop_func		*/	NULL,
	/* rand_type			*/	I2RAND_DEV,
	/* rand_data			*/	NULL
};

OWPContext
OWPContextInitialize(
	OWPInitializeConfig	config
)
{
	I2LogImmediateAttr	ia;
	OWPContext		ctx = calloc(1,sizeof(OWPContextRec));

	if(!ctx){
		OWPError(NULL,
			OWPErrFATAL,ENOMEM,":calloc(1,%d):%M",
						sizeof(OWPContextRec));
		return NULL;
	}

	if(config)
		ctx->cfg = *config;
	else
		ctx->cfg = def_cfg;

	if(!ctx->cfg.eh){
		ctx->lib_eh = True;
		ia.line_info = (I2NAME|I2MSG);
		ia.fp = stderr;
		ctx->cfg.eh = I2ErrOpen("libowamp",I2ErrLogImmediate,&ia,
				NULL,NULL);
		if(!ctx->cfg.eh){
			OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
					"Cannot init error module");
			free(ctx);
			return NULL;
		}
	}
	else
		ctx->lib_eh = False;

	if(ctx->cfg.rand_type == 0){
		ctx->cfg.rand_type = I2RAND_DEV;
		ctx->cfg.rand_data = NULL;
	}

	if( !(ctx->rand_src = I2RandomSourceInit(ctx->cfg.eh,
			       ctx->cfg.rand_type,
			       ctx->cfg.rand_data))){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
			     "Failed to initialize randomness sources");
		OWPContextFree(ctx);
		return NULL;
	}

	return ctx;
}

void
OWPContextFree(
	OWPContext	ctx
)
{
	if(ctx->lib_eh)
		I2ErrClose(ctx->cfg.eh);
	I2RandomSourceClose(ctx->rand_src);
	free(ctx);

	return;
}

OWPAddr
_OWPAddrAlloc(
	OWPContext	ctx
)
{
	OWPAddr	addr = calloc(1,sizeof(struct OWPAddrRec));

	if(!addr){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
			":calloc(1,%d):%M",sizeof(struct OWPAddrRec));
		return NULL;
	}

	addr->ctx = ctx;

	addr->node_set = 0;
	addr->node[0] = '\0';
	addr->port_set = 0;
	addr->port[0] = '\0';
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
		return err;

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
			OWPError(addr->ctx,OWPErrWARNING,
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
	OWPAddr		addr;
	char		buff[MAXHOSTNAMELEN+1];
	const char	*nptr=node;
	char		*pptr=NULL;
	char		*s1,*s2;

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
	if( (s1 = strchr(buff,'['))){
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
	else if( (s1 = strchr(buff,':'))){
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
	struct addrinfo	*dst = calloc(1,sizeof(struct addrinfo));

	if(!dst){
		OWPError(ctx,OWPErrFATAL,errno,
				":calloc(1,sizeof(struct addrinfo))");
		return NULL;
	}

	*dst = *src;

	if(src->ai_addr){
		dst->ai_addr = malloc(src->ai_addrlen);
		if(!dst->ai_addr){
			OWPError(ctx,OWPErrFATAL,errno,
				"malloc(%u):%s",src->ai_addrlen,
				strerror(errno));
			free(dst);
			return NULL;
		}
		memcpy(dst->ai_addr,src->ai_addr,src->ai_addrlen);
		dst->ai_addrlen = src->ai_addrlen;
	}
	else
		dst->ai_addrlen = 0;

	if(src->ai_canonname){
		int	len = strlen(src->ai_canonname);

		if(len > MAXHOSTNAMELEN){
			OWPError(ctx,OWPErrWARNING,
					OWPErrUNKNOWN,
					":Invalid canonname!");
			dst->ai_canonname = NULL;
		}else{
			dst->ai_canonname = malloc(sizeof(char)*(len+1));
			if(!dst->ai_canonname){
				OWPError(ctx,OWPErrWARNING,
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
			OWPAddrFree(addr);
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

OWPAddr
_OWPAddrCopy(
	OWPAddr		from
	)
{
	OWPAddr		to;
	struct addrinfo	**aip;
	struct addrinfo	*ai;
	
	if(!from)
		return NULL;
	
	if( !(to = _OWPAddrAlloc(from->ctx)))
		return NULL;

	if(from->node_set){
		strncpy(to->node,from->node,sizeof(to->node));
		to->node_set = True;
	}

	if(from->port_set){
		strncpy(to->port,from->port,sizeof(to->port));
		to->port_set = True;
	}

	to->ai_free = 1;
	aip = &to->ai;
	ai = from->ai;

	while(ai){
		*aip = _OWPCopyAddrRec(from->ctx,ai);
		if(!*aip){
			OWPAddrFree(to);
			return NULL;
		}
		if(ai->ai_addr == from->saddr){
			to->saddr = (*aip)->ai_addr;
			to->saddrlen = (*aip)->ai_addrlen;
		}

		aip = &(*aip)->ai_next;
		ai = ai->ai_next;
	}

	to->fd = from->fd;

	if(to->fd > -1)
		to->fd_user = True;

	return to;
}

int
OWPAddrFD(
	OWPAddr	addr
	)
{
	if(!addr || (addr->fd < 0))
		return -1;

	return addr->fd;
}

socklen_t
OWPAddrSockLen(
	OWPAddr	addr
	)
{
	if(!addr || !addr->saddr)
		return 0;

	return addr->saddrlen;
}

OWPControl
_OWPControlAlloc(
	OWPContext		ctx,
	void			*app_data,
	OWPErrSeverity		*err_ret
)
{
	OWPControl	cntrl;
	
	if( !(cntrl = calloc(1,sizeof(OWPControlRec)))){
		OWPError(ctx,OWPErrFATAL,errno,
				":calloc(1,%d)",sizeof(OWPControlRec));
		*err_ret = OWPErrFATAL;
		return NULL;
	}

	/*
	 * Init state fields
	 */
	cntrl->ctx = ctx;

	cntrl->app_data = app_data;

	/*
	 * Init addr fields
	 */
	cntrl->sockfd = -1;

	/*
	 * Init encryption fields
	 */
	memset(cntrl->kid_buffer,'\0',sizeof(cntrl->kid_buffer));

	/*
	 * Put this control record on the ctx list.
	 */
	cntrl->next = ctx->cntrl_list;
	ctx->cntrl_list = cntrl;

	return cntrl;
}

OWPSessionMode
OWPGetMode(
	OWPControl	cntrl
	)
{
	return cntrl->mode;
}

/*
 * Function:	OWPGetDelay
 *
 * Description:	Returns a very rough estimate of the upper-bound rtt to
 * 		the server.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
struct timeval*
OWPGetDelay(
	OWPControl	cntrl,
	struct timeval	*tval
	)
{
	if(!tval)
		return NULL;
	*tval = cntrl->delay_bound;

	return tval;
}

/*
 * Function:	OWPGetAESkeyInstance
 *
 * Description:	
 * 		Return the keyInstance associated with the "which" key.
 * 		which:
 * 			0: Decryption key
 * 			1: Encryption key
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
keyInstance*
OWPGetAESkeyInstance(
		OWPControl	cntrl,
		int		which
		)
{
	if(!cntrl)
		return NULL;

	switch(which){
		case 0:
			return &cntrl->decrypt_key;
			break;
		case 1:
			return &cntrl->encrypt_key;
			break;
		default:
			return NULL;
	}
}

OWPErrSeverity
_OWPFailControlSession(
	OWPControl	cntrl,
	int		level
	)
{
	cntrl->state = _OWPStateInvalid;
	return (OWPErrSeverity)level;
}

OWPTestSession
_OWPTestSessionAlloc(
	OWPControl	cntrl,
	OWPAddr		sender,
	OWPBoolean	send_local,
	OWPAddr		receiver,
	OWPBoolean	recv_local,
	OWPTestSpec	*test_spec
)
{
	OWPTestSession	test;

	if(!sender || ! receiver){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"_OWPTestSessionAlloc:Invalid Addr arg");
		return NULL;
	}

	if(!(test = calloc(1,sizeof(OWPTestSessionRec)))){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"calloc(1,OWPTestSessionRec):%M");
		return NULL;
	}

	test->cntrl = cntrl;
	test->sender = sender;
	test->send_local = send_local;
	test->receiver = receiver;
	test->recv_local = recv_local;
	memcpy(&test->test_spec,test_spec,sizeof(OWPTestSpec));

	return test;
}

OWPErrSeverity
_OWPTestSessionFree(
	OWPTestSession	tsession,
	OWPAcceptType	aval
)
{
	OWPTestSession	*sptr;
	OWPErrSeverity	err=OWPErrOK,err2=OWPErrOK;

	if(!tsession)
		return OWPErrOK;

	/*
	 * remove this tsession from the cntrl->tests lists.
	 */
	for(sptr = &tsession->cntrl->tests;*sptr;sptr = &(*sptr)->next)
		if(*sptr == tsession){
			*sptr = tsession->next;
			break;
		}

	if(tsession->recv_end_data)
		(void)_OWPCallEndpointStop(tsession,&tsession->recv_end_data,
					   aval,&err);
	if(tsession->send_end_data)
		(void)_OWPCallEndpointStop(tsession,&tsession->send_end_data,
					   aval,&err2);

	OWPAddrFree(tsession->sender);
	OWPAddrFree(tsession->receiver);
	free(tsession);

	return MIN(err,err2);
}

OWPErrSeverity
OWPControlClose(OWPControl cntrl)
{
	OWPErrSeverity	err = OWPErrOK;
	OWPErrSeverity	lerr = OWPErrOK;
	OWPControl	*list = &cntrl->ctx->cntrl_list;
	OWPAcceptType	acceptval = OWP_CNTRL_ACCEPT;

	/*
	 * remove all test sessions
	 */
	while(cntrl->tests){
		lerr = _OWPTestSessionFree(cntrl->tests,acceptval);
		err = MIN(err,lerr);
	}

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

OWPErrSeverity
OWPStopSessions(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval	/* in/out	*/
		)
{
	OWPErrSeverity	err,err2=OWPErrOK;
	int		msgtype;
	OWPAcceptType	aval=OWP_CNTRL_ACCEPT;

	if(!cntrl){
		OWPError(NULL,OWPErrFATAL,OWPErrINVALID,
		"OWPStopSessions called with invalid cntrl record");
		return OWPErrFATAL;
	}

	if(acceptval)
		aval = *acceptval;

	while(cntrl->tests){
		err = _OWPTestSessionFree(cntrl->tests,aval);
		err2 = MIN(err,err2);
	}

	/*
	 * If acceptval would have been "success", but stopping of local
	 * endpoints failed, send failure acceptval instead and return error.
	 * (The endpoint_stop_func should have reported the error.)
	 */
	if(!aval && (err2 < OWPErrWARNING))
		aval = OWP_CNTRL_FAILURE;

	err = (OWPErrSeverity)_OWPWriteStopSessions(cntrl,aval);
	if(err < OWPErrWARNING)
		return _OWPFailControlSession(cntrl,OWPErrFATAL);
	err2 = MIN(err,err2);

	msgtype = OWPReadRequestType(cntrl);
	if(msgtype != 3){	/* 3 is StopSessions message */
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"Invalid protocol message received...");
		return _OWPFailControlSession(cntrl,OWPErrFATAL);
	}

	err = _OWPReadStopSessions(cntrl,&aval);

	cntrl->state &= ~_OWPStateTest;

	if(acceptval)
		*acceptval = aval;

	return MIN(err,err2);
}

OWPPacketSizeT
OWPTestPayloadSize(
		int		mode, 
		u_int32_t	padding
		)
{
	OWPPacketSizeT msg_size;

	switch (mode) {
	case OWP_MODE_OPEN:
		msg_size = 12;
		break;
	case OWP_MODE_AUTHENTICATED:
		msg_size = 24;
		break;
	case OWP_MODE_ENCRYPTED:
		msg_size = 16;
		break;
	default:
		return 0;
		/* UNREACHED */
	}

	return msg_size + padding;
}

#define OWP_IP4_HDR_SIZE	20
#define OWP_IP6_HDR_SIZE	40
#define OWP_UDP_HDR_SIZE	8

/*
** Given the protocol family, OWAMP mode and packet padding,
** compute the size of resulting full IP packet.
*/
OWPPacketSizeT
OWPTestPacketSize(
		int		af,    /* AF_INET, AF_INET6 */
		int		mode, 
		u_int32_t	padding
		)
{
	OWPPacketSizeT payload_size, header_size;

	switch (af) {
	case AF_INET:
		header_size = OWP_IP4_HDR_SIZE + OWP_UDP_HDR_SIZE;
		break;
	case AF_INET6:
		header_size = OWP_IP6_HDR_SIZE + OWP_UDP_HDR_SIZE;
		break;
	default:
		return 0;
		/* UNREACHED */
	}

	if(!(payload_size = OWPTestPayloadSize(mode,padding)))
			return 0;

	return payload_size + header_size;
}

OWPBoolean
OWPSessionStatus(
		OWPControl	cntrl,
		OWPSID		sid,
		OWPBoolean	send,
		OWPAcceptType	*aval
		)
{
	OWPTestSession	tsession;
	OWPErrSeverity	err;

	for(tsession=cntrl->tests;tsession;tsession=tsession->next)
		if(memcmp(sid,tsession->sid,sizeof(OWPSID)) == 0)
			goto found;

	return False;
found:
	if(send && tsession->send_end_data)
		return _OWPCallEndpointStatus(tsession,&tsession->send_end_data,
								aval,&err);
	if(!send && tsession->recv_end_data)
		return _OWPCallEndpointStatus(tsession,&tsession->recv_end_data,
								aval,&err);
	return False;
}

int
OWPSessionsActive(
		OWPControl	cntrl
		)
{
	OWPTestSession	tsession;
	OWPAcceptType	aval;
	int		n=0;
	OWPErrSeverity	err;

	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if((tsession->recv_end_data) && _OWPCallEndpointStatus(tsession,
					&tsession->recv_end_data,&aval,&err)){
			if(aval < 0)
				n++;
		}
		if((tsession->send_end_data) && _OWPCallEndpointStatus(tsession,
					&tsession->send_end_data,&aval,&err)){
			if(aval < 0)
				n++;
		}
	}

	return n;
}

int
OWPStopSessionsWait(
	OWPControl	cntrl,
	OWPTimeStamp	*wake,
	OWPAcceptType	*acceptval,
	OWPErrSeverity	*err_ret
	)
{
	struct timeval	currtime;
	struct timeval	reltime;
	struct timeval	*waittime = NULL;
	fd_set		readfds;
	fd_set		exceptfds;
	int		rc;
	int		msgtype;
	OWPErrSeverity	err2=OWPErrOK;
	OWPAcceptType	aval=OWP_CNTRL_ACCEPT;

	if(!cntrl || cntrl->sockfd < 0){
		*err_ret = OWPErrFATAL;
		return -1;
	}

	if(acceptval)
		*acceptval = aval;

	if(wake){
		if(gettimeofday(&currtime,NULL) != 0){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"gettimeofday():%M");
			return -1;
		}
		OWPCvtTimestamp2Timeval(&reltime,wake);
		if(tvalcmp(&currtime,&reltime,<))
			tvalsub(&reltime,&currtime);
		else
			tvalclear(&reltime);

		waittime = &reltime;
	}


	FD_ZERO(&readfds);
	FD_SET(cntrl->sockfd,&readfds);
	FD_ZERO(&exceptfds);
	FD_SET(cntrl->sockfd,&exceptfds);
AGAIN:
	rc = select(cntrl->sockfd+1,&readfds,NULL,&exceptfds,waittime);

	if(rc < 0){
		if(errno != EINTR){
			OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"select():%M");
			*err_ret = OWPErrFATAL;
			return -1;
		}
		if(waittime)
			return 2;

		/*
		 * If there are tests still happening - go back to select
		 * and wait for them to complete.
		 */
		if(OWPSessionsActive(cntrl))
			goto AGAIN;

		/*
		 * Sessions are complete - send StopSessions message.
		 */
		*err_ret = OWPStopSessions(cntrl,acceptval);
		return 0;
	}
	if(rc == 0)
		return 1;

	if(!FD_ISSET(cntrl->sockfd,&readfds) &&
					!FD_ISSET(cntrl->sockfd,&exceptfds)){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"select():cntrl fd not ready?:%M");
		*err_ret = OWPErrFATAL;
		return -1;
	}

	msgtype = OWPReadRequestType(cntrl);
	if(msgtype != 3){
		OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
				"Invalid protocol message received...");
		*err_ret = OWPErrFATAL;
		cntrl->state = _OWPStateInvalid;
		return -1;
	}

	*err_ret = _OWPReadStopSessions(cntrl,acceptval);
	if(*err_ret < OWPErrOK){
		cntrl->state = _OWPStateInvalid;
		return -1;
	}

	if(acceptval)
		aval = *acceptval;

	while(cntrl->tests){
		err2 = _OWPTestSessionFree(cntrl->tests,aval);
		*err_ret = MIN(*err_ret,err2);
	}

	if(*err_ret < OWPErrWARNING){
		aval = OWP_CNTRL_FAILURE;
		if(acceptval)
			*acceptval = OWP_CNTRL_FAILURE;
	}

	err2 = _OWPWriteStopSessions(cntrl,aval);
	cntrl->state &= ~_OWPStateTest;

	*err_ret = MIN(*err_ret, err2);
	return 0;
}

/*
** Convert sockaddr to numeric name (does not use other fields of OWPAddr)
*/
void
OWPAddr2string(OWPAddr addr, char *buf, size_t len)
{
	if (!addr || !(addr->saddr) 
	    || getnameinfo(addr->saddr, addr->saddrlen, buf, len, NULL, 0,
			   NI_NUMERICHOST))
		strcpy(buf, "");
}

/*
** Write header to the data file.
** XXX - for now just works for TestSpecPoissson. Assumes that <buf>
** has at least 96 bytes (fixed-size of Poisson Session Request).
*/
void
OWPEncodeDataHeader(OWPTestSpec	*test_spec, 
		   u_int8_t version,
		   OWPBoolean server_conf_sender, 
		   OWPBoolean server_conf_receiver,
		   struct sockaddr *sender,
		   struct sockaddr *receiver,
		   OWPSID		sid,
		   u_int8_t *buf)
{
	OWPTestSpecPoisson *ptest = (OWPTestSpecPoisson*)test_spec;

	*(u_int8_t*)&buf[0] = 1;	/* Request-Session message # */
	*(u_int8_t*)&buf[1] = (version<<4) | version;
	*(u_int8_t*)&buf[2] = (server_conf_sender)?1:0;
	*(u_int8_t*)&buf[3] = (server_conf_receiver)?1:0;

	switch(version){
	struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
	struct sockaddr_in6	*saddr6;
		case 6:
			/* sender address  and port */
			saddr6 = (struct sockaddr_in6*)sender;
			memcpy(&buf[4],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[36] = saddr6->sin6_port;

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver;
			memcpy(&buf[20],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[38] = saddr6->sin6_port;

			break;
#endif
		case 4:
			/* sender address and port  */
			saddr4 = (struct sockaddr_in*)sender;
			*(u_int32_t*)&buf[4] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[36] = saddr4->sin_port;

			/* receiver address and port  */
			saddr4 = (struct sockaddr_in*)receiver;
			*(u_int32_t*)&buf[20] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[38] = saddr4->sin_port;

			break;
		default:
			/*
			 * This can't happen, but default keeps compiler
			 * warnings away.
			 */
			break;
	}

	if(sid)
		memcpy(&buf[40],sid,16);

	*(u_int32_t*)&buf[56] = htonl(ptest->InvLambda);
	*(u_int32_t*)&buf[60] = htonl(ptest->npackets);
	*(u_int32_t*)&buf[64] = htonl(ptest->packet_size_padding);

	/*
	 * timestamp...
	 */
	OWPEncodeTimeStamp((u_int32_t*)&buf[68],&ptest->start_time);

	*(u_int32_t*)&buf[76] = htonl(ptest->typeP);

	memset(&buf[80],0,16);

	return;
}

/*
** Functions for writing and reading headers. The format varies
** according to the version. In all cases the files starts
** with 4 bytes of magic number, 4 bytes of version, and
** 4 bytes of total header length (version and header length
** fields given in network byte order). The rest depends on
** the version as follows:
**
** Version 0: nothing - data records follow.
** Version 1: 80 bytes of Session Request as per version 3 of the protocol
*/

/*
** Write data header to the file. <len> is the length of the buffer - 
** any other fields have to be accounted for separately in the
** header length value.
*/
void
OWPWriteDataHeadeR(FILE *fp, u_int32_t version, u_int8_t *buf, u_int32_t len)
{
	static char magic[] = "OwA";
	u_int32_t net_ver = htonl(version);
	u_int32_t hdr_len = htonl(sizeof(magic) + sizeof(version) 
		+ sizeof(hdr_len) + len);

	fwrite(magic, 1, 4, fp);
	fwrite(&net_ver, sizeof(net_ver), 1, fp);
	fwrite(&hdr_len, sizeof(hdr_len), 1, fp);

	if (buf != NULL)
		fwrite(buf, sizeof(*buf), len, fp);
}
