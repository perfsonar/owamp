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
 *	File:		endpoint.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Wed May 29 09:17:21 MDT 2002
 *
 *	Description:	
 *		This file contains the "default" implementation for
 *		the send and recv endpoints of an OWAMP test session.
 */
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>

#include <owpcontrib/unixtime.h>
#include <owpcontrib/access.h>
#include "owampP.h"
#include "endpoint.h"
#include "conndata.h"

/*
 * This type holds all the information needed for an endpoint to be
 * managed by these functions.
 */
typedef struct _DefEndpointRec{
	OWPSID			sid;
	pid_t			child;
	OWPBoolean		send;
	OWPTestSpec		test_spec;
	int			sockfd;
	FILE			*datafile;
	char			*filepath;
	char			*fbuff;
} _DefEndpointRec, *_DefEndpoint;

static _DefEndpoint
EndpointAlloc(
	OWPContext	ctx
	)
{
	_DefEndpoint	ep = malloc(sizeof(_DefEndpointRec));

	if(!ep){
		OWPError(ctx,OWPErrFATAL,errno,"malloc(DefEndpointRec)");
		return NULL;
	}

	ep->child = 0;
	ep->test_spec.test_type = OWPTestUnspecified;

	return ep;
}

static void
EndpointFree(
	_DefEndpoint	ep
	)
{
	if(!ep)
		return;

	if(ep->filepath)
		free(ep->filepath);
	if(ep->datafile)
		fclose(ep->datafile);
	if(ep->fbuff)
		free(ep->fbuff);
	free(ep);

	return;
}

/*
 * buff must be at least (nbytes*2) +1 long or memory will be over-run.
 */
static void
hexencode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	)
{
	char		hex[]="0123456789abcdef";
	unsigned int	i;

	for(i=0;i<nbytes;i++){
		*buff++ = hex[*bytes >> 4];
		*buff++ = hex[*bytes++ & 0x0f];
	}
	*buff = '\0';
}

#ifndef	PATH_SEPARATOR
#define	PATH_SEPARATOR	"/"
#endif

static char *
make_data_dir(
	OWPContext		ctx,
	char			*data_path,
	owp_tree_node_ptr	node,
	unsigned int		add_chars
	)
{
	char		*path;

	if(node){
		/* 1 is for this node's path seperator */
		path = make_data_dir(ctx,data_path,node->parent,
						strlen(node->data)+1+add_chars);
		if(!path)
			return NULL;
		strcat(path,PATH_SEPARATOR);
		strcat(path,node->data);
	}
	else{
		if((strlen(data_path)+add_chars) > FILENAME_MAX){
			OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
						"Datapath length too long.");
			return NULL;
		}
		path = malloc(strlen(data_path)+add_chars+1);
		if(!path){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"malloc problem:(%s)",strerror(errno));
			return NULL;
		}
		strcpy(path,data_path);

	}

	if((mkdir(path,0x0755) != 0) && (errno != EEXIST)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"Unable to mkdir(%s):%s",path,strerror(errno));
		free(path);
		return NULL;
	}

	return path;
}


static FILE *
opendatafile(
	OWPContext		ctx,
	char			*data_path,
	OWPSID			sid,
	owp_tree_node_ptr	node,
	char			**file_path
)
{
	FILE	*dp;
	char	sid_name[(sizeof(OWPSID)*2)+1];
	char	*path;

	/*
	 * 35 is length of path_seperator + length of sid_name + ".i"
	 */
	if(!(path = make_data_dir(ctx,data_path,node,33)))
		return NULL;

	hexencode(sid_name,sid,sizeof(sid));
	strcat(path,PATH_SEPARATOR);
	strcat(path,sid_name);
	strcat(path,".i");	/* in-progress	*/

	dp = fopen(path,"wb");
	if(!dp){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"Unable to open datafile(%s):%s",path,strerror(errno));
		free(path);
	}

	*file_path = path;
	return dp;
}


/*
 * The endpoint init function is responsible for opening a socket, and
 * allocating a local port number.
 * If this is a recv endpoint, it is also responsible for allocating a
 * session id.
 */
OWPErrSeverity
OWPDefEndpointInit(
	void		*app_data,
	void		**end_data_ret,
	OWPBoolean	send,
	OWPAddr		localaddr,
	OWPTestSpec	*test_spec,
	OWPSID		sid
)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	struct sockaddr_storage	sbuff;
	socklen_t		sbuff_len=sizeof(sbuff);
	_DefEndpoint		ep=EndpointAlloc(cdata->ctx);
	int			sbuf_size;
	int			sopt;
	socklen_t		opt_size;

	if(!ep)
		return OWPErrFATAL;

	ep->send = send;

	if(test_spec->test_type != OWPTestPoisson){
		OWPError(cdata->ctx,OWPErrFATAL,OWPErrINVALID,
				"Incorrect test type");
		goto error;
	}
	ep->test_spec = *test_spec;

	sbuf_size = owp_ip_packet_size(localaddr->saddr->sa_family,
				cdata->mode,test_spec->any.packet_size_padding);
	sbuf_size += 128;	/* Add fuzz space for IP "options" */

	/*
	 * Create the socket.
	 */
	localaddr->fd = socket(localaddr->saddr->sa_family,localaddr->so_type,
						localaddr->so_protocol);
	if(localaddr->fd<0){
		OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"socket call failed:(%s)",strerror(errno));
		goto error;
	}

	/*
	 * bind it to the local address getting an ephemeral port number.
	 */
	if(bind(localaddr->fd,localaddr->saddr,localaddr->saddrlen) != 0){
		OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"bind call failed:(%s)",strerror(errno));
		goto error;
	}

	/*
	 * Retrieve the ephemeral port picked by the system.
	 */
	if(getsockname(localaddr->fd,(void*)&sbuff,&sbuff_len) != 0){
		OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"getsockname call failed:(%s)",strerror(errno));
		goto error;
	}

	/*
	 * set saddr to the sockaddr that was actually used.
	 * (This sets the port in saddr as well.)
	 */
	assert(localaddr->saddrlen >= sbuff_len);
	memcpy(localaddr->saddr,&sbuff,sbuff_len);

	ep->sockfd = localaddr->fd;

	/*
	 * If we are receiver - set the sid and open the file.
	 */
	if(!send){
		OWPTimeStamp	tstamp;
		u_int8_t	*aptr;
		u_int32_t	tval[2];
		size_t		size;

		/*
		 * Generate a "unique" SID from
		 * addr(4)/time(8)/random(4) values.
		 */

#ifdef	AF_INET6
		if(localaddr->saddr->sa_family == AF_INET6){
			struct sockaddr_in6	*s6;

			s6 = (struct sockaddr_in6*)localaddr->saddr;
			/* point at last 4 bytes of addr */
			aptr = &s6->sin6_addr.s6_addr[12];
		}else
#endif
		if(localaddr->saddr->sa_family == AF_INET){
			struct sockaddr_in	*s4;

			s4 = (struct sockaddr_in*)localaddr->saddr;
			aptr = (u_int8_t*)&s4->sin_addr;
		}
		else{
			OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNSUPPORTED,
					"EndpointInit:Unknown address family.");
			goto error;
		}

		memcpy(&sid[0],aptr,4);	/* addr part */

		/*
		 * time part
		 */
		(void)OWPGetTimeOfDay(&tstamp);
		OWPEncodeTimeStamp(tval,&tstamp);
		memcpy(&sid[4],tval,8);

		/*
		 * Random bytes.
		 */
		I2RandomBytes(&sid[12],4);

		/*
		 * Open file for saving data.
		 */
		ep->datafile = opendatafile(cdata->ctx,cdata->data_path,sid,
				cdata->node,&ep->filepath);
		if(!ep->datafile){
			OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Unable to open seesion file:%s",
				strerror(errno));
			goto error;
		}

		/*
		 * set file buffer such that ~ 1 second of data will fit
		 * in buffer.
		 * TODO: (This will change with the new generalized
		 * time distribution, but for now just use lambda and 1 sec.)
		 */
		size = 1000000.0/ep->test_spec.poisson.InvLambda*20;
		size = MIN(size,8192);
		if(size < 128)
			size = 0;
		else{
			ep->fbuff = malloc(size);
			if(!ep->fbuff)
				size = 0;
		}
		
		if(size)
			setvbuf(ep->datafile,ep->fbuff,_IOFBF,size);
		/*
		 * receiver - need to set the recv buffer size large
		 * enough for the packet, so we can get it in a single
		 * read.
		 */
		opt_size = sizeof(sopt);
		if(getsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
					(void*)&sopt,&opt_size) < 0){
			OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"getsockopt(RCVBUF):%s",strerror(errno));
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"setsockopt(RCVBUF=%d):%s",
						sopt,strerror(errno));
				goto error;
			}
		}

	}
	else{
		/*
		 * We are sender - need to set sockopt's to ensure we don't
		 * fragment our test packets in the socket api.
		 */

		opt_size = sizeof(sopt);
		if(getsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
					(void*)&sopt,&opt_size) < 0){
			OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"getsockopt(SNDBUF):%s",strerror(errno));
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"setsockopt(RCVBUF=%d):%s",
						sopt,strerror(errno));
				goto error;
			}
		}
	}

	*(_DefEndpoint*)end_data_ret = ep;

	return OWPErrOK;

error:
	EndpointFree(ep);
	return OWPErrFATAL;
}

static int owp_usr1;
static int owp_usr2;
static int owp_int;

static void
sig_catch(
	int	signo
	)
{
	switch(signo){
		case SIGUSR1:
			owp_usr1 = 1;
			break;
		case SIGUSR2:
			owp_usr2 = 1;
			break;
		case SIGINT:
			owp_int = 1;
			break;
		default:
			OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
					"sig_catch:Invalid signal(%d)",signo);
			exit(1);
	}
	return;
}

/*
 * The endpoint init_hook function is responsible for connecting the socket
 * to the remote endpoint. (We connect the UDP socket to improve performance,
 * we are only interested in packets coming from the sender - or sending to
 * the receiver and this lets the kernel deal with that instead of having
 * to mess with sendto/recvfrom.)
 */
OWPErrSeverity
OWPDefEndpointInitHook(
	void		*app_data,
	void		*end_data,
	OWPAddr		remoteaddr,
	OWPSID		sid
)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	_DefEndpoint		ep=(_DefEndpoint)end_data;
	struct sigaction	act;
	sigset_t		sigs,osigs;
	int			i;

	/*
	 * If we are sender - get the SID. probably don't need it, but
	 * what the heck.
	 */
	if(ep->send)
		memcpy(ep->sid,sid,sizeof(OWPSID));

	if(connect(ep->sockfd,remoteaddr->saddr,remoteaddr->saddrlen) != 0){
		OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,"connect failed:%s",
				strerror(errno));
		EndpointFree(ep);
		return OWPErrFATAL;
	}

	/*
	 * replace this with sigprocmask - then call sigsuspend later...
	 */
	owp_usr1 = 0;
	owp_usr2 = 0;
	owp_int = 0;
	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaddset(&sigs,SIGUSR1);
	sigaddset(&sigs,SIGUSR2);
	sigaddset(&sigs,SIGINT);
	
	if(	(sigprocmask(SIG_BLOCK,&sigs,&osigs) != 0) ||
					(sigaction(SIGUSR1,&act,NULL) != 0) ||
					(sigaction(SIGUSR2,&act,NULL) != 0) ||
					(sigaction(SIGINT,&act,NULL) != 0)){
		act.sa_handler = SIG_DFL;
		(void)sigaction(SIGUSR1,&act,NULL);
		(void)sigaction(SIGUSR2,&act,NULL);
		(void)sigaction(SIGINT,&act,NULL);
		OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"sigaction failed:%s",strerror(errno));
		EndpointFree(ep);
		return OWPErrFATAL;
	}

	ep->child = fork();

	if(ep->child < 0){
		/* fork error */
		act.sa_handler = SIG_DFL;
		(void)sigaction(SIGUSR1,&act,NULL);
		(void)sigaction(SIGUSR2,&act,NULL);
		(void)sigaction(SIGINT,&act,NULL);
		(void)sigprocmask(SIG_SETMASK,&osigs,NULL);
		OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,"fork failed:%s",
				strerror(errno));
		EndpointFree(ep);
		return OWPErrFATAL;
	}

	if(ep->child > 0){
		/* parent */
		act.sa_handler = SIG_DFL;
		if(	(sigaction(SIGUSR1,&act,NULL) != 0) ||
			(sigaction(SIGUSR2,&act,NULL) != 0) ||
			(sigaction(SIGINT,&act,NULL) != 0) ||
			(sigprocmask(SIG_SETMASK,&osigs,NULL) != 0)){
			OWPError(cdata->ctx,OWPErrWARNING,OWPErrUNKNOWN,
				"sigaction(DFL) failed:%s",strerror(errno));
			return OWPErrWARNING;
		}

		fclose(ep->datafile);
		ep->datafile = NULL;
		free(ep->fbuff);
		ep->fbuff = NULL;
		close(ep->sockfd);
		ep->sockfd = -1;
		return OWPErrOK;
	}

	/*
	 * We are now in the child send/recv process.
	 */

	for(i=getdtablesize()-1;i>=0;i--){
#ifndef	NDEBUG
		if(i == fileno(stderr))
			continue;
#endif
		if((i==ep->sockfd) || (i==fileno(ep->datafile)))
			continue;

		/*
		 * Ignore errors unless it was intr - then try again.
		 */
		while((close(i) < 0) && (errno == EINTR));
	}

	/*
	 * SIGUSR1 is StartSessions
	 * SIGUSR2 is StopSessions
	 * SIGINT is Terminate - making session invalid.
	 */
	while(!owp_usr1 && !owp_usr2 && !owp_int)
		sigsuspend(&sigs);

	if(owp_int){
		/* cancel everything */
	}else if(owp_usr2){
		/* bogus */
	}else if(owp_usr1){
		/* start the session */
	}

	return OWPErrOK;
}

OWPErrSeverity
OWPDefEndpointStart(
	void	*app_data,
	void	*end_data
	)
{
	return OWPErrOK;
}

OWPErrSeverity
OWPDefEndpointStop(
	void		*app_data,
	void		*end_data,
	OWPAcceptType	aval
	)
{
	return OWPErrOK;
}
