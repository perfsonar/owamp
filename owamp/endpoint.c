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
#include <sys/timex.h>

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
	OWPTestSpec		test_spec;
	OWPSessionMode		mode;
	keyInstance		*aeskey;


	OWPSID			sid;
	pid_t			child;
	OWPBoolean		send;
	int			sockfd;
	FILE			*datafile;
	char			*filepath;
	char			*fbuff;

	struct timespec		start;
	struct timespec		*relative_offsets;
	u_int8_t		*received_packets;
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
	char			*datadir,
	owp_tree_node_ptr	node,
	unsigned int		add_chars
	)
{
	char		*path;

	if(node){
		/* 1 is for this node's path seperator */
		path = make_data_dir(ctx,datadir,node->parent,
						strlen(node->data)+1+add_chars);
		if(!path)
			return NULL;
		strcat(path,PATH_SEPARATOR);
		strcat(path,node->data);
	}
	else{
		if((strlen(datadir)+add_chars) > FILENAME_MAX){
			OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
						"Datapath length too long.");
			return NULL;
		}
		path = malloc(strlen(datadir)+add_chars+1);
		if(!path){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"malloc problem:(%s)",strerror(errno));
			return NULL;
		}
		strcpy(path,datadir);

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
	char			*datadir,
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
	if(!(path = make_data_dir(ctx,datadir,node,33)))
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
	OWPContext		ctx = OWPGetContext(cdata->cntrl);
	_DefEndpoint		ep=EndpointAlloc(ctx);
	OWPPacketSizeT		tpsize;
	int			sbuf_size;
	int			sopt;
	socklen_t		opt_size;

	if(!ep)
		return OWPErrFATAL;

	ep->send = send;

	if(test_spec->test_type != OWPTestPoisson){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
				"Incorrect test type");
		goto error;
	}
	ep->test_spec = *test_spec;
	ep->mode = OWPGetMode(cdata->cntrl);
	ep->aeskey = OWPGetAESkeyInstance(cdata->cntrl,send);

	tpsize = OWPTestPacketSize(localaddr->saddr->sa_family,
				ep->mode,test_spec->any.packet_size_padding);
	tpsize += 128;	/* Add fuzz space for IP "options" */
	sbuf_size = tpsize;
	if((OWPPacketSizeT)sbuf_size != tpsize){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
				"Packet size overflow - invalid padding");
		goto error;
	}

	/*
	 * Create the socket.
	 */
	localaddr->fd = socket(localaddr->saddr->sa_family,localaddr->so_type,
						localaddr->so_protocol);
	if(localaddr->fd<0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"socket call failed:(%s)",strerror(errno));
		goto error;
	}

	/*
	 * bind it to the local address getting an ephemeral port number.
	 */
	if(bind(localaddr->fd,localaddr->saddr,localaddr->saddrlen) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"bind call failed:(%s)",strerror(errno));
		goto error;
	}

	/*
	 * Retrieve the ephemeral port picked by the system.
	 */
	if(getsockname(localaddr->fd,(void*)&sbuff,&sbuff_len) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
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
			OWPError(ctx,OWPErrFATAL,OWPErrUNSUPPORTED,
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
		ep->datafile = opendatafile(ctx,cdata->datadir,sid,
				cdata->node,&ep->filepath);
		if(!ep->datafile){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
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
		 * recv.
		 */
		opt_size = sizeof(sopt);
		if(getsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
					(void*)&sopt,&opt_size) < 0){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"getsockopt(RCVBUF):%s",strerror(errno));
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
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
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"getsockopt(SNDBUF):%s",strerror(errno));
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
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

/* Operations on timespecs */
#ifndef	timespecclear
#define timespecclear(tvp)      ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#endif

#ifndef	timespecisset
#define timespecisset(tvp)      ((tvp)->tv_sec || (tvp)->tv_nsec)
#endif

#ifndef	timespeccmp
#define timespeccmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
		((tvp)->tv_nsec cmp (uvp)->tv_nsec) :			\
		((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef	timespecadd
#define timespecadd(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec += (uvp)->tv_sec;				\
		(vvp)->tv_nsec += (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec >= 1000000000){			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_nsec -= 1000000000;			\
		}							\
	} while (0)
#endif

#ifndef timespecsub
#define timespecsub(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec -= (uvp)->tv_sec;				\
		(vvp)->tv_nsec -= (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_nsec += 1000000000;			\
		}							\
	} while (0)
#endif

static int	ntp_status;

static int
InitNTP()
{
	struct timex	ntp_conf;

	ntp_conf.modes = 0;

	if(ntp_adjtime(&ntp_conf) < 0)
		return 1;

	ntp_status = ntp_conf.status;
	return 0;
}


static struct timespec *
GetTimespec(
		struct timespec		*ts,
		u_int32_t		*esterr,
		int			*sync
		)
{
	struct ntptimeval	ntv;
	int		status;

	status = ntp_gettime(&ntv);

	if(status < 0)
		return NULL;
	if(status > 0)
		*sync = 0;
	else
		*sync = 1;

	*ts = ntv.time;
	*esterr = (u_int32_t)ntv.esterror;
	assert((long)*esterr == ntv.esterror);

#ifdef	STA_NANO
	if(ntp_status & STA_NANO)
		;
	else
#endif
		/*
		 * convert usec to nsec if not STA_NANO
		 */
		ts->tv_nsec *= 1000;

	return ts;
}


/*
 * Function:	run_sender
 *
 * Description:	
 * 		This function is the main processing function for a "sender"
 * 		sub-process.
 *
 * 		TODO: Figure out how to report errors reasonably -
 * 		OWPError will only work with the current apps if they
 * 		are printing to stderr...
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static void
run_sender(
		_DefEndpoint	ep
		)
{
	u_int32_t	i=0;
	struct timespec	currtime;
	struct timespec	nexttime;
	u_int32_t	esterror;
	int		sync;
	size_t		len_snd;
	ssize_t		sent;
	u_int32_t	*seq;
	u_int8_t	*snd_buffer;
	u_int8_t	*clr_buffer;
	u_int8_t	*payload;
	u_int32_t	*tstamp;
	OWPTimeStamp	owptstamp;

	len_snd = OWPTestPayloadSize(ep->mode,
				ep->test_spec.any.packet_size_padding);
	snd_buffer = malloc(len_snd);
	clr_buffer = malloc(16);	/* one block for encryption */

	if(!snd_buffer || !clr_buffer){
		OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%s",
				strerror(errno));
		exit(1);
	}

	/*
	 * Initialize pointers to various positions in the packet buffer,
	 * for data that changes for each packet. Also set zero padding.
	 */
	switch(ep->mode){
		case OWP_MODE_OPEN:
			seq = (u_int32_t*)snd_buffer;
			tstamp = (u_int32_t*)&snd_buffer[4];
			payload = &snd_buffer[12];
			break;
		case OWP_MODE_AUTHENTICATED:
			seq = (u_int32_t*)clr_buffer;
			tstamp = (u_int32_t*)&snd_buffer[16];
			payload = &snd_buffer[24];
			memset(&clr_buffer[4],0,12);
			break;
		case OWP_MODE_ENCRYPTED:
			seq = (u_int32_t*)clr_buffer;
			tstamp = (u_int32_t*)&clr_buffer[4];
			payload = &snd_buffer[16];
			memset(&clr_buffer[12],0,4);
			break;
		default:
			/*
			 * things would have failed way earlier
			 * but put default in to stop annoying
			 * compiler warnings...
			 */
			exit(1);
	}

	/*
	 * set random bits.
	 */
#ifndef	OWP_VARY_TEST_PAYLOAD
#ifdef	OWP_ZERO_TEST_PAYLOAD
	memset(payload,0,ep->test_spec.any.packet_size_padding);
#else
	I2RandomBytes(payload,ep->test_spec.any.packet_size_padding);
#endif
#endif

	do{
		/*
		 * First setup "this" packet.
		 */
#ifdef	OWP_VARY_TEST_PAYLOAD
#ifdef	OWP_ZERO_TEST_PAYLOAD
		memset(payload,0,ep->test_spec.any.packet_size_padding);
#else
		I2RandomBytes(payload,ep->test_spec.any.packet_size_padding);
#endif
#endif
		nexttime = ep->start;
		timespecadd(&nexttime,&ep->relative_offsets[i]);
		*seq = htonl(i);
		
		/*
		 * For AUTH mode, we can encrypt before fetching the timestamp.
		 */
		if(ep->mode == OWP_MODE_AUTHENTICATED)
			rijndaelEncrypt(ep->aeskey->rk,ep->aeskey->Nr,
						&clr_buffer[0],&snd_buffer[0]);

AGAIN:
		if(owp_int)
			exit(1);
		if(owp_usr2)
			exit(0);

		if(!GetTimespec(&currtime,&esterror,&sync)){
			OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
				"Problem retrieving time");
			exit(1);
		}

		if(timespeccmp(&nexttime,&currtime,<)){
			/* send-packet */

			(void)OWPCvtTimespec2Timestamp(&owptstamp,&currtime,
						       &esterror);
			OWPEncodeTimeStamp(tstamp,&owptstamp);

			/*
			 * For ENCRYPTED mode, we have to encrypt after
			 * fetching the timestamp.
			 */
			if(ep->mode == OWP_MODE_ENCRYPTED)
				rijndaelEncrypt(ep->aeskey->rk,ep->aeskey->Nr,
					&clr_buffer[0],&snd_buffer[0]);

			if( (sent = send(ep->sockfd,snd_buffer,len_snd,0)) < 0){
				if(errno == ENOBUFS)
					goto AGAIN;
				OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
						"send(#%d):%s",i,
						strerror(errno));
			}

			i++;
		}
		else{
			/*
			 * Sleep until we should send the next packet.
			 */
			struct timespec	sleeptime;

			sleeptime = nexttime;
			timespecsub(&sleeptime,&currtime);
			if((nanosleep(&sleeptime,NULL) == 0) ||
					(errno == EINTR))
				goto AGAIN;
			OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
					"nanosleep():%s",strerror(errno));
			exit(1);
		}

	} while(i<ep->test_spec.any.npackets);
}

static void
run_receiver(
		_DefEndpoint	ep
		)
{
	if(!ep)
		exit(1);
	exit(0);
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
	OWPContext		ctx = OWPGetContext(cdata->cntrl);
	_DefEndpoint		ep=(_DefEndpoint)end_data;
	struct sigaction	act;
	sigset_t		sigs,osigs;
	int			i;
	OWPnum64		InvLambda,sum,val;
	OWPrand_context64	*rand_ctx;

	/*
	 * If we are sender - get the SID. probably don't need it, but
	 * what the heck.
	 */
	if(ep->send)
		memcpy(ep->sid,sid,sizeof(OWPSID));

	if(connect(ep->sockfd,remoteaddr->saddr,remoteaddr->saddrlen) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"connect failed:%s",
				strerror(errno));
		EndpointFree(ep);
		return OWPErrFATAL;
	}

	/*
	 * Set the global signal flag vars to 0, call sigprocmask to block
	 * signals before the fork. (Ensures no race condition.) Then
	 * unblock the signals in the parent, and wait for the signals
	 * in the child using sigsuspend.
	 */
	owp_usr1 = 0;
	owp_usr2 = 0;
	owp_int = 0;
	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigemptyset(&sigs);
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
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
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
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fork failed:%s",
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
			OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,
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

	if(InitNTP() != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Unable to initialize clock interface.");
		exit(1);
	}

	if(!OWPCvtTimestamp2Timespec(&ep->start,&ep->test_spec.any.start_time)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"TStamp2TSpec conversion?");
		exit(1);
	}

	if(!(ep->relative_offsets = malloc(sizeof(struct timespec)*ep->test_spec.any.npackets))){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%s",
				strerror(errno));
		exit(1);
	}

	/*
	 * compute all relative offsets for sending/receiving packets.
	 * (This may need to move to the policy area once more advanced
	 * time distribution's are supported, so that rates etc. can
	 * be determined before passing the "policy" phase.)
	 */
	if(!(rand_ctx = OWPrand_context64_init(ep->sid))){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to init random context");
		exit(1);
	}

	/*
	 * Compute the relative offsets from the start time.
	 */
	sum = OWPulong2num64(0);
	InvLambda = OWPusec2num64(ep->test_spec.poisson.InvLambda);
	for(i=0;(unsigned)i<ep->test_spec.poisson.npackets;i++){
		val = OWPexp_rand64(rand_ctx);
		sum = OWPnum64_add(sum,val);
		val = OWPnum64_mul(sum,InvLambda);
		OWPnum64totimespec(val,&ep->relative_offsets[i]);
	}

	OWPrand_context64_free(rand_ctx);

	/*
	 * SIGUSR1 is StartSessions
	 * SIGUSR2 is StopSessions
	 * SIGINT is Terminate - making session invalid.
	 */

	/*
	 * wait until signal to kick-off session.
	 */
	sigemptyset(&sigs);
	while(!owp_usr1 && !owp_usr2 && !owp_int)
		(void)sigsuspend(&sigs);

	/*
	 * got a signal - continue.
	 */
	if(owp_int || owp_usr2){
		/* cancel the session */
		if(ep->filepath)
			unlink(ep->filepath);
		exit(1);
	}else if(owp_usr1){
		struct timespec currtime;
		u_int32_t	esterror;
		int		sync;

		/* start the session */
		act.sa_handler = SIG_DFL;
		(void)sigaction(SIGUSR1,&act,NULL);
		if(sigprocmask(SIG_SETMASK,&sigs,NULL) != 0){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to clear signal mask...");
			exit(1);
		}

		if(!GetTimespec(&currtime,&esterror,&sync)){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to fetch current time...");
			if(ep->filepath)
				unlink(ep->filepath);
			exit(1);
		}

		if(timespeccmp(&ep->start,&currtime,<))
			ep->start = currtime;

		if(ep->send)
			run_sender(ep);
		else
			run_receiver(ep);
	}

	/* should not get here. */
	OWPErrorLine(ctx,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
			"Shouldn't get to this line of code... Hmmpf.");
	exit(1);
}

OWPErrSeverity
OWPDefEndpointStart(
	void	*app_data,
	void	*end_data
	)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	_DefEndpoint		ep=(_DefEndpoint)end_data;

	if(kill(ep->child,SIGUSR1) == 0)
		return OWPErrOK;
	OWPError(OWPGetContext(cdata->cntrl),OWPErrFATAL,OWPErrUNKNOWN,
			"EndpointStart:Can't signal child #%d:%s",ep->child,
			strerror(errno));
	return OWPErrFATAL;
}

OWPErrSeverity
OWPDefEndpointStop(
	void		*app_data,
	void		*end_data,
	OWPAcceptType	aval
	)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	_DefEndpoint		ep=(_DefEndpoint)end_data;

	if(aval){
		if(kill(ep->child,SIGINT) == 0)
			return OWPErrOK;
		OWPError(OWPGetContext(cdata->cntrl),OWPErrFATAL,OWPErrUNKNOWN,
			"EndpointStart:Can't signal child #%d:%s",ep->child,
			strerror(errno));
		return OWPErrFATAL;
	}
	else{
		if(kill(ep->child,SIGUSR2) == 0)
			return OWPErrOK;
		OWPError(OWPGetContext(cdata->cntrl),OWPErrFATAL,OWPErrUNKNOWN,
			"EndpointStart:Can't signal child #%d:%s",ep->child,
			strerror(errno));
		return OWPErrFATAL;
	}
}
