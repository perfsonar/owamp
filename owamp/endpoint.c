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
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/timex.h>

#include <owamp/access.h>
#include "owampP.h"
#include "endpoint.h"
#include "conndata.h"

/*
 * This type holds all the information needed for an endpoint to be
 * managed by these functions.
 */
typedef struct _DefEndpointRec{
	OWPContext		ctx;
	I2RandomSource		rand_src;
	OWPTestSpec		test_spec;
	OWPSessionMode		mode;
	keyInstance		*aeskey;
	u_int32_t		lossThreshold;
#ifndef	NDEBUG
	I2Boolean		childwait;
#endif

	OWPSID			sid;
	OWPAcceptType		acceptval;
	pid_t			child;
	int			wopts;
	OWPBoolean		send;
	int			sockfd;
	FILE			*datafile;
	char			*filepath;
	char			*linkpath;
	char			*fbuff;

	struct timespec		start;
	u_int8_t		*payload;
	u_int8_t		*clr_buffer;

	size_t			len_payload;
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

	memset(ep,0,sizeof(*ep));
	ep->test_spec.test_type = OWPTestUnspecified;
	ep->sockfd = -1;
	ep->acceptval = OWP_CNTRL_INVALID;
	ep->wopts = WNOHANG;

	return ep;
}

static void
EndpointClear(
	_DefEndpoint	ep
	)
{
	if(!ep)
		return;

	if(ep->filepath){
		free(ep->filepath);
		ep->filepath = NULL;
	}
	if(ep->linkpath){
		free(ep->linkpath);
		ep->linkpath = NULL;
	}
	if(ep->datafile){
		fclose(ep->datafile);
		ep->datafile = NULL;
	}
	if(ep->fbuff){
		free(ep->fbuff);
		ep->fbuff = NULL;
	}
	if(ep->sockfd > -1){
		close(ep->sockfd);
		ep->sockfd = -1;
	}
	if(ep->payload){
		free(ep->payload);
		ep->payload = NULL;
	}
	if(ep->clr_buffer){
		free(ep->clr_buffer);
		ep->clr_buffer = NULL;
	}

	return;
}

static void
EndpointFree(
	_DefEndpoint	ep
	)
{
	if(!ep)
		return;

	EndpointClear(ep);

	free(ep);

	return;
}

static FILE*
reopen_datafile(
		OWPContext	ctx,
		int		fd
		)
{
	int	newfd;
	FILE	*fp;

	if( (newfd = dup(fd)) < 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"dup(%d):%M",fd);
		return NULL;
	}

	if( !(fp = fdopen(newfd,"ab"))){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN, "fdopen(%d):%M",newfd);
		return NULL;
	}

	return fp;
}

static FILE *
opendatafile(
	OWPContext		ctx,
	OWPPerConnData		cdata,
	_DefEndpoint		ep,
	OWPSID			sid
)
{
	FILE	*fp;
	char	sid_name[(sizeof(OWPSID)*2)+1];

	OWPHexEncode(sid_name,sid,sizeof(OWPSID));

	/*
	 * Ensure real_data_dir exists.
	 */
	if((mkdir(cdata->real_data_dir,0755) != 0) && (errno != EEXIST)){
		 OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"mkdir(%s):%M",
						  cdata->real_data_dir);
		 return NULL;
	}

	if(cdata->link_data_dir){
		/*
		 * Ensure link_data_dir exists.
		 */
		if((mkdir(cdata->link_data_dir,0755) != 0) &&
							(errno != EEXIST)){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to mkdir(%s):%M",
					cdata->link_data_dir);
			return NULL;
		}

		/*
		 * Now complete the filename for the linkpath.
		 */
		if( !(ep->linkpath 
			      = (char *)malloc(strlen(cdata->link_data_dir)
				       + OWP_PATH_SEPARATOR_LEN
				       + sizeof(OWPSID)*2
				       + strlen(OWP_INCOMPLETE_EXT) + 1))) {
			OWPError(ctx,OWPErrFATAL,errno,"malloc():%M");
			return NULL;
		}

		strcpy(ep->linkpath, cdata->link_data_dir);
		strcat(ep->linkpath,OWP_PATH_SEPARATOR);
		strcat(ep->linkpath,sid_name);
		strcat(ep->linkpath, OWP_INCOMPLETE_EXT);
	}

	/*
	 * 1 for the final '\0'.
	 */
	if (!(ep->filepath = (char *)malloc(strlen(cdata->real_data_dir)
				    + OWP_PATH_SEPARATOR_LEN
				    + sizeof(OWPSID)*2
				    + strlen(OWP_INCOMPLETE_EXT) + 1))) {
		OWPError(ctx, OWPErrFATAL, errno, 
				 "FATAL: opendatafile: malloc failed");
		goto error;
	}

	strcpy(ep->filepath,cdata->real_data_dir);
	strcat(ep->filepath,OWP_PATH_SEPARATOR);
	strcat(ep->filepath,sid_name);
	strcat(ep->filepath, OWP_INCOMPLETE_EXT);	/* in-progress	*/

	fp = fopen(ep->filepath,"wb");
	if(!fp){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Unable to open datafile(%s):%M",ep->filepath);
		goto error;
	}

	if(ep->linkpath && (symlink(ep->filepath,ep->linkpath) != 0)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"symlink():%M");
		goto error;
	}

	return fp;

error:
	if(ep->linkpath){
		free(ep->linkpath);
		ep->linkpath = NULL;
	}

	if(ep->filepath){
		free(ep->filepath);
		ep->filepath = NULL;
	}

	if(fp)
		fclose(fp);

	return NULL;
}


/*
 * If STA_NANO is defined, we insist it is set, this way we can be sure that
 * ntp_gettime is returning a timespec and not a timeval.
 */
static int
InitNTP(
		OWPContext	ctx
		)
{
	struct timex	ntp_conf;

	ntp_conf.modes = 0;

	if(ntp_adjtime(&ntp_conf) < 0)
		return 1;
#ifdef	STA_NANO
	if( !(ntp_conf.status & STA_NANO)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
		"InitNTP:STA_NANO must be set! - try /usr/sbin/ntptime -N");
		return 1;
	}
#endif

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
	int			status;

	status = ntp_gettime(&ntv);

	if(status < 0)
		return NULL;
	if(status > 0)
		*sync = 0;
	else
		*sync = 1;

	*esterr = (u_int32_t)ntv.esterror;
	assert((long)*esterr == ntv.esterror);

#ifdef	STA_NANO
	*ts = ntv.time;
#else
	/*
	 * convert usec to nsec if not STA_NANO
	 */
	*(struct timeval*)ts = ntv.time;
	ts->tv_nsec *= 1000;
#endif

	return ts;
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
	OWPSID		sid,
	int		fd
)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	struct sockaddr_storage	sbuff;
	socklen_t		sbuff_len=sizeof(sbuff);
	OWPContext		ctx = OWPGetContext(cdata->cntrl);
	_DefEndpoint		ep;
	OWPPacketSizeT		tpsize;
	int			sbuf_size;
	int			sopt;
	socklen_t		opt_size;

	*end_data_ret = NULL;

	if(InitNTP(ctx) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Unable to initialize clock interface.");
		exit(OWP_CNTRL_FAILURE);
	}

	if( !(ep=EndpointAlloc(ctx)))
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
	ep->lossThreshold = cdata->lossThreshold;
	ep->ctx = ctx;
	ep->rand_src = ctx->rand_src;
#ifndef	NDEBUG
	ep->childwait = cdata->childwait;
#endif

	tpsize = OWPTestPacketSize(localaddr->saddr->sa_family,
				ep->mode,test_spec->any.packet_size_padding);
	tpsize += 128;	/* Add fuzz space for IP "options" */
	sbuf_size = tpsize;
	if((OWPPacketSizeT)sbuf_size != tpsize){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
				"Packet size overflow - invalid padding");
		goto error;
	}

	if(!(ep->relative_offsets = malloc(sizeof(struct timespec) *
						ep->test_spec.any.npackets))){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%M");
		goto error;
	}

	ep->len_payload = OWPTestPayloadSize(ep->mode,
				ep->test_spec.any.packet_size_padding);
	ep->payload = malloc(ep->len_payload);
	ep->clr_buffer = malloc(16);	/* one block - dynamic for alignment */

	if(!ep->payload || !ep->clr_buffer){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%M");
		goto error;
	}


	/*
	 * Create the socket.
	 */
	ep->sockfd = socket(localaddr->saddr->sa_family,localaddr->so_type,
						localaddr->so_protocol);
	if(ep->sockfd<0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"socket():%M");
		goto error;
	}

	/*
	 * bind it to the local address getting an ephemeral port number.
	 */
	if(bind(ep->sockfd,localaddr->saddr,localaddr->saddrlen) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"bind call failed:():%M");
		goto error;
	}

	/*
	 * Retrieve the ephemeral port picked by the system.
	 */
	memset(&sbuff,0,sizeof(sbuff));
	if(getsockname(ep->sockfd,(void*)&sbuff,&sbuff_len) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"getsockname():%M");
		goto error;
	}

	/*
	 * set saddr to the sockaddr that was actually used.
	 * (This sets the port in saddr as well.)
	 */
	assert(localaddr->saddrlen >= sbuff_len);
	memcpy(localaddr->saddr,&sbuff,sbuff_len);

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
		if(I2RandomBytes(ep->rand_src,&sid[12],4) != 0)
			goto error;

		if(fd >= 0)
			ep->datafile = reopen_datafile(ctx,fd);
		else
			ep->datafile = opendatafile(ctx,cdata,ep,sid);

		if(!ep->datafile){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to open session file:%M");
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
			size = 20;	/* buffer a single record */
		ep->fbuff = malloc(size);
		if(!ep->fbuff)
			size = 0;
		
		if(size)
			setvbuf(ep->datafile,ep->fbuff,_IOFBF,size);

		/*
		 * Write typeP as first 4-octets of file.
		 */
		if (fd < 0) {
			*(u_int32_t *)&ep->payload[0] 
				= htonl(ep->test_spec.any.typeP);
			if (fwrite(ep->payload, sizeof(u_int32_t), 1,
				   ep->datafile) != 1){
				OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					 "fwrite(1,u_int32_t):%M");
				goto error;
			}
			fflush(ep->datafile);
		}

		/*
		 * receiver - need to set the recv buffer size large
		 * enough for the packet, so we can get it in a single
		 * recv.
		 */
		opt_size = sizeof(sopt);
		if(getsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
					(void*)&sopt,&opt_size) < 0){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"getsockopt(RCVBUF):%M");
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"setsockopt(RCVBUF=%d):%M",sopt);
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
				"getsockopt(SNDBUF):%M");
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"setsockopt(RCVBUF=%d):%M",
						sopt);
				goto error;
			}
		}

	}

	*(_DefEndpoint*)end_data_ret = ep;

	return OWPErrOK;

error:
	if(ep->filepath && (unlink(ep->filepath) != 0) && (errno != ENOENT)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"unlink():%M");
	}
	if(ep->linkpath && (unlink(ep->linkpath) != 0) && (errno != ENOENT)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"unlink():%M");
	}
	EndpointFree(ep);
	return OWPErrFATAL;
}

static int owp_usr1;
static int owp_usr2;
static int owp_int;
static int owp_alrm;

/*
 * This sighandler is used to ensure SIGCHLD events are sent to this process.
 */
static void
sig_nothing(
	int	signo
	)
{
	switch(signo){
		case SIGCHLD:
			break;
		default:
			OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
				       "sig_nothing:Invalid signal(%d)",signo);
			exit(OWP_CNTRL_FAILURE);
	}
	return;
}

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
		case SIGALRM:
			owp_alrm = 1;
			break;
		default:
			OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
					"sig_catch:Invalid signal(%d)",signo);
			exit(OWP_CNTRL_FAILURE);
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

/*
 * Function:	run_sender
 *
 * Description:	
 * 		This function is the main processing function for a "sender"
 * 		sub-process.
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
	struct timespec	sleeptime;
	u_int32_t	esterror;
	u_int32_t	lasterror=0;
	int		sync;
	ssize_t		sent;
	u_int32_t	*seq;
	u_int8_t	*clr_buffer;
	u_int8_t	*payload;
	u_int32_t	*tstamp;
	OWPTimeStamp	owptstamp;

	/*
	 * Initialize pointers to various positions in the packet buffer,
	 * for data that changes for each packet. Also set zero padding.
	 */
	switch(ep->mode){
		case OWP_MODE_OPEN:
			seq = (u_int32_t*)ep->payload;
			tstamp = (u_int32_t*)&ep->payload[4];
			payload = &ep->payload[12];
			break;
		case OWP_MODE_AUTHENTICATED:
			seq = (u_int32_t*)ep->clr_buffer;
			tstamp = (u_int32_t*)&ep->payload[16];
			payload = &ep->payload[24];
			memset(&ep->clr_buffer[4],0,12);
			break;
		case OWP_MODE_ENCRYPTED:
			seq = (u_int32_t*)ep->clr_buffer;
			tstamp = (u_int32_t*)&ep->clr_buffer[4];
			payload = &ep->payload[16];
			memset(&ep->clr_buffer[12],0,4);
			break;
		default:
			/*
			 * things would have failed way earlier
			 * but put default in to stop annoying
			 * compiler warnings...
			 */
			exit(OWP_CNTRL_FAILURE);
	}

	/*
	 * set random bits.
	 */
#if	defined(OWP_ZERO_TEST_PAYLOAD)
	memset(payload,0,ep->test_spec.any.packet_size_padding);
#elif	!defined(OWP_VARY_TEST_PAYLOAD)
	/*
	 * Ignore errors here - it isn't that critical that it be random.
	 * (just trying to defeat modem compression and the like.)
	 */
	(void)I2RandomBytes(ep->rand_src,payload,
			    ep->test_spec.any.packet_size_padding);
#endif

	do{
		/*
		 * First setup "this" packet.
		 */
#if	defined(OWP_VARY_TEST_PAYLOAD) && !defined(OWP_ZERO_TEST_PAYLOAD)
		(void)I2RandomBytes(ep->rand_src,payload,
				    ep->test_spec.any.packet_size_padding);
#endif
		nexttime = ep->start;
		timespecadd(&nexttime,&ep->relative_offsets[i]);
		*seq = htonl(i);
		
		/*
		 * For AUTH mode, we can encrypt before fetching the timestamp.
		 */
		if(ep->mode == OWP_MODE_AUTHENTICATED)
			rijndaelEncrypt(ep->aeskey->rk,ep->aeskey->Nr,
					       &clr_buffer[0],&ep->payload[0]);

AGAIN:
		if(owp_int)
			exit(OWP_CNTRL_FAILURE);
		if(owp_usr2)
			exit(OWP_CNTRL_ACCEPT);

		if(!GetTimespec(&currtime,&esterror,&sync)){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Problem retrieving time");
			exit(OWP_CNTRL_FAILURE);
		}

		if(timespeccmp(&nexttime,&currtime,<)){
			/* send-packet */

			(void)OWPCvtTimespec2Timestamp(&owptstamp,&currtime,
						       &esterror,&lasterror);
			lasterror = esterror;
			owptstamp.sync = sync;
			OWPEncodeTimeStamp(tstamp,&owptstamp);

			/*
			 * For ENCRYPTED mode, we have to encrypt after
			 * fetching the timestamp.
			 */
			if(ep->mode == OWP_MODE_ENCRYPTED)
				rijndaelEncrypt(ep->aeskey->rk,ep->aeskey->Nr,
					&clr_buffer[0],&ep->payload[0]);

			if( (sent = send(ep->sockfd,ep->payload,
						ep->len_payload,0)) < 0){
				switch(errno){
					/* retry errors */
					case ENOBUFS:
						goto AGAIN;
						break;
					/* fatal errors */
					case EBADF:
					case EACCES:
					case ENOTSOCK:
					case EFAULT:
					case EAGAIN:
						OWPError(ep->ctx,OWPErrFATAL,
							OWPErrUNKNOWN,
							"send(%d,#%d):%M",
							ep->sockfd,i);
						exit(OWP_CNTRL_FAILURE);
						break;
					/* ignore everything else */
					default:
						break;
				}

				/* but do note it as INFO for debugging */
				OWPError(ep->ctx,OWPErrINFO,OWPErrUNKNOWN,
					       "send(%d,#%d):%M",ep->sockfd,i);
			}

			i++;
		}
		else{
			/*
			 * Sleep until we should send the next packet.
			 */

			sleeptime = nexttime;
			timespecsub(&sleeptime,&currtime);
			if((nanosleep(&sleeptime,NULL) == 0) ||
							(errno == EINTR)){
				goto AGAIN;
			}
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"nanosleep(%u.%u,nil):%M",
					sleeptime.tv_sec,sleeptime.tv_nsec);
			exit(OWP_CNTRL_FAILURE);
		}

	} while(i<ep->test_spec.any.npackets);

	/*
	 * Wait until lossthresh after last packet or
	 * for a signal to exit.
	 */
	nexttime = ep->start;
	timespecadd(&nexttime,
			&ep->relative_offsets[ep->test_spec.any.npackets-1]);
	nexttime.tv_sec += ep->lossThreshold;

	while(!owp_usr2 && !owp_int){
		if(!GetTimespec(&currtime,&esterror,&sync)){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Problem retrieving time");
			exit(OWP_CNTRL_FAILURE);
		}

		if(timespeccmp(&nexttime,&currtime,<))
			break;

		sleeptime = nexttime;
		timespecsub(&sleeptime,&currtime);
		if(nanosleep(&sleeptime,NULL) == 0)
			break;
		if(errno != EINTR){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"nanosleep():%M");
			exit(OWP_CNTRL_FAILURE);
		}
	}

	exit(OWP_CNTRL_ACCEPT);
}

static void
run_receiver(
		_DefEndpoint	ep,
		struct timespec	*signal_time
		)
{
	struct timespec	currtime;
	struct timespec	lasttime;
	struct timespec	expecttime;
	u_int32_t	seq_num;
	u_int32_t	*seq;
	u_int32_t	*tstamp;
	u_int32_t	esterror,lasterror=0;
	int		sync;
	size_t		lenpath;
	char		newpath[PATH_MAX];
	char		newlink[PATH_MAX];

	newpath[0] = newlink[0] = '\0';

	/*
	 * Initialize pointers to various positions in the packet buffer,
	 * for data that changes for each packet. Also set zero padding.
	 */
	seq = (u_int32_t*)ep->payload;
	switch(ep->mode){
		case OWP_MODE_OPEN:
		case OWP_MODE_ENCRYPTED:
			tstamp = (u_int32_t*)&ep->payload[4];
			break;
		case OWP_MODE_AUTHENTICATED:
			tstamp = (u_int32_t*)&ep->payload[16];
			break;
		default:
			/*
			 * things would have failed way earlier
			 * but put default in to stop annoying
			 * compiler warnings...
			 */
			exit(OWP_CNTRL_FAILURE);
	}
	lasttime = ep->relative_offsets[ep->test_spec.any.npackets-1];
	timespecadd(&lasttime, &ep->start);
	timespecsub(&lasttime, signal_time);
	lasttime.tv_sec += ep->lossThreshold;
	lasttime.tv_sec++;

	alarm(lasttime.tv_sec);

	/*
	 * TODO: setitimer/alarm for lasttime, w/sighandler to modify sigalrm.
	 */

	while(1){
		if(owp_int){
			goto error;
		}
		if(owp_alrm || owp_usr2){
			break;
		}

		if(recvfrom(ep->sockfd,ep->payload,ep->len_payload,0,
				      NULL, NULL) != (ssize_t)ep->len_payload){
			if(errno == EINTR)
				continue;
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
							"recvfrom():%M");
			goto error;
		}

		if(!GetTimespec(&currtime,&esterror,&sync)){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"Problem retrieving time");
			goto error;
		}

		if(ep->mode & _OWP_DO_CIPHER){
			rijndaelDecrypt(ep->aeskey->rk,ep->aeskey->Nr,
					&ep->payload[0],&ep->payload[0]);
			/* TODO:validate zero bits? */
		}

		seq_num = ntohl(*seq);
		if(seq_num >= ep->test_spec.any.npackets)
			continue;

		expecttime = ep->relative_offsets[seq_num];
		timespecadd(&expecttime, &ep->start);
		expecttime.tv_sec += ep->lossThreshold;

		if(timespeccmp(&currtime,&expecttime,<)){
			OWPTimeStamp	owptstamp;

			/* write sequence number */
			if(fwrite(seq,sizeof(u_int32_t),1,ep->datafile) != 1){
				OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"fwrite():%M");
				goto error;
			}
			/* write "sent" tstamp */
			if(fwrite(tstamp,sizeof(u_int32_t),2,ep->datafile)
									!= 2){
				OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"fwrite():%M");
				goto error;
			}

			/* encode "recv" tstamp */
			(void)OWPCvtTimespec2Timestamp(&owptstamp,&currtime,
						       &esterror,&lasterror);
			lasterror = esterror;
			owptstamp.sync = sync;
			OWPEncodeTimeStamp((u_int32_t*)ep->clr_buffer,
								&owptstamp);

			/* write "recv" tstamp */
			if(fwrite(ep->clr_buffer,sizeof(u_int32_t),2,
						ep->datafile) != 2){
				OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"fwrite():%M");
				goto error;
			}

			/*
			 * TODO:
			 * If we want to short-cut the recvier to try and
			 * detect a completed session before last+lossThresh.
			 * We would need to try and detect the "completion"
			 * here - and would probably have to update some kind
			 * of data structure if it is not complete...
			 * Is it worth it?
			 */
		}
	}

	/*
	 * TODO: Should SIGUSR2 - early termination rename the file? Should
	 * the session be thought of as complete?
	 * It currently does/is.
	 */

	/*
	 * Move file from "SID^OWP_INCOMPLETE_EXT" in-progress test to "SID".
	 */
	fclose(ep->datafile);
	ep->datafile = NULL;

	/*
	 * First create new link for SID in "nodes" hierarchy.
	 */
	lenpath = strlen(ep->filepath);
	strcpy(newpath,ep->filepath);
	newpath[lenpath-strlen(OWP_INCOMPLETE_EXT)] = '\0'; /* remove the 
						     extension from the end. */
	if(link(ep->filepath,newpath) != 0){
		OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"link():%M");
		goto error;
	}

	if(ep->linkpath){
		/*
		 * Now add symlink in "sessions" for new SID file.
		 */
		lenpath = strlen(ep->linkpath);
		strcpy(newlink,ep->linkpath);
		newlink[lenpath-strlen(OWP_INCOMPLETE_EXT)] = '\0'; /* remove the 
						    extension from the end. */
		if(symlink(newpath,newlink) != 0){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
				"symlink():%M");
			goto error;
		}

		if((unlink(ep->linkpath) != 0) && (errno != ENOENT)){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"unlink():%M");
			goto error;
		}
	}

	/*
	 * Now remove old  incomplete  files - this is done in this order 
	 * to ensure no race conditions.
	 */
	if((unlink(ep->filepath) != 0) && (errno != ENOENT)){
		OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,"unlink():%M");
		goto error;
	}

	exit(OWP_CNTRL_ACCEPT);

error:
	/*
	 * unlink file - error.
	 */
	if(ep->datafile)
		fclose(ep->datafile);
	if(newlink[0] != '\0')
		unlink(newlink);
	if(newpath[0] != '\0')
		unlink(newpath);
	if(ep->linkpath)
		unlink(ep->linkpath);
	if(ep->filepath)
		unlink(ep->filepath);
	exit(OWP_CNTRL_FAILURE);
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
	void		**end_data,
	OWPAddr		remoteaddr,
	OWPSID		sid
)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	OWPContext		ctx = OWPGetContext(cdata->cntrl);
	_DefEndpoint		ep=*(_DefEndpoint*)end_data;
	struct sigaction	act;
	sigset_t		sigs,osigs;
	int			i;
	OWPnum64		InvLambda,sum,val;
	OWPrand_context64	*rand_ctx;

	memcpy(ep->sid,sid,sizeof(OWPSID));

	if(connect(ep->sockfd,remoteaddr->saddr,remoteaddr->saddrlen) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"connect():%M");
		EndpointFree(ep);
		*end_data = NULL;
		return OWPErrFATAL;
	}

	/*
	 * call sigprocmask to block signals before the fork.
	 * (This ensures no race condition.)
	 * Then unblock the signals in the parent.
	 * Child sets new sig_handlers and waits for the signals
	 * in the child using sigsuspend.
	 */
	sigemptyset(&sigs);
	sigaddset(&sigs,SIGUSR1);
	sigaddset(&sigs,SIGUSR2);
	sigaddset(&sigs,SIGINT);
	sigaddset(&sigs,SIGALRM);
	
	if(sigprocmask(SIG_BLOCK,&sigs,&osigs) != 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"sigprocmask():%M");
		EndpointFree(ep);
		*end_data = NULL;
		return OWPErrFATAL;
	}

	ep->child = fork();

	if(ep->child < 0){
		/* fork error */
		(void)sigprocmask(SIG_SETMASK,&osigs,NULL);
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fork():%M");
		EndpointFree(ep);
		*end_data = NULL;
		return OWPErrFATAL;
	}

	if(ep->child > 0){
		/* parent */

		struct sigaction	chldact;
	
		/*
		 * If there is currently no SIGCHLD handler:
		 * setup an empty CHLD handler to ensure SIGCHLD is sent
		 * to this process. (Just need the signal sent to break
		 * us out of "select" with an EINTR when we trying to
		 * determine if test sessions are complete.)
		 */
		sigemptyset(&chldact.sa_mask);
		chldact.sa_handler = SIG_DFL;
		chldact.sa_flags = 0;
		/* fetch current handler */
		if(sigaction(SIGCHLD,NULL,&chldact) != 0){
			OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,
				"sigaction():%M");
			return OWPErrWARNING;
		}
		/* if there is currently no handler - set one. */
		if(chldact.sa_handler == SIG_DFL){
			chldact.sa_handler = sig_nothing;
			if(sigaction(SIGCHLD,&chldact,NULL) != 0){
				OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,
					"sigaction(DFL) failed:%M");
				return OWPErrWARNING;
			}
		}
		/* now make sure SIGCHLD won't be masked. */
		sigdelset(&osigs,SIGCHLD);

		/* reset sig_mask to the old one (-SIGCHLD)	*/
		if(sigprocmask(SIG_SETMASK,&osigs,NULL) != 0){
			OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,
				"sigprocmask():%M");
			return OWPErrWARNING;
		}

		EndpointClear(ep);
		return OWPErrOK;
	}

	/*
	 * We are now in the child send/recv process.
	 */

	/*
	 * busy loop for systems where debugger doesn't support
	 * child follow_fork mode functionality...
	 */
#ifndef	NDEBUG
	{
		int	waitfor=ep->childwait;

		while(waitfor);
	}
#endif

	/*
	 * set the sig handlers for the currently blocked signals.
	 */
	owp_usr1 = 0;
	owp_usr2 = 0;
	owp_int = 0;
	owp_alrm = 0;
	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if(		(sigaction(SIGUSR1,&act,NULL) != 0) ||
			(sigaction(SIGUSR2,&act,NULL) != 0) ||
			(sigaction(SIGINT,&act,NULL) != 0) ||
			(sigaction(SIGALRM,&act,NULL) != 0)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"sigaction():%M");
		exit(OWP_CNTRL_FAILURE);
	}

	if(!OWPCvtTimestamp2Timespec(&ep->start,&ep->test_spec.any.start_time))
		{
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
				 "TStamp2TSpec conversion?");
			exit(OWP_CNTRL_FAILURE);
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
		exit(OWP_CNTRL_FAILURE);
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
		exit(OWP_CNTRL_REJECT);
	}else if(owp_usr1){
		/* start the session */
		struct timespec currtime;
		u_int32_t	esterror;
		int		sync;

		/* clear the sig mask so all sigs come through */
		if(sigprocmask(SIG_SETMASK,&sigs,NULL) != 0){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"sigprocmask():%M");
			exit(OWP_CNTRL_FAILURE);
		}

		if(!GetTimespec(&currtime,&esterror,&sync)){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Unable to fetch current time...");
			if(ep->filepath)
				unlink(ep->filepath);
			exit(OWP_CNTRL_FAILURE);
		}

		if(timespeccmp(&ep->start,&currtime,<))
			ep->start = currtime;

		if(ep->send){
			run_sender(ep);
		}
		else{
			run_receiver(ep,&currtime);
		}
	}

	/* should not get here. */
	OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"Shouldn't get to this line of code... Hmmpf.");
	exit(OWP_CNTRL_FAILURE);
}

OWPErrSeverity
OWPDefEndpointStart(
	void	*app_data,
	void	**end_data
	)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	_DefEndpoint		ep=*(_DefEndpoint*)end_data;

	if((ep->acceptval < 0) && ep->child && (kill(ep->child,SIGUSR1) == 0))
		return OWPErrOK;
	OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"EndpointStart:Can't signal child #%d:%M",ep->child);
	return OWPErrFATAL;
}

OWPErrSeverity
OWPDefEndpointStatus(
	void		*app_data,
	void		**end_data,
	OWPAcceptType	*aval		/* out */
	)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	_DefEndpoint		ep=*(_DefEndpoint*)end_data;
	pid_t			p;
	OWPErrSeverity		err=OWPErrOK;
	int			childstatus;

	if(ep->acceptval < 0){
AGAIN:
		p = waitpid(ep->child,&childstatus,ep->wopts);
		if(p < 0){
			if(errno == EINTR)
				goto AGAIN;
			OWPError(OWPGetContext(cdata->cntrl),OWPErrWARNING,
				OWPErrUNKNOWN,
				"EndpointStart:Can't query child #%d:%M",
				ep->child);
			ep->acceptval = OWP_CNTRL_FAILURE;
			err = OWPErrWARNING;
		}
		else if(p > 0)
		       ep->acceptval = (OWPAcceptType)WEXITSTATUS(childstatus);
	}

	*aval = ep->acceptval;
	return err;
}


OWPErrSeverity
OWPDefEndpointStop(
	void		*app_data,
	void		**end_data,
	OWPAcceptType	aval
	)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	_DefEndpoint		ep=*(_DefEndpoint*)end_data;
	int			sig;
	int			teststatus;
	OWPErrSeverity		err;

	if(ep->acceptval >= 0){
		err = OWPErrOK;
		goto done;
	}

	if(aval)
		sig = SIGINT;
	else
		sig = SIGUSR2;

	if(kill(ep->child,sig) != 0)
		goto error;

	ep->wopts &= ~WNOHANG;
	err = OWPDefEndpointStatus(app_data,end_data,&teststatus);
	if(teststatus >= 0)
		goto done;

error:
	OWPError(OWPGetContext(cdata->cntrl),OWPErrFATAL,OWPErrUNKNOWN,
			"EndpointStart:Can't signal child #%d:%M",ep->child);
done:
	EndpointFree(ep);
	*end_data = NULL;

	return err;
}
