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
typedef struct _EndpointRec{
	OWPContext		ctx;
	I2RandomSource		rand_src;
	OWPTestSpec		test_spec;
	OWPSessionMode		mode;
	keyInstance		*aeskey;
	u_int32_t		lossThreshold;
	struct timespec		delay;
#ifndef	NDEBUG
	I2Boolean		childwait;
#endif

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
} _EndpointRec, *_Endpoint;

static _Endpoint
EndpointAlloc(
	OWPContext	ctx
	)
{
	_Endpoint	ep = calloc(1,sizeof(_EndpointRec));

	if(!ep){
		OWPError(ctx,OWPErrFATAL,errno,"malloc(EndpointRec)");
		return NULL;
	}

	ep->test_spec.test_type = OWPTestUnspecified;
	ep->sockfd = -1;
	ep->acceptval = OWP_CNTRL_INVALID;
	ep->wopts = WNOHANG;

	return ep;
}

static void
EndpointClear(
	_Endpoint	ep
	)
{
	if(!ep)
		return;

	if(ep->sockfd > -1){
		close(ep->sockfd);
		ep->sockfd = -1;
	}
	if(ep->datafile){
		fclose(ep->datafile);
		ep->datafile = NULL;
	}
	if(ep->filepath){
		free(ep->filepath);
		ep->filepath = NULL;
	}
	if(ep->linkpath){
		free(ep->linkpath);
		ep->linkpath = NULL;
	}
	if(ep->fbuff){
		free(ep->fbuff);
		ep->fbuff = NULL;
	}
	if(ep->payload){
		free(ep->payload);
		ep->payload = NULL;
	}
	if(ep->clr_buffer){
		free(ep->clr_buffer);
		ep->clr_buffer = NULL;
	}

	if(ep->relative_offsets){
		free(ep->relative_offsets);
		ep->relative_offsets = NULL;
	}
	if(ep->received_packets){
		free(ep->received_packets);
		ep->received_packets = NULL;
	}

	return;
}

static void
EndpointFree(
	_Endpoint	ep
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
		FILE		*infp
		)
{
	int	newfd;
	FILE	*fp;

	if( (newfd = dup(fileno(infp))) < 0){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"dup(%d):%M",
							fileno(infp));
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
	_Endpoint		ep,
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
		OWPContext	ctx	__attribute__((unused))
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
_OWPEndpointInit(
	void		*app_data,
	OWPTestSession	tsession,
	OWPAddr		localaddr,
	FILE		*fp,
	void		**end_data_ret
)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	struct sockaddr_storage	sbuff;
	socklen_t		sbuff_len=sizeof(sbuff);
	OWPContext		ctx = OWPGetContext(tsession->cntrl);
	_Endpoint		ep;
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

	ep->send = (localaddr == tsession->sender);

	ep->test_spec = tsession->test_spec;
	ep->mode = OWPGetMode(tsession->cntrl);
	ep->aeskey = OWPGetAESkeyInstance(tsession->cntrl,ep->send);
	ep->lossThreshold = cdata->lossThreshold;
	ep->ctx = ctx;
	ep->rand_src = ctx->rand_src;
	OWPGetDelay(tsession->cntrl,(struct timeval*)&ep->delay);
	ep->delay.tv_nsec *= 1000;

#ifndef	NDEBUG
	ep->childwait = cdata->childwait;
#endif

	tpsize = OWPTestPacketSize(localaddr->saddr->sa_family,
			ep->mode,tsession->test_spec.any.packet_size_padding);
	tpsize += 128;	/* Add fuzz space for IP "options" */
	sbuf_size = tpsize;
	if((OWPPacketSizeT)sbuf_size != tpsize){
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
				"Packet size overflow - invalid padding");
		goto error;
	}

	if(!(ep->relative_offsets = malloc(sizeof(struct timespec) *
					tsession->test_spec.any.npackets))){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc():%M");
		goto error;
	}

	ep->len_payload = OWPTestPayloadSize(ep->mode,
				ep->test_spec.any.packet_size_padding);
	if(ep->len_payload < 20) ep->len_payload = 20;
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
	 * If we are receiver, sid is valid and we need to open file.
	 */
	if(!ep->send){
		size_t		size;

		/*
		 * Array to keep track of "seen" packets.
		 */
		if(!(ep->received_packets = calloc(sizeof(u_int8_t),
						ep->test_spec.any.npackets))){
			OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"calloc():%M");
			goto error;
		}


		if(fp)
			ep->datafile = reopen_datafile(ctx,fp);
		else
			ep->datafile = opendatafile(ctx,cdata,ep,tsession->sid);

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

	*(_Endpoint*)end_data_ret = ep;

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
		_Endpoint	ep
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
	u_int8_t	*tstamp;
	OWPTimeStamp	owptstamp;

	/*
	 * Initialize pointers to various positions in the packet buffer,
	 * for data that changes for each packet. Also set zero padding.
	 */
	switch(ep->mode){
		case OWP_MODE_OPEN:
			seq = (u_int32_t*)ep->payload;
			tstamp = &ep->payload[4];
			payload = &ep->payload[12];
			break;
		case OWP_MODE_AUTHENTICATED:
			seq = (u_int32_t*)ep->clr_buffer;
			tstamp = &ep->payload[16];
			payload = &ep->payload[24];
			memset(&ep->clr_buffer[4],0,12);
			break;
		case OWP_MODE_ENCRYPTED:
			seq = (u_int32_t*)ep->clr_buffer;
			tstamp = &ep->clr_buffer[4];
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
		_Endpoint	ep,
		struct timespec	*signal_time
		)
{
	struct timespec		currtime;
	struct timespec		last;
	struct timespec		final;
	struct timespec		expecttime;
	struct timespec		sendtime;
	struct timespec		tmptime;
	struct timespec		losstime;
	struct itimerval	wake;
	u_int32_t		seq_num;
	u_int32_t		*seq;
	u_int8_t		*tstamp;
	u_int8_t		*zero;
	int			zero_len;
	u_int32_t		esterror,lasterror=0;
	int			sync;
	size_t			lenpath;
	char			newpath[PATH_MAX];
	char			newlink[PATH_MAX];
	OWPTimeStamp		owptstamp;
	int			i;

	newpath[0] = newlink[0] = '\0';

	/*
	 * Initialize pointers to various positions in the packet buffer,
	 * for data that changes for each packet. Also set zero padding.
	 */
	seq = (u_int32_t*)ep->payload;
	switch(ep->mode){
		case OWP_MODE_OPEN:
			zero = NULL;
			zero_len = 0;
			tstamp = &ep->payload[4];
			break;
		case OWP_MODE_ENCRYPTED:
			zero = &ep->payload[12];
			zero_len = 4;
			tstamp = &ep->payload[4];
			break;
		case OWP_MODE_AUTHENTICATED:
			zero = &ep->payload[4];
			zero_len = 12;
			tstamp = &ep->payload[16];
			break;
		default:
			/*
			 * things would have failed way earlier
			 * but put default in to stop annoying
			 * compiler warnings...
			 */
			exit(OWP_CNTRL_FAILURE);
	}

	losstime.tv_sec = ep->lossThreshold;
	losstime.tv_nsec = 0;

	last = ep->relative_offsets[ep->test_spec.any.npackets-1];
	timespecadd(&last, &ep->start);

	tvalclear(&wake.it_value);
	timespecadd((struct timespec*)&wake.it_value,&last);
	timespecsub((struct timespec*)&wake.it_value,signal_time);

	/*
	 * Delay becomes a threshold value, if we ever get a delay larger
	 * than this, we need to increase our timer. Make it about one
	 * second larger than we expect to get.
	 */
	ep->delay.tv_sec++;

	timespecadd((struct timespec*)&wake.it_value,&ep->delay);
	wake.it_value.tv_usec /= 1000;	/* convert nsec to usec	*/
	/*
	 * Set the wake timer one second beyond our delay estimate threshold.
	 * One second padding should be plenty to ensure our process gets
	 * some processing time between when we estimate the last packet will
	 * arrive, and when this timer will go off.
	 */
	wake.it_value.tv_sec++;
	tvalclear(&wake.it_interval);

	/*
	 * Set timer for just past expected end of test. At that time, we
	 * can determine how much longer we should wait, if any.
	 */
	if(setitimer(ITIMER_REAL,&wake,NULL) != 0){
		OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,"setitimer():%M");
		goto error;
	}

	final = last;
	final.tv_sec += ep->lossThreshold;

	while(1){
again:
		/*
		 * ALARM indicates it is time to declare a packet
		 * lost, or if there are no remaining lost packets to
		 * deal with, the test is over.
		 */
		if(owp_alrm){
			owp_alrm = 0;

			if(!GetTimespec(&currtime,&esterror,&sync)){
				OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"Problem retrieving time");
				goto error;
			}
			/*
			 * Test is over.
			 */
			if(timespeccmp(&currtime,&final,>))
				goto test_over;

			/*
			 * Set expecttime to a relative offset from the
			 * start, indicating lossThreshold before currtime.
			 */
			expecttime = currtime;
			timespecsub(&expecttime,&ep->start);
			expecttime.tv_sec -= ep->lossThreshold;

			/*
			 * Search backwards for the "latest" missing packet.
			 * If we ever get further than lossThreshold into
			 * the past, we can terminate.
			 * Once we find the "latest" missing packet, set
			 * an alarm for when we can declare it missing
			 * and go back to recv loop until that time.
			 */
			for(i=ep->test_spec.any.npackets-1;(i>=0);i--){

				if(timespeccmp(&expecttime,
						&ep->relative_offsets[i],>)){
					goto test_over;
				}

				if(ep->received_packets[i]){

					continue;
				}

				/*
				 * Compute time when we can declare
				 * this last unaccounted for packet
				 * missing.
				 */
				expecttime = ep->relative_offsets[i];
				timespecadd(&expecttime, &ep->start);
				timespecsub(&expecttime, &currtime);
				tvalclear(&wake.it_value);
				timespecadd((struct timespec*)&wake.it_value,
								&expecttime);
				/* convert nsec to usec	*/
				wake.it_value.tv_usec /= 1000;
				wake.it_value.tv_sec += ep->lossThreshold;

				if(setitimer(ITIMER_REAL,&wake,NULL) != 0){
					OWPError(ep->ctx,OWPErrFATAL,
							OWPErrUNKNOWN,
							"setitimer():%M");
					goto error;
				}
				goto again;
			}
			goto test_over;
		}
		if(owp_int){
			goto error;
		}
		if(owp_usr2){
			goto test_over;
		}

		if(recvfrom(ep->sockfd,ep->payload,ep->len_payload,0,
				      NULL, NULL) != (ssize_t)ep->len_payload){
			if(errno == EINTR)
				goto again;
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
			/*
			 * Check zero bits to ensure valid encryption.
			 */
			for(i=0;i<zero_len;i++)
				if(zero[i])
					goto again;
		}

		seq_num = ntohl(*seq);
		if(seq_num >= ep->test_spec.any.npackets)
			goto again;

		/*
		 * Start the validity tests from Section 5.2 of the spec.
		 */

		/*
		 * Set expecttime to the time packet was expected to be sent.
		 */
		expecttime = ep->relative_offsets[seq_num];
		timespecadd(&expecttime, &ep->start);

		/*
		 * Set sendtime to the time the sender sent the packet.
		 */
		OWPDecodeTimeStamp(&owptstamp,tstamp);
		(void)OWPCvtTimestamp2Timespec(&sendtime,&owptstamp);

		/*
		 * discard if sent time is not within lossThresh of currtime.
		 */
		tmptime = sendtime;
		timespecdiff(&tmptime,&currtime);
		if(timespeccmp(&tmptime,&losstime,>))
			goto again;

		/*
		 * discard if sent time is not within lossThresh of
		 * expected sent time.
		 */
		tmptime = sendtime;
		timespecdiff(&tmptime,&expecttime);
		if(timespeccmp(&tmptime,&losstime,>))
			goto again;

		/*
		 * If recv time(currtime) is later than lossThreshold past
		 * expecttime discard.
		 */
		expecttime.tv_sec += ep->lossThreshold;
		if(timespeccmp(&currtime,&expecttime,>))
			goto again;

		/*
		 * Made it through the Section 5.2 gauntlet! Record the
		 * packet!
		 */

		ep->received_packets[seq_num] = True;

		/* write sequence number */
		if(fwrite(seq,sizeof(u_int32_t),1,ep->datafile) != 1){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
					"fwrite():%M");
			goto error;
		}
		/* write "sent" tstamp */
		if(fwrite(tstamp,sizeof(u_int8_t),8,ep->datafile) != 8){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"fwrite():%M");
			goto error;
		}

		/* encode "recv" tstamp */
		(void)OWPCvtTimespec2Timestamp(&owptstamp,&currtime,
						       &esterror,&lasterror);
		lasterror = esterror;
		owptstamp.sync = sync;
		OWPEncodeTimeStamp(ep->clr_buffer,&owptstamp);

		/* write "recv" tstamp */
		if(fwrite(ep->clr_buffer,sizeof(u_int8_t),8,ep->datafile) !=8){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"fwrite():%M");
			goto error;
		}

		/*
		 * Now, check the delay for this packet against our delaythresh
		 * estimate and increase the estimate if necessary.
		 */
		tmptime = currtime;
		timespecsub(&tmptime,&currtime);
		if(timespeccmp(&tmptime,&ep->delay,<))
			goto again;

		/*
		 * Increase our end-of-test alarm.
		 */
		ep->delay = tmptime;
		ep->delay.tv_sec++;

		tvalclear(&wake.it_value);
		timespecadd((struct timespec*)&wake.it_value,&last);
		timespecsub((struct timespec*)&wake.it_value,&currtime);
		timespecadd((struct timespec*)&wake.it_value,&ep->delay);
		/* convert nsec to usec	*/
		wake.it_value.tv_usec /= 1000;
		wake.it_value.tv_sec++;
		tvalclear(&wake.it_interval);

		if(setitimer(ITIMER_REAL,&wake,NULL) != 0){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
							"setitimer():%M");
			goto error;
		}

	}
test_over:

	/*
	 * Flush missing packets.
	 */
	/*
	 * Use payload buffer to record "missing" packets.
	 */
	memset(ep->payload,0,20);
	for(i=0;(unsigned)i<ep->test_spec.any.npackets;i++)
		if(!ep->received_packets[i]){
			/* sequence number */
			*(u_int32_t*)&ep->payload[0] = htonl(i);
			/* encode presumed sent time */
			expecttime = ep->relative_offsets[i];
			timespecadd(&expecttime, &ep->start);
			(void)OWPCvtTimespec2Timestamp(&owptstamp,&expecttime,
								NULL,NULL);
			OWPEncodeTimeStamp(&ep->payload[4],&owptstamp);

			/* write the record */
			if(fwrite(ep->payload,sizeof(u_int8_t),20,ep->datafile)
									!= 20){
				OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
						"fwrite():%M");
				goto error;
			}
		}

	/*
	 * Move file from "SID^OWP_INCOMPLETE_EXT" in-progress test to "SID".
	 */
	fclose(ep->datafile);
	ep->datafile = NULL;

	/*
	 * TODO: To comply with throwing out unresolved sessions, this
	 * should move to the StopSession function below, and if accept
	 * is non-zero, the file should be unlinked instead of renamed.
	 * (If the higher level api passed in a fd, then it should pay
	 * attention to the accept value returned from the StopSessions
	 * api call, and throw the data out as necessary.)
	 */
	if(ep->filepath){
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
			/* remove the extension from the end. */
			newlink[lenpath-strlen(OWP_INCOMPLETE_EXT)] = '\0';
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
		 * Now remove old  incomplete  files - this is done in this
		 * order to ensure no race conditions.
		 */
		if((unlink(ep->filepath) != 0) && (errno != ENOENT)){
			OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
								"unlink():%M");
			goto error;
		}
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
_OWPEndpointInitHook(
	void		*app_data	__attribute__((unused)),
	OWPTestSession	tsession,
	void		**end_data
)
{
	OWPContext		ctx = OWPGetContext(tsession->cntrl);
	_Endpoint		ep=*(_Endpoint*)end_data;
	struct sigaction	act;
	sigset_t		sigs,osigs;
	int			i;
	u_int8_t                buf[96]; /* size of Session request */
	OWPAddr			remoteaddr;

	if(ep->send){
		remoteaddr = tsession->receiver;
	}
	else{
		remoteaddr = tsession->sender;

		/*
		 * Prepare the header -
		 * this function should just take a tsession...
		 */
		if(_OWPEncodeTestRequest(tsession->cntrl->ctx,buf,
				tsession->sender->saddr,
				tsession->receiver->saddr,
				!tsession->send_local,!tsession->recv_local,
				tsession->sid,&tsession->test_spec) != 0){
			EndpointFree(ep);
			*end_data = NULL;
			return OWPErrFATAL;
		}

		if(OWPWriteDataHeader(ep->datafile,(u_int32_t)1,buf,
							sizeof(buf)-16) != 0){
			EndpointFree(ep);
			*end_data = NULL;
			return OWPErrFATAL;
		}
	}

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

	if(!OWPCvtTimestamp2Timespec(&ep->start,&ep->test_spec.any.start_time)){
		OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
					 "TStamp2TSpec conversion?");
		exit(OWP_CNTRL_FAILURE);
	}

	/*
	 * Convert relative offsets in OWPnum64 into timespec.
	 */
	assert(tsession->schedule);
	for(i=0;(unsigned)i<ep->test_spec.poisson.npackets;i++)
		OWPnum64totimespec(&ep->relative_offsets[i],
					tsession->schedule[i]);

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
_OWPEndpointStart(
	void	*app_data,
	void	**end_data
	)
{
	OWPPerConnData		cdata = (OWPPerConnData)app_data;
	_Endpoint		ep=*(_Endpoint*)end_data;

	if((ep->acceptval < 0) && ep->child && (kill(ep->child,SIGUSR1) == 0))
		return OWPErrOK;
	OWPError(cdata->ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"EndpointStart:Can't signal child #%d:%M",ep->child);
	return OWPErrFATAL;
}

OWPErrSeverity
_OWPEndpointStatus(
	void		*app_data	__attribute__((unused)),
	void		**end_data,
	OWPAcceptType	*aval		/* out */
	)
{
	_Endpoint		ep=*(_Endpoint*)end_data;
	pid_t			p;
	OWPErrSeverity		err=OWPErrOK;
	int			childstatus;

	if(ep->acceptval < 0){
AGAIN:
		p = waitpid(ep->child,&childstatus,ep->wopts);
		if(p < 0){
			if(errno == EINTR)
				goto AGAIN;
			OWPError(ep->ctx,OWPErrWARNING,
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
_OWPEndpointStop(
	void		*app_data	__attribute__((unused)),
	void		**end_data,
	OWPAcceptType	aval
	)
{
	_Endpoint		ep=*(_Endpoint*)end_data;
	int			sig;
	int			teststatus;
	OWPErrSeverity		err;

	if((ep->acceptval >= 0) || (ep->child == 0)){
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
	err = _OWPEndpointStatus(NULL,end_data,&teststatus);
	if(teststatus >= 0)
		goto done;

error:
	OWPError(ep->ctx,OWPErrFATAL,OWPErrUNKNOWN,
			"EndpointStart:Can't signal child #%d:%M",ep->child);
done:
	EndpointFree(ep);
	*end_data = NULL;

	return err;
}
