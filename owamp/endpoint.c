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
#include "owampP.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>


/*
 * Function:	EndpointAlloc
 *
 * Description:	
 * 	Allocate a record to keep track of the state information for
 * 	this endpoint. (Much of this state is also in the control record
 * 	and the TestSession record... May simplify this in the future
 * 	to just reference the other records.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static OWPEndpoint
EndpointAlloc(
        OWPControl	cntrl
        )
{
    OWPEndpoint	ep = calloc(1,sizeof(OWPEndpointRec));

    if(!ep){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,"malloc(EndpointRec)");
        return NULL;
    }

    ep->cntrl = cntrl;
    ep->sockfd = -1;
    ep->skiprecfd = -1;
    ep->acceptval = OWP_CNTRL_INVALID;
    ep->wopts = WNOHANG;

    return ep;
}

static void
LostFree(
        OWPLostPacket   lost
        )
{
    OWPLostPacket   lt;

    while(lost){
        lt = lost->next;
        free(lost);
        lost = lt;
    }

    return;
}

static void
SkipFree(
        OWPSkip skip
        )
{
    OWPSkip st;

    while(skip){
        st = skip->next;
        free(skip);
        skip=st;
    }

    return;
}

/*
 * Function:	EndpointClear
 *
 * Description:	
 * 	Clear out any resources that are used in the Endpoint record
 * 	that are not needed in the parent process after the endpoint
 * 	forks off to do the actual test.
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
EndpointClear(
        OWPEndpoint	ep
        )
{
    if(!ep)
        return;

    if(ep->sockfd > -1){
        close(ep->sockfd);
        ep->sockfd = -1;
    }

    if(ep->payload){
        free(ep->payload);
        ep->payload = NULL;
    }

    LostFree(ep->lost_allocated);
    ep->lost_allocated = NULL;
    SkipFree(ep->skip_allocated);
    ep->skip_allocated = NULL;

    return;
}

/*
 * Function:	EndpointFree
 *
 * Description:	
 * 	completely free all resoruces associated with an endpoint record.
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
EndpointFree(
        OWPEndpoint	ep,
        OWPAcceptType	aval
        )
{
    if(!ep)
        return;

    EndpointClear(ep);

    if(ep->skiprecfd > -1){
        close(ep->skiprecfd);
        ep->skiprecfd = -1;
    }
    if(ep->datafile){
        fclose(ep->datafile);
        ep->datafile = NULL;
    }
    if(ep->fbuff){
        free(ep->fbuff);
        ep->fbuff = NULL;
    }

    if(ep->userfile){
        _OWPCallCloseFile(ep->cntrl,ep->tsession->closure,ep->userfile,
                aval);
        ep->userfile = NULL;
    }

    free(ep);

    return;
}

/*
 * Function:	reopen_datafile
 *
 * Description:	
 * 	This function takes a fp and creates a new fp to the same file
 * 	record. This is used to ensure that the fp used for the actual
 * 	test is buffered properly. And - allows the test to write to the
 * 	same file without modifying a fp passed in by an application.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static FILE*
reopen_datafile(
        OWPContext	ctx,
        FILE		*infp
        )
{
    int	newfd;
    FILE	*fp;

    if( (newfd = dup(fileno(infp))) < 0){
        OWPError(ctx,OWPErrFATAL,errno,"dup(%d): %M",
                fileno(infp));
        return NULL;
    }

    if( !(fp = fdopen(newfd,"r+b"))){
        OWPError(ctx,OWPErrFATAL,errno, "fdopen(%d): %M",newfd);
        return NULL;
    }

    return fp;
}

/*
 * Function:	CmpLostPacket
 *
 * Description:	
 * 	Used to compare the 64 bit keys for the OWPLostPacket records.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static int
CmpLostPacket(
        I2Datum	x,
        I2Datum	y
        )
{
    u_int64_t	*xn = (u_int64_t*)x.dptr;
    u_int64_t	*yn = (u_int64_t*)y.dptr;

    return !(*xn == *yn);
}

/*
 * Function:	HashLostPacket
 *
 * Description:	
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
u_int32_t
HashLostPacket(
        I2Datum	k
        )
{
    u_int64_t	*kn = (u_int64_t*)k.dptr;

    return *kn & 0xFFFFFFFFUL;
}

/*
 * The endpoint init function is responsible for opening a socket, and
 * allocating a local port number.
 * If this is a recv endpoint, it is also responsible for allocating a
 * session id.
 */
OWPBoolean
_OWPEndpointInit(
        OWPControl	cntrl,
        OWPTestSession	tsession,
        OWPAddr		localaddr,
        FILE		*fp,
        OWPAcceptType   *aval,
        OWPErrSeverity	*err_ret
        )
{
    struct sockaddr_storage sbuff;
    socklen_t		    sbuff_len=sizeof(sbuff);
    OWPEndpoint		    ep;
    OWPPacketSizeT          tpsize;
    int			    sbuf_size;
    int			    sopt;
    socklen_t		    opt_size;
    u_int64_t		    i;
    OWPTimeStamp            tstamp;
    u_int16_t		    port=0;
    u_int16_t		    p;
    u_int16_t		    range;
    OWPPortRange            portrange=NULL;
    int			    saveerr=0;
    int			    rc=0;

    *err_ret = OWPErrFATAL;
    *aval = OWP_CNTRL_UNAVAILABLE_TEMP;

    if( !(ep=EndpointAlloc(cntrl)))
        return False;

    ep->send = (localaddr == tsession->sender);

    ep->tsession = tsession;
    ep->cntrl = cntrl;

    tpsize = OWPTestPacketSize(localaddr->saddr->sa_family,
            ep->cntrl->mode,tsession->test_spec.packet_size_padding);
    tpsize += 128;	/* Add fuzz space for IP "options" */
    sbuf_size = tpsize;
    if((OWPPacketSizeT)sbuf_size != tpsize){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Packet size overflow - invalid padding");
        *aval = OWP_CNTRL_FAILURE;
        goto error;
    }

    ep->len_payload = OWPTestPayloadSize(ep->cntrl->mode,
            ep->tsession->test_spec.packet_size_padding);
    if(ep->len_payload < _OWP_DATAREC_SIZE){
        ep->len_payload = _OWP_DATAREC_SIZE;
    }
    ep->payload = malloc(ep->len_payload);

    if(!ep->payload){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc(): %M");
        goto error;
    }

    tstamp.owptime = ep->tsession->test_spec.start_time;
    (void)OWPTimestampToTimespec(&ep->start,&tstamp);

    /*
     * Create the socket.
     */
    ep->sockfd = socket(localaddr->saddr->sa_family,localaddr->so_type,
            localaddr->so_protocol);
    if(ep->sockfd<0){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,"socket(): %M");
        goto error;
    }

    /*
     * Determine what port to try:
     */

    /* first - see if saddr specifs a port directly... */
    switch(localaddr->saddr->sa_family){
        struct sockaddr_in	*s4;
#ifdef	AF_INET6
        struct sockaddr_in6	*s6;

        case AF_INET6:
        s6 = (struct sockaddr_in6*)localaddr->saddr;
        port = ntohs(s6->sin6_port);
        break;
#endif
        case AF_INET:
        s4 = (struct sockaddr_in*)localaddr->saddr;
        port = ntohs(s4->sin_port);
        break;
        default:
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid address family for test");
        *aval = OWP_CNTRL_UNSUPPORTED;
        goto error;
    }


    if(port){
        /*
         * port specified by saddr
         */
        p = port;
    }
    else if(!(portrange = (OWPPortRange)OWPContextConfigGet(cntrl->ctx,
                    OWPTestPortRange))){
        p = port = 0;
    }else{
        u_int32_t	r;

        /*
         * Get a random 32 bit number to aid in selecting first
         * port to try.
         */
        if(I2RandomBytes(cntrl->ctx->rand_src,(u_int8_t*)&r,4) != 0)
            goto error;

        if(portrange->high < portrange->low){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid port range specified");
            *aval = OWP_CNTRL_FAILURE;
            goto error;
        }

        range = portrange->high - portrange->low;
        p = port = portrange->low + ((double)r / 0xffffffff * range);
    }

    do{
        /* Specify the port number */
        switch(localaddr->saddr->sa_family){
            struct sockaddr_in	*s4;
#ifdef	AF_INET6
            struct sockaddr_in6	*s6;

            case AF_INET6:
            s6 = (struct sockaddr_in6*)localaddr->saddr;
            s6->sin6_port = htons(p);
            break;
#endif
            case AF_INET:
            s4 = (struct sockaddr_in*)localaddr->saddr;
            s4->sin_port = htons(p);
            break;
            default:
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid address family for test");
            *aval = OWP_CNTRL_UNSUPPORTED;
            goto error;
        }

        /*
         * Try binding.
         */
        if(bind(ep->sockfd,localaddr->saddr,localaddr->saddrlen) == 0)
            goto success;
        /*
         * If it failed, and we are not using a "range" then exit
         * loop and report failure. (Or if the error is not EADDRINUSE
         * this is a permenent failure.)
         */
        if(!portrange || (errno != EADDRINUSE)){
            *aval = OWP_CNTRL_FAILURE;
            goto bind_fail;
        }

        /*
         * compute next port to try.
         */
        if(range){
            p -= portrange->low;
            p = (p + 1) % range;
            p += portrange->low;
        }
    } while(p != port);

    saveerr = errno;
    OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "Full port range exhausted");
bind_fail:
    if(!saveerr) saveerr = errno;
    OWPError(cntrl->ctx,OWPErrFATAL,saveerr,
            "bind([%s]:%d): %M",localaddr->node,p);
    goto error;

success:

    /*
     * Retrieve the saddr as defined by the system.
     */
    memset(&sbuff,0,sizeof(sbuff));
    if(getsockname(ep->sockfd,(void*)&sbuff,&sbuff_len) != 0){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "getsockname(): %M");
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
        OWPLostPacket	alist;

        /*
         * pre-allocate nodes for lost_packet buffer.
         * (estimate number of nodes needed to hold enough
         * packets for 2*Loss-timeout)
         * TODO: determine a reasonable number instead of (2).
         * (2 is just a guess... exp distribution probably
         * converges to 0 fast enough that we could get away
         * with a much smaller number... say 1.2)
         *
         * It is possible that the actual distribution will make
         * it necessary to hold more than this many nodes in the
         * buffer - but it is highly unlikely. If that happens,
         * another dynamic allocation will happen. This should
         * at least minimize the dynamic allocations during the
         * test.
         */
#define PACKBUFFALLOCFACTOR	2

        ep->freelist=NULL;
        ep->numalist = OWPTestPacketRate(cntrl->ctx,
                &tsession->test_spec) *
            OWPNum64ToDouble(
                    tsession->test_spec.loss_timeout) *
            PACKBUFFALLOCFACTOR;
        ep->numalist = MAX(ep->numalist,100);

        if(!(alist = calloc(sizeof(OWPLostPacketRec),ep->numalist))){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"calloc(): %M");
            goto error;
        }

        /*
         * [0] is used to track the list of allocated arrays so they
         * can be freed.
         */
        ep->lost_allocated = alist;
        for(i=1;i<ep->numalist;i++){
            alist[i].next = ep->freelist;
            ep->freelist = &alist[i];
        }

        if(!(ep->lost_packet_buffer = I2HashInit(cntrl->ctx->eh,
                        ep->numalist*PACKBUFFALLOCFACTOR,
                        CmpLostPacket,HashLostPacket))){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPEndpointInit: Unable to initialize lost packet buffer");
            goto error;
        }

        ep->fname[0] = '\0';
        if(!fp){
            ep->userfile = fp = _OWPCallOpenFile(cntrl,
                    tsession->closure,
                    tsession->sid,
                    ep->fname);
        }

        if(!fp){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to open session file(%s): %M",
                    ep->fname);
            goto error;
        }

        /*
         * This function dup's the fd/fp so that any seeks on
         * the fd in the parent do not effect the child reference.
         * (It also ensures that no file i/o have happened on the
         * ep->datafile which makes it much more likely that the
         * call to setvbuf will work...)
         */
        if( !(ep->datafile = reopen_datafile(cntrl->ctx,fp))){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to re-open session file(%s): %M",
                    ep->fname);
            goto error;
        }

        /*
         * Determine "optimal" file buffer size. To allow "Fetch"
         * clients to access ongoing tests - we define "optimal" as
         * approximately 1 second of buffering.
         */

        /*
         * Determine data rate. i.e. size/second.
         */
        size = OWPTestPacketRate(cntrl->ctx,&ep->tsession->test_spec) *
            _OWP_DATAREC_SIZE;

        if(size < _OWP_DATAREC_SIZE){
            /* If rate is less than one packet/second then unbuffered */
            setvbuf(ep->datafile,NULL,_IONBF,0);
        }
        else{
            struct stat	statbuf;

            /* stat to find out st_blksize */
            if(fstat(fileno(ep->datafile),&statbuf) != 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "fstat(): %M");
                goto error;
            }

            /*
             * Don't make buffer larger than "default"
             */
            size = MIN(size,(size_t)statbuf.st_blksize);


            if( !(ep->fbuff = malloc(size))){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,"malloc(): %M");
                goto error;
            }
            setvbuf(ep->datafile,ep->fbuff,_IOFBF,size);
        }

        /*
         * receiver - need to set the recv buffer size large
         * enough for the packet, so we can get it in a single
         * recv.
         */
        opt_size = sizeof(sopt);
        if(getsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
                    (void*)&sopt,&opt_size) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "getsockopt(RCVBUF): %M");
            goto error;
        }

        if(sopt < sbuf_size){
            sopt = sbuf_size;
            if(setsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
                        (void*)&sopt,sizeof(sopt)) < 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setsockopt(RCVBUF=%d): %M",sopt);
                goto error;
            }
        }

        /*
         * draft-ietf-ippm-owdp-08.txt adds TTL to the data that
         * is stored by the receiver. Use IP_RECVTTL to indicate
         * interest in receiving TTL ancillary data.
         * TODO: Determine correct sockopt for IPV6!
         */
        switch(localaddr->saddr->sa_family){
#ifdef	AF_INET6
            case AF_INET6:
#ifdef IPV6_RECVHOPLIMIT
                sopt = 1;
                if(setsockopt(ep->sockfd,IPPROTO_IPV6,
                            IPV6_RECVHOPLIMIT,
                            (void*)&sopt,sizeof(sopt)) < 0){
                    OWPError(cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "setsockopt(IPV6_RECVHOPLIMIT=1): %M");
                    goto error;
                }
#endif
                break;
#endif
            case AF_INET:
#ifdef IP_RECVTTL
                sopt = 1;
                if(setsockopt(ep->sockfd,IPPROTO_IP,IP_RECVTTL,
                            (void*)&sopt,sizeof(sopt)) < 0){
                    OWPError(cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "setsockopt(IP_RECVTTL=1): %M");
                    goto error;
                }
#endif
                break;
            default:
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                        "Invalid address family for test");
                *aval = OWP_CNTRL_UNSUPPORTED;
                goto error;
        }
    }
    else{
        OWPSkip askip;
        int     tries=0;
        char    *skiprec_file = NULL;

        /*
         * Create a file for sharing skip records. (shared memory makes
         * sense for this file, but it is not a requirements.)
         *
         * The child process will fill this with Skip information that
         * the parent will read after the child exits. The child will
         * size the memory at the completion of the session and the
         * parent can use stat to determine how much to read.
         * This could be done with a file just as easily... Just
         * using shared mem becuase it *should* work and *should* allow
         * better performance on systems with reasonable shared memory
         * implementations.
         * Note that this could not be done with a socket/pipe because it
         * is unknown how much data will be coming through, and the parent
         * api gives control of the "event loop" back to the application.
         * Therefore, there is no easy way of adding a "select" for the
         * new fd. It is possible the child will be sending more data
         * than a pipe implementation would buffer, therefore the child
         * process would need to stay around until the pipe is completely
         * read. Using a file/shm implementation allows the data to be around
         * after the child exits no matter the size.
         */
#if USE_SHMIPC
#define SHM_OPEN(a,b,c) shm_open(a,b,c)
#define SHM_UNLINK(a) shm_unlink(a)
#else
#define SHM_OPEN(a,b,c) open(a,b,c)
#define SHM_UNLINK(a) unlink(a)
#endif
#define OWP_SHM_PREFIX    "OWP_TEST_SKIP_RECORDS"
#define OWP_SHM_TRIES   5

NAME_AGAIN:
        if(skiprec_file) free(skiprec_file);
        if(!(skiprec_file = tempnam(NULL,OWP_SHM_PREFIX))){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"tempnam(): %M");
            goto error;
        }

OPEN_AGAIN:
        if((ep->skiprecfd = SHM_OPEN(skiprec_file,O_RDWR|O_CREAT|O_EXCL,
                        S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0){
            switch(errno){
                case EINTR:
                    goto OPEN_AGAIN;
                    break;
                case EEXIST:
                    /* It is conceivable that the tempnam above is not
                     * unique - so we try a couple of times.
                     * (This should be rare unless tempnam() is very
                     * broken on this OS.)
                     */
                    if(tries++ < OWP_SHM_TRIES)
                        goto NAME_AGAIN;
                    /*fallthrough*/
                default:
                    OWPError(cntrl->ctx,OWPErrFATAL,errno,"SHM_OPEN(): %M");
                    free(skiprec_file);
                    goto error;
                    break;
            }
        }

        /*
         * Unlink shm segment and free filename memory.
         */
        rc = SHM_UNLINK(skiprec_file);
        saveerr = errno;

        /* need to free the fname memory even if unlinking failed. */
        free(skiprec_file);

        /* if unlinking failed, then bail. */
        if(rc != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,saveerr,"SHM_UNLINK(): %M");
            goto error;
        }

        /*
         * pre-allocate nodes for skipped packet buffer.
         *
         * Will initially allocate MIN(100,(.10*npackets)).
         * The worst case is .5*npackets (if every other
         * packet needed to be skipped) but in most cases
         * this list of holes will be much smaller. This
         * list will dynamically grow if needed. This is
         * being pre-allocated to at least minimize the number
         * of dynamic allocations tht need to happen during
         * a test.
         */
#define PACKBUFFALLOCFACTOR	2

        ep->free_skiplist=NULL;
        ep->num_allocskip = .10 * ep->tsession->test_spec.npackets;
        ep->num_allocskip = MIN(ep->num_allocskip,100);

        if(!(askip = calloc(sizeof(OWPSkipRec),ep->num_allocskip))){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"calloc(): %M");
            goto error;
        }

        /*
         * [0] is used to track the list of allocated arrays so they
         * can be freed.
         */
        ep->skip_allocated = askip;
        for(i=1;i<ep->num_allocskip;i++){
            askip[i].next = ep->free_skiplist;
            ep->free_skiplist = &askip[i];
        }

        /*
         * Sender needs to set sockopt's to ensure test
         * packets don't fragment in the socket api.
         */

        opt_size = sizeof(sopt);
        if(getsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
                    (void*)&sopt,&opt_size) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "getsockopt(SNDBUF): %M");
            goto error;
        }

        if(sopt < sbuf_size){
            sopt = sbuf_size;
            if(setsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
                        (void*)&sopt,sizeof(sopt)) < 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setsockopt(RCVBUF=%d): %M",
                        sopt);
                goto error;
            }
        }

        /*
         * draft-ietf-ippm-owdp-08.txt adds TTL to the data that
         * is stored by the receiver. The sender should set TTL
         * to 255 to make this useful. (hoplimit is the field
         * name in IPv6.)
         */
        switch(localaddr->saddr->sa_family){
#ifdef	AF_INET6
            case AF_INET6:
#ifdef IPV6_UNICAST_HOPS
                sopt = 255;
                if(setsockopt(ep->sockfd,IPPROTO_IPV6,
                            IPV6_UNICAST_HOPS,
                            (void*)&sopt,sizeof(sopt)) < 0){
                    OWPError(cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "setsockopt(IPV6_UNICAST_HOPS=%d): %M",
                            sopt);
                    goto error;
                }
#endif
                break;
#endif
            case AF_INET:
#ifdef IP_TTL
                sopt = 255;
                if(setsockopt(ep->sockfd,IPPROTO_IP,IP_TTL,
                            (void*)&sopt,sizeof(sopt)) < 0){
                    OWPError(cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "setsockopt(IP_TTL=%d): %M",
                            sopt);
                    goto error;
                }
#endif
                break;
            default:
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                        "Invalid address family for test");
                *aval = OWP_CNTRL_UNSUPPORTED;
                goto error;
        }

        if(ep->tsession->test_spec.typeP){
            int	optname = IP_TOS;
            int	optlevel = IP_TOS;

            /*
             * TODO: Decoding of typeP will need to change if
             * the code can ever support PHB (RFC 2836). (Need
             * support in the socket API to do this...)
             * Will need to look at first two bits and do
             * something different (copy more than
             * the next 6 bits).
             *
             * For now, just verify typeP set to valid value
             * for DSCP mode:
             * Only 6 bits can be set for it to be valid
             * (bits 2-7 of the high-order byte)
             */
            if(ep->tsession->test_spec.typeP & ~0x3F000000){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNSUPPORTED,
                        "Unsupported TypeP requested");
                /*
                 * Set err_ret to OK - this was a valid
                 * request, this implementation just doesn't
                 * support it.
                 */
                *aval = OWP_CNTRL_UNSUPPORTED;
                *err_ret = OWPErrOK;
                goto error;
            }
            /*
             * TODO: Verify this works! (I am highly suspicious
             * of using IP_TOS for IPv6... I have seen IP_CLASS
             * as a possible replacement...)
             */
            switch(localaddr->saddr->sa_family){
                case AF_INET:
                    optlevel = IPPROTO_IP;
                    optname = IP_TOS;
                    break;
#ifdef	AF_INET6
                case AF_INET6:
                    optlevel = IPPROTO_IPV6;
                    optname = IP_TOS;
                    break;
#endif
                default:
                    /*NOTREACHED*/
                    break;
            }

            /* Copy high-order byte (minus first two bits) */
            sopt = (u_int8_t)(ep->tsession->test_spec.typeP >> 24);
            sopt &= 0x3F; /* this should be a no-op until PHB... */

            /* shift for setting TOS */
            sopt <<= 2;
            if(setsockopt(ep->sockfd,optlevel,optname,
                        (void*)&sopt,sizeof(sopt)) < 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setsockopt(%s,%s=%d): %M",
                        ((optlevel==IPPROTO_IP)?
                         "IPPROTO_IP":"IPPROTO_IPV6"),
                        ((optname==IP_TOS)?"IP_TOS":"IP_CLASS"),
                        sopt);
                goto error;
            }
        }
    }

    tsession->endpoint = ep;
    *aval = OWP_CNTRL_ACCEPT;
    *err_ret = OWPErrOK;
    return True;

error:
    EndpointFree(ep,OWP_CNTRL_FAILURE);
    return False;
}

static int owp_usr1;
static int owp_usr2;
static int owp_int;

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
            break;
        default:
            OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
                    "sig_catch:Invalid signal(%d)",signo);
            _exit(OWP_CNTRL_FAILURE);
    }

    return;
}

static void
skip(
        OWPEndpoint ep,
        u_int32_t   seq
        )
{
    OWPSkip node;

    /*
     * If this is the next seq in a current hole, increase the
     * hole size and return.
     */
    if(ep->tail_skip && (ep->tail_skip->end + 1 == seq)){
        ep->tail_skip->end = seq;
        return;
    }

    if(!ep->free_skiplist){
        u_int32_t   i;

        if(!(node = calloc(sizeof(OWPSkipRec),ep->num_allocskip))){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,errno,
                    "calloc(): %M");
            exit(OWP_CNTRL_UNAVAILABLE_TEMP);
        }

        /* [0] is used to hold the malloc memory blocks list from
         * skip_allocated, and is not part of the "free" nodes
         * list.
         */
        node[0].next = ep->skip_allocated;
        ep->skip_allocated = node;
        /*
         * Now take the rest of the newly allocated nodes and make them
         * part of the "free" list.
         */
        for(i=1;i<ep->num_allocskip;i++){
            node[i].next = ep->free_skiplist;
            ep->free_skiplist = &node[i];
        }
    }

    node = ep->free_skiplist;
    ep->free_skiplist = ep->free_skiplist->next;

    node->begin = node->end = seq;
    node->next = NULL;

    if(!ep->tail_skip){
        ep->tail_skip = ep->head_skip = node;
    }
    else{
        ep->tail_skip->next = node;
        ep->tail_skip = node;
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
        OWPEndpoint	ep
        )
{
    u_int32_t	    i;
    struct timespec currtime;
    struct timespec nexttime;
    struct timespec timeout;
    struct timespec latetime;
    struct timespec sleeptime;
    u_int32_t	    esterror;
    u_int32_t	    lasterror=0;
    int		    sync;
    ssize_t	    sent;
    u_int32_t	    *seq;
    u_int8_t	    clr_buffer[32];
    u_int8_t	    zeroiv[16];
    u_int8_t	    *payload;
    u_int8_t	    *tstamp;
    u_int8_t	    *tstamperr;
    OWPTimeStamp    owptstamp;
    OWPNum64	    nextoffset;
    OWPSkip         sr;
    u_int32_t	    num_skiprecs;

    /*
     * Initialize pointers to various positions in the packet buffer,
     * for data that changes for each packet. Also set zero padding.
     */
    switch(ep->cntrl->mode){
        case OWP_MODE_OPEN:
            seq = (u_int32_t*)&ep->payload[0];
            tstamp = &ep->payload[4];
            tstamperr = &ep->payload[12];
            payload = &ep->payload[14];
            break;
        case OWP_MODE_AUTHENTICATED:
            seq = (u_int32_t*)&clr_buffer[0];
            tstamp = &ep->payload[16];
            tstamperr = &ep->payload[24];
            payload = &ep->payload[32];
            memset(clr_buffer,0,32);
            break;
        case OWP_MODE_ENCRYPTED:
            seq = (u_int32_t*)&clr_buffer[0];
            tstamp = &clr_buffer[16];
            tstamperr = &clr_buffer[24];
            payload = &ep->payload[32];
            memset(clr_buffer,0,32);
            memset(zeroiv,0,16);
            break;
        default:
            /*
             * things would have failed way earlier
             * but put default in to stop annoying
             * compiler warnings...
             */
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "run_sender: Bogus \"mode\" bits!");
            exit(OWP_CNTRL_FAILURE);
    }

    /*
     * set random bits.
     */
#if	defined(OWP_ZERO_TEST_PAYLOAD)
    memset(payload,0,ep->tsession->test_spec.packet_size_padding);
#elif	!defined(OWP_VARY_TEST_PAYLOAD)
    /*
     * Ignore errors here - it isn't that critical that it be random.
     * (just trying to defeat modem compression and the like.)
     */
    (void)I2RandomBytes(ep->cntrl->ctx->rand_src,payload,
                        ep->tsession->test_spec.packet_size_padding);
#endif

    /*
     * initialize nextoffset (running sum of next sendtime relative to
     * start.
     */
    nextoffset = OWPULongToNum64(0);
    i=0;

    /*
     * initialize tspec version of "timeout"
     */
    OWPNum64ToTimespec(&timeout,ep->tsession->test_spec.loss_timeout);

    /*
     * Ensure schedule generation is starting at first packet in
     * series.
     */
    if(OWPScheduleContextReset(ep->tsession->sctx,NULL,NULL) != OWPErrOK){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "ScheduleContextReset FAILED!");
        exit(OWP_CNTRL_FAILURE);
    }

    do{
        /*
         * First setup "this" packet.
         */
#if	defined(OWP_VARY_TEST_PAYLOAD) && !defined(OWP_ZERO_TEST_PAYLOAD)
        (void)I2RandomBytes(ep->cntrl->ctx->rand_src,payload,
                            ep->tsession->test_spec.packet_size_padding);
#endif
        nextoffset = OWPNum64Add(nextoffset,
                OWPScheduleContextGenerateNextDelta(
                    ep->tsession->sctx));
        OWPNum64ToTimespec(&nexttime,nextoffset);
        timespecadd(&nexttime,&ep->start);
        *seq = htonl(i);

        /*
         * Encrypt first block. (for MODE_AUTH we are done with AES -
         * for MODE_ENCRYPT we will need to CBC the second block.
         */
        if(ep->cntrl->mode & OWP_MODE_DOCIPHER){
            rijndaelEncrypt(ep->cntrl->encrypt_key.rk,
                    ep->cntrl->encrypt_key.Nr,
                    &clr_buffer[0],&ep->payload[0]);
            memset(&clr_buffer[16],0,16);
        }

AGAIN:
        if(owp_int || owp_usr2){
            goto finish_sender;
        }

        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            exit(OWP_CNTRL_FAILURE);
        }

        /*
         * If current time is greater than next send time...
         */
        if(timespeccmp(&currtime,&nexttime,>)){

            /*
             * If current time is more than "timeout" past next
             * send time, then skip actually sending.
             */
            latetime = timeout;
            timespecadd(&latetime,&nexttime);
            if(timespeccmp(&currtime,&latetime,>)){
                skip(ep,i);
                goto SKIP_SEND;
            }

            /* send-packet */

            (void)OWPTimespecToTimestamp(&owptstamp,&currtime,
                                         &esterror,&lasterror);
            lasterror = esterror;
            owptstamp.sync = sync;
            _OWPEncodeTimeStamp(tstamp,&owptstamp);
            if(!_OWPEncodeTimeStampErrEstimate(tstamperr,
                        &owptstamp)){
                OWPError(ep->cntrl->ctx,OWPErrFATAL,
                        OWPErrUNKNOWN,
                        "Invalid Timestamp Error");
                owptstamp.multiplier = 0xFF;
                owptstamp.scale = 0x3F;
                owptstamp.sync = 0;
                (void)_OWPEncodeTimeStampErrEstimate(tstamperr,
                                                     &owptstamp);
            }

            /*
             * For ENCRYPTED mode, we have to encrypt the second
             * block after fetching the timestamp. (CBC mode)
             */
            if(ep->cntrl->mode == OWP_MODE_ENCRYPTED){
                /*
                 * For now - do CBC mode directly here.
                 * TODO: remove AES hacks in local copy of
                 * AES code - use "standard" version. This
                 * becomes easier. (OWPSendBlocks becomes more
                 * involved...)
                 */
                ((u_int32_t*)clr_buffer)[4] ^=
                    ((u_int32_t*)ep->payload)[0];
                ((u_int32_t*)clr_buffer)[5] ^=
                    ((u_int32_t*)ep->payload)[1];
                ((u_int32_t*)clr_buffer)[6] ^=
                    ((u_int32_t*)ep->payload)[2];
                ((u_int32_t*)clr_buffer)[7] ^=
                    ((u_int32_t*)ep->payload)[3];
                rijndaelEncrypt(ep->cntrl->encrypt_key.rk,
                        ep->cntrl->encrypt_key.Nr,
                        &clr_buffer[16],&ep->payload[16]);
            }

            if( (sent = sendto(ep->sockfd,ep->payload,
                            ep->len_payload,0,
                            ep->remoteaddr->saddr,
                            ep->remoteaddr->saddrlen)) < 0){
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
                        OWPError(ep->cntrl->ctx,
                                OWPErrFATAL,
                                OWPErrUNKNOWN,
                                "Unable to send([%s]:%s:(#%d): %M",
                                ep->remoteaddr->node,
                                ep->remoteaddr->port,i);
                        exit(OWP_CNTRL_FAILURE);
                        break;
                        /* ignore everything else */
                    default:
                        break;
                }

                /* but do note it as INFO for debugging */
                OWPError(ep->cntrl->ctx,OWPErrINFO,
                        OWPErrUNKNOWN,
                        "Unable to send([%s]:%s:(#%d): %M",
                        ep->remoteaddr->node,
                        ep->remoteaddr->port,i);
            }

SKIP_SEND:
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
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "nanosleep(%u.%u,nil): %M",
                    sleeptime.tv_sec,sleeptime.tv_nsec);
            exit(OWP_CNTRL_FAILURE);
        }

    } while(i < ep->tsession->test_spec.npackets);

    /*
     * Wait until lossthresh after last packet or
     * for a signal to exit.
     * (nexttime currently holds the time for the last packet sent, so
     * just add loss_timeout. Round up to the next second since I'm lazy.)
     */
    nexttime.tv_sec += (int)OWPNum64ToDouble(
            ep->tsession->test_spec.loss_timeout)+1;

    while(!owp_usr2 && !owp_int){
        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
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
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "nanosleep(%u.%u,nil): %M",
                    sleeptime.tv_sec,sleeptime.tv_nsec);
            exit(OWP_CNTRL_FAILURE);
        }
    }

finish_sender:
    if(owp_int){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "run_sender: Exiting from signal");
        exit(OWP_CNTRL_FAILURE);
    }

    /*
     * Save session information into IPC file so parent can
     * see results.
     */
    for(num_skiprecs=0,sr = ep->head_skip; sr; sr = sr->next,num_skiprecs++);

#if USE_SHMIPC
    /*
     * If SHMIPC, then the size for the file needs to be
     * specified before writing.
     */
    if( (ftruncate(ep->skiprecfd,
                    (off_t)(8 + (_OWP_SKIPREC_SIZE * num_skiprecs))) != 0)){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,errno,
                "Sizing shared-mem: ftruncate(): %M");
        exit(OWP_CNTRL_FAILURE);
    }
#endif

    /*
     * send (i = nextseq, skip records) to control process
     * for inclusion in StopSessions message...
     * Use network byte order so the data from the fd can just
     * be copied into the StopSessions message. (Besides, this
     * allows the control portion of the server to be on a different
     * architecture than the sender if this is ever extended to an
     * rpc model.)
     *
     */

    /* save "Next Seqno"    */
    i = htonl(i);
    if(I2Writeni(ep->skiprecfd,&i,4,&owp_int) != 4){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "run_sender: I2Writeni(): %M");
        exit(OWP_CNTRL_FAILURE);
    }

    /* save "Num Skip Records"    */
    num_skiprecs = htonl(num_skiprecs);
    if(I2Writeni(ep->skiprecfd,&num_skiprecs,4,&owp_int) != 4){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "run_sender: I2Writeni(): %M");
        exit(OWP_CNTRL_FAILURE);
    }

    /*
     * Now save the skip records.
     */
    for(sr = ep->head_skip; sr; sr = sr->next){
        u_int8_t   skipmsg[_OWP_SKIPREC_SIZE];

        _OWPEncodeSkipRecord((u_int8_t *)skipmsg,sr);
        if(I2Writeni(ep->skiprecfd,skipmsg,_OWP_SKIPREC_SIZE,&owp_int) !=
                _OWP_SKIPREC_SIZE){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "run_sender: I2Writeni(): %M");
            exit(OWP_CNTRL_FAILURE);
        }
    }

    exit(OWP_CNTRL_ACCEPT);
}


static OWPLostPacket
alloc_node(
        OWPEndpoint	ep,
        u_int64_t	seq
        )
{
    OWPLostPacket	node;
    I2Datum		k,v;

    if((seq >= ep->tsession->test_spec.npackets) ||
            (ep->end && (seq <= ep->end->seq))){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid seq number for OWPLostPacket buf");
        return NULL;
    }

    if(!ep->freelist){
        u_int64_t	i;

        OWPError(ep->cntrl->ctx,OWPErrINFO,OWPErrUNKNOWN,
                "alloc_node: Allocating nodes for lost-packet-buffer!");
        if(!(node = calloc(sizeof(OWPLostPacketRec),ep->numalist))){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,errno,
                    "calloc(): %M");
            return NULL;
        }

        node[0].next = ep->lost_allocated;
        ep->lost_allocated = node;
        for(i=1;i<ep->numalist;i++){
            node[i].next = ep->freelist;
            ep->freelist = &node[i];
        }
    }

    node = ep->freelist;
    ep->freelist = ep->freelist->next;

    node->seq = seq;
    node->hit = 0;
    node->next = NULL;

    k.dptr = &node->seq;
    k.dsize = sizeof(node->seq);
    v.dptr = node;
    v.dsize = sizeof(*node);

    if(I2HashStore(ep->lost_packet_buffer,k,v) != 0){
        return NULL;
    }

    return node;
}

static void
free_node(
        OWPEndpoint	ep,
        OWPLostPacket	node
        )
{
    I2Datum	k;

    k.dptr = &node->seq;
    k.dsize = sizeof(node->seq);

    if(I2HashDelete(ep->lost_packet_buffer,k) != 0){
        OWPError(ep->cntrl->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "I2HashDelete: Unable to remove seq #%llu from lost-packet hash",
                node->seq);
    }

    node->next = ep->freelist;
    ep->freelist = node;

    return;
}

static OWPLostPacket
get_node(
        OWPEndpoint	ep,
        u_int64_t	seq
        )
{
    OWPLostPacket	node;
    I2Datum		k,v;

    /*
     * optimize for most frequent case.
     */
    if(seq == ep->end->seq){
        return ep->end;
    }

    /*
     * Need to build the list from current "end" to this number.
     */
    if(seq > ep->end->seq){
        node = ep->end;

        while(node->seq < seq){
            OWPTimeStamp	abs;

            node->next = alloc_node(ep,node->seq+1);
            node->next->relative = OWPNum64Add(node->relative,
                    OWPScheduleContextGenerateNextDelta(
                        ep->tsession->sctx));
            node = node->next;

            abs.owptime = OWPNum64Add(node->relative,
                    ep->tsession->test_spec.start_time);
            (void)OWPTimestampToTimespec(&node->absolute,&abs);
        }

        ep->end = node;

        return node;
    }

    /*
     * Shouldn't be requesting this seq number... It should already
     * be loss_timeout in the past.
     */
    if(seq < ep->begin->seq){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid seq number request");
        return NULL;
    }

    /*
     * seq requested in within the begin<->end range, just fetch from
     * hash.
     */
    k.dptr = &seq;
    k.dsize = sizeof(seq);

    if(!I2HashFetch(ep->lost_packet_buffer,k,&v)){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to fetch from lost-packet-buffer");
        return NULL;
    }

    return (OWPLostPacket)v.dptr;
}

static ssize_t
recvfromttl(
        OWPContext	ctx,
        int		sockfd,
        void		*buf,
        size_t		buf_len,
        struct sockaddr	*local,
        socklen_t	local_len __attribute__((unused)),
        struct sockaddr	*peer,
        socklen_t	*peer_len,
        u_int8_t	*ttl
        )
{
    struct msghdr	msg;
    struct iovec	iov[1];
    ssize_t		rc;
    struct cmsghdr	*cmdmsgptr;
    union {
        struct cmsghdr	cm;
        char		control[CMSG_SPACE(sizeof(u_int8_t))];
    } cmdmsgdata;

    *ttl = 255;	/* initialize to default value */

    iov[0].iov_base = buf;
    iov[0].iov_len = buf_len;

    memset(&msg,0,sizeof(msg));
    msg.msg_name = peer;
    msg.msg_namelen = *peer_len;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmdmsgdata;
    msg.msg_controllen = sizeof(cmdmsgdata.control);
    msg.msg_flags = 0;

    if((rc = recvmsg(sockfd,&msg,0)) < 0){
        return rc;
    }

    *peer_len = msg.msg_namelen;

    if((msg.msg_controllen < sizeof(struct cmsghdr)) ||
            (msg.msg_flags && MSG_CTRUNC)){
        return rc;
    }

    for(cmdmsgptr = CMSG_FIRSTHDR(&msg);
            (cmdmsgptr);
            cmdmsgptr = CMSG_NXTHDR(&msg,cmdmsgptr)){
        switch(local->sa_family){
#ifdef	AF_INET6
            case AF_INET6:
                if(cmdmsgptr->cmsg_level == IPPROTO_IPV6 &&
                        cmdmsgptr->cmsg_type ==
                        IPV6_UNICAST_HOPS){
                    memcpy(ttl,CMSG_DATA(cmdmsgptr),
                            sizeof(u_int8_t));
                    goto NEXTCMSG;
                }
                break;
#endif
            case AF_INET:
                if(cmdmsgptr->cmsg_level == IPPROTO_IP &&
                        cmdmsgptr->cmsg_type == IP_TTL){
                    memcpy(ttl,CMSG_DATA(cmdmsgptr),
                            sizeof(u_int8_t));
                    goto NEXTCMSG;
                }
                break;
            default:
                OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                        "Invalid address family for test");
                return -rc;
        }

        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "recvfromttl: Unknown ancillary data, len = %d, level = %d, type = %d",
                cmdmsgptr->cmsg_len, cmdmsgptr->cmsg_level,
                cmdmsgptr->cmsg_type);
        return -rc;
NEXTCMSG:
        ;
    }

    return rc;
}

static void
run_receiver(
        OWPEndpoint	ep
        )
{
    double              fudge;
    struct timespec     currtime;
    struct timespec     fudgespec;
    struct timespec     lostspec;
    struct timespec     expectspec;
    struct itimerval    wake;
    u_int32_t           *seq;
    u_int32_t           maxseq=0;
    u_int8_t            *tstamp;
    u_int8_t            *tstamperr;
    u_int8_t            *z1,*z2;
    u_int8_t            zero[12];
    u_int8_t            iv[16];
    u_int8_t            recvbuf[10];
    u_int32_t           esterror,lasterror=0;
    int                 sync;
    OWPTimeStamp        expecttime;
    OWPSessionHeaderRec hdr;
    u_int8_t            lostrec[_OWP_DATAREC_SIZE];
    OWPLostPacket       node;
    int                 owp_intr;
    u_int32_t           finished = _OWP_SESSION_FIN_INCOMPLETE;
    OWPDataRec          datarec;

    /*
     * Prepare the file header - had to wait until now to
     * get the real starttime.
     */
    memset(&hdr,0,sizeof(hdr));
    hdr.finished = _OWP_SESSION_FIN_ERROR;
    memcpy(&hdr.sid,ep->tsession->sid,sizeof(hdr.sid));
    memcpy(&hdr.addr_sender,ep->tsession->sender->saddr,
            ep->tsession->sender->saddrlen);
    memcpy(&hdr.addr_receiver,ep->tsession->receiver->saddr,
            ep->tsession->receiver->saddrlen);
    hdr.conf_sender = ep->tsession->conf_sender;
    hdr.conf_receiver = ep->tsession->conf_receiver;
    hdr.test_spec = ep->tsession->test_spec;

    /*
     * Write the file header.
     */
    if( !OWPWriteDataHeader(ep->cntrl->ctx,ep->datafile,&hdr)){
        exit(OWP_CNTRL_FAILURE);
    }

    /*
     * Initialize pointers to various positions in the packet buffer.
     * (useful for the different "modes".)
     */
    seq = (u_int32_t*)&ep->payload[0];
    switch(ep->cntrl->mode){
        case OWP_MODE_OPEN:
            tstamp = &ep->payload[4];
            tstamperr = &ep->payload[12];
            break;
        case OWP_MODE_ENCRYPTED:
        case OWP_MODE_AUTHENTICATED:
            tstamp = &ep->payload[16];
            tstamperr = &ep->payload[24];
            z1 = &ep->payload[4];	/* 12 octets Zero Integrity */
            z2 = &ep->payload[26];	/* 6 octets Zero Integrity */
            memset(zero,0,sizeof(zero));
            break;
        default:
            /*
             * things would have failed way earlier
             * but putting default in to stop annoying
             * compiler warnings...
             */
            exit(OWP_CNTRL_FAILURE);
    }

    /*
     * Initialize the buffer used to report "lost" packets.
     */
    memset(lostrec,0,_OWP_DATAREC_SIZE);

    /*
     * Get the "average" packet interval. I use this
     * to set the wake up timer to MIN(2*packet_interval,1) past the
     * time it can be declared lost. (lets call this fudgespec)
     * With luck, this will allow the next received packet to be the
     * event that wakes up the process, instead of the timer. However,
     * I never let this be greater than 1 second so that small
     * packet rates still produce data at the expected rate.
     * (This basically sets things up so the recv process will wake up
     * 1 second past the "end-of-test" to declare it over. In most cases,
     * the sender will already have sent the StopSession message, so
     * that event will actually wake the process up instead of the
     * timer.)
     */
    fudge = 2.0/OWPTestPacketRate(ep->cntrl->ctx,&ep->tsession->test_spec);
    fudge = MIN(fudge,1.0);
    /* just using expecttime as a temp var here. */
    expecttime.owptime = OWPDoubleToNum64(fudge);
    OWPNum64ToTimespec(&fudgespec,expecttime.owptime);

    /*
     * get a timespec version of loss_timeout
     */
    OWPNum64ToTimespec(&lostspec,ep->tsession->test_spec.loss_timeout);

    /*
     * Ensure schedule generation is starting at first packet in
     * series.
     */
    if(OWPScheduleContextReset(ep->tsession->sctx,NULL,NULL) != OWPErrOK){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "ScheduleContextReset FAILED!");
        exit(OWP_CNTRL_FAILURE);
    }
    /*
     * Initialize list with first node
     */
    ep->begin = ep->end = alloc_node(ep,0);
    if(!ep->begin){
        goto error;
    }

    ep->begin->relative = OWPScheduleContextGenerateNextDelta(
            ep->tsession->sctx);
    /* just using expecttime as a temp var here. */
    expecttime.owptime = OWPNum64Add(ep->begin->relative,
            ep->tsession->test_spec.start_time);
    (void)OWPTimestampToTimespec(&ep->begin->absolute,&expecttime);

    /*
     * initialize currtime for absolute to relative time conversion
     * needed by timers.
     */
    if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Problem retrieving time");
        goto error;
    }

    while(1){
        struct sockaddr_storage	peer_addr;
        socklen_t		peer_addr_len;
again:
        /*
         * set itimer to go off just past loss_timeout after the time
         * for the last seq number in the list. Adding "fudge" so we
         * don't wake up anymore than really necessary.
         * (With luck, a received packet will actually wake this up,
         * and not the timer.)
         */
        tvalclear(&wake.it_value);
        timespecadd((struct timespec*)&wake.it_value,
                &ep->end->absolute);
        timespecadd((struct timespec*)&wake.it_value,&lostspec);
        timespecadd((struct timespec*)&wake.it_value,&fudgespec);
        timespecsub((struct timespec*)&wake.it_value,&currtime);

        wake.it_value.tv_usec /= 1000;	/* convert nsec to usec	*/
        tvalclear(&wake.it_interval);

        /*
         * Set the timer.
         */
        owp_intr = 0;
        if(setitimer(ITIMER_REAL,&wake,NULL) != 0){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "setitimer(wake=%d,%d) seq=%llu: %M",
                    wake.it_value.tv_sec,wake.it_value.tv_usec,
                    ep->end->seq);
            goto error;
        }

        if(owp_int){
            goto error;
        }
        if(owp_usr2){
            goto test_over;
        }

        peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr,0,sizeof(peer_addr));
        if(recvfromttl(ep->cntrl->ctx,ep->sockfd,
                    ep->payload,ep->len_payload,
                    ep->localaddr->saddr,ep->localaddr->saddrlen,
                    (struct sockaddr*)&peer_addr,&peer_addr_len,
                    &datarec.ttl) != (ssize_t)ep->len_payload){
            if(errno != EINTR){
                OWPError(ep->cntrl->ctx,OWPErrFATAL,
                        OWPErrUNKNOWN,"recvfromttl(): %M");
                goto error;
            }
            owp_intr = 1;
        }

        if(owp_int){
            goto error;
        }

        /*
         * Fetch time before ANYTHING else to minimize time errors.
         */
        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            goto error;
        }

        /*
         * Save that time as a timestamp
         */
        (void)OWPTimespecToTimestamp(&datarec.recv,&currtime,
                                     &esterror,&lasterror);
        lasterror = esterror;
        datarec.recv.sync = sync;

        /*
         * Set expectspec to the time the oldest (begin) packet
         * in the missing packet queue should be declared lost.
         */
        timespecclear(&expectspec);
        timespecadd(&expectspec,&ep->begin->absolute);
        timespecadd(&expectspec,&lostspec);

        /*
         * Flush the missing packet buffer. Output missing packet
         * records along the way.
         */
        while(timespeccmp(&expectspec,&currtime,<)){

            /*
             * If !hit - and the seq number is less than
             * npackets, then output a "missing packet" record.
             * (seq number could be greater than or equal to
             * npackets if it takes longer than "timeout" for
             * the stopsessions message to get to us. We could
             * already have missing packet records in our
             * queue.)
             */
            if(!ep->begin->hit &&
                    (ep->begin->seq < ep->tsession->test_spec.npackets)){
                /*
                 * set fields in datarec for missing packet
                 * record.
                 */
                /* seq no */
                datarec.seq_no = ep->begin->seq;
                /* presumed sent time */
                datarec.send.owptime = OWPNum64Add(
                        ep->tsession->test_spec.start_time,
                        ep->begin->relative);
                datarec.send.sync = 0;
                datarec.send.multiplier = 1;
                datarec.send.scale = 64;

                /* special value recv time */
                datarec.recv.owptime = OWPULongToNum64(0);

                /* recv error was set above... */

                datarec.ttl = 255;

                if( !OWPWriteDataRecord(ep->cntrl->ctx,
                            ep->datafile,&datarec)){
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "OWPWriteDataRecord()");
                    goto error;
                }
                if(datarec.seq_no > maxseq){
                    maxseq = datarec.seq_no;
                }
            }
            /*
             * This is not likely... But it is a sure indication
             * of problems.
             */
            else if((ep->begin->hit) &&
                    (ep->begin->seq >= ep->tsession->test_spec.npackets)){
                OWPError(ep->cntrl->ctx,OWPErrFATAL,
                        OWPErrINVALID,
                        "Invalid packet seq received");
                goto error;
            }


            /*
             * Pop the front off the queue.
             */
            node = ep->begin;

            if(ep->begin->next){
                ep->begin = ep->begin->next;
            }
            else if((ep->begin->seq+1) < ep->tsession->test_spec.npackets){
                ep->begin = get_node(ep,ep->begin->seq+1);
            }
            else{
                free_node(ep,node);
                ep->begin = ep->end = NULL;
                goto test_over;
            }
            free_node(ep,node);

            timespecclear(&expectspec);
            timespecadd(&expectspec,&ep->begin->absolute);
            timespecadd(&expectspec,&lostspec);
        }

        /*
         * Check signals...
         */
        if(owp_int){
            goto error;
        }
        if(owp_usr2){
            goto test_over;
        }
        if(owp_intr){
            goto again;
        }

        /*
         * Verify peer before looking at packet.
         */
        if(I2SockAddrEqual(	ep->remoteaddr->saddr,
                    ep->remoteaddr->saddrlen,
                    (struct sockaddr*)&peer_addr,
                    peer_addr_len,I2SADDR_ALL) <= 0){
            goto again;
        }

        /*
         * Decrypt the packet if needed.
         */
        if(ep->cntrl->mode & OWP_MODE_DOCIPHER){
            if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
                /* save encrypted block for CBC */
                memcpy(iv,&ep->payload[0],16);
            }
            rijndaelDecrypt(ep->cntrl->decrypt_key.rk,
                    ep->cntrl->decrypt_key.Nr,
                    &ep->payload[0],&ep->payload[0]);

            /*
             * Check zero bits to ensure valid encryption.
             */
            if(memcmp(z1,zero,12)){
                goto again;
            }

            if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
                /* second block - do CBC */
                rijndaelDecrypt(ep->cntrl->decrypt_key.rk,
                        ep->cntrl->decrypt_key.Nr,
                        &ep->payload[16],&ep->payload[16]);
                ((u_int32_t*)ep->payload)[4] ^=
                    ((u_int32_t*)iv)[0];
                ((u_int32_t*)ep->payload)[5] ^=
                    ((u_int32_t*)iv)[1];
                ((u_int32_t*)ep->payload)[6] ^=
                    ((u_int32_t*)iv)[2];
                ((u_int32_t*)ep->payload)[7] ^=
                    ((u_int32_t*)iv)[3];
                /*
                 * Check zero bits to ensure valid encryption.
                 */
                if(memcmp(z2,zero,6)){
                    goto again;
                }
            }
        }

        datarec.seq_no = ntohl(*seq);
        if(datarec.seq_no >= ep->tsession->test_spec.npackets)
            goto error;
        /*
         * If it is no-longer in the buffer, than we ignore
         * it.
         */
        if(datarec.seq_no < ep->begin->seq)
            goto again;

        /*
         * What time did we expect the sender to send the packet?
         */
        if(!(node = get_node(ep,datarec.seq_no))){
            goto error;
        }
        (void)OWPTimespecToTimestamp(&expecttime,&node->absolute,
                                     NULL,NULL);
        /*
         * What time did sender send this packet?
         */
        _OWPDecodeTimeStamp(&datarec.send,tstamp);
        if(!_OWPDecodeTimeStampErrEstimate(&datarec.send,tstamperr)){
            goto again;
        }

        /*
         * Encode the recv time to buffer right away to catch
         * problems with the esterror.
         */
        _OWPEncodeTimeStamp(&recvbuf[0],&datarec.recv);
        if(!_OWPEncodeTimeStampErrEstimate(&recvbuf[8],&datarec.recv)){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Invalid recv timestamp!");
            goto error;
        }


        /*
         * Now we can start the validity tests from Section 4.2 of
         * the spec...
         * MUST discard if:
         */

        /*
         * 1.
         * Send timestamp is more than timeout in past or future.
         * (i.e. send/recv differ by more than "timeout")
         */
        if(OWPNum64Diff(datarec.send.owptime,datarec.recv.owptime) >
                ep->tsession->test_spec.loss_timeout){
            goto again;
        }

        /*
         * 2.
         * Send timestamp differs by more than "timeout" from
         * "scheduled" send time.
         */
        if(OWPNum64Diff(datarec.send.owptime,expecttime.owptime) >
                ep->tsession->test_spec.loss_timeout){
            goto again;
        }

        /*
         * Made it through all validity tests. Record the packet!
         */
        node->hit = True;

        if( !OWPWriteDataRecord(ep->cntrl->ctx,ep->datafile,
                    &datarec)){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPWriteDataRecord()");
            goto error;
        }
        if(datarec.seq_no > maxseq){
            maxseq = datarec.seq_no;
        }
    }
test_over:

    /*
     * Set the "finished" bit in the file to "incomplete". The parent
     * process will change this to "normal" after evaluating the
     * data from the stop sessiosn message.
     */
    if( !_OWPWriteDataHeaderFinished(ep->cntrl->ctx,ep->datafile,finished,0)){
        goto error;
    }
    fclose(ep->datafile);
    ep->datafile = NULL;


    exit(OWP_CNTRL_ACCEPT);

error:
    if(ep->userfile && (strlen(ep->fname) > 0)){
        unlink(ep->fname);
    }
    if(ep->datafile)
        fclose(ep->datafile);

    exit(OWP_CNTRL_FAILURE);
}

/*
 * Note: We explicitly do NOT connect the send udp socket. This is because
 * each individual packet needs to be treated independant of the others.
 * Connecting the socket to simplify send causes the socket to close if
 * certain ICMP messages come back. We specifically do NOT want this behavior.
 */
OWPBoolean
_OWPEndpointInitHook(
        OWPControl	cntrl,
        OWPTestSession	tsession,
        OWPAcceptType	*aval,
        OWPErrSeverity	*err_ret
        )
{
    OWPContext		ctx = OWPGetContext(cntrl);
    OWPEndpoint		*end_data = &tsession->endpoint;
    OWPEndpoint		ep = tsession->endpoint;
    struct sigaction	act;
    struct sigaction	chldact,usr1act,usr2act,intact,pipeact,alrmact;
    sigset_t		sigs,osigs;

    /*
     * By default, failures from here are recoverable... Set this
     * to OWPErrFATAL to make the connection close. And by default,
     * the "reason" given for Accept is failure.
     */
    *err_ret = OWPErrWARNING;
    *aval = OWP_CNTRL_FAILURE;

    if(!ep){
        return False;
    }

    if(!ep->send){
        ep->remoteaddr = tsession->sender;
        ep->localaddr = tsession->receiver;
    }
    else{
        ep->remoteaddr = tsession->receiver;
        ep->localaddr = tsession->sender;
    }

    /*
     * call sigprocmask to block signals before the fork.
     * (This ensures no race condition.)
     * First we set the new sig_handler for the child, saving the
     * currently installed handlers.
     * Then fork.
     * Then reset the previous sig_handlers for the parent.
     * Then unblock the signals in the parent.
     * (This should ensure that this routine doesn't mess with what
     * the calling environment thinks is installed for these.)
     *
     * The Child then waits for the signals using sigsuspend, and the
     * newly installed handlers get called.
     */
    sigemptyset(&sigs);
    sigaddset(&sigs,SIGUSR1);
    sigaddset(&sigs,SIGUSR2);
    sigaddset(&sigs,SIGINT);
    sigaddset(&sigs,SIGALRM);
    sigaddset(&sigs,SIGPIPE);
    sigaddset(&sigs,SIGCHLD);

    if(sigprocmask(SIG_BLOCK,&sigs,&osigs) != 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"sigprocmask(): %M");
        EndpointFree(ep,OWP_CNTRL_FAILURE);
        *end_data = NULL;
        return False;
    }
    /*
     * set the sig handlers for the currently blocked signals.
     */
    owp_usr1 = 0;
    owp_usr2 = 0;
    owp_int = 0;
    act.sa_handler = sig_catch;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    if(		(sigaction(SIGUSR1,&act,&usr1act) != 0) ||
            (sigaction(SIGUSR2,&act,&usr2act) != 0) ||
            (sigaction(SIGINT,&act,&intact) != 0) ||
            (sigaction(SIGALRM,&act,&alrmact) != 0)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"sigaction(): %M");
        EndpointFree(ep,OWP_CNTRL_FAILURE);
        *end_data = NULL;
        return False;
    }

    act.sa_handler = SIG_IGN;
    if(		(sigaction(SIGPIPE,&act,&pipeact) != 0)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"sigaction(): %M");
        EndpointFree(ep,OWP_CNTRL_FAILURE);
        *end_data = NULL;
        return False;
    }

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
        OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,"sigaction(): %M");
        EndpointFree(ep,OWP_CNTRL_FAILURE);
        *end_data = NULL;
        return False;
    }
    /* if there is currently no handler - set one. */
    if(chldact.sa_handler == SIG_DFL){
        chldact.sa_handler = sig_nothing;
        if(sigaction(SIGCHLD,&chldact,NULL) != 0){
            OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,
                    "sigaction(DFL) failed: %M");
            EndpointFree(ep,OWP_CNTRL_FAILURE);
            *end_data = NULL;
            return False;
        }
    }
    /* now make sure SIGCHLD won't be masked. */
    sigdelset(&osigs,SIGCHLD);

    ep->child = fork();

    if(ep->child < 0){
        /* fork error */
        (void)sigprocmask(SIG_SETMASK,&osigs,NULL);
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fork(): %M");
        EndpointFree(ep,OWP_CNTRL_FAILURE);
        *end_data = NULL;
        return False;
    }

    if(ep->child > 0){
        /* parent */
        int			childstatus;

        /*
         * Reset parent's sig handlers.
         */
        if(		(sigaction(SIGUSR1,&usr1act,NULL) != 0) ||
                (sigaction(SIGUSR2,&usr2act,NULL) != 0) ||
                (sigaction(SIGINT,&intact,NULL) != 0) ||
                (sigaction(SIGPIPE,&pipeact,NULL) != 0) ||
                (sigaction(SIGALRM,&alrmact,NULL) != 0)){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "sigaction(): %M");
            goto parenterr;
        }

        /* reset sig_mask to the old one (-SIGCHLD)	*/
        if(sigprocmask(SIG_SETMASK,&osigs,NULL) != 0){
            OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,
                    "sigprocmask(): %M");
            goto parenterr;
        }


        EndpointClear(ep);
        *err_ret = OWPErrOK;
        *aval = OWP_CNTRL_ACCEPT;
        return True;
parenterr:
        kill(ep->child,SIGINT);
        ep->wopts &= ~WNOHANG;
        while((waitpid(ep->child,&childstatus,ep->wopts) < 0)
                && (errno == EINTR));
        EndpointFree(ep,OWP_CNTRL_FAILURE);
        *end_data = NULL;
        return False;
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
        int	waitfor = (int)OWPContextConfigGet(ctx,OWPChildWait);

        if(waitfor){
            OWPError(ctx,OWPErrWARNING,OWPErrUNKNOWN,
                    "PID=[%d] Busy-loop...",getpid());
            while(waitfor);
        }
    }
#endif

    /*
     * SIGUSR1 is StartSessions
     * SIGUSR2 is StopSessions
     * SIGINT is Terminate - making session invalid.
     */

    /*
     * wait until signal to kick-off session.
     */
    sigemptyset(&sigs);
    sigaddset(&sigs,SIGPIPE);
    while(!owp_usr1 && !owp_usr2 && !owp_int)
        (void)sigsuspend(&sigs);

    /*
     * got a signal - continue.
     */
    if(owp_int || owp_usr2){
        /* cancel the session */
        exit(OWP_CNTRL_REJECT);
    }else if(owp_usr1){
        /* start the session */

        /* clear the sig mask so all sigs come through */
        if(sigprocmask(SIG_SETMASK,&sigs,NULL) != 0){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "sigprocmask(): %M");
            exit(OWP_CNTRL_FAILURE);
        }

        if(ep->send){
            run_sender(ep);
        }
        else{
            run_receiver(ep);
        }
    }

    /*NOTREACHED*/
    OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "Shouldn't get to this line of code... Hmmpf.");
    exit(OWP_CNTRL_FAILURE);
}

OWPBoolean
_OWPEndpointStart(
        OWPEndpoint	ep,
        OWPErrSeverity	*err_ret
        )
{
    *err_ret = OWPErrOK;

    if((ep->acceptval < 0) && ep->child && (kill(ep->child,SIGUSR1) == 0))
        return True;

    *err_ret = OWPErrFATAL;
    OWPError(ep->tsession->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "EndpointStart:Can't signal child #%d: %M",ep->child);
    return False;
}

void
_OWPEndpointStatus(
        OWPEndpoint	ep,
        OWPAcceptType	*aval,		/* out */
        OWPErrSeverity	*err_ret
        )
{
    pid_t			p;
    int			childstatus;

    *err_ret = OWPErrOK;

    if(ep->acceptval < 0){
AGAIN:
        p = waitpid(ep->child,&childstatus,ep->wopts);
        if(p < 0){
            if(errno == EINTR)
                goto AGAIN;
            OWPError(ep->cntrl->ctx,OWPErrWARNING,
                    OWPErrUNKNOWN,
                    "_OWPEndpointStatus:Can't query child #%d: %M",
                    ep->child);
            ep->acceptval = OWP_CNTRL_FAILURE;
            *err_ret = OWPErrWARNING;
        }
        else if(p > 0){
            if(WIFEXITED(childstatus)){
                ep->acceptval =
                    (OWPAcceptType)WEXITSTATUS(childstatus);
            }
            else{
                ep->acceptval = OWP_CNTRL_FAILURE;
                *err_ret = OWPErrWARNING;
            }
        }
        /*
         * if (p == 0) Process still running just fine. Fall through.
         */
    }

    *aval = ep->acceptval;
    return;
}


void
_OWPEndpointStop(
        OWPEndpoint	ep,
        OWPAcceptType	*aval,
        OWPErrSeverity	*err_ret
        )
{
    int		    sig;
    OWPAcceptType   teststatus=OWP_CNTRL_ACCEPT;

    if((ep->acceptval >= 0) || (ep->child == 0)){
        *err_ret = OWPErrOK;
        goto done;
    }

    *err_ret = OWPErrFATAL;

    if(*aval == OWP_CNTRL_ACCEPT){
        sig = SIGUSR2;
    }
    else{
        sig = SIGINT;
    }

    /*
     * If child already exited, kill will come back with ESRCH
     */
    if((kill(ep->child,sig) != 0) && (errno != ESRCH))
        goto error;

    /*
     * Remove the WNOHANG bit. We need to wait until the exit status
     * is available.
     * (Should we add a timer to break out? No - not that paranoid yet.)
     */
    ep->wopts &= ~WNOHANG;
    _OWPEndpointStatus(ep,&teststatus,err_ret);
    if(teststatus >= 0)
        goto done;

error:
    OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "EndpointStop:Can't signal child #%d: %M",ep->child);
done:
    /*
     * If accept state was good upon calling this function, but there
     * was an error stopping this session - report the problem up.
     */
    if((*aval == OWP_CNTRL_ACCEPT) && (ep->acceptval != OWP_CNTRL_ACCEPT)){
        *aval = ep->acceptval;
    }

    return;
}

extern void
_OWPEndpointFree(
        OWPEndpoint     ep,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        )
{
    _OWPEndpointStop(ep,aval,err_ret);

    ep->tsession->endpoint = NULL;
    EndpointFree(ep,*aval);

    return;
}
