//
//      $Id$
///
//***********************************************************************
//                                                                      *
//                             Copyright (C)  2002                      *
//                                Internet2                             *
//                             All Rights Reserved                      *
//                                                                      *
//***********************************************************************/
//
//        File:         endpoint.c
//
//        Author:       Jeff W. Boote
//                      Internet2
//
//        Date:         Wed May 29 09:17:21 MDT 2002
//
//        Description:
//                This file contains the "default" implementation for
//                the send and recv endpoints of an OWAMP test session.
///
#include "owampP.h"

#include <stdio.h>
#include <math.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <pthread.h>

// NOTE: Some known issues with pthreads
//
//  * There might be a delay after SIGINT with powstream.
//
//  * Test time remaining estimates might be off.
//
//  * Some error messages might be a bit off.
//
//  * The packet delays looks suspiciously similar, but some are still different.
//
//  * Testing is ongoing for run_tw_test and run_reflector.
//
//  * Debug mode can be enabled below this comment.
//
//  * Twamp might freeze, needs SIGINT. Need a better solution for this that
//    doesn't affect powstream.
//
//    FEEDBACK WELCOME!
//
//#define DEBUG


//
// Some systems (Solaris ahem...) don't define the CMSG_SPACE macro.
// It does define related macros - I will attempt to do the "right thing".
///
#ifndef CMSG_SPACE
#if defined(_CMSG_DATA_ALIGN) && defined(_CMSG_HDR_ALIGN)
#define CMSG_SPACE(len) \
    (_CMSG_DATA_ALIGN(len) + _CMSG_DATA_ALIGN(sizeof(struct cmsghdr)))
#else
#error "CMSG_SPACE macro undefined for this OS - work to do..."
#endif
#endif

#ifdef DEBUG
#include <assert.h>
#define print_debug(fmt, ...) printf("DEBUG: %s %s %i: %i: " fmt "\n", __FILE__, __func__, __LINE__, getpid(),  ##__VA_ARGS__)
#define print_detailed(fmt, ...) \
    printf("DEBUG: %s %s %i: ep %i tid %i thread %lu sock %i sigfd %i efd %i tfd %i df %p state %i start %i stop %i term %i accept %i: " fmt "\n", __FILE__, __func__, __LINE__, \
    ep->id, ep->tid, ep->thread, ep->sockfd, ep->eventfd, ep->epollfd, ep->timerfd, ep->datafile, ep->state, ep->_owp_usr1, ep->_owp_usr2, ep->_owp_int, ep->acceptval, ##__VA_ARGS__)
#define pperror(fmt, ...) perror(fmt)
#define debug_assert(fmt) assert(fmt)

#else

#define print_debug(fmt, ...)
#define print_detailed(fmt, ...)
#define pperror(fmt, ...)
#define debug_assert(fmt)

#endif // DEBUG

//=============================================================================
//=============================================================================
// NOTE: for debugging only
enum state {
    ERROR = -1,
    INVALID = 0, // NOTE: to prevent 0
    NOT_INITIALIZED = 1,
    INITIALIZED = 2,
    RUNNING = 3,
    STARTED = 4,
    STOPPED = 5,
    TERMINATED = 6
};

static void lock_endpoint(OWPEndpoint ep){
    if (ep){
        print_detailed("locking endpoint");
        pthread_mutex_lock(&ep->mutex);
    } else {
        print_debug("can't lock endpoint that does not exist");

    }
}

static void unlock_endpoint(OWPEndpoint ep){
    if (ep){
        print_detailed("unlocking endpoint");
        pthread_mutex_unlock(&ep->mutex);
    } else {
        print_debug("can't unlock endpoint that does not exist");
    }
}


//
// Function:        EndpointAlloc
//
// Description:
//         Allocate a record to keep track of the state information for
//         this endpoint. (Much of this state is also in the control record
//         and the TestSession record... May simplify this in the future
//         to just reference the other records.)
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
static OWPEndpoint
EndpointAlloc(
        OWPControl  cntrl
        )
{
    print_debug();

    OWPEndpoint ep = calloc(1,sizeof(OWPEndpointRec));

    if(!ep){
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,errno,"malloc(EndpointRec)");
        return NULL;
    }
    int ret = pthread_mutex_init(&ep->mutex, NULL);
    if (ret != 0){
        pperror("pthread_mutex_init");
    }

    ep->cntrl = cntrl;
    ep->sockfd = -1;
    ep->skiprecfd = -1;
    ep->acceptval = OWP_CNTRL_INVALID;
    ep->wopts = WNOHANG;

    ep->epollfd = -1;
    ep->timerfd = -1;
    ep->eventfd = -1;

    ep->_owp_usr1 = -1;
    ep->_owp_usr2 = -1;
    ep->_owp_int = -1;


    ep->state = ERROR;
    ep->state = INVALID;
    ep->state = NOT_INITIALIZED;

    return ep;
}

static void
LostFree(
        OWPLostPacket   lost
        )
{
    print_debug();
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
        _OWPSkip    skip
        )
{
    print_debug();
    _OWPSkip    st;

    while(skip){
        st = skip->next;
        free(skip);
        skip=st;
    }

    return;
}

//
// Function:        EndpointClear
//
// Description:
//         Clear out any resources that are used in the Endpoint record
//         that are not needed in the parent process after the endpoint
//         forks off to do the actual test.
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
static void
EndpointClear(
        OWPEndpoint ep
        )
{
    print_detailed();
    if(!ep)
    {
        print_debug("ERROR");
        return;
    }

    // TODO NOTE move this to end of thread?
    if(ep->sockfd > -1){
        print_debug("closing socket %i", ep->sockfd);
        shutdown(ep->sockfd, SHUT_RDWR);
        close(ep->sockfd);
        ep->sockfd = -1;
    }
    if (ep->timerfd > -1){
        close(ep->timerfd);
        ep->timerfd = -1;
    }
    if (ep->eventfd > -1){
        shutdown(ep->eventfd, SHUT_RDWR);
        close(ep->eventfd);
        ep->eventfd = -1;
    }
    if (ep->epollfd > -1){
        shutdown(ep->epollfd, SHUT_RDWR);
        close(ep->epollfd);
        ep->epollfd = -1;
    }

    if(ep->payload){
        free(ep->payload);
        ep->payload = NULL;
    }

    if(ep->hmac_ctx){
        I2HMACSha1Free(ep->hmac_ctx);
        ep->hmac_ctx = NULL;
    }

    if(ep->lost_packet_buffer){
        I2HashClose(ep->lost_packet_buffer);
    }
    ep->lost_packet_buffer = NULL;
    LostFree(ep->lost_allocated);
    ep->lost_allocated = NULL;
    SkipFree(ep->skip_allocated);
    ep->skip_allocated = NULL;

    return;
}

//
// Function:        EndpointFree
//
// Description:
//         completely free all resoruces associated with an endpoint record.
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
static void
EndpointFree(
        OWPEndpoint     ep,
        OWPAcceptType   aval
        )
{
    print_detailed("EndpointFree");
    if(!ep) {
        print_detailed("ERROR");
        return;
    }
    lock_endpoint(ep);

    print_detailed("Calling EndpointClear");
    EndpointClear(ep);

    if(ep->skiprecfd > -1){
        close(ep->skiprecfd);
        ep->skiprecfd = -1;
    }

    // NOTE: for threaded applications, closing is for all threads
    //       would be better to have two opens, or another option.
    if(ep->datafile){
        print_debug("closing datafile");
        fflush(ep->datafile);
        fsync(fileno(ep->datafile));
        fclose(ep->datafile);
        ep->datafile = NULL;
    }
    if(ep->fbuff){
        free(ep->fbuff);
        ep->fbuff = NULL;
    }

    if(ep->userfile){
        fflush(ep->userfile);
        fsync(fileno(ep->userfile));
        print_debug("closing userfile");
        _OWPCallCloseFile(ep->cntrl,ep->tsession->closure,ep->userfile,
                aval);
        print_debug("after _OWPCallCloseFile");
        ep->userfile = NULL;
    }
    unlock_endpoint(ep);

    free(ep);
    pperror("free");

    return;
}

//
// Function:        reopen_datafile
//
// Description:
//         This function takes a fp and creates a new fp to the same file
//         record. This is used to ensure that the fp used for the actual
//         test is buffered properly. And - allows the test to write to the
//         same file without modifying a fp passed in by an application.
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
// TODO: This solution is somewhat wasteful, would prefer a second open or using
//       pread or something.
static FILE*
reopen_datafile(
        OWPContext  ctx,
        char        *fname,
        FILE        *infp
        )
{
    FILE    *fp;

    int oldfd = fileno(infp);
    int newfd = dup(oldfd);

    if (dup2(oldfd,newfd) == -1){
        pperror("dup2");
        print_debug("ERROR");
        OWPError(ctx,OWPErrFATAL,errno,"dup(%d): %M",
                fileno(infp));
        return NULL;
    }

    if( !(fp = fdopen(newfd,"r+b"))){
        print_debug("ERROR");
        OWPError(ctx,OWPErrFATAL,errno, "fdopen(%d): %M",newfd);
        return NULL;
    }

    return fp;
}

//
// Function:        CmpLostPacket
//
// Description:
//         Used to compare the 32 bit keys for the OWPLostPacket records.
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
static int
CmpLostPacket(
        I2Datum x,
        I2Datum y
        )
{
    print_debug();
    uint32_t   *xn = (uint32_t*)x.dptr;
    uint32_t   *yn = (uint32_t*)y.dptr;

    return !(*xn == *yn);
}

//
// Function:        HashLostPacket
//
// Description:
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
uint32_t
HashLostPacket(
        I2Datum k
        )
{
    print_debug();
    uint32_t   *kn = (uint32_t*)k.dptr;

    return *kn & 0xFFFFUL;
}

static int
anon_file(
        OWPContext  ctx
        )
{
    print_debug();
    char    *tmpdir = NULL;
    char    *fpath = NULL;
    int     pathlen;
    int     fd = -1;

    if( !(tmpdir = getenv("TMPDIR"))){
        tmpdir = _OWP_DEFAULT_TMPDIR;
    }

    pathlen = strlen(tmpdir) + strlen(OWP_PATH_SEPARATOR) +
        strlen(_OWP_SKIPFILE_FMT) + 1;

    if(pathlen > PATH_MAX){
        print_debug("ERROR");
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"TMPDIR too long");
        goto error;
    }

    if( !(fpath = calloc((size_t)pathlen,sizeof(char)))){
        print_debug("ERROR");
        OWPError(ctx,OWPErrFATAL,errno,"calloc(%d): %M",pathlen);
        goto error;
    }

    if(snprintf(fpath,pathlen,"%s%s%s",tmpdir,OWP_PATH_SEPARATOR,
                _OWP_SKIPFILE_FMT) != (pathlen-1)){
        print_debug("ERROR");
        OWPError(ctx,OWPErrFATAL,errno,"snprintf(): Wrong len");
        goto error;
    }

    if( (fd = mkstemp(fpath)) < 0){
        print_debug("ERROR");
        OWPError(ctx,OWPErrFATAL,errno,"mkstemp(%s): Check directory permissions: %M",fpath);
        goto error;
    }

    if(unlink(fpath) != 0){
        print_debug("ERROR");
        OWPError(ctx,OWPErrFATAL,errno,"unlink(): %M");
        debug_assert(0);
        goto error;
    }

    free(fpath);
    return fd;

error:
    print_debug("at error");
    if(fpath) free(fpath);
    if(fd > -1) close(fd);
    return -1;
}



//
// The endpoint init function is responsible for opening a socket, and
// allocating a local port number. (And attempting to allocate all recv
// side memory/file resources that are required so failure is not as likely
// during an actual test.)
///
// TODO
OWPBoolean
_OWPEndpointInit(
        OWPControl      cntrl,
        OWPTestSession  tsession,
        I2Addr          localaddr,
        FILE            *fp,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        )
{
    print_debug("filepointer %p", fp);
    struct sockaddr_storage sbuff;
    socklen_t               sbuff_len=sizeof(sbuff);
    struct sockaddr         *saddr;
    socklen_t               saddrlen;
    OWPEndpoint             ep;
    OWPPacketSizeT          tpsize;
    int                     sbuf_size;
    int                     sopt;
    socklen_t               opt_size;
    uint32_t                i;
    OWPTimeStamp            tstamp;
    uint16_t                port=0;
    uint16_t                p;
    uint16_t                range=0;
    OWPPortRange            portrange=NULL;
    OWPPortRangeRec         dynamic_portrange;
    int                     saveerr=0;
    char                    localnode[NI_MAXHOST];
    size_t                  localnodelen = sizeof(localnode);
    double                  enddelay = _OWP_DEFAULT_FUZZTIME;
    double                  *enddelayptr;
    size_t                  snd_payload_len;

    *err_ret = OWPErrFATAL;
    *aval = OWP_CNTRL_UNAVAILABLE_TEMP;

    if( !(saddr = I2AddrSAddr(localaddr,&saddrlen))){
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_EndpointInit: Unable to get saddr information");
        debug_assert(0);
        return False;
    }

    if(getnameinfo(saddr, saddrlen, localnode, localnodelen, NULL, 0,
            NI_NUMERICHOST) != 0){
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "getnameinfo(): failed for localaddr");
        debug_assert(0);
        return False;
    }

    if( !(ep=EndpointAlloc(cntrl))) {
        print_debug("ERROR");
        debug_assert(0);
        return False;
    }

    ep->send = (localaddr == tsession->sender);
    ep->twoway = cntrl->twoway;

    ep->tsession = tsession;
    ep->cntrl = cntrl;

    if (cntrl->twoway) {
        print_debug();
        tpsize = OWPTestTWPacketSize(saddr->sa_family,
                                     ep->cntrl->mode,tsession->test_spec.packet_size_padding);
    } else {
        print_debug();
        tpsize = OWPTestPacketSize(saddr->sa_family,
                                   ep->cntrl->mode,tsession->test_spec.packet_size_padding);
    }
    tpsize += 128;        // Add fuzz space for IP "options"
    sbuf_size = tpsize;
    if((OWPPacketSizeT)sbuf_size != tpsize){
        print_debug("Packet size overflow, invalid padding");
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Packet size overflow - invalid padding");
        *aval = OWP_CNTRL_FAILURE;
        debug_assert(0);
        goto error;
    }

    ep->len_payload = OWPTestPayloadSize(ep->cntrl->mode,
            ep->tsession->test_spec.packet_size_padding);
    snd_payload_len = ep->len_payload;
    if (cntrl->twoway) {
        print_debug();
        //
        // We attempt to reflect the same sized packet back, but only
        // if the sender has requested enough padding.
        ///
        snd_payload_len = MAX(snd_payload_len, ep->len_payload + OWPTestTWPayloadSize(
                                  ep->cntrl->mode, 0) - OWPTestPayloadSize(ep->cntrl->mode,0));
    }
    // use calloc to initialize the memory to 0
    ep->payload = calloc(1,MAX(ep->len_payload,snd_payload_len));

    if(!ep->payload){
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,"calloc(): %M");
        debug_assert(0);
        goto error;
    }

    tstamp.owptime = ep->tsession->test_spec.start_time;
    (void)OWPTimestampToTimespec(&ep->start,&tstamp);

    //
    // Create the socket.
    ///
    print_debug("Create the socket");
    ep->sockfd = socket(saddr->sa_family,I2AddrSocktype(localaddr),
            I2AddrProtocol(localaddr));
    if(ep->sockfd<0){
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,"socket(): %M");
        debug_assert(0);
        goto error;
    }

    print_debug("Socket %i interface %s", ep->sockfd, cntrl->interface);
    if(cntrl->interface &&
       !OWPSocketInterfaceBind(cntrl, ep->sockfd, cntrl->interface))
    {
        print_debug("ERROR");
        debug_assert(0);
        goto error;
    }

    //
    // Determine what port to try:
    ///
    // type punning

    // first - see if saddr specifies a port directly...
    switch(saddr->sa_family){
        struct sockaddr_in  *s4;
#ifdef        AF_INET6
        struct sockaddr_in6 *s6;

        case AF_INET6:
        s6 = (struct sockaddr_in6*)saddr;
        port = ntohs(s6->sin6_port);
        break;
#endif
        case AF_INET:
        s4 = (struct sockaddr_in*)saddr;
        port = ntohs(s4->sin_port);
        break;
        default:
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid address family for test");
        *aval = OWP_CNTRL_UNSUPPORTED;
        debug_assert(0);
        goto error;
    }

    portrange = (OWPPortRange)OWPContextConfigGetV(cntrl->ctx, OWPTestPortRange);

    //
    // If the requested TWAMP port is not within the testports range,
    // ignore it and use a random port instead.
    ///
    if(cntrl->twoway && cntrl->server && port && portrange){
        if(port < portrange->low || port > portrange->high){
            port = 0;
        }
    }

    if(port){
        //
        // port specified by saddr
        ///
        p = port;

        //
        // If the port requested by the TWAMP sender cannot be used, we
        // will attempt to find one within the configured port range.
        //
        // If a port range has not been configured then a port between the
        // requested and max ports will be used.
        ///
        if(cntrl->twoway && cntrl->server){
            if (!portrange){
                portrange = &dynamic_portrange;
                portrange->high = ~0;
                portrange->low = port;
            }
            range = portrange->high - portrange->low + 1;
        }
    }
    else if(!portrange){
        p = port = 0;
    }else{
        uint32_t   r;

        //
        // Get a random 32 bit number to aid in selecting first
        // port to try.
        ///
        if(I2RandomBytes(cntrl->ctx->rand_src,(uint8_t*)&r,4) != 0) {
            print_debug("ERROR");
            debug_assert(0);
            goto error;
        }

        range = portrange->high - portrange->low + 1;
        p = port = portrange->low + ((double)r / 0xffffffff * range);
    }

    if(portrange && portrange->high < portrange->low){
        print_debug("ERROR");
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid port range specified");
        *aval = OWP_CNTRL_FAILURE;
        debug_assert(0);
        goto error;
    }

    do{
        // Specify the port number
        switch(saddr->sa_family){
            struct sockaddr_in  *s4;
#ifdef        AF_INET6
            struct sockaddr_in6 *s6;

            case AF_INET6:
            s6 = (struct sockaddr_in6*)saddr;
            s6->sin6_port = htons(p);
            break;
#endif
            case AF_INET:
            s4 = (struct sockaddr_in*)saddr;
            s4->sin_port = htons(p);
            break;
            default:
            print_debug("ERROR");
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid address family for test");
            *aval = OWP_CNTRL_UNSUPPORTED;
            debug_assert(0);
            goto error;
        }

        //
        // Try binding.
        ///
        if(bind(ep->sockfd,saddr,saddrlen) == 0){
            goto success;
        }
        pperror("bind");
        //
        // If it failed, and we are not using a "range" then exit
        // loop and report failure. (Or if the error is not EADDRINUSE
        // this is a permenent failure.)
        ///
        if(!portrange || !range || (errno != EADDRINUSE)){
            print_debug("ERROR");
            *aval = OWP_CNTRL_FAILURE;
            debug_assert(0);
            goto bind_fail;
        }

        //
        // compute next port to try.
        ///
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
    OWPError(cntrl->ctx,OWPErrFATAL,saveerr,"bind([%s]:%d): %M",localnode,p);
    debug_assert(0);
    goto error;

success:

    //
    // Retrieve the saddr as defined by the system.
    ///
    memset(&sbuff,0,sizeof(sbuff));
    if(getsockname(ep->sockfd,(void*)&sbuff,&sbuff_len) != 0){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "getsockname(): %M");
        debug_assert(0);
        goto error;
    }

    //
    // set saddr to the sockaddr that was actually used.
    // (This sets the port in saddr as well.)
    ///
    debug_assert(saddrlen >= sbuff_len);
    memcpy(saddr,&sbuff,sbuff_len);

    //
    // Reset the saddr into the I2Addr so it reflects the new
    // port number.
    ///
    if( !I2AddrSetSAddr(localaddr,saddr,saddrlen)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "I2AddrSetSAddr(): Resetting saddr");
        debug_assert(0);
        goto error;
    }

    //
    // If we are two-way client or one-way receiver, allocate lost
    // packet buffer cache.
    ///
    if((cntrl->twoway && !cntrl->server) || (!cntrl->twoway && !ep->send)){
        OWPLostPacket   alist;

        //
        // pre-allocate nodes for lost_packet buffer.
        // (estimate number of nodes needed to hold enough
        // packets for 2*Loss-timeout)
        // TODO: determine a reasonable number instead of (2).
        // (2 is just a guess... exp distribution probably
        // converges to 0 fast enough that we could get away
        // with a much smaller number... say 1.2)
        //
        // It is possible that the actual distribution will make
        // it necessary to hold more than this many nodes in the
        // buffer - but it is highly unlikely. If that happens,
        // another dynamic allocation will happen. This should
        // at least minimize the dynamic allocations during the
        // test.
        ///
#define PACKBUFFALLOCFACTOR        2

        ep->freelist=NULL;
        ep->numalist = OWPTestPacketRate(cntrl->ctx,
                &tsession->test_spec) *
            OWPNum64ToDouble(
                    tsession->test_spec.loss_timeout) *
            PACKBUFFALLOCFACTOR;
        ep->numalist = MAX(ep->numalist,100);

        if(!(alist = calloc(ep->numalist,sizeof(OWPLostPacketRec)))){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"calloc(): %M");
            debug_assert(0);
            goto error;
        }

        //
        // [0] is used to track the list of allocated arrays so they
        // can be freed.
        ///
        ep->lost_allocated = alist;
        for(i=1;i<ep->numalist;i++){
            alist[i].next = ep->freelist;
            ep->freelist = &alist[i];
        }

        if(!(ep->lost_packet_buffer = I2HashInit(cntrl->ctx->eh,ep->numalist,
                        CmpLostPacket,HashLostPacket))){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "_OWPEndpointInit: Unable to initialize lost packet buffer");
            debug_assert(0);
            goto error;
        }
    }

    //
    // If we are two-way client or one-way receiver, sid is valid and
    // we need to open file.
    ///
    if ((cntrl->twoway && !cntrl->server) || (!cntrl->twoway && !ep->send)) {
        size_t          size;

        ep->fname[0] = '\0';
        if(!fp){
            ep->userfile = fp = _OWPCallOpenFile(cntrl,
                    tsession->closure,
                    tsession->sid,
                    ep->fname);
        }
        debug_assert(fp);

        if(!fp){
            print_debug("ERROR");
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to open session file(%s): %M",
                    ep->fname);
            goto error;
        }

        //
        // This function dup's the fd/fp so that file buffering
        // can be reset.
        ///
        // TODO: NOTE: for threads, it might be better to use another open
        if( !(ep->datafile = reopen_datafile(cntrl->ctx,ep->fname, fp))){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to re-open session file(%s): %M",
                    ep->fname);
            goto error;
        }
        debug_assert(ep->datafile);

        //
        // Determine "optimal" file buffer size. To allow "Fetch"
        // clients to access ongoing tests - we define "optimal" as
        // approximately 1 second of buffering.
        ///

        //
        // Determine data rate. i.e. size/second.
        ///
        size = OWPTestPacketRate(cntrl->ctx,&ep->tsession->test_spec) *
            _OWP_MAXDATAREC_SIZE;

        debug_assert(ep->datafile);
        if(size < _OWP_MAXDATAREC_SIZE){
            // If rate is less than one packet/second then unbuffered
            setvbuf(ep->datafile,NULL,_IONBF,0);
        }
        else{
            struct stat        statbuf;

            // stat to find out st_blksize
            if(fstat(fileno(ep->datafile),&statbuf) != 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "fstat(): %M");
                debug_assert(0);
                goto error;
            }

            //
            // Don't make buffer larger than "default"
            ///
            size = MIN(size,(size_t)statbuf.st_blksize);


            if( !(ep->fbuff = malloc(size))){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,"malloc(): %M");
                debug_assert(0);
                goto error;
            }
            setvbuf(ep->datafile,ep->fbuff,_IOFBF,size);
        }
    }

    if (cntrl->twoway || !ep->send) {
        //
        // Two-way client/server or one-way receiver - need to set the
        // recv buffer size large enough for the packet, so we can get
        // it in a single recv.
        ///
        opt_size = sizeof(sopt);
        if(getsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
                    (void*)&sopt,&opt_size) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "getsockopt(RCVBUF): %M");
            debug_assert(0);
            goto error;
        }

        if(sopt < sbuf_size){
            sopt = sbuf_size;
            if(setsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
                        (void*)&sopt,sizeof(sopt)) < 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setsockopt(RCVBUF=%d): %M",sopt);
                debug_assert(0);
                goto error;
            }
        }

        //
        // Request TTL information in ancillary data.
        // TODO: Determine correct sockopt for IPV6!
        ///
        switch(saddr->sa_family){
#ifdef        AF_INET6
            case AF_INET6:
#ifdef IPV6_RECVHOPLIMIT
                sopt = 1;
                if(setsockopt(ep->sockfd,IPPROTO_IPV6,
                            IPV6_RECVHOPLIMIT,
                            (void*)&sopt,sizeof(sopt)) < 0){
                    OWPError(cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "setsockopt(IPV6_RECVHOPLIMIT=1): %M");
                    debug_assert(0);
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
                    debug_assert(0);
                    goto error;
                }
#endif
                break;
            default:
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                        "Invalid address family for test");
                *aval = OWP_CNTRL_UNSUPPORTED;
                debug_assert(0);
                goto error;
        }
    }
    //
    // Create skip records for one-way sender. Two-way client doesn't
    // use skip records at this time.
    ///
    if (!cntrl->twoway && ep->send){
        _OWPSkip    askip;
        // NOTE

        //
        // Create a file for sharing skip records. Shared memory could
        // work for this, but porting is very painful and performance is
        // not so important for this step. (yet)
        //
        // The child process will fill this with Skip information that
        // the parent will read after the child exits.
        //
        // Note that this could not be done with a socket/pipe because it
        // is unknown how much data will be coming through, and the parent
        // api gives control of the "event loop" back to the application.
        // Therefore, there is no easy way of adding a "select" for the
        // new fd. It is possible the child will be sending more data
        // than a pipe implementation would buffer, therefore the child
        // process would need to stay around until the pipe is completely
        // read. Using a file/shm implementation allows the data to be around
        // after the child exits no matter the size.
        ///
        print_detailed("create file for sharing skip records");

        if( (ep->skiprecfd = anon_file(cntrl->ctx)) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to create skips file");
            debug_assert(0);
            goto error;
        }
        debug_assert(ep->skiprecfd);

        //
        // pre-allocate nodes for skipped packet buffer.
        //
        // Will initially allocate MAX(100,(.10*npackets)).
        // The worst case is .5*npackets (if every other
        // packet needed to be skipped) but in most cases
        // this list of holes will be much smaller. This
        // list will dynamically grow if needed. This is
        // being pre-allocated to at least minimize the number
        // of dynamic allocations tht need to happen during
        // a test.
        ///
#define PACKBUFFALLOCFACTOR        2

        ep->free_skiplist=NULL;
        ep->num_allocskip = .10 * ep->tsession->test_spec.npackets;
        ep->num_allocskip = MAX(ep->num_allocskip,100);

        if(!(askip = calloc(ep->num_allocskip,sizeof(_OWPSkipRec)))){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"calloc(): %M");
            debug_assert(0);
            goto error;
        }

        //
        // [0] is used to track the list of allocated arrays so they
        // can be freed.
        ///
        ep->skip_allocated = askip;
        for(i=1;i<ep->num_allocskip;i++){
            askip[i].next = ep->free_skiplist;
            ep->free_skiplist = &askip[i];
        }
    }

    if (cntrl->twoway || ep->send){
        //
        // Two-way client/server or sender needs to set sockopt's to
        // ensure test packets don't fragment in the socket api.
        ///

        opt_size = sizeof(sopt);
        if(getsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
                    (void*)&sopt,&opt_size) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "getsockopt(SNDBUF): %M");
            debug_assert(0);
            goto error;
        }

        if(sopt < sbuf_size){
            sopt = sbuf_size;
            if(setsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
                        (void*)&sopt,sizeof(sopt)) < 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setsockopt(RCVBUF=%d): %M",
                        sopt);
                debug_assert(0);
                goto error;
            }
        }

        //
        // draft-ietf-ippm-owdp-08.txt adds TTL to the data that
        // is stored by the receiver. The sender should set TTL
        // to 255 to make this useful. (hoplimit is the field
        // name in IPv6.)
        ///
        switch(saddr->sa_family){
#ifdef        AF_INET6
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
            int optname = IP_TOS;
            int optlevel = IP_TOS;

            //
            // TODO: Decoding of typeP will need to change if
            // the code can ever support PHB directly(RFC 2836). (Need
            // support in the socket API to do this... Not sure it really
            // makes sense - DSCP values really map to these at the
            // router... Perhaps the owamp spec should not have 16 bits for
            // this.) In any case, if this is ever to happen directly in
            // owamp, this code will need to look at first two bits and do
            // something different (copy more than
            // the next 6 bits).
            //
            // For now, just verify typeP set to valid value
            // for DSCP mode:
            // Only 6 bits can be set for it to be valid
            // (bits 2-7 of the high-order byte)
            ///
            if(ep->tsession->test_spec.typeP & ~0x3F000000){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNSUPPORTED,
                        "Unsupported TypeP requested");
                //
                // Set err_ret to OK - this was a valid
                // request, this implementation just doesn't
                // support it.
                ///
                *aval = OWP_CNTRL_UNSUPPORTED;
                *err_ret = OWPErrOK;
                goto error;
            }
            //
            // TODO: When I find a kernel that actually has IPV6_TCLASS
            // make sure it works. (This looks like the RFC 3542 way...)
            ///
            switch(saddr->sa_family){
                case AF_INET:
                    optlevel = IPPROTO_IP;
                    optname = IP_TOS;
                    break;
#ifdef        AF_INET6
                case AF_INET6:
                    optlevel = IPPROTO_IPV6;
//
// Look for RFC 3542 sockopts - have no systems with them, but look
// for them anyway...
///
#ifdef  IPV6_TCLASS
                    optname = IPV6_TCLASS;
#else
                    optname = IP_TOS;
#endif
                    break;
#endif
                default:
                    /*NOTREACHED*/
                    break;
            }

            // Copy high-order byte (minus first two bits)
            sopt = (uint8_t)(ep->tsession->test_spec.typeP >> 24);
            sopt &= 0x3F; // this should be a no-op until PHB...

            // shift for setting TOS
            sopt <<= 2;
            if(setsockopt(ep->sockfd,optlevel,optname,
                        (void*)&sopt,sizeof(sopt)) < 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setsockopt(%s,%s=%d): %M",
                        ((optlevel==IPPROTO_IP)?
                         "IPPROTO_IP":"IPPROTO_IPV6"),
                        ((optname==IP_TOS)?"IP_TOS":"IPV6_TCLASS"),
                        sopt);
                goto error;
            }
        }
    }

    //
    // Determine 'enddelay'. This is used to add a minimal delay
    // for the sender before it sends the stop sessions message.
    //
    // If clocks are offset - and the sender side is ahead of the
    // receiver side. The sender can send the stop sessions message
    // before the reciever, and more importantly before the reciever
    // has waited 'timeout' after the last packet send time. In this
    // case, the reciever is required to shorten the session by removing
    // any packet records with a send time (relative to the receivers clock)
    // that was sent after stoptime-timeout. (i.e. the time the stop sessions
    // was recieved minus timeout. This ensures that a full 'timeout' period
    // has been waited after the time each and every packet is sent so that
    // duplicates and loss packet statistics are consistently determined.
    ///
    if( (enddelayptr = OWPContextConfigGetV(cntrl->ctx,OWPEndDelay))){
        enddelay = *enddelayptr;
    }

    ep->enddelay.tv_sec = trunc(enddelay);
    enddelay -= ep->enddelay.tv_sec;
    enddelay *= 1000000000;
    ep->enddelay.tv_nsec = trunc(enddelay);

    tsession->endpoint = ep;
    *aval = OWP_CNTRL_ACCEPT;
    *err_ret = OWPErrOK;

    return True;

error:

    EndpointFree(ep,OWP_CNTRL_FAILURE);
    tsession->endpoint = NULL;
    debug_assert(0);
    return False;
}


static void
skip(
        OWPEndpoint ep,
        uint32_t   seq
    )
{
    _OWPSkip    node;

    //
    // If this is the next seq in a current hole, increase the
    // hole size and return.
    ///
    if(ep->tail_skip && (ep->tail_skip->sr.end + 1 == seq)){
        ep->tail_skip->sr.end = seq;
        return;
    }

    if(!ep->free_skiplist){
        uint32_t   i;

        if(!(node = calloc(ep->num_allocskip,sizeof(_OWPSkipRec)))){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,errno,
                    "calloc(): %M");
            exit(OWP_CNTRL_UNAVAILABLE_TEMP);
        }

        // [0] is used to hold the malloc memory blocks list from
        // skip_allocated, and is not part of the "free" nodes
        // list.
        ///
        node[0].next = ep->skip_allocated;
        ep->skip_allocated = node;
        //
        // Now take the rest of the newly allocated nodes and make them
        // part of the "free" list.
        ///
        for(i=1;i<ep->num_allocskip;i++){
            node[i].next = ep->free_skiplist;
            ep->free_skiplist = &node[i];
        }
    }

    node = ep->free_skiplist;
    ep->free_skiplist = ep->free_skiplist->next;

    node->sr.begin = node->sr.end = seq;
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

//
// Packet Formats:
//
// For unauthenticated mode:
//
//           0                   1                   2                   3
//           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        00|                        Sequence Number                        |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        04|                          Timestamp                            |
//        08|                                                               |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        12|        Error Estimate         |                               .
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               .
//          .                                                               .
//          .                         Packet Padding                        .
//          .                                                               .
//          |                                                               |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
// For authenticated and encrypted modes:
//
//           0                   1                   2                   3
//           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        00|                        Sequence Number                        |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        04|                                                               |
//        08|                        MBZ (12 octets)                        |
//        12|                                                               |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        16|                          Timestamp                            |
//        20|                                                               |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        24|        Error Estimate         |                               |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//        28|                         MBZ (6 octets)                        |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        32|                                                               |
//        36|                       HMAC (16 octets)                        |
//        40|                                                               |
//        44|                                                               |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//          .                                                               .
//          .                                                               .
//          .                         Packet Padding                        .
//          .                                                               .
//          |                                                               |
//          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
///
static int check_signals(OWPEndpoint ep, int timeout);

//
// Function:        run_sender
//
// Description:
//                 This function is the main processing function for a "sender"
//                 sub-process.
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
static int
run_sender(
        OWPEndpoint ep
        )
{
    print_detailed("run_sender");
    struct sockaddr *saddr;
    socklen_t       saddrlen=0;
    char            nodename[NI_MAXHOST];
    size_t          nodenamelen = sizeof(nodename);
    char            nodeserv[NI_MAXSERV];
    size_t          nodeservlen = sizeof(nodeserv);
    uint32_t        i;
    struct timespec currtime;
    struct timespec nexttime;
    struct timespec timeout;
    struct timespec latetime;
    struct timespec sleeptime;
    uint32_t        esterror;
    uint32_t        lasterror=0;
    uint8_t         sync;
    ssize_t         sent;
    uint32_t        *seq;
    uint32_t        clr_mem[8]; // two blocks
    char            *clr_buffer = (char *)clr_mem; // legal type pun ;)
    uint8_t         iv[16];
    char            *padding;
    char            *tstamp;
    char            *tstamperr;
    char            *hmac;
    OWPTimeStamp    owptstamp;
    OWPNum64        nextoffset;
    _OWPSkip        sr;
    uint32_t        num_skiprecs;
    int             r;

    if( !(saddr = I2AddrSAddr(ep->remoteaddr,&saddrlen)) ||
                (getnameinfo(saddr, saddrlen, nodename, nodenamelen,
                        nodeserv, nodeservlen,
                        NI_NUMERICHOST | NI_NUMERICHOST) != 0)){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_sender: Unable to extract saddr information");
            return OWP_CNTRL_FAILURE;
    }

    //
    // Initialize pointers to various positions in the packet buffer,
    // for data that changes for each packet. Also set zero padding.
    ///
    memset(clr_buffer,0,32);

    switch(ep->cntrl->mode){
        case OWP_MODE_OPEN:
            seq = (uint32_t*)&ep->payload[0];
            tstamp = &ep->payload[4];
            tstamperr = &ep->payload[12];
            hmac = NULL;
            padding = &ep->payload[14];
            break;
        case OWP_MODE_AUTHENTICATED:
            seq = (uint32_t*)&clr_buffer[0];
            tstamp = &ep->payload[16];
            tstamperr = &ep->payload[24];
            hmac = &ep->payload[32];
            padding = &ep->payload[48];
            break;
        case OWP_MODE_ENCRYPTED:
            seq = (uint32_t*)&clr_buffer[0];
            tstamp = &clr_buffer[16];
            tstamperr = &clr_buffer[24];
            hmac = &ep->payload[32];
            padding = &ep->payload[48];
            break;
        default:
            //
            // things would have failed way earlier
            // but put default in to stop annoying
            // compiler warnings...
            ///
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_sender: Bogus \"mode\" bits");
            return OWP_CNTRL_FAILURE;
    }

    //
    // initialize nextoffset (running sum of next sendtime relative to
    // start).
    ///
    nextoffset = OWPULongToNum64(0);
    i=0;

    //
    // initialize tspec version of "timeout"
    ///
    OWPNum64ToTimespec(&timeout,ep->tsession->test_spec.loss_timeout);

    //
    // Ensure schedule generation is starting at first packet in
    // series.
    ///
    if(OWPScheduleContextReset(ep->tsession->sctx,NULL,NULL) != OWPErrOK){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "ScheduleContextReset: FAILED");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }

    do{
        //
        // First setup "this" packet. calloc() used to allocate ep->payload,
        // so padding will already be zero. Just leave it if zero payload
        // is required.
        ///
#if !defined(OWP_ZERO_TEST_PAYLOAD)
        (void)I2RandomBytes(ep->cntrl->ctx->rand_src,(uint8_t *)padding,
                            ep->tsession->test_spec.packet_size_padding);
#endif
        nextoffset = OWPNum64Add(nextoffset,
                OWPScheduleContextGenerateNextDelta(
                    ep->tsession->sctx));
        OWPNum64ToTimespec(&nexttime,nextoffset);
        timespecadd(&nexttime,&ep->start);
        *seq = htonl(i);

        //
        // blockEncrypt does CBC mode. Can still use this function for
        // both authenticated and encrypted mode because CBC with iv=0
        // of one block is identical to ECB of one block. Then iv is
        // ready for the next block in the case of encrypted mode.
        ///
RETRY:
        if(ep->cntrl->mode & OWP_MODE_DOCIPHER_TEST){
            //
            // Initialize HMAC for this packet, and first block to it.
            ///
            I2HMACSha1Init(ep->hmac_ctx,ep->hmac_key,sizeof(ep->hmac_key));
            I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&clr_buffer[0],16);

            //
            // Initialize IV and encrypt the first block
            ///
            memset(iv,0,sizeof(iv));
            r = blockEncrypt(iv,&ep->aeskey,(uint8_t *)&clr_buffer[0],16*8,
                    (uint8_t *)&ep->payload[0]);
            if(r != (16*8)){
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "run_sender: Invalid ECB encryption of seq (#%ul)",i);
                return OWP_CNTRL_FAILURE;
            }
        }

AGAIN: ;
        int sig = check_signals(ep, 0);
        if (sig < 0){
            print_detailed("ERROR");
            debug_assert(0);
            goto finish_sender;
        }
        if(ep->_owp_int || ep->_owp_usr2){
            goto finish_sender;
        }

        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            return OWP_CNTRL_FAILURE;
        }

        //
        // If current time is greater than next send time...
        ///
        if(timespeccmp(&currtime,&nexttime,>)){

            //
            // If current time is more than "timeout" past next
            // send time, then skip actually sending.
            ///
            latetime = timeout;
            timespecadd(&latetime,&nexttime);
            if(timespeccmp(&currtime,&latetime,>)){
                skip(ep,i);
                goto SKIP_SEND;
            }

            // send-packet

            (void)OWPTimespecToTimestamp(&owptstamp,&currtime,
                                         &esterror,&lasterror);
            lasterror = esterror;
            owptstamp.sync = sync;
            _OWPEncodeTimeStamp((uint8_t *)tstamp,&owptstamp);
            if(!_OWPEncodeTimeStampErrEstimate((uint8_t *)tstamperr,
                        &owptstamp)){
                OWPError(ep->cntrl->ctx,OWPErrFATAL,
                        OWPErrUNKNOWN,
                        "Invalid Timestamp Error");
                owptstamp.multiplier = 0xFF;
                owptstamp.scale = 0x3F;
                owptstamp.sync = 0;
                (void)_OWPEncodeTimeStampErrEstimate((uint8_t *)tstamperr,
                                                     &owptstamp);
            }

            //
            // For ENCRYPTED mode, we have to encrypt the second
            // block after fetching the timestamp. (CBC mode)
            ///
            if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
                //
                // Append second block to HMAC (timestamp block)
                ///
                I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&clr_buffer[16],16);

                //
                // Encrypt second block
                ///
                r = blockEncrypt(iv,&ep->aeskey,(uint8_t *)&clr_buffer[16],16*8,
                        (uint8_t *)&ep->payload[16]);
                if(r != (16*8)){
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "run_sender: Invalid CBC encryption of seq (#%ul)",
                            i);
                    //exit(OWP_CNTRL_FAILURE);
                    return OWP_CNTRL_FAILURE;
                }
            }

            if(hmac){
                uint8_t hmacd[I2HMAC_SHA1_DIGEST_SIZE];

                memset(hmacd,0,sizeof(hmacd));
                I2HMACSha1Finish(ep->hmac_ctx,hmacd);
                memcpy(hmac,hmacd,MIN(16,I2HMAC_SHA1_DIGEST_SIZE));
            }

            sig = check_signals(ep, 0);
            if (sig < 0){
                print_detailed("ERROR");
                debug_assert(0);
                goto finish_sender;
            }
            if( ep->_owp_usr2 || ep->_owp_int){
                print_detailed("owp_int || owp_usr2 jump to finish_sender");
                goto finish_sender;
            }

            if( (sent = sendto(ep->sockfd,ep->payload,
                            ep->len_payload,0,saddr,saddrlen)) < 0){
                switch(errno){
                    // retry errors
                    case ENOBUFS:
                        goto RETRY;
                        break;
                        // fatal errors
                    case EBADF:
                    case EACCES:
                    case ENOTSOCK:
                    case EFAULT:
                    case EAGAIN:
                        print_detailed("ERROR");
                        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                "Unable to send([%s]:%s:(#%d): %M",
                                nodename,nodeserv,i);
                        return OWP_CNTRL_FAILURE;
                        break;
                        // ignore everything else
                    default:
                        break;
                }

                // but do note it as INFO for debugging
                print_detailed("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                        "Unable to send([%s]:%s:(#%d): %M",
                        nodename,nodeserv,i);
            }

SKIP_SEND:
            i++;
        }
        else{
            //
            // Sleep until we should send the next packet.
            ///

            sleeptime = nexttime;
            timespecsub(&sleeptime,&currtime);
            if((nanosleep(&sleeptime,NULL) == 0) || (errno == EINTR)){
                goto AGAIN;
            }
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "nanosleep(%u.%u,nil): %M",
                    sleeptime.tv_sec,sleeptime.tv_nsec);
            return OWP_CNTRL_FAILURE;
        }

    } while(i < ep->tsession->test_spec.npackets);

    //
    // Wait until lossthresh after last packet or
    // for a signal to exit.
    // (nexttime currently holds the time for the last packet sent, so
    // just add loss_timeout. Round up to the next second since I'm lazy.)
    ///
#if OLD
    nexttime.tv_sec += (int)OWPNum64ToDouble(
            ep->tsession->test_spec.loss_timeout)+1;
#endif
    latetime = timeout;
    timespecadd(&latetime,&nexttime);
    timespecadd(&latetime,&ep->enddelay);

    int sig = check_signals(ep, 0);
    while(!ep->_owp_usr2 && !ep->_owp_int){
        print_detailed("!owp_int && !owp_usr2 get timespeccmp");
        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            return OWP_CNTRL_FAILURE;
        }

        if(timespeccmp(&latetime,&currtime,<))
        {
            print_detailed("timespeccmp");
            break;
        }

        sleeptime = latetime;
        timespecsub(&sleeptime,&currtime);
#if NOT
OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_sender: end nanosleep(%lu.%lu,nil)",
                    sleeptime.tv_sec,sleeptime.tv_nsec);
#endif
        if(nanosleep(&sleeptime,NULL) == 0)
            break;
        if(errno != EINTR){
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "nanosleep(%u.%u,nil): %M",
                    sleeptime.tv_sec,sleeptime.tv_nsec);
            return OWP_CNTRL_FAILURE;
        }

        sig = check_signals(ep, 0);
        if (sig < 0){
            print_detailed("ERROR");
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }

finish_sender:
    print_detailed("finish_sender");
    if( ep->_owp_int){
        print_detailed("owp_int @ finish_sender");
        OWPError(ep->cntrl->ctx,OWPErrINFO,OWPErrUNKNOWN,
                "run_sender: Exiting from signal");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }

    //
    // Save session information into IPC file so parent can
    // see results.
    ///
    print_detailed("save session information into IPC file for parent");
    for(num_skiprecs=0,sr = ep->head_skip; sr; sr = sr->next,num_skiprecs++);

#if USE_SHMIPC
    //
    // If SHMIPC, then the size for the file needs to be
    // specified before writing.
    ///
    if( (ftruncate(ep->skiprecfd,
                    (off_t)(8 + (_OWP_SKIPREC_SIZE * num_skiprecs))) != 0)){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,errno,
                "Sizing shared-mem: ftruncate(): %M");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }
#endif

    //
    // send (i = nextseq, skip records) to control process
    // for inclusion in StopSessions message...
    // Use network byte order so the data from the fd can just
    // be copied into the StopSessions message. (Besides, this
    // allows the control portion of the server to be on a different
    // architecture than the sender if this is ever extended to an
    // rpc model.)
    //
    ///

    // save "Next Seqno"
    i = htonl(i);
    if(I2Writeni(ep->skiprecfd,&i,4,(int *)&ep->_owp_int) != 4){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "run_sender: I2Writeni(): %M");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }

    // save "Num Skip Records"
    num_skiprecs = htonl(num_skiprecs);
    print_detailed("I2Writeni save Num Skip Records");
    if(I2Writeni(ep->skiprecfd,&num_skiprecs,4,(int *)&ep->_owp_int) != 4){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "run_sender: I2Writeni(): %M");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }

    //
    // Now save the skip records.
    ///
    print_detailed("Save skip records");
    for(sr = ep->head_skip; sr; sr = sr->next){
        uint8_t   skipmsg[_OWP_SKIPREC_SIZE];

        _OWPEncodeSkipRecord((uint8_t *)skipmsg,&sr->sr);
        if(I2Writeni(ep->skiprecfd,skipmsg,_OWP_SKIPREC_SIZE,(int*)&ep->_owp_int) !=
                _OWP_SKIPREC_SIZE){
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_sender: I2Writeni(): %M");
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }

    print_detailed("EXIT OWP_CNTRL_ACCEPT");
    return OWP_CNTRL_ACCEPT;
}

OWPLostPacket
alloc_node(
        OWPEndpoint ep,
        uint32_t   seq
        )
{
    print_detailed();
    OWPLostPacket   node;
    I2Datum         k,v;

    print_detailed("npackets %i", ep->tsession->test_spec.npackets);
    if((seq >= ep->tsession->test_spec.npackets) ||
            (ep->end && (seq <= ep->end->seq))){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid seq number for OWPLostPacket buf");
        return NULL;
    }

    if(!ep->freelist){
        uint32_t   i;

        OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                "alloc_node: Pre-alloc buffer too small. Allocating additional nodes for lost-packet-buffer.");

        if(!(node = calloc(ep->numalist,sizeof(OWPLostPacketRec)))){
            OWPError(ep->cntrl->ctx,OWPErrFATAL,errno,
                    "calloc(): %M");
            debug_assert(0);
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
    node->hit = False;
    node->sent = False;
    node->next = NULL;

    k.dptr = &node->seq;
    k.dsize = sizeof(node->seq);
    v.dptr = node;
    v.dsize = sizeof(*node);

    if(I2HashStore(ep->lost_packet_buffer,k,v) != 0){
        debug_assert(0);
        return NULL;
    }

    return node;
}

static void
free_node(
        OWPEndpoint     ep,
        OWPLostPacket   node
        )
{
    I2Datum k;

    k.dptr = &node->seq;
    k.dsize = sizeof(node->seq);

    if(I2HashDelete(ep->lost_packet_buffer,k) != 0){
        OWPError(ep->cntrl->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "I2HashDelete: Unable to remove seq #%lu from lost-packet hash",
                node->seq);
    }

    node->next = ep->freelist;
    ep->freelist = node;

    return;
}

OWPLostPacket
get_node(
        OWPEndpoint ep,
        uint32_t   seq
        )
{
    OWPLostPacket   node;
    I2Datum         k,v;

    //
    // optimize for most frequent case.
    ///
    if(seq == ep->end->seq){
        return ep->end;
    }

    //
    // Need to build the list from current "end" to this number.
    ///
    if(seq > ep->end->seq){
        node = ep->end;

        while(node->seq < seq){
            OWPTimeStamp        abs;

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

    //
    // Shouldn't be requesting this seq number... It should already
    // be loss_timeout in the past.
    ///
    if(seq < ep->begin->seq){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid seq number request");
        return NULL;
    }

    //
    // seq requested in within the begin<->end range, just fetch from
    // hash.
    ///
    k.dptr = &seq;
    k.dsize = sizeof(seq);

    if(!I2HashFetch(ep->lost_packet_buffer,k,&v)){
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to fetch from lost-packet-buffer");
        debug_assert(0);
        return NULL;
    }

    return (OWPLostPacket)v.dptr;
}

static int read_eventfd(int eventfd);

// returns -1 on error, or a valid file descriptor
// reads timer and signal but not socket
// timeout_in_ms -1 for indefinite, 0 for immediate
static int is_data_available(OWPEndpoint ep, int timeout_in_ms){
    print_detailed("");

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    int nfds = 0;
    print_detailed("calling epoll_wait with timeout %i", timeout_in_ms);
    nfds = epoll_wait(ep->epollfd, &ev, 1, timeout_in_ms);
    print_detailed("epoll_wait with timeout %i returned %i", timeout_in_ms, nfds);

    if (nfds < 0){
        pperror("epoll_wait");
        print_detailed("ERROR");
        debug_assert(0);
        return -1;
    }else if (nfds ==0){
        // NOTE: Timeout available, but that means valid fd 0 can't be used.
        print_detailed("nothing available to read");
        return 0;
    }

    print_detailed("Something to read! %i", nfds);

    // TODO possibly add signalfd here?
    if (ev.data.fd == ep->timerfd){
        print_detailed("TIMER WENT OFF");
        ssize_t s;
        uint64_t exp, tot_exp;
        s = read(ep->timerfd, &exp, sizeof(uint64_t));
        print_detailed("timer read %li", s);
        return ep->timerfd;
    }else if (ev.data.fd == ep->sockfd){
        print_detailed("got sockfd");
        if (ev.events & EPOLLIN){
        } else {
            print_detailed("HUP or ERR");
            return -1;
        }
        return ep->sockfd;
    }else if (ev.data.fd == ep->eventfd){
        print_detailed("got eventfd");
        if (ev.events & EPOLLIN){
            print_detailed("got eventfd");
            int ret = read_eventfd(ep->eventfd);
            print_detailed("readeventfd got %i", ret);
            return ep->eventfd;
        } else {
            print_detailed("got eventfd HUP or ERR");
            return -1;
        }
        print_detailed("got eventfd error");
        debug_assert(0);

        return -1;
    }else{
        print_detailed("unknown");
        debug_assert(0);
        return -1;
    }
    return -1;
}


static ssize_t
recvfromttl(
        OWPContext      ctx,
        int             sockfd,
        void            *buf,
        size_t          buf_len,
        struct sockaddr *local,
        socklen_t       local_len __attribute__((unused)),
        struct sockaddr *peer,
        socklen_t       *peer_len,
        uint8_t        *ttl
        )
{
    struct msghdr       msg;
    struct iovec        iov[1];
    ssize_t             rc;
    struct cmsghdr      *cmdmsgptr;
    union {
        struct cmsghdr  cm;
        char            control[CMSG_SPACE(sizeof(uint8_t))];
    } cmdmsgdata;
    int ttl_int;

    *ttl = 255;        // initialize to default value

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
        pperror("recvmsg");
        return rc;
    }

    *peer_len = msg.msg_namelen;

    if((msg.msg_controllen < sizeof(struct cmsghdr)) ||
            (msg.msg_flags & MSG_CTRUNC)){
        print_debug("ERROR");
        return rc;
    }

    for(cmdmsgptr = CMSG_FIRSTHDR(&msg);
            (cmdmsgptr);
            cmdmsgptr = CMSG_NXTHDR(&msg,cmdmsgptr)){
        switch(local->sa_family){
#ifdef        AF_INET6
            case AF_INET6:
#ifdef  IPV6_HOPLIMIT
                if(cmdmsgptr->cmsg_level == IPPROTO_IPV6 &&
                        cmdmsgptr->cmsg_type == IPV6_HOPLIMIT){
                    //
                    // IPV6_HOPLIMIT is defined as an int, type coercion
                    // will convert it to a uint8_t.
                    ///
                    memcpy(&ttl_int, CMSG_DATA(cmdmsgptr), sizeof(int));
                    *ttl = (uint8_t)ttl_int;
                    goto NEXTCMSG;
                }
#endif
                break;
#endif
            case AF_INET:
                //
                // FreeBSD and OS X seem to use IP_RECVTTL. Linux
                // seems to use IP_TTL - but still has IP_RECVTTL
                // defined.
                //
                // Gotta love standards...
                //
                // (Looking at opendarwin kernel sources leads me to
                // believe that IP_RECVTTL is a uchar and actual
                // documentation in the CMSG man page on Linux
                // tells me IP_TTL should be treated as an int. But,
                // I have never really found the 'definitive' standard
                // for this stuff. oh well...)
                ///
#ifdef  IP_RECVTTL
                if(cmdmsgptr->cmsg_level == IPPROTO_IP &&
                        cmdmsgptr->cmsg_type == IP_RECVTTL){
                    *ttl = *(uint8_t *)CMSG_DATA(cmdmsgptr);
                    goto NEXTCMSG;
                }
                else
#endif
                if(cmdmsgptr->cmsg_level == IPPROTO_IP &&
                        cmdmsgptr->cmsg_type == IP_TTL){
                    memcpy(&ttl_int, CMSG_DATA(cmdmsgptr), sizeof(int));
                    *ttl = (uint8_t)ttl_int;
                    goto NEXTCMSG;
                }
                break;
            default:
                print_debug("ERROR");
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


//
// Function:    flush_lost
//
// Description:
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
//          < 0: error
//          > 0: test is complete
//          = 0: successfully flushed as much as needed
// Side Effect:
///
int
flush_lost(
        OWPEndpoint     ep,
        struct timespec *ctime,
        struct timespec *ltime,
        OWPTimeStamp	*errest
        )
{
    print_debug();
    OWPLostPacket       node;
    struct timespec     currtime = *ctime;
    struct timespec     lostspec = *ltime;
    struct timespec     expectspec;

    //
    // Set expectspec to the time the oldest (begin) packet
    // in the missing packet queue should be declared lost.
    ///
    timespecclear(&expectspec);
    timespecadd(&expectspec,&ep->begin->absolute);
    timespecadd(&expectspec,&lostspec);

    //
    // If owp_usr2, then StopSessions has been received. We
    // need to flush all records for the test now. So, artificailly
    // set currtime to a time greater than expectspec so the loop
    // will continue until all packet records are flushed.
    // XXX:
    // This is an over-kill solution to ensure missing
    // packet records are in the session. A better solution
    // would only flush record up through the "Next Seqno"
    // field passed in the StopSessions message from the
    // sender. But, since that is not available in this
    // process- and we have no way of knowing just how far offset the
    // sender/receiver clocks are, this is the temporary
    // fix. Unneeded records will be deleted by the parent.
    ///
    print_detailed("flush records");
    int sig = check_signals(ep, 0);
    // TODO Note: this only looks for close, but we're reading the signal
    //            so the SIGINT will disappear
    if (sig  != 0){
    //TODO: if (sig == SIGUSR2){
        print_detailed("owp_usr2-- stop session");
        timespecclear(&currtime);
        timespecadd(&currtime,&expectspec);
        timespecadd(&currtime,&lostspec);
    }

    //
    // Flush the missing packet buffer. Output missing packet
    // records along the way.
    ///
    while(timespeccmp(&expectspec,&currtime,<)){
        //
        // Stop flushing when the packet at the front of the queue
        // hasn't actually been sent yet
        ///
        if(ep->twoway && !ep->begin->sent){
            break;
        }

        //
        // If !hit - and the seq number is less than
        // npackets, then output a "missing packet" record.
        // (seq number could be greater than or equal to
        // npackets if it takes longer than "timeout" for
        // the stopsessions message to get to us. We could
        // already have missing packet records in our
        // queue.)
        ///
        if(!ep->begin->hit){
            OWPTWDataRec      lostrec;

#ifdef OWP_EXTRA_DEBUG
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                     "flush_lost: lost packet seq %u", ep->begin->seq);
#endif

            //
            // set fields in lostrec for missing packet
            // record.
            ///
            // seq no
            lostrec.sent.seq_no = ep->begin->seq;

            // presumed sent time
            lostrec.sent.send.owptime = OWPNum64Add(
                    ep->tsession->test_spec.start_time,
                    ep->begin->relative);
            lostrec.sent.send.sync = 0;
            lostrec.sent.send.multiplier = 1;
            lostrec.sent.send.scale = 64;

            // special value recv time
            lostrec.sent.recv = *errest;
            lostrec.sent.recv.owptime = OWPULongToNum64(0);

            // recv error was set above...

            lostrec.sent.ttl = 255;

            if(ep->twoway){
                lostrec.reflected.ttl = 255;
                lostrec.reflected.seq_no = 0;
                lostrec.reflected.send = lostrec.sent.recv;
                lostrec.reflected.recv = lostrec.sent.recv;

                debug_assert(ep->datafile);
                if( !OWPWriteTWDataRecord(ep->cntrl->ctx,
                            ep->datafile,&lostrec)){
                    print_detailed("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "OWPWriteTWDataRecord()");
                    debug_assert(0);
                    return -1;
                }
            }
            else{
                if( !OWPWriteDataRecord(ep->cntrl->ctx,
                            ep->datafile,&lostrec.sent)){
                    print_detailed("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,
                            "OWPWriteDataRecord()");
                    debug_assert(0);
                    return -1;
                }
            }
        }

#ifdef OWP_EXTRA_DEBUG
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                 "flush_lost: flushing packet seq %u", ep->begin->seq);
#endif

        //
        // Pop the front off the queue.
        ///
        node = ep->begin;

        if(ep->begin->next){
            ep->begin = ep->begin->next;
        }
        else if((ep->begin->seq+1) < ep->tsession->test_spec.npackets){
            ep->begin = get_node(ep,ep->begin->seq+1);
        }
        else{
            print_detailed("No more nodes?");
            free_node(ep,node);
            ep->begin = ep->end = NULL;
            return 1;
        }
        free_node(ep,node);

        timespecclear(&expectspec);
        timespecadd(&expectspec,&ep->begin->absolute);
        timespecadd(&expectspec,&lostspec);

        //
        // StopSessions received: fast-forward currtime
        ///
        sig = check_signals(ep, 0);
        if (sig < 0){
            debug_assert(0);
        }
        if(ep->_owp_usr2){
            print_detailed("ep->_owp_usr2-- stop session, fast-forward currtime");
            timespecclear(&currtime);
            timespecadd(&currtime,&expectspec);
            timespecadd(&currtime,&lostspec);
        }
    }

    return 0;
}

static int
run_receiver(
        OWPEndpoint ep
        )
{
    print_detailed("run_receiver");
    double              fudge;
    struct timespec     currtime;
    struct timespec     fudgespec;
    struct timespec     lostspec;
    struct itimerval    wake;
    uint32_t            *seq;
    char                *tstamp;
    char                *tstamperr;
    char                *hmac;
    uint32_t            esterror,lasterror=0;
    uint8_t             sync;
    OWPTimeStamp        expecttime;
    OWPSessionHeaderRec hdr;
    uint8_t             lostrec[_OWP_DATAREC_SIZE];
    OWPLostPacket       node;
    int                 owp_intr;
    uint32_t            finished = OWP_SESSION_FINISHED_INCOMPLETE;
    OWPDataRec          datarec;
    struct sockaddr     *lsaddr;
    socklen_t           lsaddrlen;
    struct sockaddr     *rsaddr;
    socklen_t           rsaddrlen;
    int                 rc;

    debug_assert(ep!=NULL);
    print_detailed("creating timer");

    if (ep->timerfd == -1){
        ep->timerfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
        if (ep->timerfd <= 0){
            print_detailed("ERROR");
            pperror("timerfd_create");
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR; // EPOLLET EPOLLHUP EPOLLERR
    ev.data.fd = ep->timerfd;
    if (epoll_ctl(ep->epollfd, EPOLL_CTL_ADD, ep->timerfd, &ev) == -1) {
        pperror("epoll_ctl: timerfd");
        print_debug("errno %i", errno);
        // TODO
        if (errno == EEXIST){
        }else {
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }

    //
    // Prepare the file header - had to wait until now to
    // get the real starttime.
    ///
    memset(&hdr,0,sizeof(hdr));
    hdr.finished = finished;
    memcpy(&hdr.sid,ep->tsession->sid,sizeof(hdr.sid));

    if( !(lsaddr = I2AddrSAddr(ep->tsession->sender,&lsaddrlen))){
        print_detailed("ERROR");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }
    memcpy(&hdr.addr_sender,lsaddr,lsaddrlen);

    if( !(lsaddr = I2AddrSAddr(ep->tsession->receiver,&lsaddrlen))){
        print_detailed("ERROR");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }
    memcpy(&hdr.addr_receiver,lsaddr,lsaddrlen);

    hdr.conf_sender = ep->tsession->conf_sender;
    hdr.conf_receiver = ep->tsession->conf_receiver;
    hdr.test_spec = ep->tsession->test_spec;

    //
    // Write the file header.
    ///
    print_detailed("Write Data Header");
    debug_assert(ep->datafile);
    if( !OWPWriteDataHeader(ep->cntrl->ctx,ep->datafile,&hdr)){
        print_detailed("ERROR");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }

    //
    // Get pointer to lsaddr used for listening.
    ///
    if( !(lsaddr = I2AddrSAddr(ep->localaddr,&lsaddrlen))){
        print_detailed("ERROR");
        return OWP_CNTRL_FAILURE;
    }
    //
    // Get pointer to rsaddr used to verify peer.
    ///
    if( !(rsaddr = I2AddrSAddr(ep->remoteaddr,&rsaddrlen))){
        print_detailed("ERROR");
        return OWP_CNTRL_FAILURE;
    }

    //
    // Initialize pointers to various positions in the packet buffer.
    // (useful for the different "modes".)
    ///
    seq = (uint32_t*)&ep->payload[0];
    switch(ep->cntrl->mode){
        case OWP_MODE_OPEN:
            tstamp = &ep->payload[4];
            tstamperr = &ep->payload[12];
            hmac = NULL;
            break;
        case OWP_MODE_ENCRYPTED:
        case OWP_MODE_AUTHENTICATED:
            tstamp = &ep->payload[16];
            tstamperr = &ep->payload[24];
            hmac = &ep->payload[32];
            break;
        default:
            //
            // things would have failed way earlier
            // but putting default in to stop annoying
            // compiler warnings...
            ///
            print_detailed("ERROR");
            return OWP_CNTRL_FAILURE;
    }

    //
    // Initialize the buffer used to report "lost" packets.
    ///
    memset(lostrec,0,_OWP_DATAREC_SIZE);

    //
    // Get the "average" packet interval. I use this
    // to set the wake up timer to MIN(2*packet_interval,1) past the
    // time it can be declared lost. (lets call this fudgespec)
    // With luck, this will allow the next received packet to be the
    // event that wakes up the process, instead of the timer. However,
    // I never let this be greater than 1 second so that small
    // packet rates still produce data at the expected rate.
    // (This basically sets things up so the recv process will wake up
    // 1 second past the "end-of-test" to declare it over. In most cases,
    // the sender will already have sent the StopSession message, so
    // that event will actually wake the process up instead of the
    // timer.)
    ///
    fudge = 2.0/OWPTestPacketRate(ep->cntrl->ctx,&ep->tsession->test_spec);
    fudge = MIN(fudge,1.0);
    // just using expecttime as a temp var here.
    expecttime.owptime = OWPDoubleToNum64(fudge);
    OWPNum64ToTimespec(&fudgespec,expecttime.owptime);

    //
    // get a timespec version of loss_timeout
    ///
    OWPNum64ToTimespec(&lostspec,ep->tsession->test_spec.loss_timeout);

    //
    // Ensure schedule generation is starting at first packet in
    // series.
    ///
    // TODO thread issue?
    if(OWPScheduleContextReset(ep->tsession->sctx,NULL,NULL) != OWPErrOK){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "ScheduleContextReset FAILED!");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }
    //
    // Initialize list with first node
    ///
    ep->begin = ep->end = alloc_node(ep,0);
    if(!ep->begin){
        print_detailed("ERROR");
        goto error;
    }

    ep->begin->relative = OWPScheduleContextGenerateNextDelta(
            ep->tsession->sctx);
    // just using expecttime as a temp var here.
    expecttime.owptime = OWPNum64Add(ep->begin->relative,
            ep->tsession->test_spec.start_time);
    (void)OWPTimestampToTimespec(&ep->begin->absolute,&expecttime);

    //
    // initialize currtime for absolute to relative time conversion
    // needed by timers.
    ///
    if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Problem retrieving time");
        goto error;
    }

    //
    // Save that time as a timestamp
    ///
    (void)OWPTimespecToTimestamp(&datarec.recv,&currtime,&esterror,&lasterror);
    lasterror = esterror;
    datarec.recv.sync = sync;

    print_detailed("flush lost");
    rc = flush_lost(ep,&currtime,&lostspec,&datarec.recv);
    if(rc < 0){
        print_detailed("ERROR");
        goto error;
    }
    else if(rc > 0){
        print_detailed("FINISH");
        goto test_over;
    }

    print_detailed("starting while loop");
    while(1){
        struct sockaddr_storage peer_addr;
        socklen_t               peer_addr_len;
        struct timespec wake_ts;
again:
        print_detailed("epid %i %lu @> again", ep->id, ep->thread);
        //
        // set itimer to go off just past loss_timeout after the time
        // for the last seq number in the list. Adding "fudge" so we
        // don't wake up anymore than really necessary.
        // (With luck, a received packet will actually wake this up,
        // and not the timer.)
        ///
        timespecclear(&wake_ts);
        timespecadd(&wake_ts,&ep->end->absolute);
        timespecadd(&wake_ts,&lostspec);
        timespecadd(&wake_ts,&fudgespec);
        timespecsub(&wake_ts,&currtime);

        wake.it_value.tv_sec = wake_ts.tv_sec;
        wake.it_value.tv_usec = wake_ts.tv_nsec / 1000; // convert nsec to usec
        while (wake.it_value.tv_usec >= 1000000) {
            wake.it_value.tv_usec -= 1000000;
            wake.it_value.tv_sec++;
        }


        tvalclear(&wake.it_interval);

        //
        // Set the timer.
        ///
        print_detailed("Setting the timer, wake is %li %li", wake.it_value.tv_sec, wake.it_value.tv_usec);
        owp_intr = 0;
        struct itimerspec  new_value;
        new_value.it_value.tv_sec = wake_ts.tv_sec;
        new_value.it_value.tv_nsec = wake_ts.tv_nsec;
        new_value.it_interval.tv_sec = 0;
        new_value.it_interval.tv_nsec =0;
        print_detailed("Setting timerfd, new_v  is %li %li", new_value.it_value.tv_sec, new_value.it_value.tv_nsec);

        print_detailed("timerfd_settime");
        // TODO?
        //int ret = timerfd_settime(ep->timerfd, TFD_TIMER_CANCEL_ON_SET, &new_value, NULL);
        int ret = timerfd_settime(ep->timerfd, 0, &new_value, NULL);
        if (ret != 0){
            pperror("timerfd_settime");
            print_detailed("timerfd_settime %i", ret);
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "setitimer(wake=%d,%d) seq=%lu: %M",
                    wake.it_value.tv_sec,wake.it_value.tv_usec,
                    ep->end->seq);
            goto error;
        }

        int sig = check_signals(ep, 0);
        if (sig != 0) {
            if (sig == SIGUSR2) {
            // TODO NOTE if(ep->_owp_usr2){
                print_detailed("ep->_owp_usr2-- stop session");
                print_detailed("FINISH");
                goto test_over;
            }
            print_detailed("owp_int");
            debug_assert(0);
            goto error;
        }

        print_detailed("calling is_data_available");

        int fd = is_data_available(ep, -1);
        print_detailed("is_data_available returned %i", fd);
        if (fd == ep->sockfd){
            peer_addr_len = sizeof(peer_addr);
            memset(&peer_addr,0,sizeof(peer_addr));

            print_detailed("calling recvfromttl");
            ssize_t len = recvfromttl(ep->cntrl->ctx, ep->sockfd,
                        ep->payload,ep->len_payload,lsaddr,lsaddrlen,
                        (struct sockaddr*)&peer_addr,&peer_addr_len,
                        &datarec.ttl);
            if (len != (ssize_t)ep->len_payload){
                // TODO not sure about this?
                if (errno == EINTR){
                    print_detailed("there was an interruption");
                    pperror("recvfromttl");
                    owp_intr = 1;
                    debug_assert(0);
                } else {
                    print_detailed("ERROR???");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,"recvfromttl(): %M");
                    debug_assert(0);
                    goto error;
                }

            }
        } else if (fd == ep->timerfd) {
            print_debug("timer");
            owp_intr = 1;
        } else if (fd == ep->eventfd) {
            print_detailed("signal");
            goto error;
        } else if (fd < 0){
            print_debug("ERROR");
            goto error;
        } else {
            print_debug("unknown");
            debug_assert(0);
            goto error;
        }

        sig = check_signals(ep, 0);
        if (sig != 0){
            print_debug("owp_int or owp_usr2 -- stop session");
            if (sig == SIGUSR2){
                print_detailed("owp_usr2 -- goto test_over");
                goto test_over;
            }
            print_detailed("owp_int || ep->_owp_int");
            goto error;
        }

        //
        // Fetch time before ANYTHING else to minimize time errors.
        ///
        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            goto error;
        }

        //
        // Check signals...
        ///
        sig = check_signals(ep, 0);
        if (sig != 0){
            print_debug("owp_int or owp_usr2 -- stop session");
            if (sig == SIGUSR2){
                print_detailed("owp_usr2 -- goto test_over");
                goto test_over;
            }
            print_detailed("owp_int || ep->_owp_int");
            goto error;
        }

        //
        // Save that time as a timestamp
        ///
        (void)OWPTimespecToTimestamp(&datarec.recv,&currtime,
                                     &esterror,&lasterror);
        lasterror = esterror;
        datarec.recv.sync = sync;

        rc = flush_lost(ep,&currtime,&lostspec,&datarec.recv);
        if(rc < 0){
            print_debug("ERROR");
            goto error;
        }
        else if(rc > 0){
            print_detailed("GO TO TEST OVER");
            goto test_over;
        }

        //
        // Check signals...
        ///
        sig = check_signals(ep, 0);
        if (sig != 0){
            if (sig == SIGUSR2){
                print_debug("owp_usr2 -- goto test_over");
                print_detailed("GO TO TEST OVER");
                goto test_over;
            }
            // TODO confirm?
            print_debug("owp_int || ep->_owp_int");
            goto error;
        }

        if(owp_intr){
            print_detailed("owp_intr -- goto again");
            print_detailed("GO TO AGAIN");
            goto again;
        }

        //
        // Verify peer before looking at packet.
        ///
        if(I2SockAddrEqual(rsaddr,rsaddrlen,
                    (struct sockaddr*)&peer_addr,
                    peer_addr_len,I2SADDR_ALL) <= 0){
            goto again;
        }

        //
        // Decrypt the packet if needed.
        ///
        if(ep->cntrl->mode & OWP_MODE_DOCIPHER_TEST){
            uint8_t iv[16];
            int     r;
            uint8_t hmacd[I2HMAC_SHA1_DIGEST_SIZE];

            //
            // Initialize HMAC and iv.
            ///
            memset(iv,0,sizeof(iv));
            I2HMACSha1Init(ep->hmac_ctx,ep->hmac_key,sizeof(ep->hmac_key));

            //
            // Decrypt first block
            ///
            r = blockDecrypt(iv,&ep->aeskey,(uint8_t *)&ep->payload[0],
                    16*8,(uint8_t *)&ep->payload[0]);
            if(r != (16*8)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "run_receiver: Invalid ECB decryption");
                goto error;
            }
            I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&ep->payload[0],16);


            if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
                //
                // Decrypt second block if full encrypted mode wanted
                // (CBC mode done by blockDecrypt)
                ///
                r = blockDecrypt(iv,&ep->aeskey,(uint8_t *)&ep->payload[16],
                        16*8,(uint8_t *)&ep->payload[16]);
                if(r != (16*8)){
                    print_debug("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "run_receiver: Invalid CBC decryption");
                    goto error;
                }
                I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&ep->payload[16],16);
            }

            memset(hmacd,0,sizeof(hmacd));
            I2HMACSha1Finish(ep->hmac_ctx,hmacd);
            if( (memcmp(hmac,hmacd,
                        MIN(_OWP_RIJNDAEL_BLOCK_SIZE,sizeof(hmacd))) != 0)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                        "run_receiver: Invalid HMAC on received packet: "
                        "ignoring");
                goto again;
            }
        }

        datarec.seq_no = ntohl(*seq);
        print_debug("datarec.seq_no %i", datarec.seq_no);
        if(datarec.seq_no >= ep->tsession->test_spec.npackets){
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_recv: Invalid seq_no received: %lu",datarec.seq_no);
            goto error;
        }
#if NOT
OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_recv: seq_no received: %lu",datarec.seq_no);
#endif

        //
        // If it is no-longer in the buffer, than we ignore
        // it.
        ///
        if(datarec.seq_no < ep->begin->seq)
            goto again;

        //
        // What time did we expect the sender to send the packet?
        ///
        if(!(node = get_node(ep,datarec.seq_no))){
            print_debug("ERROR");
            debug_assert(0);
            goto error;
        }
        (void)OWPTimespecToTimestamp(&expecttime,&node->absolute,
                                     NULL,NULL);
        //
        // What time did sender send this packet?
        ///
        _OWPDecodeTimeStamp(&datarec.send,(uint8_t *)tstamp);
        if(!_OWPDecodeTimeStampErrEstimate(&datarec.send,(uint8_t *)tstamperr)){
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Invalid send timestamp!");
            goto error;
        }

        //
        // Now we can start the validity tests from Section 4.2 of
        // the spec...
        // MUST discard if:
        ///

        //
        // 1.
        // Send timestamp is more than timeout in past or future.
        // (i.e. send/recv differ by more than "timeout")
        ///
        if(OWPNum64Diff(datarec.send.owptime,datarec.recv.owptime) >
                ep->tsession->test_spec.loss_timeout){
            goto again;
        }
#if NOT
OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_recv: seq_no passed 1: %lu",datarec.seq_no);
#endif

        //
        // 2.
        // Send timestamp differs by more than "timeout" from
        // "scheduled" send time.
        ///
        if(OWPNum64Diff(datarec.send.owptime,expecttime.owptime) >
                ep->tsession->test_spec.loss_timeout){
            goto again;
        }
#if NOT
OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_recv: seq_no passed 2: %lu",datarec.seq_no);
#endif

        //
        // Made it through all validity tests. Record the packet!
        ///
        node->hit = True;

        print_detailed("Write Data Record");
        debug_assert(ep->datafile);
        if( !OWPWriteDataRecord(ep->cntrl->ctx,ep->datafile,
                    &datarec)){
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPWriteDataRecord()");
            debug_assert(0);
            goto error;
        }
#if NOT
OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_recv: seq_no recorded: %lu",datarec.seq_no);
#endif
    }

test_over:
    print_detailed("@> test_over");

    //
    // Set the "finished" bit in the file to "incomplete". The parent
    // process will change this to "normal" after evaluating the
    // data from the stop sessions message.
    ///
    print_detailed("write WriteData Header datafile");
    print_detailed("write incomplete, parent process will change to normal after stop sessions");
    if( !_OWPWriteDataHeaderFinished(ep->cntrl->ctx,ep->datafile,finished,0)){
        print_detailed("ERROR");
        debug_assert(0);
        goto error;
    }
    debug_assert(ep->datafile);
    print_detailed("flushing ep->datafile");
    fflush(ep->datafile);
    fsync(fileno(ep->datafile));
    pperror("fsync");

    print_debug("EXIT OWP_CNTRL_ACCEPT");
    return OWP_CNTRL_ACCEPT;

error:
    print_detailed("@> error");

    if(ep->datafile){
        print_detailed("Writing data header finished");
        (void)_OWPWriteDataHeaderFinished(ep->cntrl->ctx,ep->datafile,
                                          OWP_SESSION_FINISHED_ERROR,0);
        print_detailed("flushing ep->datafile");
        // TODO/NOTE: two opens for threads?
        fflush(ep->datafile);
        fsync(fileno(ep->datafile));
        pperror("fsync");
    }

    if(ep->userfile && (strlen(ep->fname) > 0)){
        print_detailed("unlink ep->fname");
        unlink(ep->fname);
    }

    //if(owp_int || ep->_owp_int){
    if( ep->_owp_int){
        print_detailed("owp_int || ep->_owp_int");
        OWPError(ep->cntrl->ctx,OWPErrINFO,OWPErrUNKNOWN,
                "run_receiver: Exiting from signal");
    }

    return OWP_CNTRL_FAILURE;
}

// TODO: this function needs more testing
static int
run_reflector(
        OWPEndpoint ep
        )
{
    print_detailed("");
    struct timespec     currtime;
    struct itimerval    wake;
    uint32_t            *seq;
    uint32_t            clr_mem[24]; // 6 blocks
    char                *clr_buffer = (char *)clr_mem; // legal type pun ;)
    char                *tstamp;
    char                *tstamperr;
    char                *hmac;
    char                *padding;
    uint32_t            esterror,lasterror=0;
    uint32_t            recv_lasterror=0;
    uint8_t             sync;
    struct sockaddr     *lsaddr;
    socklen_t           lsaddrlen;
    struct sockaddr     *rsaddr;
    socklen_t           rsaddrlen;
    uint32_t            *reply_seq;
    char                *reply_tstamp;
    char                *reply_tstamperr;
    char                *reply_rcv_tstamp;
    uint32_t            *reply_snd_seq;
    char                *reply_snd_tstamp;
    char                *reply_snd_tstamperr;
    char                *reply_snd_ttl;
    char                *reply_hmac;
    char                *reply_padding;
    uint8_t             iv[16];
    OWPTimeStamp        owptstamp;
    int                 r;
    int                 sent;
    int                 i;
    char                snd_tstamp_val[8];
    uint32_t            snd_seq_val;
    uint16_t            snd_tstamperr_val;
    OWPTimeStamp        recv_tstamp;
    uint8_t             ttl;
    size_t              snd_payload_len;
    uint32_t            testtimeout;

    print_debug("creating timerfd");
    if (ep->timerfd == -1){
        ep->timerfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
        if (ep->timerfd <= 0){
            print_debug("ERROR");
            pperror("timerfd_create");
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR; // EPOLLET EPOLLHUP EPOLLERR
    ev.data.fd = ep->timerfd;
    if (epoll_ctl(ep->epollfd, EPOLL_CTL_ADD, ep->timerfd, &ev) == -1) {
        pperror("epoll_ctl: timerfd");
        print_debug("errno %i", errno);
        if (errno == EEXIST){
        }else {
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }


    if( !(lsaddr = I2AddrSAddr(ep->tsession->sender,&lsaddrlen))){
        print_debug("ERROR");
        return OWP_CNTRL_FAILURE;
    }

    if( !(lsaddr = I2AddrSAddr(ep->tsession->receiver,&lsaddrlen))){
        print_debug("ERROR");
        return OWP_CNTRL_FAILURE;
    }

    //
    // Get pointer to lsaddr used for listening.
    ///
    if( !(lsaddr = I2AddrSAddr(ep->localaddr,&lsaddrlen))){
        print_debug("ERROR");
        return OWP_CNTRL_FAILURE;
    }
    //
    // Get pointer to rsaddr used to verify peer.
    ///
    if( !(rsaddr = I2AddrSAddr(ep->remoteaddr,&rsaddrlen))){
        print_debug("ERROR");
        return OWP_CNTRL_FAILURE;
    }

    memset(clr_buffer,0,96);

    //
    // Initialize pointers to various positions in the packet buffer.
    // (useful for the different "modes".)
    // Note: ep->payload has been allocated such that it can be reused
    // for the larger reply packet
    ///
    seq = (uint32_t*)&ep->payload[0];
    switch(ep->cntrl->mode){
    case OWP_MODE_OPEN:
    case TWP_MODE_MIXED:
        tstamp = &ep->payload[4];
        tstamperr = &ep->payload[12];
        hmac = NULL;
        padding = &ep->payload[14];

        reply_seq = (uint32_t*)&ep->payload[0];
        reply_tstamp = &ep->payload[4];
        reply_tstamperr = &ep->payload[12];
        reply_rcv_tstamp = &ep->payload[16];
        reply_snd_seq = (uint32_t*)&ep->payload[24];
        reply_snd_tstamp = &ep->payload[28];
        reply_snd_tstamperr = &ep->payload[36];
        reply_snd_ttl = &ep->payload[40];
        reply_hmac = NULL;
        reply_padding = &ep->payload[41];
        break;
    case OWP_MODE_AUTHENTICATED:
        tstamp = &ep->payload[16];
        tstamperr = &ep->payload[24];
        hmac = &ep->payload[32];
        padding = &ep->payload[48];

        reply_seq = (uint32_t*)&clr_buffer[0];
        reply_tstamp = &ep->payload[16];
        reply_tstamperr = &ep->payload[24];
        reply_rcv_tstamp = &ep->payload[32];
        reply_snd_seq = (uint32_t*)&ep->payload[48];
        reply_snd_tstamp = &ep->payload[64];
        reply_snd_tstamperr = &ep->payload[72];
        reply_snd_ttl = &ep->payload[80];
        reply_hmac = &ep->payload[96];
        reply_padding = &ep->payload[112];
        break;
    case OWP_MODE_ENCRYPTED:
        tstamp = &ep->payload[16];
        tstamperr = &ep->payload[24];
        hmac = &ep->payload[32];
        padding = &ep->payload[48];

        reply_seq = (uint32_t*)&clr_buffer[0];
        reply_tstamp = &clr_buffer[16];
        reply_tstamperr = &clr_buffer[24];
        reply_rcv_tstamp = &clr_buffer[32];
        reply_snd_seq = (uint32_t*)&clr_buffer[48];
        reply_snd_tstamp = &clr_buffer[64];
        reply_snd_tstamperr = &clr_buffer[72];
        reply_snd_ttl = &clr_buffer[80];
        reply_hmac = &ep->payload[96];
        reply_padding = &ep->payload[112];
        break;
    default:
        //
        // things would have failed way earlier
        // but putting default in to stop annoying
        // compiler warnings...
        ///
        print_debug("ERROR");
        return OWP_CNTRL_FAILURE;
    }

    //
    // Retrieve the test timeout - how long to wait for test packets
    ///
    if (! OWPContextConfigGetU32(ep->cntrl->ctx,TWPTestTimeout,&testtimeout)) {
        testtimeout = _TWP_DEFAULT_TEST_TIMEOUT;
    }

    //
    // initialize currtime for absolute to relative time conversion
    // needed by timers.
    ///
    if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
        print_debug("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Problem retrieving time");
        goto error;
    }

    i = 0;

    while(1){
        struct sockaddr_storage peer_addr;
        socklen_t               peer_addr_len;
again:
        print_debug("@> again");
        //
        // Set the REFWAIT timer.
        ///
        print_debug("Set the REFWAIT timer");
        tvalclear(&wake.it_value);
        wake.it_value.tv_sec = testtimeout;
        tvalclear(&wake.it_interval);
        //owp_alrm = 0;
        print_debug("setitimer wake %li owp_alrm = 0", wake.it_value.tv_sec);
        struct itimerspec  new_value;
        new_value.it_value.tv_sec = wake.it_value.tv_sec;
        new_value.it_value.tv_nsec = 0;
        new_value.it_interval.tv_sec = 0;
        new_value.it_interval.tv_nsec =0;

        print_debug("timerfd_settime");
        print_detailed("Setting timerfd, new_v  is %li %li", new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
        // TODO?
        //int ret = timerfd_settime(ep->timerfd, TFD_TIMER_CANCEL_ON_SET, &new_value, NULL);
        int ret = timerfd_settime(ep->timerfd, 0, &new_value, NULL);
        if (ret != 0){
            pperror("timerfd_settime");
            print_debug("timerfd_settime %i", ret);
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "setitimer(wake=%d,%d) seq=%lu: %M",
                    wake.it_value.tv_sec,wake.it_value.tv_usec,
                    ep->end->seq);
            goto error;
        }

        int sig = check_signals(ep, 0);
        if (sig != 0){
            if (sig == SIGUSR2){
                print_debug("owp_usr2 -- goto test_over");
                goto test_over;
            }
            print_debug("owp_int or owp_usr2 -- stop session");
            goto error;
        }


        print_detailed("calling is_data_available");
        int fd = is_data_available(ep, -1);
        print_detailed("is_data_available returned %i", fd);
        if (fd == ep->sockfd){
            print_debug("sockfd");
            peer_addr_len = sizeof(peer_addr);
            memset(&peer_addr,0,sizeof(peer_addr));

            print_debug("%i recvfromttl", ep->id);
            sig = check_signals(ep, 0);
            if (sig < 0){
                debug_assert(0);
                print_debug("signal error");
                goto error;
            }
            if(!ep->_owp_usr2 &&
                    (recvfromttl(ep->cntrl->ctx, ep->sockfd,
                        ep->payload,ep->len_payload,lsaddr,lsaddrlen,
                        (struct sockaddr*)&peer_addr,&peer_addr_len,
                        &ttl) != (ssize_t)ep->len_payload)){
                print_debug("!owp_usr2");
                if(errno != EINTR){
                    print_debug("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,
                            OWPErrUNKNOWN,"recvfromttl(): %M");
                    goto error;
                }else {
                    // TODO not sure about this?
                    debug_assert(0);
                }
            }
        } else if (fd == ep->timerfd){
            print_detailed("timerfd");
        } else if (fd == ep->eventfd){
            print_detailed("got eventfd");
            // TODO check_signals?
            if (ep->_owp_usr2){
                goto test_over;
            }
            goto error;
        } else {
            print_detailed("ERROR");
            debug_assert(0);
            goto error;
        }

        sig = check_signals(ep, 0);
        if (sig < 0){
            debug_assert(0);
            goto error;
        }
        if(ep->_owp_int){
            print_detailed("owp_int || owp_alrm");
            goto error;
        }
        if(ep->_owp_usr2){
            print_debug("owp_usr2 -- goto test_over");
            goto test_over;
        }

        //
        // Fetch time before ANYTHING else to minimize time errors.
        ///
        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            goto error;
        }

        //
        // Received a packet, so cancel REFWAIT timer.
        ///
        print_debug("received a packet, cancel REFWAIT timer");
        tvalclear(&wake.it_value);
        tvalclear(&wake.it_interval);
        print_debug("setitimer wake it_value %li %li it_interval %li %li", wake.it_value.tv_sec, wake.it_value.tv_usec,
                     wake.it_interval.tv_sec, wake.it_interval.tv_usec);

        //struct itimerspec  new_value;
        new_value.it_value.tv_sec = 0;
        new_value.it_value.tv_nsec = 0;
        new_value.it_interval.tv_sec = 0;
        new_value.it_interval.tv_nsec =0;

        print_detailed("Setting timerfd, new_v  is %li %li", new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
        ret = timerfd_settime(ep->timerfd, TFD_TIMER_CANCEL_ON_SET, &new_value, NULL);
        print_debug("timerfd_settime ret %i", ret);
        if (ret != 0){
            pperror("timerfdsettime");
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "setitimer(disable): %M");
            goto error;
        }

        //
        // Check signals...
        ///
        sig = check_signals(ep, 0);
        if (sig < 0){
            print_detailed("ERROR");
            debug_assert(0);
            goto error;
        }
        if( ep->_owp_int){
            print_debug("owp_int || ep->_owp_int");
            goto error;
        }
        if(ep->_owp_usr2){
            print_debug("owp_usr2 -- goto test_over");
            goto test_over;
        }

        //
        // Save that time as a timestamp
        ///
        (void)OWPTimespecToTimestamp(&recv_tstamp,&currtime,
                                     &esterror,&recv_lasterror);
        recv_lasterror = esterror;

        //
        // Check signals...
        ///
        sig = check_signals(ep, 0);
        if (sig < 0){
            print_detailed("ERROR");
            debug_assert(0);
            goto error;
        }
        if( ep->_owp_int){
            print_debug("ep->_owp_int");
            goto error;
        }
        if(ep->_owp_usr2){
            print_debug("owp_usr2 -- goto test_over");
            goto test_over;
        }

        //
        // Verify peer before looking at packet.
        ///
        if(I2SockAddrEqual(rsaddr,rsaddrlen,
                    (struct sockaddr*)&peer_addr,
                    peer_addr_len,I2SADDR_ALL) <= 0){
            goto again;
        }

#ifdef OWP_EXTRA_DEBUG
        {
            char remotenode[256];
            char remoteserv[256];

            r = getnameinfo((struct sockaddr *)&peer_addr,peer_addr_len,
                            remotenode,sizeof(remotenode),
                            remoteserv,sizeof(remoteserv),
                            NI_NUMERICSERV|NI_NUMERICSERV);
            if (r) {
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                         "Reflector: getnameinfo: %s",
                         gai_strerror(r));
                strcpy(remotenode, "unknown");
                strcpy(remoteserv, "unknown");
            }
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                     "Reflector packet from [%s]:%s",
                     remotenode,remoteserv);
        }
#endif

        //
        // Decrypt the packet if needed.
        ///
        if(ep->cntrl->mode & OWP_MODE_DOCIPHER_TEST){
            uint8_t iv[16];
            int     r;
            uint8_t hmacd[I2HMAC_SHA1_DIGEST_SIZE];

            //
            // Initialize HMAC and iv.
            ///
            memset(iv,0,sizeof(iv));
            I2HMACSha1Init(ep->hmac_ctx,ep->hmac_key,sizeof(ep->hmac_key));

            //
            // Decrypt first block
            ///
            r = blockDecrypt(iv,&ep->aeskey,(uint8_t *)&ep->payload[0],
                    16*8,(uint8_t *)&ep->payload[0]);
            if(r != (16*8)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "run_reflector: Invalid ECB decryption");
                goto error;
            }
            I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&ep->payload[0],16);


            if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
                //
                // Decrypt second block if full encrypted mode wanted
                // (CBC mode done by blockDecrypt)
                ///
                r = blockDecrypt(iv,&ep->aeskey,(uint8_t *)&ep->payload[16],
                        16*8,(uint8_t *)&ep->payload[16]);
                if(r != (16*8)){
                    print_debug("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "run_reflector: Invalid CBC decryption");
                    goto error;
                }
                I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&ep->payload[16],16);
            }

            memset(hmacd,0,sizeof(hmacd));
            I2HMACSha1Finish(ep->hmac_ctx,hmacd);
            if( (memcmp(hmac,hmacd,
                        MIN(_OWP_RIJNDAEL_BLOCK_SIZE,sizeof(hmacd))) != 0)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                        "run_reflector: Invalid HMAC on received packet: "
                        "ignoring");
                goto again;
            }
        }

        // Cache values before we reuse the payload
        snd_seq_val = *seq;
        memcpy(&snd_tstamp_val, tstamp, sizeof(snd_tstamp_val));
        memcpy(&snd_tstamperr_val, tstamperr, sizeof(snd_tstamperr_val));

        // send-packet

        snd_payload_len = MAX(ep->len_payload, OWPTestTWPayloadSize(
                                  ep->cntrl->mode, 0));

        if (ep->len_payload > reply_padding - ep->payload) {
            memmove(reply_padding, padding, ep->len_payload - (reply_padding - ep->payload));
        }
        // Reset payload to 0 for MBZ fields
        memset(ep->payload, 0, reply_padding - ep->payload);

        *reply_seq = htonl(i);
        _OWPEncodeTimeStamp((uint8_t *)reply_rcv_tstamp,&recv_tstamp);
        *reply_snd_seq = snd_seq_val;
        memcpy(reply_snd_tstamp, &snd_tstamp_val, sizeof(snd_tstamp_val));
        memcpy(reply_snd_tstamperr, &snd_tstamperr_val, sizeof(snd_tstamperr_val));
        *reply_snd_ttl = ttl;

RETRY:
        print_debug("@> RETRY");
        //
        // Fetch time again for the reply timestamp
        ///
        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            goto error;
        }

        (void)OWPTimespecToTimestamp(&owptstamp,&currtime,
                                     &esterror,&lasterror);
        lasterror = esterror;
        owptstamp.sync = sync;
        _OWPEncodeTimeStamp((uint8_t *)reply_tstamp,&owptstamp);
        if(!_OWPEncodeTimeStampErrEstimate((uint8_t *)reply_tstamperr,
                                           &owptstamp)){
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,
                     OWPErrUNKNOWN,
                     "Invalid Timestamp Error");
            owptstamp.multiplier = 0xFF;
            owptstamp.scale = 0x3F;
            owptstamp.sync = 0;
            (void)_OWPEncodeTimeStampErrEstimate((uint8_t *)reply_tstamperr,
                                                 &owptstamp);
        }

        //
        // blockEncrypt does CBC mode. Can still use this function for
        // both authenticated and encrypted mode because CBC with iv=0
        // of one block is identical to ECB of one block. Then iv is
        // ready for the next block in the case of encrypted mode.
        ///
        if(ep->cntrl->mode & OWP_MODE_DOCIPHER_TEST){
            //
            // Initialize HMAC for this packet, and first block to it.
            ///
            I2HMACSha1Init(ep->hmac_ctx,ep->hmac_key,sizeof(ep->hmac_key));
            I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&clr_buffer[0],16);

            //
            // Initialize IV and encrypt the first block
            ///
            memset(iv,0,sizeof(iv));
            r = blockEncrypt(iv,&ep->aes_tw_reply_key,(uint8_t *)&clr_buffer[0],16*8,
                    (uint8_t *)&ep->payload[0]);
            if(r != (16*8)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "run_reflector: Invalid ECB encryption of seq (#%ul)",i);
                return OWP_CNTRL_FAILURE;
            }
        }

        //
        // For ENCRYPTED mode, we have to encrypt the subsequent 5
        // blocks after fetching the timestamp. (CBC mode)
        ///
        if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
            //
            // Append subsequent 5 blocks to HMAC
            ///
            I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&clr_buffer[16],80);

            //
            // Encrypt subsequent 5 blocks
            ///
            r = blockEncrypt(iv,&ep->aes_tw_reply_key,(uint8_t *)&clr_buffer[16],80*8,
                             (uint8_t *)&ep->payload[16]);
            if(r != (80*8)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "run_reflector: Invalid CBC encryption of seq (#%ul)",
                         i);
                return OWP_CNTRL_FAILURE;
            }
        }

        if(reply_hmac){
            uint8_t hmacd[I2HMAC_SHA1_DIGEST_SIZE];

            memset(hmacd,0,sizeof(hmacd));
            I2HMACSha1Finish(ep->hmac_ctx,hmacd);
            memcpy(reply_hmac,hmacd,MIN(16,I2HMAC_SHA1_DIGEST_SIZE));
        }

        sig = check_signals(ep, 0);
        if (sig < 0){
            print_detailed("ERROR");
            debug_assert(0);
            goto error;
        }
        if( ep->_owp_usr2 || ep->_owp_int){
            print_debug("ERROR");
            print_debug("_owp_usr2  || ep->_owp_int-- goto err");
            goto error;
        }

        print_debug("sendto");
        if( (sent = sendto(ep->sockfd,ep->payload,
                           snd_payload_len,0,
                           (struct sockaddr*)&peer_addr,peer_addr_len)) < 0){
            switch(errno){
                // retry errors
            case ENOBUFS:
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "run_reflector: no buffer space (#%ul)",i);
                goto RETRY;
                break;
                // fatal errors
            case EBADF:
            case EACCES:
            case ENOTSOCK:
            case EFAULT:
            case EAGAIN:
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "Unable to send([%s]:%s:(#%d): %M",
                         "","",i);
                return OWP_CNTRL_FAILURE;
                break;
                // ignore everything else
            default:
                break;
            }

            // but do note it as INFO for debugging
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrINFO,OWPErrUNKNOWN,
                     "Unable to send([%s]:%s:(#%d): %M",
                     "","",i);
        }
        i++;

    }

test_over:
    print_debug("@> test_over");

    print_debug("EXIT OWP_CNTRL_ACCEPT");
    return OWP_CNTRL_ACCEPT;

error:
    print_debug("@ error");

    return OWP_CNTRL_FAILURE;
}

//
// Function:        run_tw_test
//
// Description:
//                 This function is the main processing function for a "two-way test"
//                 sub-process.
//
// In Args:
//
// Out Args:
//
// Scope:
// Returns:
// Side Effect:
///
// TODO this function needs more testing
// TODO might need more timers?
static int
run_tw_test(
        OWPEndpoint ep
        )
{
    print_detailed("");
    struct sockaddr *lsaddr;
    socklen_t       lsaddrlen;
    struct sockaddr *rsaddr;
    socklen_t       rsaddrlen;
    char            nodename[NI_MAXHOST];
    size_t          nodenamelen = sizeof(nodename);
    char            nodeserv[NI_MAXSERV];
    size_t          nodeservlen = sizeof(nodeserv);
    uint32_t        i;
    struct timespec currtime;
    struct timespec nexttime;
    struct timespec timeout;
    struct timespec latetime;
    struct timespec sleeptime;
    struct itimerval wake;
    uint32_t        esterror;
    uint32_t        lasterror=0;
    uint8_t         sync;
    ssize_t         sent;
    uint32_t        *seq;
    uint32_t        clr_mem[8]; // two blocks
    char            *clr_buffer = (char *)clr_mem; // legal type pun ;)
    uint8_t         iv[16];
    char            *padding;
    char            *tstamp;
    char            *tstamperr;
    char            *hmac;
    OWPTimeStamp    owptstamp;
    int             r;
    size_t          resp_len_payload;
    struct sockaddr_storage peer_addr;
    socklen_t       peer_addr_len;
    uint32_t        *reply_seq;
    char            *reply_tstamp;
    char            *reply_tstamperr;
    char            *reply_rcv_tstamp;
    uint32_t        *reply_snd_seq;
    char            *reply_snd_tstamp;
    char            *reply_snd_tstamperr;
    char            *reply_snd_ttl;
    char            *reply_hmac;
    ssize_t         resp_len;
    OWPSessionHeaderRec hdr;
    OWPTWDataRec    twdatarec;
    OWPLostPacket node;
    int flush_rc;

    if (ep->timerfd == -1){
        ep->timerfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
        if (ep->timerfd <= 0){
            print_detailed("ERROR");
            pperror("timerfd_create");
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR; // EPOLLET EPOLLHUP EPOLLERR
    ev.data.fd = ep->timerfd;
    if (epoll_ctl(ep->epollfd, EPOLL_CTL_ADD, ep->timerfd, &ev) == -1) {
        pperror("epoll_ctl: timerfd");
        print_debug("errno %i", errno);
        if (errno == EEXIST){
        }else {
            debug_assert(0);
            return OWP_CNTRL_FAILURE;
        }
    }

    //
    // Get pointer to lsaddr used for listening.
    ///
    if( !(lsaddr = I2AddrSAddr(ep->localaddr,&lsaddrlen))){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                 "run_tw_test: Unable to extract local saddr information");
        return OWP_CNTRL_FAILURE;
    }

    if( !(rsaddr = I2AddrSAddr(ep->remoteaddr,&rsaddrlen)) ||
                (getnameinfo(rsaddr, rsaddrlen, nodename, nodenamelen,
                             nodeserv, nodeservlen,
                             NI_NUMERICHOST | NI_NUMERICSERV) != 0)){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                 "run_tw_test: Unable to extract remote saddr information");
        return OWP_CNTRL_FAILURE;
    }

    //
    // Prepare the file header - had to wait until now to
    // get the real starttime.
    ///
    memset(&hdr,0,sizeof(hdr));
    hdr.twoway = True;
    hdr.finished = OWP_SESSION_FINISHED_INCOMPLETE;
    memcpy(&hdr.sid,ep->tsession->sid,sizeof(hdr.sid));
    hdr.conf_sender = ep->tsession->conf_sender;
    hdr.conf_receiver = ep->tsession->conf_receiver;
    hdr.test_spec = ep->tsession->test_spec;
    memcpy(&hdr.addr_sender,lsaddr,lsaddrlen);
    memcpy(&hdr.addr_receiver,rsaddr,rsaddrlen);

    //
    // Write the file header.
    ///
    debug_assert(ep->datafile);
    if( !OWPWriteDataHeader(ep->cntrl->ctx,ep->datafile,&hdr)){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                 "run_tw_test: Unable to write data file header");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }

    //
    // Initialize pointers to various positions in the packet buffer,
    // for data that changes for each packet. Also set zero padding.
    ///
    memset(clr_buffer,0,32);

    switch(ep->cntrl->mode){
        case OWP_MODE_OPEN:
        case TWP_MODE_MIXED:
            seq = (uint32_t*)&ep->payload[0];
            tstamp = &ep->payload[4];
            tstamperr = &ep->payload[12];
            hmac = NULL;
            padding = &ep->payload[14];
            break;
        case OWP_MODE_AUTHENTICATED:
            seq = (uint32_t*)&clr_buffer[0];
            tstamp = &ep->payload[16];
            tstamperr = &ep->payload[24];
            hmac = &ep->payload[32];
            padding = &ep->payload[48];
            break;
        case OWP_MODE_ENCRYPTED:
            seq = (uint32_t*)&clr_buffer[0];
            tstamp = &clr_buffer[16];
            tstamperr = &clr_buffer[24];
            hmac = &ep->payload[32];
            padding = &ep->payload[48];
            break;
        default:
            //
            // things would have failed way earlier
            // but put default in to stop annoying
            // compiler warnings...
            ///
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "run_tw_test: Bogus \"mode\" bits");
            return OWP_CNTRL_FAILURE;
    }

    switch(ep->cntrl->mode){
    case OWP_MODE_OPEN:
    case TWP_MODE_MIXED:
        reply_seq = (uint32_t*)&ep->payload[0];
        reply_tstamp = &ep->payload[4];
        reply_tstamperr = &ep->payload[12];
        reply_rcv_tstamp = &ep->payload[16];
        reply_snd_seq = (uint32_t*)&ep->payload[24];
        reply_snd_tstamp = &ep->payload[28];
        reply_snd_tstamperr = &ep->payload[36];
        reply_snd_ttl = &ep->payload[40];
        reply_hmac = NULL;
        break;
    case OWP_MODE_AUTHENTICATED:
    case OWP_MODE_ENCRYPTED:
        reply_seq = (uint32_t*)&ep->payload[0];
        reply_tstamp = &ep->payload[16];
        reply_tstamperr = &ep->payload[24];
        reply_rcv_tstamp = &ep->payload[32];
        reply_snd_seq = (uint32_t*)&ep->payload[48];
        reply_snd_tstamp = &ep->payload[64];
        reply_snd_tstamperr = &ep->payload[72];
        reply_snd_ttl = &ep->payload[80];
        reply_hmac = &ep->payload[96];
        break;
    default:
        //
        // things would have failed way earlier
        // but put default in to stop annoying
        // compiler warnings...
        ///
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                 "run_tw_test: Bogus \"mode\" bits");
        return OWP_CNTRL_FAILURE;
    }

    i=0;

    //
    // initialize tspec version of "timeout"
    ///
    OWPNum64ToTimespec(&timeout,ep->tsession->test_spec.loss_timeout);

    //
    // Ensure schedule generation is starting at first packet in
    // series.
    ///
    if(OWPScheduleContextReset(ep->tsession->sctx,NULL,NULL) != OWPErrOK){
        print_detailed("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "ScheduleContextReset: FAILED");
        debug_assert(0);
        return OWP_CNTRL_FAILURE;
    }

    //
    // Initialize packet buffer with first node
    ///
    ep->begin = ep->end = alloc_node(ep,0);
    if(!ep->begin){
        print_detailed("ERROR");
        return OWP_CNTRL_FAILURE;
    }

    ep->begin->relative = OWPScheduleContextGenerateNextDelta(
            ep->tsession->sctx);
    // just using owptstamp as a temp var here.
    owptstamp.owptime = OWPNum64Add(ep->begin->relative,
            ep->tsession->test_spec.start_time);
    (void)OWPTimestampToTimespec(&ep->begin->absolute,&owptstamp);

    do{
        //
        // First setup "this" packet. calloc() used to allocate ep->payload,
        // so padding will already be zero. Just leave it if zero payload
        // is required.
        ///
#if !defined(OWP_ZERO_TEST_PAYLOAD)
        (void)I2RandomBytes(ep->cntrl->ctx->rand_src,(uint8_t *)padding,
                            ep->tsession->test_spec.packet_size_padding);
#endif

        if(!(node = get_node(ep,i))){
            print_detailed("ERROR");
            goto finish_sender;
        }
        OWPNum64ToTimespec(&nexttime,node->relative);
        timespecadd(&nexttime,&ep->start);
        *seq = htonl(i);

        //
        // blockEncrypt does CBC mode. Can still use this function for
        // both authenticated and encrypted mode because CBC with iv=0
        // of one block is identical to ECB of one block. Then iv is
        // ready for the next block in the case of encrypted mode.
        ///
RETRY:
        print_detailed("@> RETRY");
        if(ep->cntrl->mode & OWP_MODE_DOCIPHER_TEST){
            //
            // Initialize HMAC for this packet, and first block to it.
            ///
            I2HMACSha1Init(ep->hmac_ctx,ep->hmac_key,sizeof(ep->hmac_key));
            I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&clr_buffer[0],16);

            //
            // Initialize IV and encrypt the first block
            ///
            memset(iv,0,sizeof(iv));
            r = blockEncrypt(iv,&ep->aeskey,(uint8_t *)&clr_buffer[0],16*8,
                    (uint8_t *)&ep->payload[0]);
            if(r != (16*8)){
                print_detailed("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "run_tw_test: Invalid ECB encryption of seq (#%ul)",i);
                return OWP_CNTRL_FAILURE;
            }
        }

AGAIN:
        print_detailed("@> AGAIN");
        int sig = check_signals(ep, 0);
        if (sig < 0){
            print_detailed("ERROR");
            debug_assert(0);
            goto error;
        }
        if( ep->_owp_usr2 || ep->_owp_int){
            print_detailed("owp_int || owp_usr2  || ep->_owp_int-- jump to finish_sender");
            goto finish_sender;
        }

        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            print_detailed("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Problem retrieving time");
            return OWP_CNTRL_FAILURE;
        }

        //
        // If current time is greater than next send time...
        ///
        if(timespeccmp(&currtime,&nexttime,>)){

            //
            // If current time is more than "timeout" past next
            // send time, then skip actually sending.
            ///
            latetime = timeout;
            timespecadd(&latetime,&nexttime);
            if(timespeccmp(&currtime,&latetime,>)){
#ifdef OWP_EXTRA_DEBUG
                print_detailed("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                         "run_tw_test: missed send time (not sent): seq %u",i);
#endif
                //
                // Pretend it was sent and received so that it will
                // be flushed from the packet buffer
                ///
                node->sent = True;
                node->hit = True;
                goto SKIP_SEND;
            }

            // send-packet

            (void)OWPTimespecToTimestamp(&owptstamp,&currtime,
                                         &esterror,&lasterror);
            lasterror = esterror;
            owptstamp.sync = sync;
            _OWPEncodeTimeStamp((uint8_t *)tstamp,&owptstamp);
            if(!_OWPEncodeTimeStampErrEstimate((uint8_t *)tstamperr,
                        &owptstamp)){
                print_detailed("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,
                        OWPErrUNKNOWN,
                        "Invalid Timestamp Error");
                owptstamp.multiplier = 0xFF;
                owptstamp.scale = 0x3F;
                owptstamp.sync = 0;
                (void)_OWPEncodeTimeStampErrEstimate((uint8_t *)tstamperr,
                                                     &owptstamp);
            }

            //
            // For ENCRYPTED mode, we have to encrypt the second
            // block after fetching the timestamp. (CBC mode)
            ///
            if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
                //
                // Append second block to HMAC (timestamp block)
                ///
                I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&clr_buffer[16],16);

                //
                // Encrypt second block
                ///
                r = blockEncrypt(iv,&ep->aeskey,(uint8_t *)&clr_buffer[16],16*8,
                        (uint8_t *)&ep->payload[16]);
                if(r != (16*8)){
                    print_detailed("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "run_tw_test: Invalid CBC encryption of seq (#%ul)",
                            i);
                    return OWP_CNTRL_FAILURE;
                }
            }

            if(hmac){
                uint8_t hmacd[I2HMAC_SHA1_DIGEST_SIZE];

                memset(hmacd,0,sizeof(hmacd));
                I2HMACSha1Finish(ep->hmac_ctx,hmacd);
                memcpy(hmac,hmacd,MIN(16,I2HMAC_SHA1_DIGEST_SIZE));
            }

            sig = check_signals(ep, 0);
            if (sig < 0){
                print_detailed("ERROR");
                debug_assert(0);
                goto error;
            }
            if( ep->_owp_usr2 || ep->_owp_int){
                print_detailed("owp_int || ep->_owp_usr2 -- jump to finish_sender");
                goto finish_sender;
            }

            print_detailed("sendto");
            if( (sent = sendto(ep->sockfd,ep->payload,
                            ep->len_payload,0,rsaddr,rsaddrlen)) < 0){
                switch(errno){
                    // retry errors
                    case ENOBUFS:
                        goto RETRY;
                        break;
                        // fatal errors
                    case EBADF:
                    case EACCES:
                    case ENOTSOCK:
                    case EFAULT:
                    case EAGAIN:
                        print_detailed("ERROR");
                        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                "Unable to send([%s]:%s:(#%d): %M",
                                nodename,nodeserv,i);
                        return OWP_CNTRL_FAILURE;
                        break;
                    case EINTR:
                        print_detailed("EINTR");
                        goto SKIP_SEND;
                        // ignore everything else
                    default:
                        break;
                }

                // but do note it as INFO for debugging
                print_detailed("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                        "Unable to send([%s]:%s:(#%d): %M",
                        nodename,nodeserv,i);
            }
            node->sent = True;
            node->absolute = currtime;

RECEIVE:
            sig = check_signals(ep, 0);
            if (sig < 0){
                print_detailed("ERROR");
                debug_assert(0);
                goto error;
            }
            if( ep->_owp_usr2 || ep->_owp_int){
                print_detailed("owp_int || ep->_owp_usr2 -- jump to finish_sender");
                goto finish_sender;
            }

            //
            // Set the timer.
            ///
            // TODO which timer?
            tvalclear(&wake.it_interval);
            wake.it_value.tv_sec = timeout.tv_sec;
            wake.it_value.tv_usec = timeout.tv_nsec / 1000;
            print_detailed("Set the timer wake %li %li", wake.it_value.tv_sec, wake.it_value.tv_usec);

            // How long do we have till the next send?
            if(i < ep->tsession->test_spec.npackets - 1){
                node = get_node(ep, i+1);
                OWPNum64ToTimespec(&nexttime,node->relative);
                timespecadd(&nexttime,&ep->start);

                // Next send is already late?
                if(timespeccmp(&nexttime,&currtime,<)){
                    goto SKIP_SEND;
                }

                // Next send real soon now?
                sleeptime = nexttime;
                timespecsub(&sleeptime,&currtime);
                if(sleeptime.tv_sec == 0 && sleeptime.tv_nsec < 1000000){
                    goto SKIP_SEND;
                }

                // Set timer till next send (but not longer than timeout)
                if(timespeccmp(&sleeptime,&timeout,<)){
                    print_detailed("set the timer til next send but not longer than timeout");
                    wake.it_value.tv_sec = sleeptime.tv_sec;
                    wake.it_value.tv_usec = sleeptime.tv_nsec / 1000;
                }
            }

            print_detailed("setitimer wake %li %li", wake.it_value.tv_sec, wake.it_value.tv_usec);

            struct itimerspec  new_value;
            new_value.it_value.tv_sec = wake.it_value.tv_sec;
            new_value.it_value.tv_nsec = wake.it_value.tv_usec * 1000;
            new_value.it_interval.tv_sec = 0;
            new_value.it_interval.tv_nsec =0;
            print_detailed("timerfd_settime");
            print_detailed("Setting timerfd, new_v  is %li %li", new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
            // TODO?
            //int ret = timerfd_settime(ep->timerfd, TFD_TIMER_CANCEL_ON_SET, &new_value, NULL);
            int ret = timerfd_settime(ep->timerfd, 0, &new_value, NULL);
            if (ret != 0){
                pperror("timerfd_settime");
                debug_assert(0);
                print_detailed("timerfd_settime returned %i", ret);
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setitimer(wake=%d,%d) seq=%lu: %M",
                        wake.it_value.tv_sec,wake.it_value.tv_usec,
                        ep->end->seq);
                goto error;
            }

            //
            // Note: ep->payload has been allocated such that it can
            // be reused for the larger reply packet
            ///
            resp_len_payload = ep->len_payload +
                (OWPTestTWPayloadSize(ep->cntrl->mode,0) -
                 OWPTestPayloadSize(ep->cntrl->mode,0));
            peer_addr_len = sizeof(peer_addr);
            memset(&peer_addr,0,sizeof(peer_addr));

            print_detailed("calling is_data_available");
            // TODO probably shouldn't set timeout?
            int fd  = is_data_available(ep, -1);
            print_detailed("is_data_available returned %i", fd);
            if (fd == ep->sockfd)
            {
                print_detailed("calling recvfromttl sockfd %i", ep->sockfd);
                resp_len = recvfromttl(ep->cntrl->ctx, ep->sockfd,
                                       ep->payload,resp_len_payload,lsaddr,lsaddrlen,
                                       (struct sockaddr*)&peer_addr,&peer_addr_len,
                                       &twdatarec.reflected.ttl);
                print_detailed("expecting resp_len %li to equal resp_len_payload %li", resp_len, resp_len_payload);

                // TODO?
                // ORIGINAL: if(resp_len != resp_len_payload && errno != EINTR){
                if(resp_len < 0){
                    // TODO might hang?
                    pperror("resp_len != resp_len_payload");
                    print_detailed("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,
                             OWPErrUNKNOWN,"recvfromttl(): %M");
                    goto finish_sender;
                }

                // TODO not sure about this?
                if(resp_len != resp_len_payload){
                    pperror("resp_len != resp_len_payload");
                    // TODO checks if errno is interrupt?
                    //if (errno != EINTR){
                    //    print_detailed("ERROR");
                    //    OWPError(ep->cntrl->ctx,OWPErrFATAL,
                    //             OWPErrUNKNOWN,"recvfromttl(): %M");
                    //    goto finish_sender;
                    //}
                }
            } else if (fd == ep->timerfd) {
                // TODO not sure about this?
                print_detailed("timer  -- hmm interrupt");
                //goto finish_sender;
            } else if (fd == ep->eventfd) {
                // TODO not sure about this?
                print_detailed("got signal, goto finish sender");
                goto finish_sender;
            } else {
                print_detailed("unknown");
                debug_assert(0);
                goto error;
            }

            // TODO this is just a double check, can remove in the future
            sig = check_signals(ep, 0);
            if (sig < 0){
                print_detailed("ERROR");
                debug_assert(0);
                goto error;
            }
            if( ep->_owp_usr2 || ep->_owp_int){
                print_detailed("owp_int || owp_usr2 -- jump to finish_sender");
                goto finish_sender;
            }

            //
            // Fetch time before ANYTHING else to minimize time errors.
            ///
            if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
                print_detailed("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "Problem retrieving time");
                goto finish_sender;
            }
            //
            // Save that time as a timestamp
            ///
            (void)OWPTimespecToTimestamp(&twdatarec.reflected.recv,&currtime,
                                         &esterror,NULL);
            twdatarec.reflected.recv.sync = sync;

            //
            // Received a packet, so cancel timeout timer.
            ///
            tvalclear(&wake.it_value);
            tvalclear(&wake.it_interval);
            print_detailed("received a packet, so cancel timeout timer");
            print_detailed("setitimer wake %li %li", wake.it_value.tv_sec, wake.it_value.tv_usec);
            new_value.it_value.tv_sec = 0;
            new_value.it_value.tv_nsec = 0;
            new_value.it_interval.tv_sec = 0;
            new_value.it_interval.tv_nsec =0;
            print_detailed("Setting timerfd, new_v  is %li %li", new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
            //ret = timerfd_settime(ep->timerfd, TFD_TIMER_CANCEL_ON_SET, &new_value, NULL);
            ret = timerfd_settime(ep->timerfd, TFD_TIMER_CANCEL_ON_SET, &new_value, NULL);
            print_detailed("timerfd_settime ret %i", ret);
            if (ret != 0){
                pperror("timerfdsettime");
                print_detailed("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "setitimer(disable): %M");
                goto error;
            }

            //
            // Flush buffer of packets that have reached their timeout
            ///
            print_debug("flush buffer of packets that have reached their timeout");
            flush_rc = flush_lost(ep,&currtime,&timeout,&twdatarec.reflected.recv);
            if(flush_rc < 0){
                print_debug("ERROR");
                goto error;
            }
            else if(flush_rc > 0){
                print_debug("goto FINISH_SENDER");
                goto finish_sender;
            }

            //
            // If we didn't actually receive anything then just skip
            // to process the next packet
            ///
            if(resp_len < OWPTestTWPayloadSize(ep->cntrl->mode, 0)){
                goto SKIP_SEND;
            }

            //
            // Decrypt the packet if needed.
            ///
            if(ep->cntrl->mode & OWP_MODE_DOCIPHER_TEST){
                uint8_t iv[16];
                int     r;
                uint8_t hmacd[I2HMAC_SHA1_DIGEST_SIZE];

                //
                // Initialize HMAC and iv.
                ///
                memset(iv,0,sizeof(iv));
                I2HMACSha1Init(ep->hmac_ctx,ep->hmac_key,sizeof(ep->hmac_key));

                //
                // Decrypt first block
                ///
                r = blockDecrypt(iv,&ep->aes_tw_reply_key,(uint8_t *)&ep->payload[0],
                                 16*8,(uint8_t *)&ep->payload[0]);
                if(r != (16*8)){
                    print_debug("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                             "run_tw_test: Invalid ECB decryption");
                    goto SKIP_SEND;
                }
                I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&ep->payload[0],16);

                if(ep->cntrl->mode & OWP_MODE_ENCRYPTED){
                    //
                    // Decrypt subsequent blocks if full encrypted mode wanted
                    // (CBC mode done by blockDecrypt)
                    ///
                    r = blockDecrypt(iv,&ep->aes_tw_reply_key,(uint8_t *)&ep->payload[16],
                                     80*8,(uint8_t *)&ep->payload[16]);
                    if(r != (80*8)){
                        print_debug("ERROR");
                        OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                 "run_tw_test: Invalid CBC decryption");
                        goto SKIP_SEND;
                    }
                    I2HMACSha1Append(ep->hmac_ctx,(uint8_t *)&ep->payload[16],80);
                }

                memset(hmacd,0,sizeof(hmacd));
                I2HMACSha1Finish(ep->hmac_ctx,hmacd);
                if( (memcmp(reply_hmac,hmacd,
                            MIN(_OWP_RIJNDAEL_BLOCK_SIZE,sizeof(hmacd))) != 0)){
                    print_debug("ERROR");
                    OWPError(ep->cntrl->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                             "run_tw_test: Invalid HMAC on received packet: "
                             "ignoring");
                    goto SKIP_SEND;
                }
            }

#ifdef OWP_EXTRA_DEBUG
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                     "run_tw_test: packet received: seq %u, sender seq %u, size %u",
                     ntohl(*reply_seq), ntohl(*reply_snd_seq), resp_len);
#endif

            //
            // Retrieve reflected sender sequence number
            ///
            twdatarec.sent.seq_no = ntohl(*reply_snd_seq);
            if(twdatarec.sent.seq_no > i){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "Invalid reflected sender sequence number!");
                goto finish_sender;
            }

            //
            // If we received a packet that has already timed out
            // and been flushed from the buffer just go back to
            // receive another packet
            ///
            if(twdatarec.sent.seq_no < ep->begin->seq){
#ifdef OWP_EXTRA_DEBUG
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                         "run_tw_test: packet discarded: seq %u, sender seq %u, size %u",
                         ntohl(*reply_seq), ntohl(*reply_snd_seq), resp_len);
#endif
                goto RECEIVE;
            }

            //
            // What time did sender send this packet?
            ///
            _OWPDecodeTimeStamp(&twdatarec.sent.send,(uint8_t *)reply_snd_tstamp);
            if(!_OWPDecodeTimeStampErrEstimate(&twdatarec.sent.send,(uint8_t *)reply_snd_tstamperr)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "Invalid sent send timestamp!");
                goto finish_sender;
            }
            _OWPDecodeTimeStamp(&twdatarec.sent.recv,(uint8_t *)reply_rcv_tstamp);
            if(!_OWPDecodeTimeStampErrEstimate(&twdatarec.sent.recv,(uint8_t *)reply_tstamperr)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "Invalid sent recv timestamp!");
                goto finish_sender;
            }
            twdatarec.sent.ttl = *reply_snd_ttl;

            twdatarec.reflected.seq_no = ntohl(*reply_seq);
            _OWPDecodeTimeStamp(&twdatarec.reflected.send,(uint8_t *)reply_tstamp);
            if(!_OWPDecodeTimeStampErrEstimate(&twdatarec.reflected.send,(uint8_t *)reply_tstamperr)){
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "Invalid reflected send timestamp!");
                goto finish_sender;
            }

            debug_assert(ep->datafile);
            print_detailed("about to OWPWriteTWDataRecord");
            if( !OWPWriteTWDataRecord(ep->cntrl->ctx,ep->datafile,
                                      &twdatarec)){
                print_debug("ERROR");
                debug_assert(0);
                OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "OWPWriteTWDataRecord()");
                goto finish_sender;
            }

            //
            // Retrieve node from buffer for the received sender
            // sequence number
            ///
            if(!(node = get_node(ep,twdatarec.sent.seq_no))){
                print_debug("ERROR");
                goto finish_sender;
            }

            //
            // This packet is a duplicate, so go back to receive
            // another packet
            ///
            if(node->hit){
#ifdef OWP_EXTRA_DEBUG
                print_debug("ERROR");
                OWPError(ep->cntrl->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                         "run_tw_test: duplicate packet: seq %u, sender seq %u, size %u",
                         ntohl(*reply_seq), ntohl(*reply_snd_seq), resp_len);
#endif
                goto RECEIVE;
            }

            //
            // Record that an original packet has been received
            ///
            node->hit = True;

            //
            // Try receive again, maybe there is still time till next send
            ///
            goto RECEIVE;

SKIP_SEND:
            i++;
        }
        else{
            //
            // Sleep until we should send the next packet.
            ///

            sleeptime = nexttime;
            timespecsub(&sleeptime,&currtime);
            print_detailed("sleeping until %lu,%lu",sleeptime.tv_sec, sleeptime.tv_nsec );

            if((nanosleep(&sleeptime,NULL) == 0) || (errno == EINTR)){
                goto AGAIN;
            }
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "nanosleep(%u.%u,nil): %M",
                    sleeptime.tv_sec,sleeptime.tv_nsec);
            return OWP_CNTRL_FAILURE;
        }

    } while(i < ep->tsession->test_spec.npackets);

finish_sender:
    //
    // Perform a final flush to ensure that all required packets are
    // processed, if the last flush did not result in the end of the test
    ///
    if(!flush_rc){
        if(!_OWPGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
            print_debug("ERROR");
            OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                     "Problem retrieving time");
        }
        else{
            (void)OWPTimespecToTimestamp(&twdatarec.reflected.recv,&currtime,
                                         &esterror,NULL);
            twdatarec.reflected.recv.sync = sync;

            if(flush_lost(ep,&currtime,&timeout,&twdatarec.reflected.recv) < 0){
                print_debug("ERROR");
                goto error;
            }
        }
    }

    if( ep->_owp_int){
        print_debug("ERROR");
        OWPError(ep->cntrl->ctx,OWPErrINFO,OWPErrUNKNOWN,
                "run_tw_test: Exiting from signal");

error:
        debug_assert(ep->datafile);
        _OWPWriteDataHeaderFinished(ep->cntrl->ctx,ep->datafile,OWP_SESSION_FINISHED_ERROR,0);
        fflush(ep->datafile);
        fsync(fileno(ep->datafile));
        pperror("fsync");

        return OWP_CNTRL_FAILURE;
    }

    debug_assert(ep->datafile);
    _OWPWriteDataHeaderFinished(ep->cntrl->ctx,ep->datafile,OWP_SESSION_FINISHED_NORMAL,0);
    fflush(ep->datafile);
    fsync(fileno(ep->datafile));

    return OWP_CNTRL_ACCEPT;
}


int _epoll_process_data(OWPEndpoint ep);

static int read_eventfd(int eventfd){
    ssize_t s;
    uint64_t sig;
    s = read(eventfd, &sig, sizeof(uint64_t));
    if (s < 0){
        pperror("read eventfd");
        return -1;
    }
    return (int)sig;

}

static int write_eventfd(int *eventfd, int signal){
    print_debug("write_event writing %i", signal);
    uint64_t u = (uint64_t) signal;
    ssize_t s;
    s = write(*eventfd, &u, sizeof(uint64_t));
    if (s != sizeof(uint64_t)){
        pperror("write eventfd");
        return -1;
    }
    return 0;
}


// Use this for "blocking" and "nonblocking" checks for signals
static int check_signals(OWPEndpoint ep, int timeout_in_ms){
    print_detailed();
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    int nfds = 0;
    print_detailed("calling epoll_wait with timeout_in_ms %i", timeout_in_ms);

    nfds = epoll_wait(ep->epollfd, &ev, 1, timeout_in_ms);
    if (nfds < 0){
        pperror("epoll_wait");
        print_detailed("error");
        return -1;
    } else if (nfds == 0){
        pperror("nothing to read");
        return 0;
    }

    if (ev.data.fd !=  ep->eventfd){
        print_detailed("not a signal: fd is %i", ev.data.fd);
        return 0;
    }

    int sig = read_eventfd(ep->eventfd);
    if (sig == SIGUSR1){
        debug_assert(ep->_owp_usr1 == 0);
        ep->_owp_usr1 = 1;
    } else if (sig == SIGUSR2){
        debug_assert(ep->_owp_usr2 == 0);
        ep->_owp_usr2 = 1;
    }else if (sig == SIGINT){
        debug_assert(ep->_owp_int == 0);
        ep->_owp_int = 1;
    } else {
        // TODO check this? HUP or ERR?
        print_detailed("unknown signal %i", sig);

    }
    return sig;
}

static void * child_thread(void * param){
    print_debug("child_thread");

    OWPEndpoint ep = (OWPEndpoint) param;
    debug_assert(ep != NULL);
    ep->tid = pthread_self();
    //
    // We are now in the child send/recv process.
    ///
    print_detailed("child_thread epid %i is going to be set to RUNNING %i", ep->id, ep->state);
    ep->state = RUNNING;

    // Wait for a "signal" from eventfd to start
    int signal = check_signals(ep, -1);
    if (signal != SIGUSR1){
        print_detailed("got signal %i", signal);
        ep->state = TERMINATED;
        debug_assert(0);
        // cancel the session
        unlock_endpoint(ep);
        pthread_exit( (void*)OWP_CNTRL_REJECT);
    }

    lock_endpoint(ep);
    ep->state = STARTED;

    debug_assert(ep->state == STARTED);

    //
    // SIGUSR1 is StartSessions
    // SIGUSR2 is StopSessions
    // SIGINT is Terminate - making session invalid.
    ///

    //
    // wait until signal to kick-off session.
    ///

    int ret =0;
    if(ep->send){
        if(ep->twoway){
            ret = run_tw_test(ep);
        } else {
            ret = run_sender(ep);
        }
    }
    else{
        if(ep->twoway){
            ret = run_reflector(ep);
        } else {
            ret = run_receiver(ep);
        }
    }

    if (ep->_owp_usr2 == 1);
    {
        ep->state = STOPPED;
    }

    if (ep->_owp_int == 1);
    {
        ep->state = TERMINATED;
    }

    print_detailed("epid %i thread %lu ENDING ret %i state %i", ep->id, ep->thread, ret, ep->state);

    unlock_endpoint(ep);

    // TODO NOTE: close fd's here?

    pthread_exit((void*)(ret));
}


static OWPBoolean
_set_pthread_sigmask(OWPEndpoint ep){
    print_detailed();
    debug_assert(ep);
    print_detailed("Blocking SIGINT in all threads");
    sigemptyset(&ep->signals.sigs);
    sigaddset(&ep->signals.sigs,SIGINT);

    if(pthread_sigmask(SIG_BLOCK,&ep->signals.sigs, &ep->signals.osigs) != 0){
        pperror("sigprocmask");
        print_detailed("ERROR");
        return False;
    }
    return True;
}

static OWPBoolean
_reset_pthread_sigmask(OWPEndpoint ep){
    print_detailed();
    debug_assert(ep);

    if(pthread_sigmask(SIG_SETMASK,&ep->signals.osigs, NULL) != 0){
        pperror("sigprocmask");
        print_detailed("ERROR");
        debug_assert(0);
        return False;
    }
    return True;
}



static OWPBoolean
_initialize_eventfd(OWPEndpoint ep) {
    print_detailed();
    debug_assert(ep);

    ep->eventfd = eventfd(0, EFD_CLOEXEC );
    if (ep->eventfd < 0){
        pperror("eventfd");
        return False;
    }

    debug_assert(ep->eventfd > 0);

    return True;
}

static OWPBoolean
_initialize_epoll(OWPEndpoint ep)
{
    print_detailed("");
    debug_assert(ep);

    if (ep->epollfd < 0)
    {
        print_debug("NEW EPOLLFD");
        ep->epollfd = epoll_create1(EPOLL_CLOEXEC);
        if (ep->epollfd < 0){
            pperror("epoll_create1");
            return False;
        }
    }

    // Add sockfd to epollfd
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR; // EPOLLET EPOLLHUP EPOLLERR
    ev.data.fd = ep->sockfd;
    if (epoll_ctl(ep->epollfd, EPOLL_CTL_ADD, ep->sockfd, &ev) !=0) {
        if (errno == EEXIST){
        } else {
            pperror("epoll_ctl: sockfd");
            return False;
        }
    }
    print_detailed("epoll listening to sockfd");

    if (ep->eventfd > 0){
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLHUP | EPOLLERR; // EPOLLET EPOLLHUP EPOLLERR
        ev.data.fd = ep->eventfd;
        if (epoll_ctl(ep->epollfd, EPOLL_CTL_ADD, ep->eventfd, &ev) !=0) {
            pperror("epoll_ctl: eventfd");
            if (errno == EEXIST){
            } else {
                pperror("epoll_ctl: eventfd");
                return False;
            }
       }
       print_detailed("epoll listening to eventfd");
    }
    return True;

}

// Sets pthread_sigmask so that the child inherits, then reset the parent's
// pthread_sigmask to catch SIGINT.
// TODO fix errors?
OWPBoolean _run(OWPEndpoint ep){
    print_detailed("_run");

    // There should never be a thread
    debug_assert(!ep->thread);

    print_detailed("initializing epoll");

    if (!_initialize_eventfd(ep)){
        print_detailed("ERROR");
        return False;
    }

    if (!_initialize_epoll(ep)){
        print_detailed("ERROR");
        return False;
    }

    ep->_owp_usr1 = 0;
    ep->_owp_usr2 = 0;
    ep->_owp_int = 0;
    ep->state = INITIALIZED;

    // Block SIGINT in child threads
    if (!_set_pthread_sigmask(ep)){
        print_detailed("ERROR");
        return False;
    }

    int ret = pthread_create(&ep->thread, NULL, &child_thread, (void*)ep);
    if (ret != 0){
        print_detailed("ERROR");
        pperror("pthread_create");
    }

    // Reset main thread signals to allow SIGINT immediately, regardless of
    // return value, then check return value
    if(!_reset_pthread_sigmask(ep)){
        print_detailed("ERROR");
        return False;
    }

    // TODO debugging only
    print_detailed("pthread_create returned %i", ret);

    if(ret < 0){
        return False;
    }

    return True;

}

//
// Note: We explicitly do NOT connect the send udp socket. This is because
// each individual packet needs to be treated independant of the others.
// Connecting the socket to simplify send causes the socket to close if
// certain ICMP messages come back. We specifically do NOT want this behavior.
///
OWPBoolean
_prepare_to_run(
        OWPControl      cntrl,
        OWPTestSession  tsession,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        )
{
    OWPContext          ctx = OWPGetContext(cntrl);
    OWPEndpoint         *end_data = &tsession->endpoint;
    OWPEndpoint         ep = tsession->endpoint;

    //
    // By default, failures from here are recoverable... Set this
    // to OWPErrFATAL to make the connection close. And by default,
    // the "reason" given for Accept is failure.
    ///
    *err_ret = OWPErrWARNING;
    *aval = OWP_CNTRL_FAILURE;

    if(!ep){
        return False;
    }

    //
    // Initialize crypto if needed
    ///
    if(ep->cntrl->mode & OWP_MODE_DOCIPHER_TEST){
        uint8_t     iv[16];
        keyInstance sidkey;
        int         r;

        //
        // Generate AES and HMAC keys needed for Test Session crypto.
        // (See Section 4.1 of RFC 4656.)
        //
        // initialize an aes key structure to be used for generating the
        // test aeskey and hmac-key. (key bytes for this is from SID)
        ///
        sidkey.Nr = rijndaelKeySetupEnc(sidkey.rk,tsession->sid,
                sizeof(tsession->sid)*8);

        //
        // generate OWAMP test aes key bytes AES ECB mode, and initialize
        // an aes key structure.
        ///
        rijndaelEncrypt(sidkey.rk,sidkey.Nr,ep->cntrl->aessession_key,
                ep->aesbytes);

        if(ep->cntrl->twoway){
            if (ep->cntrl->server){
                ep->aeskey.Nr = rijndaelKeySetupDec(ep->aeskey.rk,ep->aesbytes,
                        sizeof(ep->aesbytes)*8);
                ep->aes_tw_reply_key.Nr = rijndaelKeySetupEnc(ep->aes_tw_reply_key.rk,
                        ep->aesbytes,sizeof(ep->aesbytes)*8);
            }
            else {
                ep->aeskey.Nr = rijndaelKeySetupEnc(ep->aeskey.rk,ep->aesbytes,
                        sizeof(ep->aesbytes)*8);
                ep->aes_tw_reply_key.Nr = rijndaelKeySetupDec(ep->aes_tw_reply_key.rk,
                        ep->aesbytes,sizeof(ep->aesbytes)*8);
            }
        }
        else if(ep->send){
            // send side needs encryption
            ep->aeskey.Nr = rijndaelKeySetupEnc(ep->aeskey.rk,ep->aesbytes,
                    sizeof(ep->aesbytes)*8);
        }
        else{
            // recv side needs decryption
            ep->aeskey.Nr = rijndaelKeySetupDec(ep->aeskey.rk,ep->aesbytes,
                    sizeof(ep->aesbytes)*8);
        }

        //
        // generate OWAMP test hmac key bytes AES CBC mode.
        ///
        memset(iv,0,sizeof(iv));
        r = blockEncrypt(iv,&sidkey,cntrl->hmac_key,sizeof(cntrl->hmac_key)*8,
                ep->hmac_key);
        if(r != (sizeof(cntrl->hmac_key)*8)){
            print_detailed("ERROR");
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "blockEncrypt(): Failed to create Test Session HMAC");
            return False;
        }

        //
        // Allocate an hmac_ctx for Test packets
        ///
        if( !(ep->hmac_ctx = I2HMACSha1Alloc(OWPContextErrHandle(cntrl->ctx)))){
            return False;
        }
    }

    if(!ep->send){
        ep->remoteaddr = tsession->sender;
        ep->localaddr = tsession->receiver;
    }
    else{
        ep->remoteaddr = tsession->receiver;
        ep->localaddr = tsession->sender;
    }

    return True;
}

OWPBoolean
_OWPEndpointInitHook(
        OWPControl      cntrl,
        OWPTestSession  tsession,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        )
{
    print_debug();

    OWPContext          ctx = OWPGetContext(cntrl);
    OWPEndpoint         *end_data = &tsession->endpoint;
    OWPEndpoint         ep = tsession->endpoint;

    *err_ret = OWPErrWARNING;
    *aval = OWP_CNTRL_FAILURE;

    OWPBoolean ret =  _prepare_to_run(cntrl, tsession, aval, err_ret);

    if (ret != True) {
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"_prepare_to_run(): %M");
        return False;
    }

    print_debug("ret is %li", ret);

    // TODO check errors?
    if ( _run(ep) != True){
        *err_ret = OWPErrFATAL;
        return False;
    }
    debug_assert(ep->thread);

    *err_ret = OWPErrOK;
    *aval = OWP_CNTRL_ACCEPT;

    return ret;
}


OWPBoolean
_OWPEndpointStart(
        OWPEndpoint     ep,
        OWPErrSeverity  *err_ret
        )
{
    print_detailed("_OWPEndpointStart");

    *err_ret = OWPErrOK;

    debug_assert(ep->_owp_usr1 == 0);

    if (write_eventfd(&ep->eventfd, SIGUSR1) != 0){
        print_detailed("ERROR");
        return False;
    }

    print_detailed("parent continuing");

    return True;
}

// NOTE: trying to reproduce waitpid with pthreads.
void
_OWPEndpointStatus(
        OWPEndpoint     ep,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        )
{
    print_detailed("_OWPEndpointStatus");
    pid_t   p;
    int ret = 0;
    int     childstatus;

    *err_ret = OWPErrOK;

    print_detailed("epid %i status wopts %i", ep->id, ep->wopts);
    print_detailed("acceptval %i", ep->acceptval);
    print_detailed("*aval is %is", *aval);

    if (ep->acceptval <0){
AGAIN:
        if (ep->wopts == WNOHANG){
            // TODO: NOTE This is mostly for a hang in twamp, there's probably a better solution
            print_detailed("WNOHANG");
            if (ep->thread) {
                ret = pthread_tryjoin_np(ep->thread, (void *)&childstatus);
                if (ret == 0){
                    print_detailed("pthread_tryjoin_np returned %i childstatus %i", ret, childstatus);

                    print_detailed("Changing acceptval");
                    ep->acceptval = (OWPAcceptType)childstatus;
                } else {
                    pperror("pthread_tryjoin_np");
                }
            }
        } else {
            print_detailed("HANGING");
            if (ep->thread){
                    print_detailed("Trying to join");
                    ret = pthread_join(ep->thread, (void*)&childstatus);
                    if (ret != 0){
                        pperror("pthread_join");
                        print_detailed("ret is %i", ret);
                        if (ret == ESRCH){
                        } else if (ret == EDEADLK){
                        } else if (ret == EINTR){
                            print_detailed("INTERRUPTED");
                            goto AGAIN;
                        }
                    }
                    print_detailed("pthread_join returned %i childstatus %i", ret, childstatus);

                    print_detailed("Changing acceptval");
                    ep->acceptval = (OWPAcceptType)childstatus;
            }
        }
    }
    *aval =  ep->acceptval;

    if(*aval == OWP_CNTRL_ACCEPT){
        *aval = ep->acceptval;
    }

    return;
}


void
_OWPEndpointStop(
        OWPEndpoint     ep,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        )
{
    debug_assert(ep!=NULL);
    print_detailed("_OWPEndpointStop");

    int             sig;
    OWPAcceptType   teststatus=OWP_CNTRL_ACCEPT;

    // TODO double check the order on this
    // There's an extra stop in free, so this is okay
    if ((ep->acceptval >= 0) || (!ep->thread) ){
        print_detailed("Already stopped");
        *err_ret = OWPErrOK;
        goto done;
    }
    debug_assert(ep->_owp_usr2 == 0);
    debug_assert(ep->_owp_usr1 == 1);


    print_detailed("epid %i tid %i Stop", ep->id, ep->tid);

    *err_ret = OWPErrFATAL;

    if(*aval == OWP_CNTRL_ACCEPT){
        sig = SIGUSR2;
        print_detailed("sig OWP_CNTRL_ACCEPT sig= SIGUSR2");
        *err_ret = OWPErrOK;
    } else{
        sig = SIGINT;
        print_detailed("OWP_CNTRL_ACCEPT !=?");
    }

    if (write_eventfd(&ep->eventfd, sig) != 0){
        print_detailed("write_eventfd failed");
        goto error;
    }

    //
    // Remove the WNOHANG bit. We need to wait until the exit status
    // is available.
    // (Should we add a timer to break out? No - not that paranoid yet.)
    ///
    ep->wopts &= ~WNOHANG;
    _OWPEndpointStatus(ep,&teststatus,err_ret);
    print_detailed("teststatus %i", teststatus);
    if(teststatus >= 0) {
        print_detailed("goto done");
        goto done;
    }

error:
    OWPError(ep->cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "EndpointStop:Can't signal child #%d: %M",ep->thread);
done:
    //
    // If accept state was good upon calling this function, but there
    // was an error stopping this session - report the problem up.
    ///
    if(*aval == OWP_CNTRL_ACCEPT){
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
    print_detailed("_OWPEndpointFree");
    if (!ep){
        return;
    }
    _OWPEndpointStop(ep,aval,err_ret);

    ep->tsession->endpoint = NULL;

    EndpointFree(ep,*aval);

    return;
}
