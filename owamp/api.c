/*
 **      $Id$
 */
/************************************************************************
 *                                                                       *
 *                             Copyright (C)  2002                       *
 *                                Internet2                              *
 *                             All Rights Reserved                       *
 *                                                                       *
 ************************************************************************/
/*
 **        File:         api.c
 **
 **        Author:       Jeff W. Boote
 **                      Anatoly Karp
 **
 **        Date:         Fri Mar 29 15:36:44  2002
 **
 **        Description:        
 */
/* define _GNU_SOURCE to get definition of ftello */
#define        _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

#include "./owampP.h"

OWPAddr
_OWPAddrAlloc(
        OWPContext        ctx
        )
{
    OWPAddr        addr = calloc(1,sizeof(struct OWPAddrRec));

    if(!addr){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                ":calloc(1,%d):%M",sizeof(struct OWPAddrRec));
        return NULL;
    }

    addr->ctx = ctx;

    addr->node_set = 0;
    strncpy(addr->node,"unknown",sizeof(addr->node));
    addr->port_set = 0;
    strncpy(addr->port,"unknown",sizeof(addr->port));
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
        OWPAddr        addr
        )
{
    OWPErrSeverity        err = OWPErrOK;

    if(!addr)
        return err;

    if(addr->ai){
        if(!addr->ai_free){
            freeaddrinfo(addr->ai);
        }else{
            struct addrinfo *ai, *next;

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
        OWPContext        ctx,
        const char        *node
        )
{
    OWPAddr     addr;
    char        buff[MAXHOSTNAMELEN+1];
    const char  *nptr=node;
    char        *pptr=NULL;
    char        *s1,*s2;

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
        OWPContext              ctx,
        const struct addrinfo   *src
        )
{
    struct addrinfo *dst = calloc(1,sizeof(struct addrinfo));

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
        int        len = strlen(src->ai_canonname);

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
        OWPContext              ctx,
        const struct addrinfo   *ai
        )
{
    OWPAddr         addr = _OWPAddrAlloc(ctx);
    struct addrinfo **aip;

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
        OWPContext  ctx,
        int         fd
        )
{
    OWPAddr addr = _OWPAddrAlloc(ctx);

    if(!addr)
        return NULL;

    addr->fd_user = 1;
    addr->fd = fd;

    return addr;
}

OWPAddr
_OWPAddrCopy(
        OWPAddr from
        )
{
    OWPAddr         to;
    struct addrinfo **aip;
    struct addrinfo *ai;

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
        OWPAddr addr
        )
{
    if(!addr || (addr->fd < 0))
        return -1;

    return addr->fd;
}

socklen_t
OWPAddrSockLen(
        OWPAddr addr
        )
{
    if(!addr || !addr->saddr)
        return 0;

    return addr->saddrlen;
}

/*
 * Function:        OWPGetContext
 *
 * Description:        
 *         Returns the context pointer that was referenced when the
 *         given control connection was created.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPContext
OWPGetContext(
        OWPControl  cntrl
        )
{
    return cntrl->ctx;
}

/*
 * Function:        OWPGetMode
 *
 * Description:        
 *         Returns the "mode" of the control connection.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPSessionMode
OWPGetMode(
        OWPControl  cntrl
        )
{
    return cntrl->mode;
}

/*
 * Function:        OWPControlFD
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
int
OWPControlFD(
        OWPControl  cntrl
        )
{
    return cntrl->sockfd;
}

/*
 * Function:        OWPGetRTTBound
 *
 * Description:        Returns a very rough estimate of the upper-bound rtt to
 *                 the server.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 *                 bound or 0 if unavailable
 * Side Effect:        
 */
OWPNum64
OWPGetRTTBound(
        OWPControl  cntrl
        )
{
    return cntrl->rtt_bound;
}

/*
 * Function:        _OWPFailControlSession
 *
 * Description:        
 *         Simple convienience to set the state and return the failure at
 *         the same time.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPErrSeverity
_OWPFailControlSession(
        OWPControl  cntrl,
        int         level
        )
{
    cntrl->state = _OWPStateInvalid;
    return (OWPErrSeverity)level;
}

/*
 * Function:        _OWPTestSessionAlloc
 *
 * Description:        
 *         This function is used to allocate/initialize the memory record used
 *         to maintain state information about a "configured" test.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPTestSession
_OWPTestSessionAlloc(
        OWPControl  cntrl,
        OWPAddr     sender,
        OWPBoolean  conf_sender,
        OWPAddr     receiver,
        OWPBoolean  conf_receiver,
        OWPTestSpec *test_spec
        )
{
    OWPTestSession  test;

    /*
     * Address records must exist.
     */
    if(!sender || ! receiver){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPTestSessionAlloc:Invalid Addr arg");
        return NULL;
    }

    if(!(test = calloc(1,sizeof(OWPTestSessionRec)))){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "calloc(1,OWPTestSessionRec): %M");
        return NULL;
    }

    /*
     * Initialize address records and test description record fields.
     */
    test->cntrl = cntrl;
    test->sender = sender;
    test->conf_sender = conf_sender;
    test->receiver = receiver;
    test->conf_receiver = conf_receiver;
    memcpy(&test->test_spec,test_spec,sizeof(OWPTestSpec));

    /*
     * Allocate memory for slot records if they won't fit in the
     * pre-allocated "buffer" already associated with the TestSession
     * record. Then copy the slot records.
     * (From the server side, slots will be 0 at this point - the
     * SessionRecord is allocated before reading the slots off the
     * socket so the SessionRecord slot "buffer" can potentially be used.)
     */
    if(test->test_spec.slots){
        if(test->test_spec.nslots > _OWPSLOT_BUFSIZE){
            if(!(test->test_spec.slots =
                        calloc(test->test_spec.nslots,
                            sizeof(OWPSlot)))){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "calloc(%d,OWPSlot): %M",
                        test->test_spec.nslots);
                free(test);
                return NULL;
            }
        }else{
            test->test_spec.slots = test->slot_buffer;
        }
        memcpy(test->test_spec.slots,test_spec->slots,
                test_spec->nslots*sizeof(OWPSlot));
    }

    return test;
}

/*
 * Function:        _OWPTestSessionFree
 *
 * Description:        
 *         This function is used to free the memory associated with a "configured"
 *         test session.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPErrSeverity
_OWPTestSessionFree(
        OWPTestSession  tsession,
        OWPAcceptType   aval
        )
{
    OWPTestSession  *sptr;
    OWPAcceptType   alocal = aval;
    OWPErrSeverity  err=OWPErrOK;

    if(!tsession){
        return OWPErrOK;
    }

    /*
     * remove this tsession from the cntrl->tests lists.
     */
    for(sptr = &tsession->cntrl->tests;*sptr;sptr = &(*sptr)->next){
        if(*sptr == tsession){
            *sptr = tsession->next;
            break;
        }
    }

    if(tsession->endpoint){
        _OWPEndpointFree(tsession->endpoint,&alocal,&err);
    }

    if(tsession->closure){
        _OWPCallTestComplete(tsession,aval);
    }

    OWPAddrFree(tsession->sender);
    OWPAddrFree(tsession->receiver);

    if(tsession->sctx){
        OWPScheduleContextFree(tsession->sctx);
    }

    if(tsession->test_spec.slots &&
            (tsession->test_spec.slots != tsession->slot_buffer)){
        free(tsession->test_spec.slots);
    }

    free(tsession);

    return err;
}


/*
 * Function:        _OWPCreateSID
 *
 * Description:        
 *         Generate a "unique" SID from addr(4)/time(8)/random(4) values.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 *         0 on success
 * Side Effect:        
 */
int
_OWPCreateSID(
        OWPTestSession        tsession
        )
{
    OWPTimeStamp    tstamp;
    u_int8_t        *aptr;

#ifdef        AF_INET6
    if(tsession->receiver->saddr->sa_family == AF_INET6){
        struct sockaddr_in6        *s6;

        s6 = (struct sockaddr_in6*)tsession->receiver->saddr;
        /* point at last 4 bytes of addr */
        aptr = &s6->sin6_addr.s6_addr[12];
    }else
#endif
        if(tsession->receiver->saddr->sa_family == AF_INET){
            struct sockaddr_in        *s4;

            s4 = (struct sockaddr_in*)tsession->receiver->saddr;
            aptr = (u_int8_t*)&s4->sin_addr;
        }
        else{
            OWPError(tsession->cntrl->ctx,OWPErrFATAL,OWPErrUNSUPPORTED,
                    "_OWPCreateSID:Unknown address family");
            return 1;
        }

    memcpy(&tsession->sid[0],aptr,4);

    (void)OWPGetTimeOfDay(tsession->cntrl->ctx,&tstamp);
    _OWPEncodeTimeStamp(&tsession->sid[4],&tstamp);

    if(I2RandomBytes(tsession->cntrl->ctx->rand_src,&tsession->sid[12],4)
            != 0){
        return 1;
    }

    return 0;
}

OWPPacketSizeT
OWPTestPayloadSize(
        OWPSessionMode  mode, 
        u_int32_t       padding
        )
{
    OWPPacketSizeT msg_size;

    switch (mode) {
        case OWP_MODE_OPEN:
            msg_size = 14;
            break;
        case OWP_MODE_AUTHENTICATED:
        case OWP_MODE_ENCRYPTED:
            msg_size = 32;
            break;
        default:
            return 0;
            /* UNREACHED */
    }

    return msg_size + padding;
}

/*
 * Function:        OWPTestPacketRate
 *
 * Description:        
 *         This function returns the # packets/ second as a double.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
double
OWPTestPacketRate(
        OWPContext  ctx,
        OWPTestSpec *tspec
        )
{
    OWPNum64    duration = OWPULongToNum64(0);
    u_int32_t   i;

    if(!tspec){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPTestPacketRate: Invalid tspec arg");
        return 0;
    }

    if(!tspec->nslots || !tspec->slots){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPTestPacketRate: Invalid empty test specification");
        return 0;
    }

    for(i=0;i<tspec->nslots;i++){
        duration = OWPNum64Add(duration,tspec->slots[i].any.mean_delay);
    }

    if(duration <= 0){
        return 0;
    }

    return (double)tspec->nslots / OWPNum64ToDouble(duration);
}

/* These lengths assume no IP options. */
#define OWP_IP4_HDR_SIZE        20        /* rfc 791 */
#define OWP_IP6_HDR_SIZE        40        /* rfc 2460 */
#define OWP_UDP_HDR_SIZE        8        /* rfc 768 */

/*
 ** Given the protocol family, OWAMP mode and packet padding,
 ** compute the size of resulting full IP packet.
 */
OWPPacketSizeT
OWPTestPacketSize(
        int             af,    /* AF_INET, AF_INET6 */
        OWPSessionMode  mode, 
        u_int32_t       padding
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

/*
 * Function:        OWPTestPacketBandwidth
 *
 * Description:        
 *         returns the average bandwidth requirements of the given test using
 *         the given address family, and authentication mode.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
double
OWPTestPacketBandwidth(
        OWPContext      ctx,
        int             af,
        OWPSessionMode  mode, 
        OWPTestSpec     *tspec
        )
{
    if(!tspec){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPTestPacketBandwidth: Invalid tspec arg");
        return 0;
    }

    return OWPTestPacketRate(ctx,tspec) *
        OWPTestPacketSize(af,mode,tspec->packet_size_padding) * 8;
}

/*
 * Function:        OWPSessionStatus
 *
 * Description:        
 *         This function returns the "status" of the test session identified
 *         by the sid. "send" indicates which "side" of the test to retrieve
 *         information about.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        True if status was available, False otherwise.
 *                 aval contains the actual "status":
 *                         <0        Test is not yet complete
 *                         >=0        Valid OWPAcceptType - see enum for meaning.
 * Side Effect:        
 */
OWPBoolean
OWPSessionStatus(
        OWPControl      cntrl,
        OWPSID          sid,
        OWPAcceptType   *aval
        )
{
    OWPTestSession  tsession;
    OWPErrSeverity  err;

    /*
     * First find the tsession record for this test.
     */
    for(tsession=cntrl->tests;tsession;tsession=tsession->next)
        if(memcmp(sid,tsession->sid,sizeof(OWPSID)) == 0)
            goto found;

    return False;

found:
    if(tsession->endpoint){
        _OWPEndpointStatus(tsession->endpoint,aval,&err);
        return True;
    }

    return False;
}

int
OWPSessionsActive(
        OWPControl      cntrl,
        OWPAcceptType   *aval
        )
{
    OWPTestSession  tsession;
    OWPAcceptType   laval;
    OWPAcceptType   raval = 0;
    int             n=0;
    OWPErrSeverity  err;

    for(tsession = cntrl->tests;tsession;tsession = tsession->next){
        if(tsession->endpoint){
            /* initialize laval before querying status */
            laval = OWP_CNTRL_ACCEPT;
            _OWPEndpointStatus(tsession->endpoint,&laval,&err);
            if(laval < 0){
                n++;
            } else{
                raval = MAX(laval,raval);
            }
        }
    }

    if(aval)
        *aval = raval;

    return n;
}

/*
 * Function:    _OWPStopSendSessions
 *
 * Description:    
 *              This function is used to stop send sessions. Skip
 *              records are somewhat validated for use in the
 *              _OWPWriteStopSessions function.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static OWPErrSeverity
_OWPStopSendSessions(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval_ret,  /* in/out */
        u_int32_t       *num_sessions
        )
{
    OWPErrSeverity  err,err2=OWPErrOK;
    OWPAcceptType   aval=OWP_CNTRL_ACCEPT;
    OWPAcceptType   *acceptval = &aval;
    OWPTestSession  sptr;
    u_int32_t       num_senders=0;

    if(acceptval_ret){
        acceptval = acceptval_ret;
    }
    *num_sessions = 0;

    /*
     * Stop each session - count the "send" sessions and verify that
     * the "skip records" saved at each fd are at least a consistent size.
     */
    for(sptr=cntrl->tests; sptr; sptr = sptr->next){
        u_int32_t   sdr[2];
        u_int32_t   nskip;
        struct stat sbuf;

        /*
         * Validity check.
         */
        if(!sptr->endpoint){
            OWPError(cntrl->ctx,OWPErrWARNING,EINVAL,
                    "_OWPStopSendSessions: no endpoint state!");
            *acceptval = OWP_CNTRL_FAILURE;
            break;
        }

        /*
         * Receive sessions are not done here.
         */
        if(!sptr->endpoint->send) continue;

        /*
         * Stop local sessions
         */
        _OWPEndpointStop(sptr->endpoint,acceptval,&err);
        err2 = MIN(err,err2);

        /* count senders for inclusion in StopSessions message */
        num_senders++;

        /*
         * simple check to validate skip records:
         * Just verify size of file matches reported number
         * of skip records.
         */
        if(fstat(sptr->endpoint->skiprecfd,&sbuf) != 0){
            OWPError(cntrl->ctx,OWPErrWARNING,errno,"fstat(skiprecfd): %M");
            *acceptval = OWP_CNTRL_FAILURE;
            err2 = MIN(OWPErrWARNING,err2);
            continue;
        }

        /*
         * Seek to beginning of file for reading.
         */
        if(lseek(sptr->endpoint->skiprecfd,0,SEEK_SET) == -1){
            OWPError(cntrl->ctx,OWPErrWARNING,errno,"lseek(skiprecfd,0): %M");
            *acceptval = OWP_CNTRL_FAILURE;
            err2 = MIN(OWPErrWARNING,err2);
            continue;
        }

        /*
         * Read next_seqno and num_skips for verification purposes.
         * (IGNORE intr for this local file i/o)
         */
        if(I2Readn(sptr->endpoint->skiprecfd,sdr,8) != 8){
            OWPError(cntrl->ctx,OWPErrWARNING,errno,"I2Readni(skiprecfd): %M");
            *acceptval = OWP_CNTRL_FAILURE;
            err2 = MIN(OWPErrWARNING,err2);
            continue;
        }

        /*
         * Reset fd to beginning of file for reading.
         */
        if(lseek(sptr->endpoint->skiprecfd,0,SEEK_SET) == -1){
            OWPError(cntrl->ctx,OWPErrWARNING,errno,"lseek(skiprecfd,0): %M");
            *acceptval = OWP_CNTRL_FAILURE;
            err2 = MIN(OWPErrWARNING,err2);
            continue;
        }

        nskip = ntohl(sdr[1]);

        /*
         * Each skip record is 8 bytes, plus 8 bytes for next_seqno and
         * num_skip_records means: filesize == ((nskip+1)*8)
         */
        if((off_t)((nskip+1)*8) != sbuf.st_size){
            OWPError(cntrl->ctx,OWPErrWARNING,EINVAL,
                    "_OWPStopSendSessions: Invalid skiprecfd data");
            *acceptval = OWP_CNTRL_FAILURE;
            err2 = MIN(OWPErrWARNING,err2);
            continue;
        }

        sptr->endpoint->skiprecsize = sbuf.st_size;
    }

    *num_sessions = num_senders;
    return err2;
}

/*
 * Function:    _OWPStopRecvSessions
 *
 * Description:    
 *              This function is used to stop recv sessions.
 *              Skip records and next_seqno reported from the send side
 *              of the test will be used to finish writing the datafile.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static OWPErrSeverity
_OWPStopRecvSessions(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval_ret
        )
{
    OWPErrSeverity  err,err2=OWPErrOK;
    OWPAcceptType   aval=OWP_CNTRL_ACCEPT;
    OWPAcceptType   *acceptval = &aval;
    OWPTestSession  sptr;

    if(acceptval_ret){
        acceptval = acceptval_ret;
    }

    /*
     * Stop each "recv" session
     */
    for(sptr=cntrl->tests; sptr; sptr = sptr->next){
        /*
         * Validity check.
         */
        if(!sptr->endpoint){
            OWPError(cntrl->ctx,OWPErrWARNING,EINVAL,
                    "_OWPStopRecvSessions: no endpoint state!");
            *acceptval = OWP_CNTRL_FAILURE;
            break;
        }

        /*
         * Send sessions not done here.
         */
        if(sptr->endpoint->send) continue;

        /*
         * Stop local sessions
         */
        _OWPEndpointStop(sptr->endpoint,acceptval,&err);
        err2 = MIN(err,err2);
    }

    return err2;
}


/*
 * Function:    
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
OWPErrSeverity
OWPStopSessions(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval_ret        /* in/out        */
        )
{
    OWPErrSeverity  err,err2=OWPErrOK;
    OWPRequestType  msgtype;
    OWPAcceptType   aval=OWP_CNTRL_ACCEPT;
    OWPAcceptType   *acceptval=&aval;
    int             ival=0;
    int             *intr=&ival;
    u_int32_t       num_sessions=0;
    OWPTimeStamp    stoptime;

    if(acceptval_ret){
        acceptval = acceptval_ret;
    }

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    err = _OWPStopSendSessions(cntrl,acceptval,&num_sessions);
    err2 = MIN(err,err2);
    if(err2 < OWPErrWARNING){
        goto done;
    }
    err = _OWPWriteStopSessions(cntrl,intr,*acceptval,num_sessions);
    err2 = MIN(err,err2);
    if(err2 < OWPErrWARNING){
        goto done;
    }

    msgtype = OWPReadRequestType(cntrl,intr);
    switch(msgtype){
        case OWPReqStopSessions:
            break;

        case OWPReqSockClose:
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPStopSessions: Control socket closed: %M");
            err2 = OWPErrFATAL;
            goto done;
            break;

        case OWPReqSockIntr:
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPStopSessions: Session cancelled by interrupt: %M");
            err2 = OWPErrFATAL;
            goto done;
            break;

        default:
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "OWPStopSessions: Invalid protocol message received.");
            err2 = OWPErrFATAL;
            goto done;
    }

    /*
     * Get time StopSessions was recieved and use that to
     * delete all packets with a presumed send time later
     * than stoptime-timeout. (As per section 3.8 owamp draft 14)
     */
    (void)OWPGetTimeOfDay(cntrl->ctx,&stoptime);


    /*
     * Stop Recv side sessions now that we have received the
     * StopSessions message (even though it has not been completely
     * read yet).
     */
    err = _OWPStopRecvSessions(cntrl,acceptval);
    err2 = MIN(err,err2);
    if(err2 < OWPErrWARNING){
        goto done;
    }

    /*
     * Now read the full StopSessions message.
     * This will take the NextSeq and SkipRecords and
     * put them in the recv session files as well.
     */
    err = _OWPReadStopSessions(cntrl,intr,acceptval,stoptime);
    err2 = MIN(err,err2);
    if(err2 < OWPErrWARNING){
        goto done;
    }

done:
    if(err2 < OWPErrWARNING){
        if(*acceptval == OWP_CNTRL_ACCEPT){
            *acceptval = OWP_CNTRL_FAILURE;
        }
        (void)_OWPFailControlSession(cntrl,err2);
    }

    /*
     * Free memory from sessions
     */
    while(cntrl->tests){
        err = _OWPTestSessionFree(cntrl->tests,*acceptval);
        err2 = MIN(err,err2);
    }


    cntrl->state &= ~_OWPStateTest;

    return MIN(err,err2);
}

int
OWPStopSessionsWait(
        OWPControl      cntrl,
        OWPNum64        *wake,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval_ret,
        OWPErrSeverity  *err_ret
        )
{
    struct timeval  currtime;
    struct timeval  reltime;
    struct timeval  *waittime = NULL;
    fd_set          readfds;
    fd_set          exceptfds;
    int             rc;
    int             msgtype;
    OWPErrSeverity  err2=OWPErrOK;
    OWPAcceptType   aval;
    OWPAcceptType   *acceptval=&aval;
    int             ival=0;
    int             *intr=&ival;
    u_int32_t       num_sessions=0;
    OWPTimeStamp    stoptime;

    *err_ret = OWPErrOK;
    if(acceptval_ret){
        acceptval = acceptval_ret;
    }
    *acceptval = OWP_CNTRL_ACCEPT;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    if(!cntrl || cntrl->sockfd < 0){
        *err_ret = OWPErrFATAL;
        return -1;
    }

    /*
     * If there are no active sessions, get the status and return.
     */
    if(!OWPSessionsActive(cntrl,acceptval) || (*acceptval)){
        /*
         * Sessions are complete - send StopSessions message.
         */
        *err_ret = OWPStopSessions(cntrl,intr,acceptval);
        return 0;
    }

    if(wake){
        OWPTimeStamp        wakestamp;

        /*
         * convert abs wake time to timeval
         */
        wakestamp.owptime = *wake;
        OWPTimestampToTimeval(&reltime,&wakestamp);

        /*
         * get current time.
         */
        if(gettimeofday(&currtime,NULL) != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "gettimeofday():%M");
            return -1;
        }

        /*
         * compute relative wake time from current time and abs wake.
         */
        if(tvalcmp(&currtime,&reltime,<)){
            tvalsub(&reltime,&currtime);
        }
        else{
            tvalclear(&reltime);
        }

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
        if(waittime || *intr){
            return 2;
        }

        /*
         * If there are tests still happening, and no tests have
         * ended in error - go back to select and wait for the
         * rest of the tests to complete.
         */
        if(OWPSessionsActive(cntrl,acceptval) && !*acceptval){
            goto AGAIN;
        }

        /*
         * Sessions are complete - send StopSessions message.
         */
        *err_ret = OWPStopSessions(cntrl,intr,acceptval);

        return 0;
    }
    if(rc == 0)
        return 1;

    if(!FD_ISSET(cntrl->sockfd,&readfds) &&
            !FD_ISSET(cntrl->sockfd,&exceptfds)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "select():cntrl fd not ready?:%M");
        *err_ret = _OWPFailControlSession(cntrl,OWPErrFATAL);
        goto done;
    }

    msgtype = OWPReadRequestType(cntrl,intr);
    switch(msgtype){
        case OWPReqStopSessions:
            break;

        case OWPReqSockClose:
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPStopSessionsWait: Control socket closed: %M");
            *err_ret = OWPErrFATAL;
            goto done;
            break;

        case OWPReqSockIntr:
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPStopSessionsWait: Session cancelled by interrupt: %M");
            *err_ret = OWPErrFATAL;
            goto done;
            break;

        default:
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "OWPStopSessionsWait: Invalid protocol message received.");
            *err_ret = OWPErrFATAL;
            goto done;
    }

    /*
     * Get time StopSessions was recieved and use that to
     * delete all packets with a presumed send time later
     * than stoptime-timeout. (As per section 3.8 owamp draft 14)
     */
    (void)OWPGetTimeOfDay(cntrl->ctx,&stoptime);

    /*
     * Stop Send sessions - the other side does not want more packets.
     * Do this first to be a "good" citizen.
     */
    err2 = _OWPStopSendSessions(cntrl,acceptval,&num_sessions);
    *err_ret = MIN(*err_ret,err2);
    if(*err_ret < OWPErrWARNING){
        goto done;
    }

    /*
     * Stop Recv side sessions now that we have received the
     * StopSessions message (even though it has not been completely
     * read yet).
     */
    err2 = _OWPStopRecvSessions(cntrl,acceptval);
    *err_ret = MIN(*err_ret,err2);
    if(*err_ret < OWPErrWARNING){
        goto done;
    }

    /*
     * Read the rest of the stop sessions message and complete
     * the recv side session files.
     */
    err2 = _OWPReadStopSessions(cntrl,intr,acceptval,stoptime);
    *err_ret = MIN(*err_ret,err2);

done:

    /*
     * If errors are non-fatal (warning or better) then send the
     * stop sessions message.
     */
    if(*err_ret >= OWPErrWARNING){
        err2 = _OWPWriteStopSessions(cntrl,intr,*acceptval,num_sessions);
        *err_ret = MIN(*err_ret,err2);
    }

    /*
     * Clean up memory.
     */
    while(cntrl->tests){
        err2 = _OWPTestSessionFree(cntrl->tests,*acceptval);
        *err_ret = MIN(*err_ret,err2);
    }

    /*
     * If anything has failed along the way, report failure.
     */
    if(*err_ret < OWPErrWARNING){
        *acceptval = OWP_CNTRL_FAILURE;
        _OWPFailControlSession(cntrl,OWPErrFATAL);
        return -1;
    }

    /*
     * Otherwise, report success.
     */
    cntrl->state &= ~_OWPStateTest;

    return 0;
}

/*
 * Function:        OWPAddrNodeName
 *
 * Description:        
 *         This function gets a char* node name for a given OWPAddr.
 *         The len parameter is an in/out parameter.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
void
OWPAddrNodeName(
        OWPAddr addr,
        char    *buf,
        size_t  *len
        )
{
    assert(buf);
    assert(len);
    assert(*len > 0);

    if(!addr){
        goto bail;
    }

    if(!addr->node_set && addr->saddr &&
            getnameinfo(addr->saddr,addr->saddrlen,
                addr->node,sizeof(addr->node),
                addr->port,sizeof(addr->port),
                NI_NUMERICHOST|NI_NUMERICSERV) == 0){
        addr->node_set = 1;
        addr->port_set = 1;
    }

    if(addr->node_set){
        *len = MIN(*len,sizeof(addr->node));
        strncpy(buf,addr->node,*len);
        return;
    }

bail:
    *len = 0;
    buf[0] = '\0';
    return;
}

/*
 * Function:        OWPAddrNodeService
 *
 * Description:        
 *         This function gets a char* service name for a given OWPAddr.
 *         The len parameter is an in/out parameter.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
void
OWPAddrNodeService(
        OWPAddr addr,
        char    *buf,
        size_t  *len
        )
{
    assert(buf);
    assert(len);
    assert(*len > 0);

    if(!addr){
        goto bail;
    }

    if(!addr->port_set && addr->saddr &&
            getnameinfo(addr->saddr,addr->saddrlen,
                addr->node,sizeof(addr->node),
                addr->port,sizeof(addr->port),
                NI_NUMERICHOST|NI_NUMERICSERV) == 0){
        addr->node_set = 1;
        addr->port_set = 1;
    }

    if(addr->port_set){
        *len = MIN(*len,sizeof(addr->port));
        strncpy(buf,addr->port,*len);
        return;
    }

bail:
    *len = 0;
    buf[0] = '\0';
    return;
}

/*
 * Might throw these into I2Util sometime...
 */
#ifndef htonll
static u_int64_t
htonll(
        u_int64_t   h64
      )
{
    u_int64_t   n64;
    u_int8_t    *t8;

    /* Use t8 to byte address the n64 */
    t8 = (u_int8_t*)&n64;

    /* set low-order bytes */
    *(u_int32_t*)&t8[4] = htonl(h64 & 0xFFFFFFFFUL);

    /* set high-order bytes */
    h64 >>=32;
    *(u_int32_t*)&t8[0] = htonl(h64 & 0xFFFFFFFFUL);

    return n64;
}
#endif

#ifndef ntohll
static u_int64_t
ntohll(
        u_int64_t   n64
      )
{
    u_int64_t   h64;
    u_int8_t    *t8;

    /* Use t8 to byte address the n64 */
    t8 = (u_int8_t*)&n64;

    /* High order bytes */
    h64 = ntohl(*(u_int32_t*)&t8[0]);
    h64 <<= 32;

    /* Low order bytes */
    h64 |= ntohl(*(u_int32_t*)&t8[4]);

    return h64;
}
#endif


/*
 *  Functions for writing and reading headers. The format varies
 *  according to the version. In all cases the files starts
 *  with 4 bytes of magic number, 4 bytes of version, and
 *  8 bytes of total header length (version and header length
 *  fields given in network byte order). The rest depends on
 *  the version as follows:
 *
 *  Version 0: nothing - data records follow "hdr length".
 *  Version 2: Session Request as per version 5 of the protocol (use hdr len
 *  to skip session request, or read it using the format described
 *  below. (All values are in network byte order.)
 *
 *  0 format is as follows:
 * 
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    00|       "O"     |       "w"     |       "A"     |       \0      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    04|                        Version                                |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    08|                      hdr length (unsigned 64bit)              |
 *    12|                                                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  2 format is as follows:
 *
 * 
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    00|       "O"     |       "w"     |       "A"     |       \0      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    04|                        Version                                |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    08|                      hdr length (unsigned 64bit)              |
 *    12|                                                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    16|                        Finished                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    20|                                                               |
 *      ...                 TestRequestPreamble (protocol.c)          ...
 *   128|                                                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   132|                                                               |
 *   136|                   Slot(1) definitions (16 octets each)        |
 *   140|                                                               |
 *   144|                                                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   148:(148+(16*(nslots-1)) (16 octets for each additional slot)
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                                                               |
 *      |                   Zero Integrity Padding (16 octets)          |
 *      |                                                               |
 *      |                                                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Then individual packet records start. (hdr_len should point to here.)
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    00|                   Sequence Number                             |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    04|                                                               |
 *    08|                   Send Timestamp                              |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    12|  Send Error Estimate          |                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    16|                   Recv Timestamp                              |
 *      +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*    20|                               |       Recv Error Estimate     |
*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*
*  Version 3: Session Request as per version 12 of the protocol (use hdr len
        *  to skip the file header which includes file specific fields, the
        *  session request and possibly the skip records. (skip records
            *  can be between the session request and the packet records or
            *  follow everything.
            *
            *       0                   1                   2                   3
            *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            *    00|       "O"     |       "w"     |       "A"     |       \0      |
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            *    04|                            Version                            |
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            *    08|                            Finished                           |
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            *    12|                           Next Seqno                          |
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            *    16|                     Number of Skip Ranges                     |
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            *    20|                       Number of Records                       |
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            *    24|                      oset to Skip Ranges                      |
            *    28|                                                               |
            *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        *    32|                        oset to Records                        |
        *    36|                                                               |
        *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        *    40|                                                               |
        *      ...                 TestRequestPreamble (protocol.c)          ...
        *   148|                                                               |
        *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        *   152|                                                               |
        *   156|                   Slot(1) definitions (16 octets each)        |
        *   160|                                                               |
        *   164|                                                               |
    *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   168:(168+(16*(nslots-1))) (16 octets for each additional slot)
    *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    *      |                                                               |
    *      |                   Integrity Zero Padding (16 octets)          |
    *      |                                                               |
    *      |                                                               |
    *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    *
    * Then individual packet records or skip records start. It does not matter
    * which is first. The Num Skip Records and Num Data Records fields are
    * used to determine how long these ranges will be.
    *
    * The format for individual packet records is documented in the
    * header for the _OWPDecodeDataRecord function which should be used
    * to fetch them.
    *
    * The format for individual skip records is documented in the
    * header for the _OWPDecodeSkipRecord function which should be used
    * to fetch them.
    *
    * If Number of Skip Ranges == 0, then the value of oset to Skip Ranges
    * can remain nil.
    *
    * The API is setup to work from two points of view.
    *
    * Endpoint Reciever:
    *  Packets come in and it will not know about skips until
    *  after all data records are done. If WriteDataHeader is called with
    *  num_skiprecs == 0, then the file will be setup in this mode. Then
    *  the WriteDataHeaderNumDataRecs function will need to be called to
    *  set that field in the file data records are complete. When the
    *  StopSessions message comes across it will include the skip_recs and
    *  the WriteDataHeaaderNumSkipRecs function can be called to add skip
    *  records. This function will set the skip_oset if skip_oset is
    *  currently nil in addition to the num_skips. Then skip records
    *  are written until complete. The num_datarecs field MUST be set
    *  before the WriteDataHeaderNumskips can be called.
    *
    * FetchClient:
    *  Entire session is retrieved. Skip records come before data records
    *  in a Fetch response so WriteDataHeader is called with num_skiprecs
    *  set. (If num_skiprecs is 0, then oset_skips will be initialized
            *  to null.) SkipRecords can be written until they are complete. Then
    *  datarecords can be written. In this case the number of records will
    *  also have already been set with WriteDataHeader.
    *  WriteDataHeaderNumSkipRecs is not valid to be called for a file that
    *  is initialized this way but WriteDataHeaderNumDataRecs 
    *
    */

    /*
     * Function:    _OWPReadDataHeaderInitial
     *
     * Description:
     *      This function reads the initial file fields and also verifies the
     *      file is valid.
     *
     *
     * In Args:    
     *
     * Out Args:    
     *
     * Scope:    
     * Returns:    
     * Side Effect:    
     *      fp will be advanced to the start of the TestRequestPreamble
     *      for version >= 2 files. For version <=1 files fp will be
     *      at the begining of data records.
     */
    static u_int8_t owp_magic[] = _OWP_MAGIC_FILETYPE;
    OWPBoolean
    _OWPReadDataHeaderInitial(
            OWPContext                  ctx,
            FILE                        *fp,
            _OWPSessionHeaderInitial    phdr
            )
{
    u_int8_t    read_magic[sizeof(owp_magic)];
    int         err;
    u_int64_t   oset;

    /*
     * Initialize private file header record.
     */
    memset(phdr,0,sizeof(*phdr));

    /*
     * Stat the file to get the size and check that it is really there.
     */
    if(fstat(fileno(fp),&phdr->sbuf) < 0){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fstat(): %M");
        errno = err;
        return False;
    }

    /*
     * Position fp to beginning of file.
     */
    if(fseeko(fp,0,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return False;
    }

    /*
     * File must be at least as big as the initial header information.
     * 16 bytes is magic+version+hdr_length which is the minimum
     * size of any valid owp file. (version 0 files)
     */
    if(phdr->sbuf.st_size < (off_t)16){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPReadDataHeaderInitial: Invalid owp file");
        /*
         * TODO: Check validity of this errno... May need to
         * use ENOSYS...
         */
        errno = EFTYPE;
        return False;
    }

    /*
     * Read and check "magic".
     * 4 bytes
     */
    if(fread(&read_magic[0], 1, 4, fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    if(memcmp(read_magic,owp_magic,4) != 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPReadDataHeaderInitial: Invalid owp file:wrong magic");
        /*
         * TODO: Check validity of this errno... May need to
         * use ENOSYS...
         */
        errno = EFTYPE;
        return False;
    }

    /*
     * Get the file "version".
     * 4 byte "network long" quantity
     */
    if(fread(&phdr->version, 1, 4, fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    phdr->version = ntohl(phdr->version);

    /*
     * Currently it supports 0 and 2 and 3.
     */
    phdr->header = True;
    switch(phdr->version){
        case 0:
            phdr->header = False;
        case 2:
            if(fread(&oset, 1, 8, fp) != 8){
                err = errno;
                OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
                errno = err;
                return False;
            }
            oset = ntohll(oset);
            phdr->hdr_len = (off_t)oset;
            if(oset != (u_int64_t)phdr->hdr_len){
                OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "OWPReadDataHeaderInitial: Unable to represent file offset (%ull)",
                        oset);
                return False;
            }

            break;
        case 3:
            break;
        default:
            OWPError(ctx,OWPErrFATAL,EINVAL,
                    "_OWPReadDataHeaderInitial: Invalid file version (%ul)",
                    phdr->version);
            return False;
    }

    if(phdr->version == 0)
        return True;

    /*
     * Finished
     */
    if(fread(&phdr->finished, 1, 4, fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    phdr->finished = ntohl(phdr->finished);

    if(phdr->version < 3)
        return True;

    /*
     * Next Seqno
     */
    if(fread(&phdr->next_seqno, 1, 4, fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    phdr->next_seqno = ntohl(phdr->next_seqno);

    /*
     * Num Skips
     */
    if(fread(&phdr->num_skiprecs, 1, 4, fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    phdr->num_skiprecs = ntohl(phdr->num_skiprecs);

    /*
     * Num Datarecs
     */
    if(fread(&phdr->num_datarecs, 1, 4, fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    phdr->num_datarecs = ntohl(phdr->num_datarecs);

    /*
     * Skips oset
     */
    if(fread(&oset, 1, 8, fp) != 8){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    oset = ntohll(oset);
    phdr->oset_skiprecs = (off_t)oset;
    if(oset != (u_int64_t)phdr->oset_skiprecs){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPReadDataHeaderInitial: Unable to represent file offset (%ull)",
                oset);
        return False;
    }

    /*
     * Datarecs oset
     */
    if(fread(&oset, 1, 8, fp) != 8){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    oset = ntohll(oset);
    phdr->oset_datarecs = (off_t)oset;
    if(oset != (u_int64_t)phdr->oset_datarecs){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPReadDataHeaderInitial: Unable to represent file offset (%ull)",
                oset);
        return False;
    }
    phdr->hdr_len = phdr->oset_datarecs;

    return True;
}

/*
 * Function:        _OWPWriteDataHeaderFinished
 *
 * Description:        
 *        Write a new "finished" word into the file. This function seeks to
 *        the correct offset for a version 3 file.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPBoolean
_OWPWriteDataHeaderFinished(
        OWPContext  ctx,
        FILE        *fp,
        u_int32_t   finished,
        u_int32_t   next_seqno
        )
{
    int err;

    if(finished > 2){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteDataHeaderFinished: Invalid \"finished\"");
        return False;
    }

    /*
     * seek to finished word.
     */
    if(fseeko(fp,8,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return False;
    }

    /*
     * Write
     */
    finished = htonl(finished);
    if(fwrite(&finished,1,sizeof(finished),fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fwrite(): %M");
        errno = err;
        return False;
    }

    next_seqno = htonl(next_seqno);
    if(fwrite(&next_seqno,1,sizeof(next_seqno),fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fwrite(): %M");
        errno = err;
        return False;
    }

    if(fflush(fp) != 0){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fflush(): %M");
        errno = err;
        return False;
    }

    return True;
}

/*
 * Function:    OWPWriteDataHeaderNumSkipRecs
 *
 * Description:    
 *              Sets the num_skips field and the oset_skips
 *              field. oset_datarecs and num_datarecs
 *              MUST be set prior to this call. (Either by calling
 *              WriteDataHeader with num_datarecs or by calling
 *              WriteDataHeaderRecords.)
 *
 *              This function should only be called if skip records are
 *              being placed after datarecs, and then only after the
 *              number of datarecs has been fixed. If skip records are
 *              first in the file these fields MUST be initalized with
 *              the proper num_skips.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 *              fp will be advanced to an undefined offset.
 */
OWPBoolean
OWPWriteDataHeaderNumSkipRecs(
        OWPContext ctx,
        FILE       *fp,
        u_int32_t  num_skiprecs
        )
{
    _OWPSessionHeaderInitialRec phrec;
    u_int32_t                   n32;
    u_int64_t                   n64;
    int                         err;

    if(!_OWPReadDataHeaderInitial(ctx,fp,&phrec)){
        return False;
    }

    /*
     * Files before version 3 don't have skips.
     */
    if(phrec.version < 3){
        OWPError(ctx,OWPErrFATAL,EINVAL,
                "_OWPWriteDataHeaderNumSkipRecs: Invalid file version (%ul)",
                phrec.version);
        errno = EINVAL;
        return False;
    }

    /*
     * This function should not be called on a file that already has
     * initialized num_skiprecs and oset_skiprecs.
     */
    if(phrec.num_skiprecs || phrec.oset_skiprecs){
        OWPError(ctx,OWPErrFATAL,EINVAL,
                "_OWPWriteDataHeaderNumSkipRecs: Number skips already defined");
        errno = EINVAL;
        return False;
    }

    /*
     * Position fp to num_skiprecs field.
     */
    if(fseeko(fp,16,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return False;
    }

    /*
     * write num_skiprecs
     */
    n32 = htonl(num_skiprecs);
    if(fwrite(&n32, 1, sizeof(n32), fp) != sizeof(n32)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fwrite(): %M");
        errno = err;
        return False;
    }

    /*
     * Position fp to oset_skiprecs field.
     */
    if(fseeko(fp,24,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return False;
    }

    /*
     * Convert off_t oset_skiprecs to network ordered u_int64_t
     */
    phrec.oset_skiprecs = phrec.oset_datarecs +
        (_OWP_DATAREC_SIZE * phrec.num_datarecs);
    n64 = (u_int64_t)phrec.oset_skiprecs;
    if(phrec.oset_skiprecs != (off_t)n64){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPWriteDataHeaderNumSkipRecs: Unable to represet file offset (%ull)",
                phrec.oset_skiprecs);
        return False;
    }
    n64 = htonll(n64);

    /*
     * write oset_skiprecs
     */
    if(fwrite(&n64, 1, sizeof(n64), fp) != sizeof(n64)){

        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fwrite(): %M");
        errno = err;
        return False;
    }

    return True;
}

/*
 * Function:    OWPWriteDataHeaderNumDataRecs
 *
 * Description:    
 *              Sets the num_datarecs field.
 *              If oset_skiprecs is nil, this function sets that to
 *              just beyond the data records.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
OWPBoolean
OWPWriteDataHeaderNumDataRecs(
        OWPContext ctx,
        FILE       *fp,
        u_int32_t  num_datarecs
        )
{
    _OWPSessionHeaderInitialRec phrec;
    u_int32_t                   n32;
    int                         err;

    if(!_OWPReadDataHeaderInitial(ctx,fp,&phrec)){
        return False;
    }

    /*
     * Files before version 3 not supported for writing.
     */
    if(phrec.version < 3){
        OWPError(ctx,OWPErrFATAL,EINVAL,
                "_OWPWriteDataHeaderNumDataRecs: Invalid file version (%ul)",
                phrec.version);
        errno = EINVAL;
        return False;
    }

    /*
     * This function should not be called on a file that has
     * initialized oset_skiprecs to a greater offset than oset_datarecs.
     */
    if(phrec.oset_datarecs < phrec.oset_skiprecs){
        OWPError(ctx,OWPErrFATAL,EINVAL,
                "_OWPWriteDataHeaderNumDataRecs: Can't change number of datarecs.");
        errno = EINVAL;
        return False;
    }

    /*
     * Position fp to num_datarecs field.
     */
    if(fseeko(fp,20,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return False;
    }

    /*
     * write num_datarecs
     */
    n32 = htonl(num_datarecs);
    if(fwrite(&n32, 1, sizeof(n32), fp) != sizeof(n32)){

        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fwrite(): %M");
        errno = err;
        return False;
    }


    return True;
}

/*
 * Function:    OWPWriteDataHeader
 *
 * Description:    
 *    Write data header to the file.
 *
 * The fp is left pointing just past the IZP ready for either skip records
 * or data records.
 *
 * If num_skiprecs is non-zero, the file is configured for skip records
 * to come before data records and oset_skiprecs and oset_datarecs is
 * initialized in the file and returned in hdr.
 *
 * If num_skiprecs is zero, the file is configured for data records to
 * come before skip records. oset_datarecs will be set to just beyond
 * the header. If num_datarecs is zero, oset_skiprecs will be nil. If
 * num_datarecs is set, oset_skiprecs will be initialized as well.
 *
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:
 *      This function does not catch signals in the I/O with the
 *      file. If there is a signal - the fwrite will fail and this
 *      function will fail. The caller is responsible for checking any
 *      signal state.
 */
OWPBoolean
OWPWriteDataHeader(
        OWPContext         ctx,
        FILE               *fp,
        OWPSessionHeader   hdr
        )
{
    u_int32_t   ver;
    u_int32_t   finished = 2; /* 2 means unknown */
    u_int64_t   oset;
    u_int64_t   skip_oset = 0;
    u_int64_t   data_oset;
    off_t       oset_off;

    /* use u_int32_t for proper alignment */
    u_int32_t   msg[_OWP_TEST_REQUEST_PREAMBLE_SIZE/sizeof(u_int32_t)];
    u_int32_t   len = sizeof(msg);
    u_int32_t   i;
    u_int32_t   net32;
    u_int64_t   net64;

    if(!hdr){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPWriteDataHeader: No hdr data specified");
        return False;
    }

    /*
     * encode test_spec early so failure is detected early.
     */
    if((_OWPEncodeTestRequestPreamble(ctx,msg,&len,
                    (struct sockaddr*)&hdr->addr_sender,
                    (struct sockaddr*)&hdr->addr_receiver,
                    hdr->conf_sender,hdr->conf_receiver,
                    hdr->sid,&hdr->test_spec) != 0) || !len){
        return False;
    }
    ver = htonl(3);

    /*
     * Compute the offset to the end of the "header" information. Either
     * the data records, or the skip records depending upon which comes
     * first:
     *     MAGIC +
     *     Version +
     *     Finished +
     *     NextSeqno +
     *     NumSkips +
     *     NumRecs +
     *     OsetSkips +
     *     OsetRecs +
     *     TestRequestPramble +
     *     Slots
     */
    oset = sizeof(owp_magic) +
        sizeof(ver) +
        sizeof(finished) +
        sizeof(hdr->next_seqno) +
        sizeof(hdr->num_skiprecs) +
        sizeof(hdr->num_datarecs) +
        sizeof(oset)+
        sizeof(oset)+
        len +
        16*(hdr->test_spec.nslots+1);

    oset_off = (off_t)oset;
    if(oset != (u_int64_t)oset_off){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPWriteDataHeader: Header too large for format representation (%llu)",
                oset);
        return False;
    }


    /*
     * write magic
     */
    if(fwrite(owp_magic, 1, sizeof(owp_magic), fp) != sizeof(owp_magic)){
        return False;
    }

    /*
     * write version
     */
    if(fwrite(&ver, 1, sizeof(ver), fp) != sizeof(ver)){
        return False;
    }

    /*
     * write finished
     */
    if(hdr){
        switch(hdr->finished){
            case 0:
            case 1:
                finished = hdr->finished;
                break;
            default:
                break;
        }
    }
    net32 = htonl(finished);
    if(fwrite(&net32,1,sizeof(net32),fp) != sizeof(net32)){
        return False;
    }

    /*
     * Rest of "fixed" header.
     */
    net32 = htonl(hdr->next_seqno);
    if(fwrite(&net32,1,sizeof(net32),fp) != sizeof(net32)){
        return False;
    }
    net32 = htonl(hdr->num_skiprecs);
    if(fwrite(&net32,1,sizeof(net32),fp) != sizeof(net32)){
        return False;
    }
    net32 = htonl(hdr->num_datarecs);
    if(fwrite(&net32,1,sizeof(net32),fp) != sizeof(net32)){
        return False;
    }

    /*
     * write osets
     * 
     * This logic puts the skip records first in the file if num_skiprecs
     * is set, and puts datarecords first otherwise. If data records are
     * first, the number of datarecs MUST be set in the file before any
     * skip records can be written.
     *
     */
    if(hdr->num_skiprecs){
        skip_oset = oset;
        data_oset = oset + (hdr->num_skiprecs * _OWP_SKIPREC_SIZE);
    }
    else{
        data_oset = oset;

        if(hdr->num_datarecs){
            skip_oset = oset + (hdr->num_datarecs * _OWP_DATAREC_SIZE);
        }
    }

    net64 = htonll(skip_oset);
    if(fwrite(&net64,1,sizeof(net64),fp)!=sizeof(net64)){
        return False;
    }

    net64 = htonll(data_oset);
    if(fwrite(&net64,1,sizeof(net64),fp)!=sizeof(net64)){
        return False;
    }

    /*
     * write TestRequest preamble
     */
    if(fwrite(msg,1,len,fp) != len){
        return False;
    }

    /*
     * write slots
     */
    for(i=0;i<hdr->test_spec.nslots;i++){
        /*
         * Each slot is one block (16 bytes)
         */
        if(_OWPEncodeSlot(msg,&hdr->test_spec.slots[i]) !=
                OWPErrOK){
            OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                    "OWPWriteDataHeader: Invalid slot record");
            return False;
        }
        if(fwrite(msg,1,16,fp) != 16){
            return False;
        }

    }

    /*
     * write 16 Zero Integrity bytes
     */
    memset(msg,0,16);
    if(fwrite(msg,1,16,fp) != 16){
        return False;
    }

    fflush(fp);
    return True;
}

/*
 * Function:        OWPTestDiskspace
 *
 * Description:        
 *         Returns the size of file a given testspec will require.
 *         (Specific to version 3 files - all write functions only
 *         support latest version of files.)
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
u_int64_t
OWPTestDiskspace(
        OWPTestSpec        *tspec
        )
{
    u_int64_t   hdr_len;

    /*
     * 56 == 40 for initial portion + 16 for ending IZP
     */
    hdr_len = 56 + +_OWP_TEST_REQUEST_PREAMBLE_SIZE+
        16*(tspec->nslots+1);
    return hdr_len + tspec->npackets*_OWP_DATAREC_SIZE;
}

/*
 * Function:        OWPWriteDataRecord
 *
 * Description:        
 *         Write a single data record described by rec to file fp.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPBoolean
OWPWriteDataRecord(
        OWPContext  ctx,
        FILE        *fp,
        OWPDataRec  *rec
        )
{
    u_int8_t    buf[_OWP_DATAREC_SIZE];

    if(!_OWPEncodeDataRecord(buf,rec)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPWriteDataRecord: Unable to encode data record");
        return False;
    }

    /*
     * write data record
     */
    if(fwrite(buf,1,_OWP_DATAREC_SIZE,fp) != _OWP_DATAREC_SIZE){
        OWPError(ctx,OWPErrFATAL,errno,
                "OWPWriteDataRecord: fwrite(): %M");
        return False;
    }

    return True;
}


/*
 * Function:        OWPReadDataHeader
 *
 * Description:        
 * Version 0:
 *      nothing - data records follow.
 * Version 2:
 *      Session Request as per version 5 of the protocol
 *         This function does NOT read the slots into the hdr_ret->test_spec.
 *         A separate function OWPReadDataHeaderSlots has been provided to do
 *         that. (Memory for the slots must be provided by the caller.)
 * Version 3:
 *      Same as 2, but api modifed to not return hdr_len as a field.
 *      hdr_ret is now REQUIRED to be filled in, and the oset to data
 *      and/or skip records can be retrieved from fields in that record.
 *
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
OWPReadDataHeader(
        OWPContext          ctx,
        FILE                *fp,
        OWPSessionHeader    hdr_ret
        )
{
    _OWPSessionHeaderInitialRec phrec;
    int                         err;

    /* buffer for TestRequest 32 bit aligned */
    u_int32_t                   msg[_OWP_TEST_REQUEST_PREAMBLE_SIZE /
        sizeof(u_int32_t)];

    hdr_ret->header = 0;

    if(!_OWPReadDataHeaderInitial(ctx,fp,&phrec)){
        return 0;
    }

    hdr_ret->version = phrec.version;
    hdr_ret->sbuf = phrec.sbuf;

    switch(phrec.version){
        case 0: case 1: case 2:
            hdr_ret->rec_size = _OWP_DATARECV2_SIZE;
            break;
        case 3:
        default:
            hdr_ret->rec_size = _OWP_DATAREC_SIZE;
            break;
    }

    /*
     * Decode the header if present(version 2).
     */
    if(phrec.version >= 2){

        hdr_ret->finished = phrec.finished;

        /*
         * read TestRequestPreamble
         */
        if(fread(msg,1,_OWP_TEST_REQUEST_PREAMBLE_SIZE,fp) !=
                _OWP_TEST_REQUEST_PREAMBLE_SIZE){
            err = errno;
            OWPError(ctx,OWPErrFATAL,errno,"fread(): %M");
            errno = err;
            return 0;
        }

        hdr_ret->addr_len = sizeof(hdr_ret->addr_sender);
        /*
         * Now decode it into the hdr_ret variable.
         */
        if(_OWPDecodeTestRequestPreamble(ctx,False,msg,
                    _OWP_TEST_REQUEST_PREAMBLE_SIZE,
                    (struct sockaddr*)&hdr_ret->addr_sender,
                    (struct sockaddr*)&hdr_ret->addr_receiver,
                    &hdr_ret->addr_len,&hdr_ret->ipvn,
                    &hdr_ret->conf_sender,&hdr_ret->conf_receiver,
                    hdr_ret->sid,&hdr_ret->test_spec) != OWPErrOK){
            /*
             * TODO: Check validity of this errno... May need to
             * use ENOSYS...
             */
            errno = EFTYPE;
            return 0;
        }

        hdr_ret->header = True;
    }

    /*
     * Forward fp to data records.
     */
    if(fseeko(fp,phrec.hdr_len,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return 0;
    }

    /*
     * Make sure num_datarecs is not larger than the file allows.
     */
    if(phrec.num_datarecs > ((phrec.sbuf.st_size - phrec.hdr_len)/
                hdr_ret->rec_size)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPReadDataHeader: num_datarecs field too large.");
        return 0;
    }

    if(phrec.version < 3){
        hdr_ret->num_datarecs = (phrec.sbuf.st_size - phrec.hdr_len)/
            hdr_ret->rec_size;
        return hdr_ret->num_datarecs;
    }

    hdr_ret->next_seqno = phrec.next_seqno;
    hdr_ret->num_skiprecs = phrec.num_skiprecs;
    hdr_ret->oset_skiprecs = phrec.oset_skiprecs;
    hdr_ret->oset_datarecs = phrec.oset_datarecs;
    if(!phrec.finished){
        hdr_ret->num_datarecs = (phrec.sbuf.st_size - phrec.hdr_len)/
            hdr_ret->rec_size;
    }
    else{
        hdr_ret->num_datarecs = phrec.num_datarecs;
    }

    return hdr_ret->num_datarecs;
}

/*
 * Function:        OWPReadDataHeaderSlots
 *
 * Description:        
 *         This function will read all the slot records out of the
 *         file fp. slots is assumed to be an array of OWPSlot records of
 *         length nslots.
 *
 *         This function will position the fp to the beginning of the data
 *         records.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPBoolean
OWPReadDataHeaderSlots(
        OWPContext  ctx,
        FILE        *fp,
        u_int32_t   nslots,
        OWPSlot     *slots
        )
{
    int                         err;
    _OWPSessionHeaderInitialRec phrec;
    u_int32_t                   fileslots;
    u_int32_t                   i;
    off_t                       slot_off = 152; /* see above layout of bytes */
    off_t                       hdr_off;

    /* buffer for Slots 32 bit aligned */
    u_int32_t                   msg[16/sizeof(u_int32_t)];
    u_int32_t                   zero[16/sizeof(u_int32_t)];

    /*
     * validate array.
     */
    assert(slots);

    /*
     * Stat the file and get the "initial" fields from the header.
     */
    if(!_OWPReadDataHeaderInitial(ctx,fp,&phrec)){
        return False;
    }

    /*
     * this function is currently only supported for version 2 files.
     */
    if(phrec.version < 2){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPReadDataHeaderSlots: Invalid file version (%d)",
                phrec.version);
        errno = ENOSYS;
        return False;
    }

    /*
     * Find offset to the end of the "header".
     */
    hdr_off = MIN(phrec.oset_skiprecs,phrec.oset_datarecs);
    if(!hdr_off){
        hdr_off = MAX(phrec.oset_skiprecs,phrec.oset_datarecs);
    }

    /*
     * validate nslots passed in with what is in the file.
     * hdr_off should point to the offset in the file where the slots
     * are finished and the 1 block of zero padding is finished.
     */
    fileslots = hdr_off - slot_off; /* bytes for slots */

    /*
     * bytes for slots/zero padding must be of block size 16
     */
    if(fileslots%16){
        OWPError(ctx,OWPErrFATAL,EFTYPE,
                "OWPReadDataHeaderSlots: Invalid hdr_offset (%llu)",
                hdr_off);
        /*
         * TODO: Check validity of this errno... May need to
         * use ENOSYS...
         */
        errno = EFTYPE;
        return False;
    }

    /*
     * Convert bytes to number of slots. Divide by block size, then
     * subtract 1 for zero integrity block.
     */
    fileslots/=16;
    fileslots--;

    if(fileslots != nslots){
        OWPError(ctx,OWPErrFATAL,EINVAL,
                "OWPReadDataHeaderSlots: nslots mismatch with file: fileslots(%d), nslots(%d)",
                fileslots,nslots);
        errno = EINVAL;
        return False;
    }

    /*
     * Position fp to beginning of slot records.
     */
    if(fseeko(fp,slot_off,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return False;
    }

    for(i=0;i<nslots;i++){

        /*
         * Read slot into buffer.
         */
        if(fread(msg,1,16,fp) != 16){
            err = errno;
            OWPError(ctx,OWPErrFATAL,errno,"fread(): %M");
            errno = err;
            return False;
        }

        /*
         * Decode slot buffer into slot record.
         */
        if(_OWPDecodeSlot(&slots[i],msg) != OWPErrOK){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPReadDataHeaderSlots: Invalid Slot record");
            errno = EFTYPE;
            return False;
        }
    }

    /*
     * Read block of Zero Integrity bytes into buffer.
     */
    if(fread(msg,1,16,fp) != 16){
        err = errno;
        OWPError(ctx,OWPErrFATAL,errno,"fread(): %M");
        errno = err;
        return False;
    }

    /*
     * check to make sure Zero bytes are zero.
     */
    memset(zero,0,16);
    if(memcmp(zero,msg,16) != 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPReadDataHeaderSlots: Invalid zero padding");
        errno = EFTYPE;
        return False;
    }

    return True;
}

/*
 * Function:        OWPParseRecords
 *
 * Description:        
 *         Fetch num_rec records from disk calling the record proc function
 *         on each record.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPErrSeverity
OWPParseRecords(
        OWPContext      ctx,
        FILE            *fp,
        u_int32_t       num_rec,
        u_int32_t       file_version,
        OWPDoDataRecord proc_rec,
        void            *app_data
        )
{
    size_t      len_rec;
    u_int8_t    rbuf[_OWP_DATAREC_SIZE];
    u_int32_t   i;
    OWPDataRec  rec;
    int         rc;

    /*
     * This function is used to abstract away the different requirements
     * of different versions of the owd data files.
     * Currently it supports 0 and 2, (both of which
     * require the same 24 octet data records) and 3 which requires
     * 25 octets.
     */
    switch(file_version){
        case 0: case 2:
            len_rec = _OWP_DATARECV2_SIZE;
            break;
        case 3:
            len_rec = _OWP_DATAREC_SIZE;
            break;
        default:
            OWPError(ctx,OWPErrFATAL,EINVAL,
                    "OWPParseRecords: Invalid file version (%d)",
                    file_version);
            return OWPErrFATAL;
    }

    for(i=0;i<num_rec;i++){
        if(fread(rbuf,len_rec,1,fp) < 1){
            if(ferror(fp)){
                OWPError(ctx,OWPErrFATAL,errno,
                        "fread(): STREAM ERROR: offset=%llu,i=%lu",
                        ftello(fp),i);
            }
            else if(feof(fp)){
                OWPError(ctx,OWPErrFATAL,errno,
                        "fread(): EOF: offset=%llu",ftello(fp));
            }
            return OWPErrFATAL;
        }
        if(!_OWPDecodeDataRecord(file_version,&rec,rbuf)){
            errno = EFTYPE;
            OWPError(ctx,OWPErrFATAL,errno,
                    "OWPParseRecords: Invalid Data Record: %M");
            return OWPErrFATAL;
        }
        rc = proc_rec(&rec,app_data);
        if(!rc) continue;
        if(rc < 0)
            return OWPErrFATAL;
        return OWPErrOK;

    }

    return OWPErrOK;
}

/*
 * Function:        OWPIsLostRecord
 *
 * Description:        
 *         Returns true if the given DataRec indicates a "lost" packet. This
 *         is determined by looking at the recv timestamp. If it is a string
 *         of zero bits, then it is lost.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPBoolean
OWPIsLostRecord(
        OWPDataRec *rec
        )
{
    return !rec->recv.owptime;
}
