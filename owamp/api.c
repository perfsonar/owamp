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
#include "./owampP.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <poll.h>


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
        I2Addr      sender,
        OWPBoolean  conf_sender,
        I2Addr      receiver,
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

    I2AddrFree(tsession->sender);
    I2AddrFree(tsession->receiver);

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
    uint8_t        *aptr;
    struct sockaddr *saddr;

    if( !(saddr = I2AddrSAddr(tsession->receiver,NULL))){
            OWPError(tsession->cntrl->ctx,OWPErrFATAL,OWPErrUNSUPPORTED,
                    "_OWPCreateSID: Invalid socket address");
        return 1;
    }

#ifdef        AF_INET6
    if(saddr->sa_family == AF_INET6){
        struct sockaddr_in6        *s6;

        s6 = (struct sockaddr_in6*)saddr;
        /* point at last 4 bytes of addr */
        aptr = &s6->sin6_addr.s6_addr[12];
    }else
#endif
        if(saddr->sa_family == AF_INET){
            struct sockaddr_in        *s4;

            s4 = (struct sockaddr_in*)saddr;
            aptr = (uint8_t*)&s4->sin_addr;
        }
        else{
            OWPError(tsession->cntrl->ctx,OWPErrFATAL,OWPErrUNSUPPORTED,
                    "_OWPCreateSID:Unknown address family");
            return 1;
        }

    memcpy(&tsession->sid[0],aptr,4);

    (void)OWPGetTimeOfDay(tsession->cntrl->ctx,&tstamp);
    _OWPEncodeTimeStamp(&tsession->sid[4],&tstamp);

    if(I2RandomBytes(tsession->cntrl->ctx->rand_src,
                (uint8_t *)&tsession->sid[12],4)
            != 0){
        return 1;
    }

    return 0;
}

OWPPacketSizeT
OWPTestPayloadSize(
        OWPSessionMode  mode, 
        uint32_t       padding
        )
{
    OWPPacketSizeT msg_size = 0;

    switch (mode) {
        case OWP_MODE_OPEN:
            msg_size = 14;
            break;
        case OWP_MODE_AUTHENTICATED:
        case OWP_MODE_ENCRYPTED:
            msg_size = 48;
            break;
    }

    return msg_size + padding;
}

OWPPacketSizeT
OWPTestTWPayloadSize(
        OWPSessionMode  mode,
        uint32_t       padding
        )
{
    OWPPacketSizeT msg_size = 0;

    switch (mode) {
        case OWP_MODE_OPEN:
            msg_size = 41;
            break;
        case OWP_MODE_AUTHENTICATED:
        case OWP_MODE_ENCRYPTED:
            msg_size = 112;
            break;
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
    uint32_t   i;

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
        uint32_t       padding
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
 ** Given the protocol family, OWAMP mode and packet padding,
 ** compute the size of resulting full IP packet.
 */
OWPPacketSizeT
OWPTestTWPacketSize(
        int             af,    /* AF_INET, AF_INET6 */
        OWPSessionMode  mode,
        uint32_t       padding
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

    if(!(payload_size = OWPTestTWPayloadSize(mode,padding)))
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
        uint32_t        *num_sessions
        )
{
    OWPErrSeverity  err,err2=OWPErrOK;
    OWPAcceptType   aval=OWP_CNTRL_ACCEPT;
    OWPAcceptType   *acceptval = &aval;
    OWPTestSession  sptr;
    uint32_t       num_senders=0;

    if(acceptval_ret){
        acceptval = acceptval_ret;
    }
    *num_sessions = 0;

    /*
     * Stop each session - count the "send" sessions and verify that
     * the "skip records" saved at each fd are at least a consistent size.
     */
    for(sptr=cntrl->tests; sptr; sptr = sptr->next){
        uint32_t   sdr[2];
        uint32_t   nskip;
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
         * Two-way and receive sessions are not done here.
         */
        if(!cntrl->twoway && !sptr->endpoint->send) continue;

        /*
         * Stop local sessions
         */
        _OWPEndpointStop(sptr->endpoint,acceptval,&err);
        err2 = MIN(err,err2);

        /* count senders for inclusion in StopSessions message */
        num_senders++;

        if (!cntrl->twoway) {
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
                OWPError(cntrl->ctx,OWPErrWARNING,errno,"I2Readn(skiprecfd): %M");
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
        OWPTimeStamp    stoptime,
        OWPBoolean      nowait,
        OWPAcceptType   *acceptval_ret
        )
{
    OWPErrSeverity  err,err2=OWPErrOK;
    OWPAcceptType   aval=OWP_CNTRL_ACCEPT;
    OWPAcceptType   *acceptval = &aval;
    OWPTestSession  sptr;
    struct timespec currts;
    struct timespec stopts;
    struct timespec lossts;

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
         * One-way send sessions not done here.
         */
        if(!cntrl->twoway && sptr->endpoint->send) continue;

        if (cntrl->twoway && cntrl->server && !nowait) {
            uint32_t esterr;
            uint8_t sync;

            _OWPGetTimespec(cntrl->ctx,&currts,&esterr,&sync);
            OWPTimestampToTimespec(&stopts, &stoptime);

            // TODO: this should be bounded by REFWAIT timeout
            OWPNum64ToTimespec(&lossts,sptr->test_spec.loss_timeout);
            timespecadd(&stopts,&lossts);

            if(timespeccmp(&stopts,&currts,<))
                break;

            /*
             * Convert from absolute to relative
             */
            timespecsub(&stopts,&currts);
            /*
             * Wait for loss timeout time to allow in-flight packets
             * to still be reflected.
             */
            nanosleep(&stopts, NULL);
        }

        /*
         * Stop local sessions
         */
        _OWPEndpointStop(sptr->endpoint,acceptval,&err);
        err2 = MIN(err,err2);
    }

    return err2;
}

/*
 * Function:    _OWPCleanDataRecs
 *
 * Description:    
 *          Function is used to remove data records from the recieve
 *          side test based on the information from the StopSession
 *          message. (stoptime, next_seqno)
 *
 *          If StopSession message is not exchanged, then next_seqno
 *          MUST be set to 0xFFFFFFFF.
 *
 *          The caller should have locked the file before calling this.
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
OWPBoolean
_OWPCleanDataRecs(
        OWPContext      ctx,
        OWPTestSession  tptr,
        uint32_t        next_seqno,
        OWPTimeStamp    stoptime,
        uint32_t        *max_recv_rtn,
        off_t           *off_start_rtn
        )
{
    FILE        *rfp, *wfp;
    char        sid_name[sizeof(OWPSID)*2+1];
    off_t       toff;
    OWPDataRec  rec;
    _OWPSessionHeaderInitialRec fhdr;
    char        rbuf[_OWP_MAXDATAREC_SIZE];
    uint32_t    j;
    uint32_t    lowI,midI,highI,num_recs;
    OWPNum64    lowR,midR,highR,threshR;
    uint32_t    max_recv_data;
    uint32_t    *max_recv = &max_recv_data;
    off_t       off_start_data;
    off_t       *off_start = &off_start_data;

    if(max_recv_rtn)
        max_recv = max_recv_rtn;
    *max_recv = 0;
    if(off_start_rtn)
        off_start = off_start_rtn;
    *off_start = 0;


    I2HexEncode(sid_name,tptr->sid,sizeof(OWPSID));

    rfp = tptr->endpoint->datafile;
    wfp = rfp;

    /*
     * Read needed file header info.
     */
    if(!_OWPReadDataHeaderInitial(ctx,rfp,&fhdr)){
        goto err;
    }

    /*
     * Compute number of data records currently in file using filesizes.
     * (Verify that disk space is a multiple of datarec size too...)
     */
    toff = fhdr.sbuf.st_size - fhdr.oset_datarecs;
    if(toff % fhdr.rec_size){
        OWPError(ctx,OWPErrFATAL,EFTYPE,
                "_OWPCleanDataRecs: Invalid records for sid(%s)",
                sid_name);
        goto err;
    }
    fhdr.num_datarecs = num_recs = toff / fhdr.rec_size;

    /*
     * If there is no data, this is a very simple file...
     */
    if(!fhdr.num_datarecs) goto clean_data;

    /*
     * Seek to beginning of data records.
     */
    if(fseeko(rfp,fhdr.oset_datarecs,SEEK_SET) != 0){
        OWPError(ctx,OWPErrFATAL,errno,"fseeko(): %M");
        goto err;
    }

    /*
     * Delete data records with a computed send time later than
     * currenttime (ie. stoptime) - timeout as per section 3.8 RFC 4656.
     *
     * To do this is somewhat non-trivial. The records in the file
     * are sorted by recv time. There is a relationship between
     * recv time and send time because of the "timeout" parameter
     * of a test. A packet is only accepted and saved if the recv
     * time is within "timeout" of the recv time. Therefore, this
     * algorithm starts by finding the first packet record in the
     * file with a recv time greater than (stoptime - (2 * timeout)).
     * (recv time can be timeout less than send time if clocks are
     * offset).
     *
     * Additionally, the next_seqno from the StopSessions message
     * comes into play. Let the presumed sendtime of next_seqno be
     * next_seqno_time. Then, the parsing may need to start
     * as early as (next_seqno_time - (2 * timeout)).
     *
     * Therefore, the search algorithm actually looks for the minimum
     * of those two values.
     *
     * lowI will be the index to the packet record with the
     * largest recv time less than the threshold (stoptime - (2 * timeout))
     * upon completion of the binary search. (If one exists.)
     *
     * After the binary search, the algorithm sequentially goes
     * forward through the file deleting all packet records with
     * (sendtime > (stoptime - timeout)).  During this pass, if any
     * index is >= next_seqno, the entire session will be declared
     * invalid. Additionally, any LostPacket records with
     * index >= next_seqno will be removed.
     *
     */
    if(next_seqno == 0xFFFFFFFF){
        next_seqno = tptr->test_spec.npackets;
    }

    if(next_seqno > tptr->test_spec.npackets){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPCleanDataRecs: Invalid \'next_seqno\': %lu",next_seqno);
        goto err;
    }

    /*
     * First use an interpolated binary search to find the "threshold"
     * point in the file.
     */

    /* Initializing variables for search. */

    /* find threshold time. MIN(stoptime,next_seqno_time) - (2 * timeout) */
    if(OWPScheduleContextReset(tptr->sctx,NULL,NULL) != OWPErrOK){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPCleanDataRecs: SchedulecontextReset(): FAILED");
        goto err;
    }

    /* find next_seqno_time */
    lowI = 0;
    threshR = tptr->test_spec.start_time;
    while(lowI < next_seqno){
        threshR = OWPNum64Add(threshR,
                OWPScheduleContextGenerateNextDelta(tptr->sctx));
        lowI++;
    }

    /* find MIN(next_seqno_time,stoptime) */
    threshR = OWPNum64Min(threshR,stoptime.owptime);

    /*
     * Set actual threshold to 2*timeout less than that to deal with
     * offset clocks.
     */
    threshR = OWPNum64Sub(threshR,
            OWPNum64Mult(tptr->test_spec.loss_timeout,OWPULongToNum64(2)));
    highI = fhdr.num_datarecs;
    highR = stoptime.owptime;
    lowI = 0;

    /*
     * Read the first packet record to get the recv(0) for lowR.
     */
    if(fread(rbuf,fhdr.rec_size,1,rfp) != 1){
        OWPError(ctx,OWPErrFATAL,errno,
                "fread(): Reading session file for sid(%s): %M",sid_name);
        goto err;
    }
    if(!_OWPDecodeDataRecord(fhdr.version,&rec,rbuf)){
        errno = EFTYPE;
        OWPError(ctx,OWPErrFATAL,errno,
                "_OWPCleanDataRecs: Invalid data record for sid(%s)",
                sid_name);
        goto err;
    }

    if(OWPIsLostRecord(&rec)){
        lowR = OWPNum64Add(rec.send.owptime,tptr->test_spec.loss_timeout);
    }
    else{
        lowR = rec.recv.owptime;
    }

    /*
     * If lowR is not less than threshR than we are done.
     */
    if(!(OWPNum64Cmp(lowR,threshR) < 0)){
        goto thresh_pos;
    }

    /*
     * This loop is the meat of the interpolated binary search
     */
    while((highI - lowI) > 1){
        OWPNum64    portion;
        OWPNum64    range;

        range = OWPNum64Sub(highR,lowR);

        /*
         * If there are multiple records with the same recv time,
         * interpolation will fail - in this case fall back to strict
         * binary.
         */
        if(!range){
            midI = (highI - lowI) / 2;
        }
        else{
            /*
             * Interpolate
             */
            portion = OWPNum64Sub(threshR,lowR);
            midI = lowI + ((OWPNum64ToDouble(portion) * (highI - lowI)) /
                    OWPNum64ToDouble(range));
            if(midI == lowI) midI++;
        }

        /*
         * determine offset from midI
         */
        toff = fhdr.oset_datarecs + midI * fhdr.rec_size;

        /*
         * Seek to midI data record.
         */
        if(fseeko(rfp,toff,SEEK_SET) != 0){
            OWPError(ctx,OWPErrFATAL,errno,"fseeko(): %M");
            goto err;
        }

        /*
         * Read the packet record from midI.
         */
        if(fread(rbuf,fhdr.rec_size,1,rfp) != 1){
            OWPError(ctx,OWPErrFATAL,errno,
                    "fread(): Reading session file for sid(%s): %M",
                    sid_name);
            goto err;
        }
        if(!_OWPDecodeDataRecord(fhdr.version,&rec,rbuf)){
            errno = EFTYPE;
            OWPError(ctx,OWPErrFATAL,errno,
                    "_OWPCleanDataRecs: Invalid data record for sid(%s)",
                    sid_name);
            goto err;
        }

        /*
         * If midR is less than thresh, update lowI. Otherwise,
         * update highI.
         */
        if(OWPIsLostRecord(&rec)){
            midR = OWPNum64Add(rec.send.owptime,
                    tptr->test_spec.loss_timeout);
        }
        else{
            midR = rec.recv.owptime;
        }
        if(OWPNum64Cmp(midR,threshR) < 0){
            lowI = midI;
            lowR = midR;
        }
        else{
            highI = midI;
            highR = midR;
        }
    }
thresh_pos:

    /*
     * Now, step through all records lowI and after to examine the
     * sent time. The sent time must be less than (stop - timeout)
     * and the index must be less than next_seqno for the record
     * to be kept. (If index is greater than or equal to next_seqno,
     * and it is not a lost packet record, the entire session
     * MUST be deleted as per the spec.)
     *
     */
    *off_start = toff = fhdr.oset_datarecs + (lowI * fhdr.rec_size);
    threshR = OWPNum64Sub(stoptime.owptime,tptr->test_spec.loss_timeout);

    /*
     * Seek to lowI data record to start parsing.
     */
    if(fseeko(rfp,toff,SEEK_SET) != 0){
        OWPError(ctx,OWPErrFATAL,errno,"fseeko(): %M");
        goto err;
    }

    for(j=lowI;j<fhdr.num_datarecs;j++){

        /*
         * Read the packet record from midI.
         */
        if(fread(rbuf,fhdr.rec_size,1,rfp) != 1){
            OWPError(ctx,OWPErrFATAL,errno,
                    "fread(): Reading session file sid(%s): %M",
                    sid_name);
            goto loop_err;
        }
        if(!_OWPDecodeDataRecord(fhdr.version,&rec,rbuf)){
            errno = EFTYPE;
            OWPError(ctx,OWPErrFATAL,errno,
                    "_OWPCleanDataRecs: Invalid data record sid(%s)",
                    sid_name);
            goto loop_err;
        }

        /*
         * If the seq_no is >= next_seqno, and it is not a lost
         * packet record, then this session MUST be thrown out.
         * Otherwise, if the packet was not sent after threshR, then keep it
         * by writing it back into the file if necessary.
         * Finally, drop the packet.
         */

        /* Invalid session */
        if((rec.seq_no >= next_seqno) && !OWPIsLostRecord(&rec)){
            errno = EFTYPE;
            OWPError(ctx,OWPErrFATAL,errno,
                    "_OWPCleanDataRecs: Invalid data record (seq_no too large) sid(%s)",
                    sid_name);
            goto loop_err;
        }
        /* Good record */
        else if((rec.seq_no < next_seqno) &&
                (OWPNum64Cmp(rec.send.owptime,threshR) <= 0)){
            *max_recv = MAX(rec.seq_no,*max_recv);
            if(wfp != rfp){
                if(fwrite(rbuf,fhdr.rec_size,1,wfp) != 1){
                    OWPError(ctx,OWPErrFATAL,errno,
                            "fwrite(): Writing session file sid(%s): %M",
                            sid_name);
                    goto loop_err;
                }
            }
        }
        /*
         * The packet record should not be kept.
         */
        else{
            num_recs--;
            /*
             * If wfp==rfp, then create another fp for wfp and point
             * it at the current record so it will be written over.
             */
            if(wfp == rfp){
                int     newfd;
                char    tmpfname[PATH_MAX];
                char    *dname;
                char    *tmpl = "owamp.XXXXXXXX";

                /*
                 * Need another file for bookkeeping... First determine
                 * what dir to put it in.
                 */
                dname = NULL;
                memset(tmpfname,'\0',sizeof(tmpfname));

                /* put it in the same dir as session data if possible */
                if( strlen(tptr->endpoint->fname) > 0){
                    strncpy(tmpfname,tptr->endpoint->fname,PATH_MAX);
                    dname = dirname(tmpfname);
                }

                /* otherwise use tmpdir */
                if( !dname){
                    dname = getenv("TMPDIR");
                }
                if( !dname){
                    dname = "/tmp";
                }

                /* Make sure pathname will not over-run memory. */
                if(strlen(tmpl) + OWP_PATH_SEPARATOR_LEN + strlen(dname) >
                        PATH_MAX){
                    OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "_OWPCleanDataRecs: Unable to create temp file: Path Too Long");
                    goto err;
                }

                /* create template (fname) string for mkstemp */
                strcpy(tmpfname,dname);
                strcat(tmpfname,OWP_PATH_SEPARATOR);
                strcat(tmpfname,tmpl);
                if( (newfd = mkstemp(tmpfname)) < 0){
                    OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "_OWPCleanDataRecs: mkstemp(%s): %M",
                            tmpfname);
                    goto err;
                }

                /* immediately unlink - no need for a directory entry */
                if(unlink(tmpfname) != 0){
                    OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "unlink(%s): %M",tmpfname);
                    close(newfd);
                    goto err;
                }

                /*
                 * Copy original file into tmpfile from the beginning
                 * until just before the current record.
                 */
                toff = fhdr.oset_datarecs + (j * fhdr.rec_size);
                if(I2CopyFile(OWPContextErrHandle(ctx),
                            newfd,fileno(rfp),toff) != 0){
                    OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                            "_OWPCleanDataRecs: Unable to copy session data: I2CopyFile(): %M");
                    close(newfd);
                    goto err;
                }

                if( !(wfp = fdopen(newfd,"r+b"))){
                    OWPError(ctx,OWPErrFATAL,errno,"fdopen(%d): %M",
                            newfd);
                    close(newfd);
                    goto err;
                }

                /*
                 * Seek new wfp to end of tmpfile.
                 */
                if(fseeko(wfp,0,SEEK_END) != 0){
                    OWPError(ctx,OWPErrFATAL,errno,"fseeko(): %M");
                    goto loop_err;
                }
            }
        }
        continue;
loop_err:
        if(wfp != rfp){
            fclose(wfp);
        }
        goto err;
    }

clean_data:

    /*
     * If two fp's were used, then the tmpfile needs to be copied
     * back to the original file.
     */
    if(wfp != rfp){
        if(I2CopyFile(OWPContextErrHandle(ctx),
                    fileno(rfp),fileno(wfp),0) != 0){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "_OWPCleanDataRecs: Unable to copy session data: I2CopyFile(): %M");
            fclose(wfp);
            goto err;
        }
        fclose(wfp);
    }

    /*
     * Write NumDataRecords into file.
     * (This MUST be done before adding any skip records to the file
     * or there is a race condition where partial session results could
     * interpret skip records as data records!)
     */
    if( !OWPWriteDataHeaderNumDataRecs(ctx,rfp,num_recs)){
        goto err;
    }

    return True;

err:
    OWPError(ctx, OWPErrFATAL,OWPErrUNKNOWN,
            "_OWPCleanDataRecs: Failed");
    return False;
}

typedef struct _maxrecv_rec{
    OWPBoolean  found;
    uint32_t    index;          /* count records (index in file) */
    uint32_t    maxrecv;        /* max seqno for received records */
    uint32_t    badlost;        /* seqno for *first* throw-away lost rec */
    uint32_t    index_badlost;  /* record index in file for badlost */
} _maxrecv_rec;

static int
GetMaxRecv(
        OWPDataRec  *rec,
        void        *data
        )
{
    _maxrecv_rec    *mrec = (_maxrecv_rec *)data;


    /*
     * If this record is not lost, update maxrecv
     */
    if(!OWPIsLostRecord(rec)){
        mrec->found = True;
        mrec->maxrecv = MAX(mrec->maxrecv,rec->seq_no);
    }
    /*
     * lost - if this is the first one greater than maxrecv, then
     * record the badlost.
     */
    else if((rec->seq_no > mrec->maxrecv) &&
            (mrec->badlost < mrec->maxrecv)){
        mrec->badlost = rec->seq_no;
        mrec->index_badlost = mrec->index;
    }

    mrec->index++;

    return 0;
}

/*
 * Function:    _OWPCleanUpSessions
 *
 * Description:    
 *              This function updates the "recv" side sessions.
 *              The StopSessions message was not read in this case,
 *              so it relies on the stoptime of the session to
 *              clean things up. Also, it deletes all trailing
 *              Missing packet records in the file.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static OWPBoolean
_OWPCleanUpSessions(
        OWPControl      cntrl,
        int             *intr __attribute__((unused)),
        OWPAcceptType   *acceptval_ret,
        OWPTimeStamp    stoptime
        )
{
    OWPAcceptType   aval;
    OWPAcceptType   *acceptval = &aval;
    OWPTestSession  tptr;

    if(acceptval_ret)
        acceptval = acceptval_ret;
    *acceptval = OWP_CNTRL_ACCEPT;

    if (cntrl->twoway && cntrl->server) {
        /*
         * No cleanup required for server two-way sessions, since no
         * datafile is created.
         */
        return True;
    }

    /*
     * Parse test session list and pull recv sessions into the receivers
     * list.
     */
    for(tptr = cntrl->tests;tptr;tptr = tptr->next){
        char                        sid_name[sizeof(OWPSID)*2+1];
        off_t                       toff;
        FILE                        *rfp,*wfp;
        _OWPSessionHeaderInitialRec fhdr;
        struct flock                flk;
        uint32_t                    j;
        OWPDataRec                  rec;
        char                        rbuf[_OWP_MAXDATAREC_SIZE];
        uint32_t                    max_recv,num_recs;

        if(!tptr->endpoint){
            OWPError(cntrl->ctx,OWPErrFATAL,EINVAL,
                    "_OWPCleanUpSessions: no endpoint state!");
            goto err;
        }

        /*
         * Only need to clean recv sessions.
         */
        if(!cntrl->twoway && tptr->endpoint->send){
            continue;
        }


        I2HexEncode(sid_name,tptr->sid,sizeof(OWPSID));

        if (!tptr->endpoint->datafile) {
            continue;
        }
        rfp = wfp = tptr->endpoint->datafile;

        /*
         * Lock the data file for writing. This is needed so FetchSessions
         * coming in from other control connections will get consistent
         * information.
         */
        memset(&flk,0,sizeof(flk));
        flk.l_start = 0;
        flk.l_len = 0;
        flk.l_whence = SEEK_SET;
        flk.l_type = F_WRLCK;

        if( fcntl(fileno(rfp), F_SETLKW, &flk) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "_OWPCleanUpSessions: Unable to lock file sid(%s): %M",
                    sid_name);
            goto err;
        }

        max_recv = 0;
        if( !_OWPCleanDataRecs(cntrl->ctx,tptr,0xFFFFFFFF,stoptime,&max_recv,
                    &toff)){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "_OWPCleanUpSessions: Unable to clean data sid(%s): %M",
                    sid_name);
            goto err;
        }

        /*
         * Read needed file header info.
         */
        if(!_OWPReadDataHeaderInitial(cntrl->ctx,rfp,&fhdr)){
            goto err;
        }

        /*
         * Because this is from a broken control connection, I
         * now need to clean out any records with an index greater than
         * the last received packet.
         *
         * If CleanDataRecs was unable to get a max index, then
         * this degrades to a full parse of the dataset for the max
         * 'found' index.
         */
        if(!max_recv){
            _maxrecv_rec    maxrec;

            memset(&maxrec,0,sizeof(maxrec));
            if(fseeko(rfp,fhdr.oset_datarecs,SEEK_SET) != 0){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
                goto err;
            }
            if(OWPParseRecords(cntrl->ctx,rfp,fhdr.num_datarecs,fhdr.version,
                        GetMaxRecv,(void*)&maxrec) != OWPErrOK){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "_OWPCleanUpSessions: GetMaxRecv failed");
                goto err;
            }

            /*
             * If no records were actually received - truncate the
             * file to oset_datarecs and set num_datarecs to 0 and
             * be done.
             */
            if(!maxrec.found){
                if(ftruncate(fileno(rfp),fhdr.oset_datarecs) != 0){
                    OWPError(cntrl->ctx,OWPErrFATAL,errno,"ftruncate(): %M");
                    goto err;
                }
                if( !OWPWriteDataHeaderNumDataRecs(cntrl->ctx,rfp,0)){
                    goto err;
                }

                /* goto next session */
                continue;
            }
            max_recv = maxrec.maxrecv;
            toff = fhdr.oset_datarecs + (maxrec.index_badlost * fhdr.rec_size);
        }
            
        /*
         * Advance fp to toff and remove all lost records with
         * index greater than max_recv from there to the end.
         */
        if(fseeko(rfp,toff,SEEK_SET) != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
            goto err;
        }

        num_recs = fhdr.num_datarecs;
        for(j=(toff - fhdr.oset_datarecs)/fhdr.rec_size;
                j<fhdr.num_datarecs;
                j++){

            /*
             * Read the packet record from midI.
             */
            if(fread(rbuf,fhdr.rec_size,1,rfp) != 1){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "fread(): Reading session file sid(%s): %M",
                        sid_name);
                goto loop_err;
            }
            if(!_OWPDecodeDataRecord(fhdr.version,&rec,rbuf)){
                errno = EFTYPE;
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "_OWPCleanDataRecs: Invalid data record sid(%s)",
                        sid_name);
                goto loop_err;
            }

            /*
             * If seq_no is > max_recv then delete the packet
             */
            if(rec.seq_no > max_recv){
                num_recs--;
                /*
                 * If wfp==rfp, then create another fp for wfp and point
                 * it at the current record so it will be written over.
                 */
                if(wfp == rfp){
                    int     newfd;
                    char    tmpfname[PATH_MAX];
                    char    *dname;
                    char    *tmpl = "owamp.XXXXXXXX";

                    /*
                     * Need another file for bookkeeping... First determine
                     * what dir to put it in.
                     */
                    dname = NULL;
                    memset(tmpfname,'\0',sizeof(tmpfname));

                    /* put it in the same dir as session data if possible */
                    if( strlen(tptr->endpoint->fname) > 0){
                        strncpy(tmpfname,tptr->endpoint->fname,PATH_MAX);
                        dname = dirname(tmpfname);
                    }

                    /* otherwise use tmpdir */
                    if( !dname){
                        dname = getenv("TMPDIR");
                    }
                    if( !dname){
                        dname = "/tmp";
                    }

                    /* Make sure pathname will not over-run memory. */
                    if(strlen(tmpl) + OWP_PATH_SEPARATOR_LEN + strlen(dname) >
                            PATH_MAX){
                        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                "_OWPCleanUpSessions: Unable to create temp file: Path Too Long");
                        goto err;
                    }

                    /* create template (fname) string for mkstemp */
                    strcpy(tmpfname,dname);
                    strcat(tmpfname,OWP_PATH_SEPARATOR);
                    strcat(tmpfname,tmpl);
                    if( (newfd = mkstemp(tmpfname)) < 0){
                        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                "_OWPCleanUpSessions: mkstemp(%s): %M",
                                tmpfname);
                        goto err;
                    }

                    /* immediately unlink - no need for a directory entry */
                    if(unlink(tmpfname) != 0){
                        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                "unlink(%s): %M",tmpfname);
                        close(newfd);
                        goto err;
                    }

                    /*
                     * Copy original file into tmpfile from the beginning
                     * until just before the current record.
                     */
                    toff = fhdr.oset_datarecs + (j * fhdr.rec_size);
                    if(I2CopyFile(OWPContextErrHandle(cntrl->ctx),
                                newfd,fileno(rfp),toff) != 0){
                        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                "_OWPCleanUpSessions: Unable to copy session data: I2CopyFile(): %M");
                        close(newfd);
                        goto err;
                    }

                    if( !(wfp = fdopen(newfd,"r+b"))){
                        OWPError(cntrl->ctx,OWPErrFATAL,errno,"fdopen(%d): %M",
                                newfd);
                        close(newfd);
                        goto err;
                    }

                    /*
                     * Seek new wfp to end of tmpfile.
                     */
                    if(fseeko(wfp,0,SEEK_END) != 0){
                        OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
                        goto loop_err;
                    }
                }
            }
            /*
             * Otherwise, this is a good packet and it should be kept.
             */
            else{
                if(wfp != rfp){
                    if(fwrite(rbuf,fhdr.rec_size,1,wfp) != 1){
                        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                                "fwrite(): Writing session file sid(%s): %M",
                                sid_name);
                        goto loop_err;
                    }
                }
            }
            continue;
loop_err:
            if(wfp != rfp){
                fclose(wfp);
            }
            goto err;
        }

        /*
         * If two fp's were used, then the tmpfile needs to be copied
         * back to the original file.
         */
        if(wfp != rfp){
            if(I2CopyFile(OWPContextErrHandle(cntrl->ctx),
                        fileno(rfp),fileno(wfp),0) != 0){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "_OWPCleanUpSessions: Unable to copy session data: I2CopyFile(): %M");
                fclose(wfp);
                goto err;
            }
            fclose(wfp);
        }

        /*
         * Write num_recs and "finished" into file.
         */
        if( !OWPWriteDataHeaderNumDataRecs(cntrl->ctx,rfp,num_recs)){
            goto err;
        }

        /*
         * Session should still be marked as incomplete because
         * the StopSessions message information was not available.
         */
        if( !_OWPWriteDataHeaderFinished(cntrl->ctx,rfp,
                    OWP_SESSION_FINISHED_INCOMPLETE,0)){
            goto err;
        }

        flk.l_type = F_UNLCK;
        if( fcntl(fileno(rfp), F_SETLKW, &flk) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "_OWPCleanUpSessions: Unable to unlock file sid(%s): %M",
                    sid_name);
            goto err;
        }
    }

    return True;

err:

    *acceptval = OWP_CNTRL_FAILURE;
    OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                                            "_OWPCleanUpSessions: Failed");
    return False;
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
    uint32_t        num_sessions=0;
    OWPTimeStamp    stoptime;
    OWPBoolean      readstop = True;

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
        readstop = False;
        goto clean_sessions;
    }

    if (cntrl->twoway && !cntrl->server) {
        /*
         * Using TWAMP, we don't expect a response from the server so
         * skip straight to cleaning up test sessions.
         */
        readstop = False;
        goto clean_sessions;
    }

    msgtype = OWPReadRequestType(cntrl,intr);
    switch(msgtype){
        case OWPReqStopSessions:
            break;

        case OWPReqSockClose:
        case OWPReqSockIntr:
            readstop = False;
            break;

        default:
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "OWPStopSessions: Invalid protocol message received.");
            err2 = OWPErrFATAL;
            goto done;
    }

clean_sessions:

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
     *
     * This also stops two-way sessions.
     */
    err = _OWPStopRecvSessions(cntrl,stoptime,!readstop,acceptval);
    err2 = MIN(err,err2);
    if(err2 < OWPErrWARNING){
        goto done;
    }

    /*
     * Now read the full StopSessions message.
     * This will take the NextSeq and SkipRecords and
     * put them in the recv session files as well.
     */
    if(readstop){
        err = _OWPReadStopSessions(cntrl,intr,acceptval,stoptime);
        err2 = MIN(err,err2);
    }
    else if(!_OWPCleanUpSessions(cntrl,intr,acceptval,stoptime)){
        err2 = OWPErrFATAL;
    }

done:
    /*
     * Free memory from sessions
     */
    while(cntrl->tests){
        err = _OWPTestSessionFree(cntrl->tests,*acceptval);
        err2 = MIN(err,err2);
    }

    if(err2 < OWPErrWARNING){
        if(*acceptval == OWP_CNTRL_ACCEPT){
            *acceptval = OWP_CNTRL_FAILURE;
        }
        return _OWPFailControlSession(cntrl,err2);
    }
    else if(!readstop){
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }

    cntrl->state &= ~_OWPStateTest;

    return err2;
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
    struct timespec reltime;
    int             timeout;
    struct pollfd   fds[1];
    int             rc;
    int             msgtype;
    OWPErrSeverity  err2=OWPErrOK;
    OWPAcceptType   aval;
    OWPAcceptType   *acceptval=&aval;
    int             ival=0;
    int             *intr=&ival;
    uint32_t        num_sessions=0;
    OWPTimeStamp    stoptime;
    OWPBoolean      readstop=!(cntrl->twoway && !cntrl->server);

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

    if (cntrl->twoway && cntrl->server) {
        if (!OWPSessionsActive(cntrl,acceptval) && (*acceptval)) {
            /*
             * Sessions completed with error - don't wait for
             * StopSessions message, just return.
             */
            cntrl->state &= ~_OWPStateTest;
            return 0;
        }
    } else {
        if (!OWPSessionsActive(cntrl,acceptval) || (*acceptval)){
            /*
             * Sessions are complete - send StopSessions message.
             */
            *err_ret = OWPStopSessions(cntrl,intr,acceptval);
            return 0;
        }
    }

    /*
     * Before polling, check if we have been interrupted, and if so
     * return to caller.
     */
    if (*intr){
        return 2;
    }

    if(wake){
        OWPTimeStamp    currstamp;
        OWPNum64        wakenum;

        if(!OWPGetTimeOfDay(cntrl->ctx,&currstamp)){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPGetTimeOfDay(): %M");
            return -1;
        }

        if(OWPNum64Cmp(currstamp.owptime,*wake) < 0){
            wakenum = OWPNum64Sub(*wake,currstamp.owptime);
            OWPNum64ToTimespec(&reltime,wakenum);
        }
        else{
            timespecclear(&reltime);
        }

        timeout = (reltime.tv_sec * 1000 + reltime.tv_nsec / 1000000);
    }else{
        timeout = -1;
    }

    fds[0].fd = cntrl->sockfd;
    fds[0].events = POLLIN | POLLERR | POLLHUP;
    fds[0].revents = 0;
AGAIN:
    rc = poll(fds,sizeof(fds)/sizeof(fds[0]),timeout);

    if(rc < 0){
        if(errno != EINTR){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "select():%M");
            *err_ret = OWPErrFATAL;
            return -1;
        }
        if(wake || *intr){
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

        if (cntrl->twoway && cntrl->server) {
            if (!OWPSessionsActive(cntrl,acceptval) && (*acceptval)) {
                /*
                 * Sessions completed with error - don't wait for
                 * StopSessions message, just return.
                 */
                cntrl->state &= ~_OWPStateTest;
                return 0;
            }
            /*
             * Otherwise, wait for StopSessions message.
             */
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

    if(!(fds[0].revents & (POLLIN | POLLERR | POLLHUP))){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "poll():cntrl fd not ready?:%M");
        *err_ret = _OWPFailControlSession(cntrl,OWPErrFATAL);
        goto done;
    }

    msgtype = OWPReadRequestType(cntrl,intr);
    switch(msgtype){
        case OWPReqStopSessions:
            if (cntrl->twoway && !cntrl->server) {
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                         "OWPStopSessionsWait: StopSessions message should "
                         "not be received by TWAMP client");
                *err_ret = OWPErrFATAL;
                goto done;
            }
            break;

        case OWPReqSockClose:
        case OWPReqSockIntr:
            /*
             * Go through all recv sessions and delete
             * all missing packet records *after* the last
             * good one. (section 3.8 of draft 14)
             * (readstop indicates the call of _OWPCleanUpSessions()
             * and that does the section 3.8 cleanup.)
             */
            readstop = False;
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
     *
     * This also stops two-way sessions.
     */
    err2 = _OWPStopRecvSessions(cntrl,stoptime,!readstop,acceptval);
    *err_ret = MIN(*err_ret,err2);
    if(*err_ret < OWPErrWARNING){
        goto done;
    }

    /*
     * Read the rest of the stop sessions message and complete
     * the recv side session files.
     */
    if(readstop){
        err2 = _OWPReadStopSessions(cntrl,intr,acceptval,stoptime);
        *err_ret = MIN(*err_ret,err2);
    }
    else if(!_OWPCleanUpSessions(cntrl,intr,acceptval,stoptime)){
        *err_ret = OWPErrFATAL;
    }

done:

    if(*err_ret < OWPErrWARNING){
        *acceptval = OWP_CNTRL_FAILURE;
    }

    /*
     * If errors are non-fatal (warning or better) then send the
     * stop sessions message.
     */
    if(readstop && (*err_ret >= OWPErrWARNING) &&
       !(cntrl->twoway && cntrl->server)){
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
    else if(!readstop){
        _OWPFailControlSession(cntrl,OWPErrFATAL);
        return -1;
    }


    /*
     * Otherwise, report success.
     */
    cntrl->state &= ~_OWPStateTest;

    return 0;
}

static OWPSessionFinishedType
GetSessionFinishedType(
        OWPContext  ctx,
        uint32_t   val
        )
{
    switch(val){
        case OWP_SESSION_FINISHED_ERROR:
            return OWP_SESSION_FINISHED_ERROR;
        case OWP_SESSION_FINISHED_NORMAL:
            return OWP_SESSION_FINISHED_NORMAL;
        case OWP_SESSION_FINISHED_INCOMPLETE:
            return OWP_SESSION_FINISHED_INCOMPLETE;
        default:
            OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                    "GetSessionFinishedType: Invalid val %u",val);
            return OWP_SESSION_FINISHED_ERROR;
    }
}

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
 static uint8_t owp_magic[] = _OWP_MAGIC_FILETYPE;
 OWPBoolean
 _OWPReadDataHeaderInitial(
         OWPContext                  ctx,
         FILE                        *fp,
         _OWPSessionHeaderInitial    phdr
         )
{
    uint8_t    read_magic[sizeof(owp_magic)];
    int         err;
    uint64_t   oset;
    uint32_t   finished=0;

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
            if(oset != (uint64_t)phdr->hdr_len){
                OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "OWPReadDataHeaderInitial: Unable to represent file offset (%ull)",
                        oset);
                return False;
            }
            phdr->rec_size = _OWP_DATARECV2_SIZE;

            break;
        case 3:
            phdr->rec_size = _OWP_DATARECV3_SIZE;
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
    if(fread(&finished, 1, 4, fp) != 4){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fread(): %M");
        errno = err;
        return False;
    }
    phdr->finished = GetSessionFinishedType(ctx,ntohl(finished));

    if(phdr->version < 3){
        phdr->oset_skiprecs = 0;
        phdr->num_skiprecs = 0;
        phdr->oset_datarecs = phdr->hdr_len;
        phdr->num_datarecs = (phdr->sbuf.st_size - phdr->hdr_len)/
            phdr->rec_size;
        phdr->next_seqno = 0;

        return True;
    }

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
    if(oset != (uint64_t)phdr->oset_skiprecs){
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
    if(oset != (uint64_t)phdr->oset_datarecs){
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
        OWPContext              ctx,
        FILE                    *fp,
        OWPSessionFinishedType  finished,
        uint32_t               next_seqno
        )
{
    int err;
    uint32_t   finword;

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
    finword = htonl((uint32_t)finished);
    if(fwrite(&finword,1,sizeof(finword),fp) != 4){
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
        uint32_t  num_skiprecs
        )
{
    _OWPSessionHeaderInitialRec phrec;
    uint32_t                   n32;
    uint64_t                   n64;
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
     * Convert off_t oset_skiprecs to network ordered uint64_t
     */
    phrec.oset_skiprecs = phrec.oset_datarecs +
        (phrec.rec_size * phrec.num_datarecs);
    n64 = (uint64_t)phrec.oset_skiprecs;
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
        uint32_t  num_datarecs
        )
{
    _OWPSessionHeaderInitialRec phrec;
    uint32_t                   n32;
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
    uint32_t   ver;
    uint32_t   finished = OWP_SESSION_FINISHED_INCOMPLETE;
    uint64_t   oset;
    uint64_t   skip_oset = 0;
    uint64_t   data_oset;
    off_t       oset_off;

    /* use uint32_t for proper alignment */
    uint32_t   msg[_OWP_TEST_REQUEST_PREAMBLE_SIZE/sizeof(uint32_t)];
    uint32_t   len = sizeof(msg);
    uint32_t   i;
    uint32_t   net32;
    uint64_t   net64;

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
                    hdr->conf_sender,hdr->conf_receiver,False,
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
    if(oset != (uint64_t)oset_off){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "OWPWriteDataHeader: Header too large for format representation (%"
            PRIu64 ")", oset);
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
            skip_oset = oset + (hdr->num_datarecs * hdr->rec_size);
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
     * write 16 Zero bytes in place of HMAC
     */
    memset(msg,0,16);
    if(fwrite(msg,1,16,fp) != 16){
        return False;
    }

    fflush(fp);
    return True;
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
    char    buf[_OWP_DATAREC_SIZE];

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
uint32_t
OWPReadDataHeader(
        OWPContext          ctx,
        FILE                *fp,
        OWPSessionHeader    hdr_ret
        )
{
    _OWPSessionHeaderInitialRec phrec;
    int         err;

    /* buffer for TestRequest 32 bit aligned */
    uint32_t    msg[_OWP_TEST_REQUEST_PREAMBLE_SIZE / sizeof(uint32_t)];

    hdr_ret->header = 0;

    if(!_OWPReadDataHeaderInitial(ctx,fp,&phrec)){
        return 0;
    }

    hdr_ret->version = phrec.version;
    hdr_ret->sbuf = phrec.sbuf;
    hdr_ret->rec_size = phrec.rec_size;

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
                    False,
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
                "OWPReadDataHeader: num_datarecs field larger than filesize.");
        return 0;
    }

    hdr_ret->next_seqno = phrec.next_seqno;
    hdr_ret->num_skiprecs = phrec.num_skiprecs;
    hdr_ret->oset_skiprecs = phrec.oset_skiprecs;
    hdr_ret->oset_datarecs = phrec.oset_datarecs;
    if(phrec.finished != OWP_SESSION_FINISHED_NORMAL){
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
        uint32_t   nslots,
        OWPSlot     *slots
        )
{
    int                         err;
    _OWPSessionHeaderInitialRec phrec;
    uint32_t                    fileslots;
    uint32_t                    i;
    off_t                       slot_off;
    off_t                       hdr_off;

    /* buffer for Slots 32 bit aligned */
    uint32_t                    msg[16/sizeof(uint32_t)];
    uint32_t                    zero[16/sizeof(uint32_t)];

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
     * this function is currently only supported for version >=2
     */
    if(phrec.version < 2){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPReadDataHeaderSlots: Invalid file version (%d)",
                phrec.version);
        errno = ENOSYS;
        return False;
    }
    else if(phrec.version == 2){
        slot_off = 132; /* see above layout of bytes */
        hdr_off = phrec.hdr_len;
    }
    else{
        slot_off = 152; /* see above layout of bytes */

        /*
         * Find offset to the end of the "header".
         */
        hdr_off = MIN(phrec.oset_skiprecs,phrec.oset_datarecs);
        if(!hdr_off){
            hdr_off = MAX(phrec.oset_skiprecs,phrec.oset_datarecs);
        }
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
                "OWPReadDataHeaderSlots: Invalid hdr_offset (%" PRIu64 ")",
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
        uint32_t       num_rec,
        uint32_t       file_version,
        OWPDoDataRecord proc_rec,
        void            *app_data
        )
{
    size_t      len_rec;
    char        rbuf[_OWP_MAXDATAREC_SIZE];
    uint32_t    i;
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
                        "fread(): STREAM ERROR: offset=%" PRIuPTR ",i=%" PRIu32,
                        ftello(fp),i);
            }
            else if(feof(fp)){
                OWPError(ctx,OWPErrFATAL,errno,
                        "fread(): EOF: offset=%" PRIu64,ftello(fp));
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
 * Function:        OWPReadDataSkips
 *
 * Description:        
 *         This function will read all the skip records out of the
 *         file fp. skips is assumed to be an array of OWPSkip records of
 *         length nskips.
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
OWPReadDataSkips(
        OWPContext  ctx,
        FILE        *fp,
        uint32_t   nskips,
        OWPSkip     skips
        )
{
    int                         err;
    _OWPSessionHeaderInitialRec phrec;
    uint32_t                    i;

    /* buffer for Skips 32 bit aligned */
    char                        msg[_OWP_SKIPREC_SIZE];

    /*
     * validate array.
     */
    assert(skips);

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
                "OWPReadDataSkips: Invalid file version (%d)",
                phrec.version);
        errno = ENOSYS;
        return False;
    }

    if(phrec.num_skiprecs != nskips){
        OWPError(ctx,OWPErrFATAL, OWPErrINVALID,
                "OWPReadDataSkips: nskips requested (%lu) doesn't match file (%lu).",
                nskips,phrec.num_skiprecs);

        return False;
    }

    /*
     * Position fp to beginning of skip records.
     */
    if(fseeko(fp,phrec.oset_skiprecs,SEEK_SET)){
        err = errno;
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"fseeko(): %M");
        errno = err;
        return False;
    }

    for(i=0;i<nskips;i++){

        /*
         * Read slot into buffer.
         */
        if(fread(msg,1,_OWP_SKIPREC_SIZE,fp) != _OWP_SKIPREC_SIZE){
            err = errno;
            OWPError(ctx,OWPErrFATAL,errno,"fread(): %M");
            errno = err;
            return False;
        }

        /*
         * Decode slot buffer into slot record.
         */
        _OWPDecodeSkipRecord(&skips[i],msg);
    }

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
uint64_t
OWPTestDiskspace(
        OWPTestSpec        *tspec
        )
{
    uint64_t   hdr_len;

    /*
     * 56 == 40 for initial portion + 16 for ending IZP
     */
    hdr_len = 56 + +_OWP_TEST_REQUEST_PREAMBLE_SIZE+
        16*(tspec->nslots+1);
    return hdr_len + tspec->npackets*_OWP_DATAREC_SIZE;
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

OWPBoolean
OWPControlIsTwoWay(
    OWPControl cntrl)
{
    return cntrl->twoway;
}
