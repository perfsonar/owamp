/*
 **      $Id$
 */
/************************************************************************
 *                                                                      *
 *                             Copyright (C)  2002                      *
 *                                Internet2                             *
 *                             All Rights Reserved                      *
 *                                                                      *
 ************************************************************************/
/*
 **        File:        protocol.c
 **
 **        Author:      Jeff W. Boote
 **                     Anatoly Karp
 **
 **        Date:        Tue Apr  2 10:42:12  2002
 **
 **        Description: This file contains the private functions that
 **                     speak the owamp protocol directly.
 **                     (i.e. read and write the data and save it
 **                     to structures for the rest of the api to deal
 **                     with.)
 **
 **                     The idea is to basically keep all network ordering
 **                     architecture dependant things in this file. And
 **                     hopefully to minimize the impact of any changes
 **                     to the actual protocol message formats.
 **
 **                     The message templates are here for convienent
 **                     reference for byte offsets in the code - for
 **                     explainations of the fields please see the
 **                     relevant specification document.
 **                     (currently draft-ietf-ippm-owdp-14.txt)
 **
 **                     (ease of referenceing byte offsets is also why
 **                     the &buf[BYTE] notation is being used.)
 */

#include <I2util/util.h>

#include <owampP.h>

/*
 *         ServerGreeting message format:
 *
 *         size: 32 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                                                               |
 *        04|                         MBZ (12 octets)                       |
 *        08|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        12|                            Modes                              |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                     Challenge (16 octets)                     |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteServerGreeting(
        OWPControl  cntrl,
        u_int32_t   avail_modes,
        u_int8_t    *challenge,        /* [16] */
        int         *retn_on_err
        )
{
    /*
     * buf_aligned it to ensure u_int32_t alignment, but I use
     * buf for actuall assignments to make the array offsets agree with
     * the byte offsets shown above.
     */
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIsInitial(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteServerGreeting:called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Set unused bits to 0.
     */
    memset(buf,0,12);

    *((u_int32_t *)&buf[12]) = htonl(avail_modes);
    memcpy(&buf[16],challenge,16);
    if(I2Writeni(cntrl->sockfd,buf,32,retn_on_err) != 32){
        return OWPErrFATAL;
    }

    cntrl->state = _OWPStateSetup;

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadServerGreeting(
        OWPControl  cntrl,
        u_int32_t   *mode,      /* modes available - returned   */
        u_int8_t    *challenge  /* [16] : challenge - returned  */
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIsInitial(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadServerGreeting:called in wrong state.");
        return OWPErrFATAL;
    }

    if(I2Readn(cntrl->sockfd,buf,32) != 32){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Read failed:(%s)",strerror(errno));
        return (int)OWPErrFATAL;
    }

    *mode = ntohl(*((u_int32_t *)&buf[12]));
    memcpy(challenge,&buf[16],16);

    cntrl->state = _OWPStateSetup;

    return OWPErrOK;
}

/*
 *
 *
 *         ClientGreeting message format:
 *
 *         size: 68 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                             Mode                              |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                                                               |
 *        08|                     Username (16 octets)                      |
 *        12|                                                               |
 *        16|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        20|                                                               |
 *        24|                       Token (32 octets)                       |
 *        28|                                                               |
 *        32|                                                               |
 *        36|                                                               |
 *        40|                                                               |
 *        44|                                                               |
 *        48|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        52|                                                               |
 *        56|                     Client-IV (16 octets)                     |
 *        60|                                                               |
 *        64|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteClientGreeting(
        OWPControl  cntrl,
        u_int8_t    *token        /* [32]        */
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIsSetup(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteClientGreeting:called in wrong state.");
        return OWPErrFATAL;
    }

    *(u_int32_t *)&buf[0] = htonl(cntrl->mode);

    if(cntrl->mode & OWP_MODE_DOCIPHER){
        memcpy(&buf[4],cntrl->userid,16);
        memcpy(&buf[20],token,32);
        memcpy(&buf[52],cntrl->writeIV,16);
    }else{
        memset(&buf[4],0,64);
    }

    if(I2Writen(cntrl->sockfd, buf, 68) != 68)
        return OWPErrFATAL;

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadClientGreeting(
        OWPControl  cntrl,
        u_int32_t   *mode,
        u_int8_t    *token,         /* [32] - return        */
        u_int8_t    *clientIV,      /* [16] - return        */
        int         *retn_on_intr
        )
{
    ssize_t     len;
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIsSetup(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadClientGreeting: called in wrong state.");
        return OWPErrFATAL;
    }

    if((len = I2Readni(cntrl->sockfd,buf,68,retn_on_intr)) != 68){
        if((len < 0) && *retn_on_intr && (errno == EINTR)){
            return OWPErrFATAL;
        }
        /*
         * if len == 0 - this is just a socket close, no error
         * should be printed.
         */
        if(len != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"I2Readni(): %M");
        }
        return OWPErrFATAL;
    }

    *mode = ntohl(*(u_int32_t *)&buf[0]);
    memcpy(cntrl->userid_buffer,&buf[4],16);
    memcpy(token,&buf[20],32);
    memcpy(clientIV,&buf[52],16);

    return OWPErrOK;
}

static OWPAcceptType
GetAcceptType(
        OWPControl  cntrl,
        u_int8_t    val
        )
{
    switch(val){
        case OWP_CNTRL_ACCEPT:
            return OWP_CNTRL_ACCEPT;
        case OWP_CNTRL_REJECT:
            return OWP_CNTRL_REJECT;
        case OWP_CNTRL_FAILURE:
            return OWP_CNTRL_FAILURE;
        case OWP_CNTRL_UNSUPPORTED:
            return OWP_CNTRL_UNSUPPORTED;
        case OWP_CNTRL_UNAVAILABLE_PERM:
            return OWP_CNTRL_UNAVAILABLE_PERM;
        case OWP_CNTRL_UNAVAILABLE_TEMP:
            return OWP_CNTRL_UNAVAILABLE_TEMP;
        default:
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "GetAcceptType:Invalid val %u",val);
            return OWP_CNTRL_INVALID;
    }
}

/*
 *         ServerOK message format:
 *
 *         size: 48 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                                                               |
 *        04|                         MBZ (15 octets)                       |
 *        08|                                                               |
 *          +                                               +-+-+-+-+-+-+-+-+
 *        12|                                               |   Accept      |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                     Server-IV (16 octets)                     |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        32|                      Uptime (Timestamp)                       |
 *        36|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        40|              Integrity Zero Padding (8 octets)                |
 *        44|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteServerOK(
        OWPControl      cntrl,
        OWPAcceptType   code,
        OWPNum64        uptime,
        int             *retn_on_intr
        )
{
    ssize_t         len;
    OWPTimeStamp    tstamp;
    u_int8_t        *buf = (u_int8_t*)cntrl->msg;
    int             ival=0;
    int             *intr=&ival;

    if(!_OWPStateIsSetup(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteServerOK:called in wrong state.");
        return OWPErrFATAL;
    }

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    memset(&buf[0],0,15);
    *(u_int8_t *)&buf[15] = code & 0xff;
    memcpy(&buf[16],cntrl->writeIV,16);
    if((len = I2Writeni(cntrl->sockfd,buf,32,intr)) != 32){
        if((len < 0) && *intr && (errno == EINTR)){
            return OWPErrFATAL;
        }
        return OWPErrFATAL;
    }

    if(code == OWP_CNTRL_ACCEPT){
        /*
         * Uptime should be encrypted if encr/auth mode so use Block
         * func.
         */
        tstamp.owptime = uptime;
        _OWPEncodeTimeStamp(&buf[0],&tstamp);
        memset(&buf[8],0,8);
        if(_OWPSendBlocksIntr(cntrl,buf,1,intr) != 1){
            if((len < 0) && *intr && (errno == EINTR)){
                return OWPErrFATAL;
            }
            return OWPErrFATAL;
        }
        cntrl->state = _OWPStateRequest;
    }
    else{
        cntrl->state = _OWPStateInvalid;
        memset(&buf[0],0,16);
        if((len = I2Writeni(cntrl->sockfd,buf,16,intr)) != 16){
            if((len < 0) && *intr && (errno == EINTR)){
                return OWPErrFATAL;
            }
            return OWPErrFATAL;
        }
    }

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadServerOK(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval        /* ret        */
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIsSetup(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadServerOK:called in wrong state.");
        return OWPErrFATAL;
    }

    if(I2Readn(cntrl->sockfd,buf,32) != 32){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Read failed:(%s)",strerror(errno));
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    *acceptval = GetAcceptType(cntrl,buf[15]);
    if(*acceptval == OWP_CNTRL_INVALID){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    memcpy(cntrl->readIV,&buf[16],16);

    cntrl->state = _OWPStateUptime;

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadServerUptime(
        OWPControl  cntrl,
        OWPNum64    *uptime        /* ret        */
        )
{
    u_int8_t        *buf = (u_int8_t*)cntrl->msg;
    OWPTimeStamp    tstamp;

    if(!_OWPStateIs(_OWPStateUptime,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadServerUptime: called in wrong state.");
        return OWPErrFATAL;
    }

    if(_OWPReceiveBlocks(cntrl,buf,1) != 1){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadServerUptime: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(memcmp(&buf[8],cntrl->zero,8)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadServerUptime: Invalid zero padding");
        return OWPErrFATAL;
    }

    _OWPDecodeTimeStamp(&tstamp,&buf[0]);
    *uptime = tstamp.owptime;

    cntrl->state = _OWPStateRequest;

    return OWPErrOK;
}

/*
 * This function is called on the server side to read the first block
 * of client requests. The remaining read request messages MUST be called
 * next!.
 * It is also called by the client side from OWPStopSessionsWait and
 * OWPStopSessions
 */
OWPRequestType
OWPReadRequestType(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    u_int8_t    msgtype;
    int         n;
    int         ival=0;
    int         *intr = &ival;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    if(!_OWPStateIsRequest(cntrl) || _OWPStateIsReading(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPReadRequestType:called in wrong state.");
        return OWPReqInvalid;
    }

    /* Read one block so we can peek at the message type */
    n = _OWPReceiveBlocksIntr(cntrl,(u_int8_t*)cntrl->msg,1,intr);
    if(n != 1){
        cntrl->state = _OWPStateInvalid;
        if((n < 0) && *intr && (errno == EINTR)){
            return OWPReqSockIntr;
        }
        return OWPReqSockClose;
    }

    msgtype = *(u_int8_t*)cntrl->msg;

    /*
     * StopSessions(3) message is only allowed during active tests,
     * and it is the only message allowed during active tests.
     */
    if((_OWPStateIs(_OWPStateTest,cntrl) && (msgtype != 3)) ||
            (!_OWPStateIs(_OWPStateTest,cntrl) && (msgtype == 3))){
        cntrl->state = _OWPStateInvalid;
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPReadRequestType: Invalid request.");
        return OWPReqInvalid;
    }

    switch(msgtype){
        /*
         * TestRequest
         */
        case        1:
            cntrl->state |= _OWPStateTestRequest;
            break;
        case        2:
            cntrl->state |= _OWPStateStartSessions;
            break;
        case        3:
            cntrl->state |= _OWPStateStopSessions;
            break;
        case        4:
            cntrl->state |= _OWPStateFetchSession;
            break;
        default:
            cntrl->state = _OWPStateInvalid;
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "OWPReadRequestType: Unknown msg:%d",msgtype);
            return OWPReqInvalid;
    }

    return (OWPRequestType)msgtype;
}

/*
 *         TestRequestPreamble message format:
 *
 *         size:112 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|      1        |  MBZ  | IPVN  | Conf-Sender   | Conf-Receiver |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                  Number of Schedule Slots                     |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                      Number of Packets                        |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        12|          Sender Port          |         Receiver Port         |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                        Sender Address                         |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        20|              Sender Address (cont.) or Unused                 |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        32|                        Receiver Address                       |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        36|              Receiver Address (cont.) or Unused               |
 *        40|                                                               |
 *        44|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        48|                                                               |
 *        52|                        SID (16 octets)                        |
 *        56|                                                               |
 *        60|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        64|                          Padding Length                       |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        68|                            Start Time                         |
 *        72|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        76|                             Timeout                           |
 *        80|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        84|                         Type-P Descriptor                     |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        88|                                MBZ                            |
 *        92|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        96|                                                               |
 *     100|                Integrity Zero Padding (16 octets)             |
 *     104|                                                               |
 *     108|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int
_OWPEncodeTestRequestPreamble(
        OWPContext      ctx,
        u_int32_t       *msg,
        u_int32_t       *len_ret,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        OWPBoolean      server_conf_sender, 
        OWPBoolean      server_conf_receiver,
        OWPSID          sid,
        OWPTestSpec     *tspec
        )
{
    u_int8_t        *buf = (u_int8_t*)msg;
    u_int8_t        version;
    OWPTimeStamp    tstamp;

    if(*len_ret < 112){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPEncodeTestRequestPreamble:Buffer too small");
        *len_ret = 0;
        return OWPErrFATAL;
    }
    *len_ret = 0;

    /*
     * Check validity of input variables.
     */

    /* valid "conf" setup? */
    if(!server_conf_sender && !server_conf_receiver){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPEncodeTestRequestPreamble:Request for empty config?");
        return OWPErrFATAL;
    }

    /* consistant addresses? */
    if(sender->sa_family != receiver->sa_family){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "Address Family mismatch");
        return OWPErrFATAL;
    }

    /*
     * Addresses are consistant. Can we deal with what we
     * have been given? (We only support AF_INET and AF_INET6.)
     */
    switch (sender->sa_family){
        case AF_INET:
            version = 4;
            break;
#ifdef        AF_INET6
        case AF_INET6:
            version = 6;
            break;
#endif
        default:
            OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid IP Address Family");
            return 1;
    }

    /*
     * Do we have "valid" schedule variables?
     */
    if((tspec->npackets < 1) || (tspec->nslots < 1) || !tspec->slots){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid test distribution parameters");
        return OWPErrFATAL;
    }

    /*
     * set simple values
     */
    buf[0] = 1;        /* Request-Session message # */
    buf[1] = version & 0xF;
    buf[2] = (server_conf_sender)?1:0;
    buf[3] = (server_conf_receiver)?1:0;

    /*
     * slots and npackets... convert to network byte order.
     */
    *(u_int32_t*)&buf[4] = htonl(tspec->nslots);
    *(u_int32_t*)&buf[8] = htonl(tspec->npackets);

    /*
     * Now set addr values. (sockaddr vars should already have
     * values in network byte order.)
     */
    switch(version){
        struct sockaddr_in        *saddr4;
#ifdef        AF_INET6
        struct sockaddr_in6        *saddr6;
        case 6:
        /* sender address  and port */
        saddr6 = (struct sockaddr_in6*)sender;
        memcpy(&buf[16],saddr6->sin6_addr.s6_addr,16);
        *(u_int16_t*)&buf[12] = saddr6->sin6_port;

        /* receiver address and port  */
        saddr6 = (struct sockaddr_in6*)receiver;
        memcpy(&buf[32],saddr6->sin6_addr.s6_addr,16);
        *(u_int16_t*)&buf[14] = saddr6->sin6_port;

        break;
#endif
        case 4:
        /* sender address and port  */
        saddr4 = (struct sockaddr_in*)sender;
        *(u_int32_t*)&buf[16] = saddr4->sin_addr.s_addr;
        *(u_int16_t*)&buf[12] = saddr4->sin_port;

        /* receiver address and port  */
        saddr4 = (struct sockaddr_in*)receiver;
        *(u_int32_t*)&buf[32] = saddr4->sin_addr.s_addr;
        *(u_int16_t*)&buf[14] = saddr4->sin_port;

        break;
        default:
        /*
         * This can't happen, but default keeps compiler
         * warnings away.
         */
        abort();
        break;
    }

    if(sid)
        memcpy(&buf[48],sid,16);

    *(u_int32_t*)&buf[64] = htonl(tspec->packet_size_padding);

    /*
     * timestamps...
     */
    tstamp.owptime = tspec->start_time;
    _OWPEncodeTimeStamp(&buf[68],&tstamp);
    tstamp.owptime = tspec->loss_timeout;
    _OWPEncodeTimeStamp(&buf[76],&tstamp);

    *(u_int32_t*)&buf[84] = htonl(tspec->typeP);

    /*
     * Set MBZ and Integrity Zero Padding
     */
    memset(&buf[88],0,24);

    *len_ret = 112;

    return 0;
}
OWPErrSeverity
_OWPDecodeTestRequestPreamble(
        OWPContext      ctx,
        OWPBoolean      request,
        u_int32_t       *msg,
        u_int32_t       msg_len,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        socklen_t       *socklen,
        u_int8_t        *ipvn,
        OWPBoolean      *server_conf_sender,
        OWPBoolean      *server_conf_receiver,
        OWPSID          sid,
        OWPTestSpec     *tspec
        )
{
    u_int8_t        *buf = (u_int8_t*)msg;
    u_int8_t        zero[_OWP_RIJNDAEL_BLOCK_SIZE];
    OWPTimeStamp    tstamp;

    if(msg_len != 112){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPDecodeTestRequestPreamble:Invalid message size");
        return OWPErrFATAL;
    }

    memset(zero,0,_OWP_RIJNDAEL_BLOCK_SIZE);
    if(memcmp(zero,&buf[96],_OWP_RIJNDAEL_BLOCK_SIZE)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPDecodeTestRequestPreamble:Invalid zero padding");
        return OWPErrFATAL;
    }


    *ipvn = buf[1] & 0xF;
    tspec->nslots = ntohl(*(u_int32_t*)&buf[4]);
    tspec->npackets = ntohl(*(u_int32_t*)&buf[8]);

    switch(buf[2]){
        case 0:
            *server_conf_sender = False;
            break;
        case 1:
        default:
            *server_conf_sender = True;
            break;
    }
    switch(buf[3]){
        case 0:
            *server_conf_receiver = False;
            break;
        case 1:
        default:
            *server_conf_receiver = True;
            break;
    }

    if(!*server_conf_sender && !*server_conf_receiver){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPDecodeTestRequestPreamble:Invalid null request");
        return OWPErrWARNING;
    }

    switch(*ipvn){
        struct sockaddr_in  *saddr4;
#ifdef        AF_INET6
        struct sockaddr_in6 *saddr6;
        case 6:
        if(*socklen < sizeof(struct sockaddr_in6)){
            OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                    "_OWPDecodeTestRequestPreamble: socklen not large enough (%d < %d)",
                    *socklen,sizeof(struct sockaddr_in6));
            *socklen = 0;
            return OWPErrFATAL;
        }
        *socklen = sizeof(struct sockaddr_in6);

        /* sender address  and port */
        saddr6 = (struct sockaddr_in6*)sender;
        saddr6->sin6_family = AF_INET6;
        memcpy(saddr6->sin6_addr.s6_addr,&buf[16],16);
        if(request && *server_conf_sender)
            saddr6->sin6_port = 0;
        else
            saddr6->sin6_port = *(u_int16_t*)&buf[12];

        /* receiver address and port  */
        saddr6 = (struct sockaddr_in6*)receiver;
        saddr6->sin6_family = AF_INET6;
        memcpy(saddr6->sin6_addr.s6_addr,&buf[32],16);
        if(request && *server_conf_receiver)
            saddr6->sin6_port = 0;
        else
            saddr6->sin6_port = *(u_int16_t*)&buf[14];

        break;
#endif
        case 4:
        if(*socklen < sizeof(struct sockaddr_in)){
            *socklen = 0;
            OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                    "_OWPDecodeTestRequestPreamble: socklen not large enough (%d < %d)",
                    *socklen,sizeof(struct sockaddr_in));
            return OWPErrFATAL;
        }
        *socklen = sizeof(struct sockaddr_in);

        /* sender address and port  */
        saddr4 = (struct sockaddr_in*)sender;
        saddr4->sin_family = AF_INET;
        saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[16];
        if(request && *server_conf_sender)
            saddr4->sin_port = 0;
        else
            saddr4->sin_port = *(u_int16_t*)&buf[12];

        /* receiver address and port  */
        saddr4 = (struct sockaddr_in*)receiver;
        saddr4->sin_family = AF_INET;
        saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[32];
        if(request && *server_conf_receiver)
            saddr4->sin_port = 0;
        else
            saddr4->sin_port = *(u_int16_t*)&buf[14];

        break;
        default:
        OWPError(ctx,OWPErrWARNING,OWPErrINVALID,
                "_OWPDecodeTestRequestPreamble: Unsupported IP version (%d)",
                *ipvn);
        return OWPErrWARNING;
    }

#ifdef        HAVE_STRUCT_SOCKADDR_SA_LEN
    sender->sa_len = receiver->sa_len = *socklen;
#endif

    memcpy(sid,&buf[48],16);

    tspec->packet_size_padding = ntohl(*(u_int32_t*)&buf[64]);

    _OWPDecodeTimeStamp(&tstamp,&buf[68]);
    tspec->start_time = tstamp.owptime;
    _OWPDecodeTimeStamp(&tstamp,&buf[76]);
    tspec->loss_timeout = tstamp.owptime;

    /*
     * Rely on implementation in endpoint.c to verify bits.
     * (This allows typeP to be expanded in the future for
     * implementations that understand it.)
     */
    tspec->typeP = ntohl(*(u_int32_t*)&buf[84]);

    return OWPErrOK;
}


/*
 *         Encode/Decode Slot
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|    Slot Type  |                                               |
 *          +-+-+-+-+-+-+-+-+              MBZ                              +
 *        04|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                 Slot Parameter (Timestamp)                    |
 *        12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*
 * Function:        _OWPEncodeSlot
 *
 * Description:        
 *         This function is used to encode a slot record in a single block
 *         in the format needed to send a slot over the wire.
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
_OWPEncodeSlot(
        u_int32_t   msg[4], /* 1 block 32bit aligned */
        OWPSlot     *slot
        )
{
    u_int8_t        *buf = (u_int8_t*)msg;
    OWPTimeStamp    tstamp;

    /*
     * Initialize block to zero
     */
    memset(buf,0,16);

    switch(slot->slot_type){
        case OWPSlotRandExpType:
            buf[0] = 0;
            tstamp.owptime = slot->rand_exp.mean;
            break;
        case OWPSlotLiteralType:
            buf[0] = 1;
            tstamp.owptime = slot->literal.offset;
            break;
        default:
            return OWPErrFATAL;
    }
    _OWPEncodeTimeStamp(&buf[8],&tstamp);

    return OWPErrOK;
}
/*
 * Function:        _OWPDecodeSlot
 *
 * Description:        
 *         This function is used to read a slot in protocol format into a
 *         slot structure record.
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
_OWPDecodeSlot(
        OWPSlot     *slot,
        u_int32_t   msg[4] /* 1 block 32bit aligned */
        )
{
    u_int8_t        *buf = (u_int8_t*)msg;
    OWPTimeStamp    tstamp;

    _OWPDecodeTimeStamp(&tstamp,&buf[8]);
    switch(buf[0]){
        case 0:
            slot->slot_type = OWPSlotRandExpType;
            slot->rand_exp.mean = tstamp.owptime;
            break;
        case 1:
            slot->slot_type = OWPSlotLiteralType;
            slot->literal.offset = tstamp.owptime;
            break;
        default:
            return OWPErrFATAL;
    }

    return OWPErrOK;
}

OWPErrSeverity
_OWPWriteTestRequest(
        OWPControl      cntrl,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        OWPBoolean      server_conf_sender,
        OWPBoolean      server_conf_receiver,
        OWPSID          sid,
        OWPTestSpec     *test_spec
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;
    u_int32_t   buf_len = sizeof(cntrl->msg);
    u_int32_t   i;

    /*
     * Ensure cntrl is in correct state.
     */
    if(!_OWPStateIsRequest(cntrl) || _OWPStateIsPending(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteTestRequest:called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Encode test request variables that were passed in into
     * the "buf" in the format required by V5 of owamp spec section 4.3.
     */
    if((_OWPEncodeTestRequestPreamble(cntrl->ctx,cntrl->msg,&buf_len,
                    sender,receiver,server_conf_sender,
                    server_conf_receiver,sid,test_spec) != 0) ||
            (buf_len != 112)){
        return OWPErrFATAL;
    }

    /*
     * Now - send the request! 112 octets == 7 blocks.
     */
    if(_OWPSendBlocks(cntrl,buf,7) != 7){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * Send slots
     */
    for(i=0;i<test_spec->nslots;i++){
        if(_OWPEncodeSlot(cntrl->msg,&test_spec->slots[i]) != OWPErrOK){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "_OWPWriteTestRequest: Invalid slot record");
            cntrl->state = _OWPStateInvalid;
            return OWPErrFATAL;
        }
        if(_OWPSendBlocks(cntrl,buf,1) != 1){
            cntrl->state = _OWPStateInvalid;
            return OWPErrFATAL;
        }
    }

    /*
     * Send 1 block of Integrity Zero Padding.
     */
    memset(buf,0,16);
    if(_OWPSendBlocks(cntrl,buf,1) != 1){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    cntrl->state |= _OWPStateTestAccept;

    return OWPErrOK;
}


/*
 * Function:        _OWPReadTestRequestSlots
 *
 * Description:        
 *         This function reads nslot slot descriptions off of the socket.
 *         If slots is non-null, each slot description is decoded and
 *         placed in the "slots" array. It is assumed to be of at least
 *         length "nslots". If "slots" is NULL, then nslots are read
 *         off the socket and discarded.
 *
 *         The _OWPDecodeSlot function is called to decode each individual
 *         slot. Then the last block of integrity zero padding is checked
 *         to complete the reading of the TestRequest.
 *
 *         The formats are as follows:
 *
 *         size: Each Slot is 16 octets. All slots are followed by 16 octets
 *         of Integrity Zero Padding.
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|    Slot Type  |                                               |
 *          +-+-+-+-+-+-+-+-+              MBZ                              +
 *        04|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                 Slot Parameter (Timestamp)                    |
 *        12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *          ...
 *          ...
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                                                               |
 *      04|                Integrity Zero Padding (16 octets)             |
 *      08|                                                               |
 *      12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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
_OWPReadTestRequestSlots(
        OWPControl  cntrl,
        int         *intr,
        u_int32_t   nslots,
        OWPSlot     *slots
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;
    u_int32_t   i;
    int         len;

    if(!_OWPStateIs(_OWPStateTestRequestSlots,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadTestRequestSlots called in wrong state.");
        return OWPErrFATAL;
    }

    for(i=0;i<nslots;i++){

        /*
         * Read slot into buffer.
         */
        if((len = _OWPReceiveBlocksIntr(cntrl,&buf[0],1,intr)) != 1){
            cntrl->state = _OWPStateInvalid;
            if((len < 0) && *intr && (errno==EINTR)){
                return OWPErrFATAL;
            }
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "_OWPReadTestRequestSlots: Read Error: %M");
            return OWPErrFATAL;
        }

        /*
         * slots will be null if we are just reading the slots
         * to get the control connection in the correct state
         * to respond with a denied Accept message.
         */
        if(!slots){
            continue;
        }

        /*
         * Decode slot from buffer into slot record.
         */
        if(_OWPDecodeSlot(&slots[i],cntrl->msg) != OWPErrOK){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "_OWPReadTestRequestSlots: Invalid Slot");
            cntrl->state = _OWPStateInvalid;
            return OWPErrFATAL;
        }

    }

    /*
     * Now read Integrity Zero Padding
     */
    if((len=_OWPReceiveBlocksIntr(cntrl,&buf[0],1,intr)) != 1){
        cntrl->state = _OWPStateInvalid;
        if((len<0) && *intr && (errno == EINTR)){
            return OWPErrFATAL;
        }
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPReadTestRequestSlots: Read Error: %M");
        return OWPErrFATAL;
    }

    /*
     * Now check the integrity.
     */
    if(memcmp(cntrl->zero,&buf[0],_OWP_RIJNDAEL_BLOCK_SIZE) != 0){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadTestRequestSlots:Invalid zero padding");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * TestRequestSlots are read, now ready to send TestAccept message.
     */
    cntrl->state &= ~_OWPStateTestRequestSlots;

    return OWPErrOK;
}

/*
 * Function:        AddrBySAddrRef
 *
 * Description:        
 *         Construct an OWPAddr record given a sockaddr struct.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
static OWPAddr
AddrBySAddrRef(
        OWPContext      ctx,
        struct sockaddr *saddr,
        socklen_t       saddrlen
        )
{
    OWPAddr         addr;
    struct addrinfo *ai=NULL;
    int             gai;

    if(!saddr){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "AddrBySAddrRef:Invalid saddr");
        return NULL;
    }

    if(!(addr = _OWPAddrAlloc(ctx)))
        return NULL;

    if(!(ai = malloc(sizeof(struct addrinfo)))){
        OWPError(addr->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "malloc():%s",strerror(errno));
        (void)OWPAddrFree(addr);
        return NULL;
    }

    if(!(addr->saddr = malloc(saddrlen))){
        OWPError(addr->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "malloc():%s",strerror(errno));
        (void)OWPAddrFree(addr);
        (void)free(ai);
        return NULL;
    }
    memcpy(addr->saddr,saddr,saddrlen);
    ai->ai_addr = addr->saddr;
    addr->saddrlen = saddrlen;
    ai->ai_addrlen = saddrlen;

    ai->ai_flags = 0;
    ai->ai_family = saddr->sa_family;
    ai->ai_socktype = SOCK_DGRAM;
    ai->ai_protocol = IPPROTO_IP;        /* reasonable default.        */
    ai->ai_canonname = NULL;
    ai->ai_next = NULL;

    addr->ai = ai;
    addr->ai_free = True;
    addr->so_type = SOCK_DGRAM;
    addr->so_protocol = IPPROTO_IP;

    if( (gai = getnameinfo(addr->saddr,addr->saddrlen,
                    addr->node,sizeof(addr->node),
                    addr->port,sizeof(addr->port),
                    NI_NUMERICHOST | NI_NUMERICSERV)) != 0){
        OWPError(addr->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "getnameinfo(): %s",gai_strerror(gai));
        strncpy(addr->node,"unknown",sizeof(addr->node));
        strncpy(addr->port,"unknown",sizeof(addr->port));
    }
    addr->node_set = True;
    addr->port_set = True;

    return addr;
}

/*
 * Function:        _OWPReadTestRequest
 *
 * Description:        
 *         This function reads a test request off the wire and encodes
 *         the information in a TestSession record.
 *
 *         If it is called in a server context, the acceptval pointer will
 *         be non-null and will be set. (i.e. if there is a memory allocation
 *         error, it will be set to OWP_CNTRL_FAILURE. If there is invalid
 *         data in the TestRequest it will be set to OWP_CNTRL_REJECT.)
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
_OWPReadTestRequest(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPTestSession  *test_session,
        OWPAcceptType   *accept_ret
        )
{
    u_int8_t                *buf = (u_int8_t*)cntrl->msg;
    OWPErrSeverity          err_ret=OWPErrOK;
    struct sockaddr_storage sendaddr_rec;
    struct sockaddr_storage recvaddr_rec;
    socklen_t               addrlen = sizeof(sendaddr_rec);
    OWPAddr                 SendAddr=NULL;
    OWPAddr                 RecvAddr=NULL;
    u_int8_t                ipvn;
    OWPBoolean              conf_sender;
    OWPBoolean              conf_receiver;
    OWPSID                  sid;
    OWPTestSpec             tspec;
    int                     rc;
    OWPTestSession          tsession;
    OWPAcceptType           accept_mem;
    OWPAcceptType           *accept_ptr = &accept_mem;
    int                     ival=0;
    int                     *intr=&ival;

    *test_session = NULL;
    memset(&sendaddr_rec,0,addrlen);
    memset(&recvaddr_rec,0,addrlen);
    memset(&tspec,0,sizeof(tspec));
    memset(sid,0,sizeof(sid));

    if(!_OWPStateIs(_OWPStateTestRequest,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadTestRequest: called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Setup an OWPAcceptType return in the event this function is
     * called in a "server" context.
     */
    if(accept_ret)
        accept_ptr = accept_ret;
    *accept_ptr = OWP_CNTRL_ACCEPT;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    /*
     * If this was called from the client side, we need to read
     * one block of data into the cntrl buffer. (Server side already
     * did this to determine the message type - client is doing this
     * as part of a fetch session.
     */
    if(!accept_ret && (_OWPReceiveBlocksIntr(cntrl,&buf[0],1,intr) != 1)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadTestRequest: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        *accept_ptr = OWP_CNTRL_INVALID;
        return OWPErrFATAL;
    }

    /*
     * Already read the first block - read the rest for this message
     * type.
     */
    if(_OWPReceiveBlocksIntr(cntrl,&buf[16],_OWP_TEST_REQUEST_BLK_LEN-1,
                intr) != (_OWP_TEST_REQUEST_BLK_LEN-1)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadTestRequest: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        *accept_ptr = OWP_CNTRL_INVALID;
        return OWPErrFATAL;
    }

    /*
     * Now - fill in the Addr records, ipvn, server_conf varaibles,
     * sid and "tspec" with the values in the msg buffer.
     */
    if( (err_ret = _OWPDecodeTestRequestPreamble(cntrl->ctx,
                    (accept_ret!=NULL),cntrl->msg,
                    _OWP_TEST_REQUEST_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE,
                    (struct sockaddr*)&sendaddr_rec,
                    (struct sockaddr*)&recvaddr_rec,&addrlen,&ipvn,
                    &conf_sender,&conf_receiver,sid,&tspec)) != OWPErrOK){
        /*
         * INFO/WARNING indicates a request that we cannot honor.
         * FATAL indicates inproper formatting, and probable
         * control connection corruption.
         */
        if(err_ret < OWPErrWARNING){
            cntrl->state = _OWPStateInvalid;
            *accept_ptr = OWP_CNTRL_INVALID;
            return OWPErrFATAL;
        }else if(accept_ret){
            /*
             * only return in server context
             */
            *accept_ptr = OWP_CNTRL_UNSUPPORTED;
            return OWPErrFATAL;
        }
    }

    /*
     * TestRequest Preamble is read, now ready to read slots.
     */
    cntrl->state &= ~_OWPStateTestRequest;
    cntrl->state |= _OWPStateTestRequestSlots;

    /*
     * Prepare the address buffers.
     * (Don't bother checking for null return - it will be checked
     * by _OWPTestSessionAlloc.)
     */
    SendAddr = AddrBySAddrRef(cntrl->ctx,(struct sockaddr*)&sendaddr_rec,
            addrlen);
    RecvAddr = AddrBySAddrRef(cntrl->ctx,(struct sockaddr*)&recvaddr_rec,
            addrlen);

    /*
     * Allocate a record for this test.
     */
    if( !(tsession = _OWPTestSessionAlloc(cntrl,SendAddr,conf_sender,
                    RecvAddr,conf_receiver,&tspec))){
        err_ret = OWPErrWARNING;
        *accept_ptr = OWP_CNTRL_FAILURE;
        goto error;
    }

    /*
     * copy sid into tsession - if the sid still needs to be
     * generated - it still will be in sapi.c:OWPProcessTestRequest
     */
    memcpy(tsession->sid,sid,sizeof(sid));

    /*
     * Allocate memory for slots...
     */
    if(tsession->test_spec.nslots > _OWPSLOT_BUFSIZE){
        /*
         * Will check for memory allocation failure after
         * reading slots from socket. (We can gracefully
         * decline the request even if we can't allocate memory
         * to hold the slots this way.)
         */
        tsession->test_spec.slots =
            calloc(tsession->test_spec.nslots,sizeof(OWPSlot));
    }else{
        tsession->test_spec.slots = tsession->slot_buffer;
    }

    /*
     * Now, read the slots of the control socket.
     */
    if( (rc = _OWPReadTestRequestSlots(cntrl,intr,
                    tsession->test_spec.nslots,
                    tsession->test_spec.slots)) < OWPErrOK){
        cntrl->state = _OWPStateInvalid;
        err_ret = (OWPErrSeverity)rc;
        *accept_ptr = OWP_CNTRL_INVALID;
        goto error;
    }

    /*
     * We were unable to save the slots - server should decline the request.
     */
    if(!tsession->test_spec.slots){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "calloc(%d,OWPSlot): %M",
                tsession->test_spec.nslots);
        *accept_ptr = OWP_CNTRL_FAILURE;
        err_ret = OWPErrFATAL;
        goto error;
    }

    /*
     * In the server context, we are going to _OWPStateTestAccept.
     * In the client "fetching" context we are ready to read the
     * record header and the records.
     */
    if(accept_ret){
        cntrl->state |= _OWPStateTestAccept;
    }else{
        cntrl->state |= _OWPStateFetching;
    }

    *test_session = tsession;

    return OWPErrOK;

error:
    if(tsession){
        _OWPTestSessionFree(tsession,OWP_CNTRL_FAILURE);
    }else{
        OWPAddrFree(SendAddr);
        OWPAddrFree(RecvAddr);
    }

    return err_ret;
}

/*
 *
 *         TestAccept message format:
 *
 *         size: 32 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|    Accept     |     MBZ       |            Port               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                                                               |
 *        08|                        SID (16 octets)                        |
 *        12|                                                               |
 *        16|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        20|                                                               |
 *        24|                      Zero Padding (12 octets)                 |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteTestAccept(
        OWPControl      cntrl,
        int             *intr,
        OWPAcceptType   acceptval,
        u_int16_t       port,
        OWPSID          sid
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIs(_OWPStateTestAccept,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteTestAccept called in wrong state.");
        return OWPErrFATAL;
    }

    buf[0] = acceptval & 0xff;
    *(u_int16_t *)&buf[2] = htons(port);
    if(sid)
        memcpy(&buf[4],sid,16);
    memset(&buf[20],0,12);

    if(_OWPSendBlocksIntr(cntrl,buf,2,intr) != 2){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    cntrl->state &= ~_OWPStateTestAccept;

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadTestAccept(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval,
        u_int16_t       *port,
        OWPSID          sid
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIs(_OWPStateTestAccept,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadTestAccept called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Get the servers response.
     */
    if(_OWPReceiveBlocks(cntrl,buf,2) != 2){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadTestAccept:Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * Check zero padding first.
     */
    if(memcmp(&buf[20],cntrl->zero,12)){
        cntrl->state = _OWPStateInvalid;
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid Accept-Session message received");
        return OWPErrFATAL;
    }

    *acceptval = GetAcceptType(cntrl,buf[0]);
    if(*acceptval == OWP_CNTRL_INVALID){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(port)
        *port = ntohs(*(u_int16_t*)&buf[2]);

    if(sid)
        memcpy(sid,&buf[4],16);

    cntrl->state &= ~_OWPStateTestAccept;

    return OWPErrOK;
}

/*
 *
 *         StartSessions message format:
 *
 *         size: 32 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|      2        |                                               |
 *          +-+-+-+-+-+-+-+-+                                               +
 *        04|                         MBZ (15 octets)                       |
 *        08|                                                               |
 *        12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                    Zero Padding (16 octets)                   |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteStartSessions(
        OWPControl  cntrl
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIsRequest(cntrl) || _OWPStateIsPending(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteStartSessions:called in wrong state.");
        return OWPErrFATAL;
    }

    buf[0] = 2;        /* start-session identifier        */
#ifndef        NDEBUG
    memset(&buf[1],0,15);        /* Unused        */
#endif
    memset(&buf[16],0,16);        /* Zero padding */

    if(_OWPSendBlocks(cntrl,buf,2) != 2){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    cntrl->state |= _OWPStateStartAck;
    cntrl->state |= _OWPStateTest;
    return OWPErrOK;
}

OWPErrSeverity
_OWPReadStartSessions(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    int         n;
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIs(_OWPStateStartSessions,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartSessions called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Already read the first block - read the rest for this message
     * type.
     */
    n = _OWPReceiveBlocksIntr(cntrl,&buf[16],
            _OWP_STOP_SESSIONS_BLK_LEN-1,retn_on_intr);

    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != (_OWP_STOP_SESSIONS_BLK_LEN-1)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadStartSessions:Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(memcmp(cntrl->zero,&buf[16],16)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadTestRequest:Invalid zero padding");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(buf[0] != 2){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartSessions:Not a StartSessions message...");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * The control connection is now ready to send the response.
     */
    cntrl->state &= ~_OWPStateStartSessions;
    cntrl->state |= _OWPStateStartAck;
    cntrl->state |= _OWPStateTest;

    return OWPErrOK;
}

/*
 *
 *         StartAck message format:
 *
 *         size: 32 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|     Accept    |                                               |
 *          +-+-+-+-+-+-+-+-+                                               +
 *        04|                         MBZ (15 octets)                       |
 *        08|                                                               |
 *        12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                    Zero Padding (16 octets)                   |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteStartAck(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval
        )
{
    int         n;
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIs(_OWPStateStartAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteStartAck called in wrong state.");
        return OWPErrFATAL;
    }

    buf[0] = acceptval & 0xff;
#ifndef        NDEBUG
    memset(&buf[1],0,15);        /* Unused        */
#endif
    memset(&buf[16],0,16);        /* Zero padding */

    n = _OWPSendBlocksIntr(cntrl,buf,_OWP_START_ACK_BLK_LEN,retn_on_intr);

    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != _OWP_START_ACK_BLK_LEN){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * StartAck has been sent, leave that state.
     */
    cntrl->state &= ~_OWPStateStartAck;

    /*
     * Test was denied - go back to Request state.
     */
    if(acceptval != OWP_CNTRL_ACCEPT){
        cntrl->state &= ~_OWPStateTest;
    }

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadStartAck(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    *acceptval = OWP_CNTRL_INVALID;

    if(!_OWPStateIs(_OWPStateStartAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartAck called in wrong state.");
        return OWPErrFATAL;
    }

    if(_OWPReceiveBlocks(cntrl,&buf[0],_OWP_START_ACK_BLK_LEN) != 
            (_OWP_START_ACK_BLK_LEN)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadStartAck:Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(memcmp(cntrl->zero,&buf[16],16)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartAck:Invalid zero padding");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }
    *acceptval = GetAcceptType(cntrl,buf[0]);
    if(*acceptval == OWP_CNTRL_INVALID){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * received StartAck - leave that state.
     */
    cntrl->state &= ~_OWPStateStartAck;

    /* If StartSessions was rejected get back into StateRequest */
    if (*acceptval != OWP_CNTRL_ACCEPT){
        cntrl->state &= ~_OWPStateTest;
        cntrl->state |= _OWPStateRequest;
    }

    return OWPErrOK;
}

/*
 * Full StopSessions message format:
 *
 * size: variable
 *
 *  header portion: size 16 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|      3        |    Accept     |               MBZ             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                      Number of Sessions                       |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                         MBZ (8 octets)                        |
 *        12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 ** [ N Session Description Records]
 **  Session Description Record: size variable
 **  (Number of Sessions above indicates how many of these)
 **
 **    header of this sub-record: size 24 octets
 **
 **            0                   1                   2                   3
 **            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 **          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **        00|                                                               |
 **        04|                        SID (16 octets)                        |
 **        08|                                                               |
 **        12|                                                               |
 **          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **        16|                           Next Seqno                          |
 **          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **        24|                     Number of Skip Ranges                     |
 **          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **
 *** [ N Skip Ranges]
 ***
 ***    Skip Ranges: size 8 octets each
 ***    Number of Skip Ranges above indicates how many of these in this
 ***    session description record.
 ***
 ***         SkipRecord format:
 ***
 ***         size: 8 octets
 ***
 ***            0                   1                   2                   3
 ***            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 ***          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ***        00|                      First Seqno Skipped                      |
 ***          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ***        04|                       Last Seqno Skipped                      |
 ***          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ***
 *** [END Skip Ranges]
 ***
 ***    Then the Session Description Record is padded out to complete the
 ***    current block.
 ***
 *** [END SessionDescription Records]
 *
 * After all SessionDescription Records a final block of IZP completes
 * the StopSession message:
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                                                               |
 *        04|                        IZP (16 octets)                        |
 *        08|                                                               |
 *        12|                                                               |
*          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
/*
 * Function:    
 *                  _OWPWriteStopSessions
 *
 * Description:    
 *  Sends the StopSessions message as described above. Also
 *  stops local sessions.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 *  All local sessions are stopped.
 */
OWPErrSeverity
_OWPWriteStopSessions(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval,
        u_int32_t       num_sessions
        )
{
    OWPTestSession  sptr;
    u_int8_t        *buf = (u_int8_t*)cntrl->msg;

    if(!(_OWPStateIs(_OWPStateRequest,cntrl) &&
                _OWPStateIs(_OWPStateTest,cntrl))){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteStopSessions called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * WriteStopSessions header
     */
    memset(&buf[0],0,16);

    buf[0] = 3;
    buf[1] = acceptval & 0xff;
    *(u_int32_t*)&buf[4] = htonl(num_sessions);

    if(_OWPSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }

    /*
     * Loop through each session, write out a session description
     * record for each "send" session.
     */
    for(sptr=cntrl->tests; sptr; sptr = sptr->next){
        off_t       sd_size;

        /*
         * Receive sessions don't need more work here.
         */
        if(!sptr->endpoint->send) continue;

        if(_OWPSendBlocksIntr(cntrl,sptr->sid,1,retn_on_intr) != 1){
            return _OWPFailControlSession(cntrl,OWPErrFATAL);
        }

        sd_size = sptr->endpoint->skiprecsize;

        /*
         * First send out complete blocks
         */
        while(sd_size >= 16){
            if(I2Readni(sptr->endpoint->skiprecfd,buf,16,retn_on_intr) != 16){
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
            if(_OWPSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
            sd_size -= 16;
        }

        /*
         * If last skip record does not end on a block boundry, then
         * there can be 8 octets of skip records left to send.
         */
        if(sd_size == 8){
            if(I2Readni(sptr->endpoint->skiprecfd,buf,8,retn_on_intr) != 8){
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
            memset(&buf[8],0,8);
            if(_OWPSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
            sd_size -= 8;
        }

        /*
         * If all data has not been sent, there is an error.
         */
        if(sd_size != 0){
            return _OWPFailControlSession(cntrl,OWPErrFATAL);
        }
    }

    /*
     * Complete WriteStopSessions by sending IZP.
     */
    memset(buf,0,16);
    if(_OWPSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }

    return OWPErrOK;
}

/*
 *         SkipRecord format:
 *
 *         size: 8 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                      First Seqno Skipped                      |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                       Last Seqno Skipped                      |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/*
 * Function:        _OWPEncodeSkipRecord
 *
 * Description:        
 *         This function is used to encode a single 8 octet/2 integer skip
 *         record used to indicate a range of test packets that were never
 *         sent due to scheduling issues on the sender host.
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
_OWPEncodeSkipRecord(
        u_int8_t    buf[_OWP_SKIPREC_SIZE],
        OWPSkip     skip
        )
{
    u_int32_t        nlbuf;

    /* begin seq */
    nlbuf = htonl(skip->begin);
    memcpy(&buf[0],&nlbuf,4);

    /* end seq */
    nlbuf = htonl(skip->end);
    memcpy(&buf[4],&nlbuf,4);

    return;
}


/*
 * Function:        OWPDecodeSkipRecord
 *
 * Description:        
 *         This function is used to decode the "skip record" and
 *         place the values in the given OWPSkipRec.
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
_OWPDecodeSkipRecord(
        OWPSkip     skip,
        u_int8_t    buf[_OWP_SKIPREC_SIZE]
        )
{
    /*
     * memcpy buf in case it is not 32bit aligned.
     */
    memcpy(&skip->begin,&buf[0],4);
    skip->begin = ntohl(skip->begin);

    memcpy(&skip->end,&buf[4],4);
    skip->end = ntohl(skip->end);

    return;
}

/*
 * Function:    _OWPReadStopSessions
 *
 * Description:    
 *              This function updates the "recv" side sessions with
 *              the data from the senders in the Stop Sessions message.
 *              This includes updating the recv file record. Therefore,
 *              there are possible race-conditions. It is imperative that
 *              things be done in the correct order to avoid this.
 *
 *              Correct order:
 *                  No skip records can be added into the file until
 *                  after the number of data records in the file has
 *                  become fixed. This way ProcessFetchSessions can
 *                  use the file size to determine the number of records
 *                  if the file is not "complete". Also, the "finished"
 *                  field of the file should not be modified to "complete"
 *                  until all other field have been updated. Therefore,
 *                  for the basic receiver, the order should be:
 *                      1. write header - no num_records or num_skips
 *                      2. write data records
 *                      3. write num_datarecs
 *                      4. write skips
 *                      5. write num_skips
 *                      6. write next_seqno/finished
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
_OWPReadStopSessions(
        OWPControl      cntrl,
        int             *intr,
        OWPAcceptType   *acceptval,
        OWPTimeStamp    stoptime
        )
{
    int             n;
    u_int8_t        *buf = (u_int8_t*)cntrl->msg;
    OWPAcceptType   aval;
    u_int32_t       i,j,num_sessions;
    OWPTestSession  *sptr,tptr;
    OWPTestSession  receivers = NULL;
    off_t           toff;

    if(!(_OWPStateIs(_OWPStateRequest,cntrl) &&
                _OWPStateIs(_OWPStateTest,cntrl))){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStopSessions called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Decode first block of StopSessions message.
     */
    if(memcmp(cntrl->zero,&buf[2],2) || memcmp(cntrl->zero,&buf[8],4)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStopSessions:Invalid zero padding");
        goto err;
    }

    aval = GetAcceptType(cntrl,buf[1]);
    if(acceptval)
        *acceptval = aval;

    if(aval == OWP_CNTRL_INVALID){
        goto err;
    }

    num_sessions = ntohl(*(u_int32_t*)&buf[4]);

    /*
     * Parse test session list and pull recv sessions into the receivers
     * list - the StopSessions message must account for all of them.
     */
    sptr = &cntrl->tests;
    while(*sptr){
        tptr = *sptr;
        if(!tptr->endpoint){
            OWPError(cntrl->ctx,OWPErrFATAL,EINVAL,
                    "_OWPReadStopSessions: no endpoint state!");
            goto err;
        }

        /*
         * Leave send sessions in the "tests" list.
         */
        if(tptr->endpoint->send){
            sptr = &(*sptr)->next;
            continue;
        }

        /*
         * Pull this node out of the "tests" list and add it to the
         * receivers list.
         */
        *sptr = tptr->next;
        tptr->next = receivers;
        receivers = tptr;
    }

    /*
     * Now read and decode the variable length portion of the
     * StopSessions message.
     */
    for(i=0;i<num_sessions;i++){
        FILE                        *rfp,*wfp;
        char                        sid_name[sizeof(OWPSID)*2+1];
        _OWPSessionHeaderInitialRec fhdr;
        struct flock                flk;
        OWPNum64                    lowR,highR,threshR;
        u_int32_t                   lowI,midI,highI,num_recs;
        u_int8_t                    rbuf[_OWP_DATAREC_SIZE];
        OWPDataRec                  rec;
        OWPSkipRec                  prev_skip, curr_skip;
        u_int32_t                   next_seqno;
        u_int32_t                   num_skips;

        /*
         * Read sid from session description record
         */
        n = _OWPReceiveBlocksIntr(cntrl,buf,1,intr);
        if(n != 1){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "_OWPReadStopSessions: Unable to read session record (%d)",
                    i);
            goto err;
        }

        /*
         * Match TestSession record with session description record
         */
        sptr = &receivers;
        tptr = NULL;
        while(*sptr){
            /*
             * If this is not it, try the next one.
             */
            if(memcmp(buf,(*sptr)->sid,sizeof(OWPSID))){
                sptr = &(*sptr)->next;
                continue;
            }

            /*
             * Found: remove this record from the receivers list
             * and put it back in the "tests" list and break out
             * of this loop.
             */
            tptr = *sptr;
            *sptr = tptr->next;
            tptr->next = cntrl->tests;
            cntrl->tests = tptr;
            break;
        }

        /*
         * If sid not found, this is an invalid StopSessions message.
         */
        if(!tptr){
            OWPError(cntrl->ctx,OWPErrFATAL,EINVAL,
                    "_OWPReadStopSessions: sid from StopSessions not valid.");
            goto err;
        }


        I2HexEncode(sid_name,tptr->sid,sizeof(OWPSID));

        rfp = tptr->endpoint->datafile;
        wfp = rfp;

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
                    "_OWPReadStopSessions: Unable to lock file sid(%s): %M",
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
         * Compute number of data records currently in file using filesizes.
         * (Verify that disk space is a multiple of datarec size too...)
         */
        toff = fhdr.sbuf.st_size - fhdr.oset_datarecs;
        if(toff % _OWP_DATAREC_SIZE){
            OWPError(cntrl->ctx,OWPErrFATAL,EFTYPE,
                    "_OWPReadStopSessions: Invalid records for sid(%s)",
                    sid_name);
            goto err;
        }
        fhdr.num_datarecs = num_recs = toff / _OWP_DATAREC_SIZE;

        /*
         * If there is no data, this is a very simple file...
         */
        if(!fhdr.num_datarecs) goto done_data;

        /*
         * Seek to beginning of data records.
         */
        if(fseeko(rfp,fhdr.oset_datarecs,SEEK_SET) != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
            goto err;
        }

        /*
         * Delete data records sent later than stoptime-timeout as per
         * section 3.8 owdp-draft-14
         *
         * To do this is somewhat non-trivial. The records in the file
         * are sorted by recv time. There is a relationship between
         * recv time and send time because of the "timeout" parameter
         * of a test. A packet is only accepted and saved if the recv
         * time is within "timeout" of the recv time. Therefore, this
         * algorithm starts by finding the first packet record in the
         * file with a recv time greater than (stoptime - (2 * timeout)).
         * Then sequentially goes forward through the file deleting
         * all packet records with (sendtime > (stoptime - timeout)).
         *
         * lowI will be the index to the packet record with the
         * largest recv time less than the threshold (stoptime - (2 * timeout))
         * upon completion of the binary search. (If one exists.)
         *
         */

        /*
         * First use an interpolated binary search to find the "threshold"
         * point in the file.
         */

        /* Initializing variables for search. */
        threshR = OWPNum64Sub(stoptime.owptime,
                OWPNum64Mult(tptr->test_spec.loss_timeout,OWPULongToNum64(2)));
        highI = fhdr.num_datarecs;
        highR = stoptime.owptime;
        lowI = 0;

        /*
         * Read the first packet record to get the recv(0) for lowR.
         */
        if(fread(rbuf,_OWP_DATAREC_SIZE,1,rfp) != 1){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "fread(): Reading session file for sid(%s): %M",sid_name);
            goto err;
        }
        if(!_OWPDecodeDataRecord(fhdr.version,&rec,rbuf)){
            errno = EFTYPE;
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "_OWPReadStopSessions: Invalid data record for sid(%s)",
                    sid_name);
            goto err;
        }

        lowR = rec.recv.owptime;

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
            toff = fhdr.oset_datarecs + midI * _OWP_DATAREC_SIZE;

            /*
             * Seek to midI data record.
             */
            if(fseeko(rfp,toff,SEEK_SET) != 0){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
                goto err;
            }

            /*
             * Read the packet record from midI.
             */
            if(fread(rbuf,_OWP_DATAREC_SIZE,1,rfp) != 1){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "fread(): Reading session file for sid(%s): %M",
                        sid_name);
                goto err;
            }
            if(!_OWPDecodeDataRecord(fhdr.version,&rec,rbuf)){
                errno = EFTYPE;
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "_OWPReadStopSessions: Invalid data record for sid(%s)",
                        sid_name);
                goto err;
            }

            /*
             * If midR is less than thresh, update lowI. Otherwise,
             * update highI.
             */
            if(OWPNum64Cmp(rec.recv.owptime,threshR) < 0){
                lowI = midI;
                lowR = rec.recv.owptime;
            }
            else{
                highI = midI;
                highR = rec.recv.owptime;
            }
        }
thresh_pos:

        /*
         * Now, step through all records lowI and after to examine the
         * sent time. The sent time must be less than (stop - timeout)
         * for the record to be kept.
         */
        toff = fhdr.oset_datarecs + (lowI * _OWP_DATAREC_SIZE);
        threshR = OWPNum64Sub(stoptime.owptime,tptr->test_spec.loss_timeout);

        /*
         * Seek to lowI data record to start parsing.
         */
        if(fseeko(rfp,toff,SEEK_SET) != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
            goto err;
        }

        for(j=lowI;j<fhdr.num_datarecs;j++){

            /*
             * Read the packet record from midI.
             */
            if(fread(rbuf,_OWP_DATAREC_SIZE,1,rfp) != 1){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "fread(): Reading session file sid(%s): %M",
                        sid_name);
                goto loop_err;
            }
            if(!_OWPDecodeDataRecord(fhdr.version,&rec,rbuf)){
                errno = EFTYPE;
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "_OWPReadStopSessions: Invalid data record sid(%s)",
                        sid_name);
                goto loop_err;
            }

            /*
             * If the packet was not sent after threshR, then keep it
             * by writing it back into the file if necessary.
             */
            if(!(OWPNum64Cmp(rec.send.owptime,threshR) > 0)){
                if(wfp != rfp){
                    if(fwrite(rbuf,_OWP_DATAREC_SIZE,1,wfp) != 1){
                        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                                "fwrite(): Writing session file sid(%s): %M",
                                sid_name);
                        goto loop_err;
                    }
                }
            }
            /*
             * If the packet record should not be kept.
             */
            else{
                num_recs--;
                /*
                 * If wfp==rfp, then create another fp for wfp and point
                 * it at the current record so it will be written over.
                 */
                if(wfp == rfp){
                    int newfd;

                    if( (newfd = dup(fileno(rfp))) < 0){
                        OWPError(cntrl->ctx,OWPErrFATAL,errno,"dup(%d): %M",
                                fileno(wfp));
                        goto err;
                    }

                    if( !(wfp = fdopen(newfd,"wb"))){
                        OWPError(cntrl->ctx,OWPErrFATAL,errno,"fdopen(%d): %M",
                                newfd);
                        close(newfd);
                        goto err;
                    }

                    /*
                     * Seek new wfp to beginning of record that is not
                     * valid. It will be written over.
                     */
                    toff = fhdr.oset_datarecs + (j * _OWP_DATAREC_SIZE);
                    if(fseeko(wfp,toff,SEEK_SET) != 0){
                        OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
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
         * No longer need two fp's.
         */
        if(wfp != rfp){
            fclose(wfp);
        }

done_data:
        /*
         * Write NumDataRecords into file.
         * (This MUST be done before adding any skip records to the file
         * or there is a race condition where partial session results could
         * interpret skip records as data records!)
         */
        if( !OWPWriteDataHeaderNumDataRecs(cntrl->ctx,rfp,num_recs)){
            goto err;
        }

        /*
         * Read next_seqno, num_skips from SessionDescription record
         */
        n = _OWPReceiveBlocksIntr(cntrl,buf,1,intr);
        if(n != 1){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                    "_OWPReadStopSessions: Unable to read session record (%d)",
                    i);
            goto err;
        }
        next_seqno = ntohl(*(u_int32_t*)&buf[0]);
        num_skips = ntohl(*(u_int32_t*)&buf[4]);

        if(!num_skips) goto done_skips;

        /*
         * Advance fp beyond datarecords, write skip records and write
         * NumSkipRecords
         */
        toff = fhdr.oset_datarecs + (num_recs * _OWP_DATAREC_SIZE);
        if(fseeko(rfp,toff,SEEK_SET) != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
            goto err;
        }


        prev_skip.begin = prev_skip.end = 0;
        for(j=0; j < num_skips; j++){
            u_int8_t    bufi;

            /*
             * Index into buffer for this skip record. (Either 0 or 8)
             */
            bufi = ((j+1) % 2) * 8;

            /*
             * Only need to read another record when bufi == 0
             */
            if(!bufi){
                /*
                 * Read next block
                 */
                n = _OWPReceiveBlocksIntr(cntrl,buf,1,intr);
                if(n != 1){
                    OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                            "_OWPReadStopSessions: Unable to read skip record sid(%s)",
                            sid_name);
                    goto err;
                }
            }

            /*
             * Validate skip record. (begin <= end) and this skip_range
             * is greater-than the previous.
             */
            _OWPDecodeSkipRecord(&curr_skip,&buf[bufi]);
            if(curr_skip.end < curr_skip.begin){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                        "_OWPReadStopSessions: Invalid skip record sid(%s): end < begin",
                        sid_name);
            }
            if(prev_skip.end && (curr_skip.begin < prev_skip.end)){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                        "_OWPReadStopSessions: Invalid skip record sid(%s): skips out of order",
                        sid_name);
            }

            /*
             * Write this skip record into the file.
             *
             * Using 8 for test so this will fail immediately if skip record
             * size changes. This whole routine will need to be modified...
             */
            if(fwrite(&buf[bufi],1,_OWP_SKIPREC_SIZE,rfp) != 8){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,
                        "fwrite(): Writing session file sid(%s): %M",
                        sid_name);
                goto err;
            }
        }

done_skips:
        /*
         * If num_skips is even, then there should be 8 bytes of zero
         * padding to complete the block. Verify.
         */
        if( !(num_skips % 2)){
            if(memcmp(cntrl->zero,&buf[8],8)){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                        "_OWPReadStopSessions: Session sid(%s): Invalid zero padding",
                        sid_name);
                goto err;
            }
        }

        /*
         * Write num_skips and "finished" into file.
         */
        if( !OWPWriteDataHeaderNumSkipRecs(cntrl->ctx,rfp,num_skips)){
            goto err;
        }

        if( !_OWPWriteDataHeaderFinished(cntrl->ctx,rfp,_OWP_SESSION_FIN_NORMAL,
                    next_seqno)){
            goto err;
        }

        flk.l_type = F_UNLCK;
        if( fcntl(fileno(rfp), F_SETLKW, &flk) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "_OWPReadStopSessions: Unable to unlock file sid(%s): %M",
                    sid_name);
            goto err;
        }
    }


    /*
     * IZP completes the StopSessions message.
     */
    n = _OWPReceiveBlocksIntr(cntrl,buf,1,intr);
    if(n != 1){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStopSessions: Unable to read final IZP block");
        goto err;
    }
    if(memcmp(cntrl->zero,&buf[0],16)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStopSessions: Invalid final IZP block");
        goto err;
    }

    /*
     * The control connection is now ready to send the response.
     */
    cntrl->state &= ~_OWPStateStopSessions;
    cntrl->state |= _OWPStateRequest;

    return OWPErrOK;

err:
    /*
     * take everything in receivers list and put it back in tests list
     * so error cleanup at higher levels will work.
     */

    OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "_OWPReadStopSessions: Failed");
    return _OWPFailControlSession(cntrl,OWPErrFATAL);
}

/*
 *         FetchSession message format:
 *
 *         size: 48 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|      4        |                                               |
 *          +-+-+-+-+-+-+-+-+                                               +
 *        04|                        MBZ (7 octets)                         |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                         Begin Seq                             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        12|                          End Seq                              |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                        SID (16 octets)                        |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        32|                                                               |
 *        36|                    Zero Padding (16 octets)                   |
 *        40|                                                               |
 *        44|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteFetchSession(
        OWPControl  cntrl,
        u_int32_t   begin,
        u_int32_t   end,
        OWPSID      sid
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIs(_OWPStateRequest,cntrl) || _OWPStateIsTest(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteFetchSession called in wrong state.");
        return OWPErrFATAL;
    }

    buf[0] = 4;
#ifndef        NDEBUG
    memset(&buf[1],0,7);        /* Unused        */
#endif
    *(u_int32_t*)&buf[8] = htonl(begin);
    *(u_int32_t*)&buf[12] = htonl(end);
    memcpy(&buf[16],sid,16);
    memset(&buf[32],0,16);        /* Zero padding */

    if(_OWPSendBlocks(cntrl,buf,3) != 3)
        return OWPErrFATAL;

    cntrl->state |= (_OWPStateFetchAck | _OWPStateFetchSession);
    cntrl->state &= ~(_OWPStateRequest);
    return OWPErrOK;
}

OWPErrSeverity
_OWPReadFetchSession(
        OWPControl  cntrl,
        int         *retn_on_intr,
        u_int32_t   *begin,
        u_int32_t   *end,
        OWPSID      sid
        )
{
    int         n;
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIs(_OWPStateFetchSession,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchSession called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Already read the first block - read the rest for this message
     * type.
     */
    n = _OWPReceiveBlocksIntr(cntrl,&buf[16],_OWP_FETCH_SESSION_BLK_LEN-1,
            retn_on_intr);

    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != (_OWP_FETCH_SESSION_BLK_LEN-1)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadFetchSession:Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(memcmp(cntrl->zero,&buf[32],16)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchSession:Invalid zero padding");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }
    if(buf[0] != 4){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchSession:Invalid message...");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    *begin = ntohl(*(u_int32_t*)&buf[8]);
    *end = ntohl(*(u_int32_t*)&buf[12]);
    memcpy(sid,&buf[16],16);

    /*
     * The control connection is now ready to send the response.
     * (We are no-longer in FetchSession/Request state, we are
     * in FetchAck/Fetching state.)
     */
    cntrl->state &= (~_OWPStateFetchSession & ~_OWPStateRequest);
    cntrl->state |= _OWPStateFetchAck|_OWPStateFetching;

    return OWPErrOK;
}

/*
 *
 *         FetchAck message format:
 *
 *         size: 32 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|     Accept    |   Finished    |         MBZ (2 octets)        |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                          Next Seqno                           |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                     Number of Skip Ranges                     |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        12|                       Number of Records                       |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                        IZP (16 octets)                        |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteFetchAck(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval,
        u_int8_t        finished,
        u_int32_t       next_seqno,
        u_int32_t       num_skiprecs,
        u_int32_t       num_datarecs
        )
{
    int         n;
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    if(!_OWPStateIs(_OWPStateFetchAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteFetchAck called in wrong state.");
        return OWPErrFATAL;
    }

    buf[0] = acceptval & 0xff;
    buf[1] = finished & 0xff;

#ifndef        NDEBUG
    memset(&buf[1],0,2);        /* Unused        */
#endif

    *(u_int32_t*)&buf[4] = htonl(next_seqno);
    *(u_int32_t*)&buf[8] = htonl(num_skiprecs);
    *(u_int32_t*)&buf[12] = htonl(num_datarecs);

    memset(&buf[16],0,16);        /* IZP */

    n = _OWPSendBlocksIntr(cntrl,buf,_OWP_FETCH_ACK_BLK_LEN,retn_on_intr);

    /*
     * Return control to a higher level on interrupt.
     */
    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != _OWP_FETCH_ACK_BLK_LEN){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * FetchAck has been sent, leave that state.
     */
    cntrl->state &= ~_OWPStateFetchAck;

    /*
     * Fetch was denied - this short-cuts fetch response to "only"
     * the actual FetchAck message - no data will follow.
     * So, leave Fetching state and go back to plain Request state.
     */
    if(acceptval != OWP_CNTRL_ACCEPT){
        cntrl->state &= ~_OWPStateFetching;
        cntrl->state |= _OWPStateRequest;
    }

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadFetchAck(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval,
        u_int8_t        *finished,
        u_int32_t       *next_seqno,
        u_int32_t       *num_skiprecs,
        u_int32_t       *num_datarecs
        )
{
    u_int8_t    *buf = (u_int8_t*)cntrl->msg;

    *acceptval = OWP_CNTRL_INVALID;

    if(!_OWPStateIs(_OWPStateFetchAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchAck called in wrong state.");
        return OWPErrFATAL;
    }

    if(_OWPReceiveBlocks(cntrl,buf,_OWP_FETCH_ACK_BLK_LEN) != 
            (_OWP_FETCH_ACK_BLK_LEN)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadFetchAck:Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(memcmp(cntrl->zero,&buf[16],16)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchAck:Invalid zero padding");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    *acceptval = GetAcceptType(cntrl,buf[0]);
    if(*acceptval == OWP_CNTRL_INVALID){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    *finished = buf[1];
    *next_seqno = ntohl(*(u_int32_t*)&buf[4]);
    *num_skiprecs = ntohl(*(u_int32_t*)&buf[8]);
    *num_datarecs = ntohl(*(u_int32_t*)&buf[12]);

    /*
     * received FetchAck - leave that state.
     */
    cntrl->state &= ~_OWPStateFetchAck;
    cntrl->state &= ~(_OWPStateFetchSession);

    /* If FetchRequest was rejected get back into StateRequest */
    if(*acceptval != OWP_CNTRL_ACCEPT){
        cntrl->state |= _OWPStateRequest;
    }else{
        /* Otherwise prepare to read the TestRequest */
        cntrl->state |= _OWPStateTestRequest;
    }

    return OWPErrOK;
}

/*
 *         DataRecord V2 format:
 *
 *         size: 24 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                          Seq Number                           |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                         Send Timestamp                        |
 *        08|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        12|      Send Error Estimate      |                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *        16|                       Receive Timestamp                       |
 *          +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        20|                               |    Receive Error Estimate     |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
/*
 *         DataRecord V3 format:
 *
 *         size: 25 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                          Seq Number                           |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|      Send Error Estimate      |    Receive Error Estimate     |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                         Send Timestamp                        |
 *        12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                       Receive Timestamp                       |
 *        20|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        24|       TTL       |
 *          +-+-+-+-+-+-+-+-+-+
 *
 */

/*
 * Function:        _OWPEncodeDataRecord
 *
 * Description:        
 *         This function is used to encode the 25 octet "packet record" from
 *         the values in the given OWPDataRec. It returns false if the
 *         timestamp err estimates are invalid values.
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
_OWPEncodeDataRecord(
        u_int8_t    buf[25],
        OWPDataRec  *rec
        )
{
    u_int32_t   nlbuf;

    memset(buf,0,25);
    nlbuf = htonl(rec->seq_no);

    /* seq no */
    memcpy(&buf[0],&nlbuf,4);

    /* send stamp */
    _OWPEncodeTimeStamp(&buf[8],&rec->send);

    /* send err */
    if(!_OWPEncodeTimeStampErrEstimate(&buf[4],&rec->send)){
        return False;
    }

    /* recv err */
    if(!_OWPEncodeTimeStampErrEstimate(&buf[6],&rec->recv)){
        return False;
    }

    /* recv stamp */
    _OWPEncodeTimeStamp(&buf[16],&rec->recv);

    buf[24] = rec->ttl;

    return True;
}

/*
 * Function:        OWPDecodeDataRecord
 *
 * Description:        
 *         This function is used to decode the "packet record" and
 *         place the values in the given OWPDataRec. It returns false if the
 *         timestamp err estimates are invalid values.
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
_OWPDecodeDataRecord(
        u_int32_t   file_version,
        OWPDataRec  *rec,
        u_int8_t    *buf
        )
{
    /*
     * Have to memcpy buf because it is not 32bit aligned.
     */
    memset(rec,0,sizeof(OWPDataRec));
    memcpy(&rec->seq_no,&buf[0],4);
    rec->seq_no = ntohl(rec->seq_no);

    switch(file_version){
        case 0:
        case 2:
            _OWPDecodeTimeStamp(&rec->send,&buf[4]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->send,&buf[12])){
                return False;
            }

            _OWPDecodeTimeStamp(&rec->recv,&buf[14]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->recv,&buf[22])){
                return False;
            }

            rec->ttl = 255;
            break;
        case 3:
            _OWPDecodeTimeStamp(&rec->send,&buf[8]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->send,&buf[4])){
                return False;
            }

            _OWPDecodeTimeStamp(&rec->recv,&buf[16]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->recv,&buf[6])){
                return False;
            }

            rec->ttl = buf[24];
            break;
        default:
            return False;
    }

    return True;
}
