/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabls-mode: nil -*-
 *      $Id$
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
 **                     RFC 4656
 **
 **                     Ease of referenceing byte offsets is also why
 **                     the &buf[BYTE] notation is being used.
 **                     Now the C99 may actually start to take hold,
 **                     (char *) is the type being used to accomplish this.
 */

#include <owampP.h>
#include <I2util/util.h>

/*
 *         ServerGreeting message format:
 *
 *         size: 64 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                                                               |
 *        04|                        Unused (12 octets)                     |
 *        08|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        12|                            Modes                              |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                     Challenge (16 octets)                     |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        32|                                                               |
 *        36|                        Salt (16 octets)                       |
 *        40|                                                               |
 *        44|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        48|                       Count (4 octets)                        |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        52|                                                               |
 *        56|                        MBZ (12 octets)                        |
 *        60|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteServerGreeting(
        OWPControl  cntrl,
        int         *retn_on_err,
        uint32_t    avail_modes,
        uint8_t     *challenge,     /* [16] */
        uint8_t     *salt,          /* [16] */
        uint32_t    count
        )
{
    /*
     * buf_aligned it to ensure uint32_t alignment, but I use
     * buf for actual assignments to make the array offsets agree with
     * the byte offsets shown above.
     */
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIsInitial(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteServerGreeting:called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Set unused/MBZ bits to 0. (and initialize rest)
     */
    memset(buf,0,64);

    *((uint32_t *)&buf[12]) = htonl(avail_modes);
    memcpy(&buf[16],challenge,16);
    memcpy(&buf[32],salt,16);
    *((uint32_t *)&buf[48]) = htonl(count);
    if(I2Writeni(cntrl->sockfd,buf,64,retn_on_err) != 64){
        return OWPErrFATAL;
    }

    cntrl->state = _OWPStateSetup;

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadServerGreeting(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint32_t    *mode,      /* modes available - returned   */
        uint8_t     *challenge, /* [16] : challenge - returned  */
        uint8_t     *salt,      /* [16] : challenge - returned  */
        uint32_t    *count      /* count - returned   */
        )
{
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIsInitial(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadServerGreeting: called in wrong state.");
        return OWPErrFATAL;
    }

    if(I2Readni(cntrl->sockfd,buf,64,retn_on_intr) != 64){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Read failed: (%s)",strerror(errno));
        return (int)OWPErrFATAL;
    }

    *mode = ntohl(*((uint32_t *)&buf[12]));
    memcpy(challenge,&buf[16],16);
    memcpy(salt,&buf[32],16);
    *count = ntohl(*((uint32_t *)&buf[48]));

    cntrl->state = _OWPStateSetup;

    return OWPErrOK;
}

/*
 *         SetupResponse message format:
 *
 *         size: 164 octets
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                             Mode                              |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                                                               |
 *        08|                       KeyID (80 octets)                       |
 *        12|                                                               |
 *        16|                                                               |
 *                                      ...
 *
 *        80|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        84|                                                               |
 *        88|                       Token (64 octets)                       |
 *        92|                                                               |
 *        96|                                                               |
 *                                      ...
 *       144|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       148|                                                               |
 *       152|                     Client-IV (16 octets)                     |
 *       156|                                                               |
 *       160|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteSetupResponse(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint8_t     *token        /* [64]        */
        )
{
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIsSetup(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteSetupResponse: called in wrong state.");
        return OWPErrFATAL;
    }

    memset(&buf[0],0,164);

    *(uint32_t *)&buf[0] = htonl(cntrl->mode);
    if(cntrl->mode & OWP_MODE_DOCIPHER){
        memcpy(&buf[4],cntrl->userid,80);
        memcpy(&buf[84],token,64);
        memcpy(&buf[148],cntrl->writeIV,16);
    }

    if(I2Writeni(cntrl->sockfd,buf,164,retn_on_intr) != 164)
        return OWPErrFATAL;

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadSetupResponse(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint32_t    *mode,
        uint8_t     *token,         /* [64] - return        */
        uint8_t     *clientIV       /* [16] - return        */
        )
{
    ssize_t len;
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIsSetup(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadClientGreeting: called in wrong state.");
        return OWPErrFATAL;
    }

    if((len = I2Readni(cntrl->sockfd,buf,164,retn_on_intr)) != 164){
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

    *mode = ntohl(*(uint32_t *)&buf[0]);
    memcpy(cntrl->userid_buffer,&buf[4],80);
    memcpy(token,&buf[84],64);
    memcpy(clientIV,&buf[148],16);

    return OWPErrOK;
}

static OWPAcceptType
GetAcceptType(
        OWPControl  cntrl,
        uint8_t     val
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
 *         ServerStart message format:
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
 *        40|                         MBZ (8 octets)                        |
 *        44|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteServerStart(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   code,
        OWPNum64        uptime
        )
{
    ssize_t         len;
    OWPTimeStamp    tstamp;
    char            *buf = (char *)cntrl->msg;
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

    /*
     * Write first two blocks of message - not encrypted
     */
    memset(&buf[0],0,15);
    *(uint8_t *)&buf[15] = code & 0xff;
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
        _OWPEncodeTimeStamp((uint8_t *)&buf[0],&tstamp);
        memset(&buf[8],0,8);

        cntrl->state = _OWPStateRequest;
    }
    else{
        /* encryption not valid - reset to clear mode and reject */
        cntrl->mode = OWP_MODE_OPEN;
        memset(&buf[0],0,16);
        cntrl->state = _OWPStateInvalid;
    }

    /*
     * Add this block to HMAC, and then send it.
     * No HMAC digest field in this message - so this block gets
     * include as part of the text for the next digest sent in the
     * 'next' message.
     */
    _OWPSendHMACAdd(cntrl,buf,1);
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,intr) != 1){
        if((len < 0) && *intr && (errno == EINTR)){
            return OWPErrFATAL;
        }
        return OWPErrFATAL;
    }

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadServerStart(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval, /* ret        */
        OWPNum64        *uptime     /* ret        */
        )
{
    char            *buf = (char *)cntrl->msg;
    OWPTimeStamp    tstamp;

    if(!_OWPStateIsSetup(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadServerStart: called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * First read unencrypted blocks
     */
    if(I2Readni(cntrl->sockfd,buf,32,retn_on_intr) != 32){
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

    /*
     * If the session is not accepted, there is no key available
     * for ReceiveBlocksIntr to decode, so turn off encryption here.
     */
    if(*acceptval != OWP_CNTRL_ACCEPT){
        cntrl->mode = OWP_MODE_OPEN;
    }

    /*
     * Now read encrypted blocks (In encrypted modes, everything after
     * IV is encrypted.
     * Add block to HMAC
     */
    if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadServerStart: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }
    _OWPRecvHMACAdd(cntrl,buf,1);

    _OWPDecodeTimeStamp(&tstamp,(uint8_t *)&buf[0]);
    *uptime = tstamp.owptime;

    /*
     * Now in normal request state
     */
    cntrl->state = _OWPStateRequest;

    return OWPErrOK;
}

/*
 * This function is called on the server side to read the first block
 * of client requests. The remaining read request messages MUST be called
 * next!.
 * It is also called by the client side from OWPStopSessionsWait and
 * OWPStopSessions.
 *
 * This function does NOT add any data to the HMAC.
 */
OWPRequestType
OWPReadRequestType(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    uint8_t msgtype;
    int     n;
    int     ival=0;
    int     *intr = &ival;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    if(!_OWPStateIsRequest(cntrl) || _OWPStateIsReading(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPReadRequestType:called in wrong state.");
        return OWPReqInvalid;
    }

    /* Read one block so we can peek at the message type */
    n = _OWPReceiveBlocksIntr(cntrl,(uint8_t *)cntrl->msg,1,intr);
    if(n != 1){
        cntrl->state = _OWPStateInvalid;
        if((n < 0) && *intr && (errno == EINTR)){
            return OWPReqSockIntr;
        }
        return OWPReqSockClose;
    }

    msgtype = *(char *)cntrl->msg;

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
        case        5:
            cntrl->state |= _OWPStateTestRequestTW;
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
 *        20|              Sender Address (cont.) or MBZ (12 octets)        |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        32|                        Receiver Address                       |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        36|              Receiver Address (cont.) or MBZ (12 octets)      |
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
 *        76|                           Timeout (8 octets)                  |
 *        80|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        84|                         Type-P Descriptor                     |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        88|                           MBZ (8 octets)                      |
 *        92|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        96|                                                               |
 *       100|                           HMAC (16 octets)                    |
 *       104|                                                               |
 *       108|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int
_OWPEncodeTestRequestPreamble(
        OWPContext      ctx,
        uint32_t       *msg,
        uint32_t       *len_ret,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        OWPBoolean      server_conf_sender, 
        OWPBoolean      server_conf_receiver,
        OWPBoolean      twoway,
        OWPSID          sid,
        OWPTestSpec     *tspec
        )
{
    char            *buf = (char*)msg;
    char            version;
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
    if(!twoway && !server_conf_sender && !server_conf_receiver){
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
    if(!twoway && ((tspec->npackets < 1) || (tspec->nslots < 1) || !tspec->slots)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                 "Invalid test distribution parameters");
        return OWPErrFATAL;
    }

    /*
     * set simple values
     */
    if (twoway) {
        buf[0] = OWPReqTestTW;
    } else {
        buf[0] = OWPReqTest;
    }
    buf[1] = version & 0xF;
    buf[2] = (server_conf_sender && !twoway)?1:0;
    buf[3] = (server_conf_receiver && !twoway)?1:0;

    /*
     * slots and npackets... convert to network byte order.
     */
    *(uint32_t*)&buf[4] = htonl(twoway ? 0 : tspec->nslots);
    *(uint32_t*)&buf[8] = htonl(twoway ? 0 : tspec->npackets);

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
        *(uint16_t*)&buf[12] = saddr6->sin6_port;

        /* receiver address and port  */
        saddr6 = (struct sockaddr_in6*)receiver;
        memcpy(&buf[32],saddr6->sin6_addr.s6_addr,16);
        *(uint16_t*)&buf[14] = saddr6->sin6_port;

        break;
#endif
        case 4:
        /* sender address and port  */
        saddr4 = (struct sockaddr_in*)sender;
        *(uint32_t*)&buf[16] = saddr4->sin_addr.s_addr;
        *(uint16_t*)&buf[12] = saddr4->sin_port;

        /* receiver address and port  */
        saddr4 = (struct sockaddr_in*)receiver;
        *(uint32_t*)&buf[32] = saddr4->sin_addr.s_addr;
        *(uint16_t*)&buf[14] = saddr4->sin_port;

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

    *(uint32_t*)&buf[64] = htonl(tspec->packet_size_padding);

    /*
     * timestamps...
     */
    tstamp.owptime = tspec->start_time;
    _OWPEncodeTimeStamp((uint8_t *)&buf[68],&tstamp);
    tstamp.owptime = tspec->loss_timeout;
    _OWPEncodeTimeStamp((uint8_t *)&buf[76],&tstamp);

    *(uint32_t*)&buf[84] = htonl(tspec->typeP);

    /*
     * Set MBZ and HMAC area to 0
     */
    memset(&buf[88],0,24);

    *len_ret = 112;

    return 0;
}
OWPErrSeverity
_OWPDecodeTestRequestPreamble(
        OWPContext      ctx,
        OWPBoolean      request,
        uint32_t       *msg,
        uint32_t       msg_len,
        OWPBoolean      is_twoway,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        socklen_t       *socklen,
        uint8_t        *ipvn,
        OWPBoolean      *server_conf_sender,
        OWPBoolean      *server_conf_receiver,
        OWPSID          sid,
        OWPTestSpec     *tspec
        )
{
    char            *buf = (char *)msg;
    OWPTimeStamp    tstamp;

    if(msg_len != 112){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPDecodeTestRequestPreamble: Invalid message size");
        return OWPErrFATAL;
    }

    *ipvn = buf[1] & 0xF;
    tspec->nslots = ntohl(*(uint32_t*)&buf[4]);
    tspec->npackets = ntohl(*(uint32_t*)&buf[8]);

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

    if(!*server_conf_sender && !*server_conf_receiver && !is_twoway){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPDecodeTestRequestPreamble: Invalid null request");
        return OWPErrWARNING;
    } else if (is_twoway && (*server_conf_sender || *server_conf_receiver)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPDecodeTestRequestPreamble: Invalid role for two-way request");
        return OWPErrWARNING;
    }

    if(is_twoway && (tspec->nslots != 0 || tspec->npackets != 0)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                 "_OWPDecodeTestRequestPreamble: Invalid slots/number of packets for two-way request: %d/%d",
                 tspec->nslots, tspec->npackets);
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
            saddr6->sin6_port = *(uint16_t*)&buf[12];

        /* receiver address and port  */
        saddr6 = (struct sockaddr_in6*)receiver;
        saddr6->sin6_family = AF_INET6;
        memcpy(saddr6->sin6_addr.s6_addr,&buf[32],16);
        if(request && *server_conf_receiver)
            saddr6->sin6_port = 0;
        else
            saddr6->sin6_port = *(uint16_t*)&buf[14];

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
        saddr4->sin_addr.s_addr = *(uint32_t*)&buf[16];
        if(request && *server_conf_sender)
            saddr4->sin_port = 0;
        else
            saddr4->sin_port = *(uint16_t*)&buf[12];

        /* receiver address and port  */
        saddr4 = (struct sockaddr_in*)receiver;
        saddr4->sin_family = AF_INET;
        saddr4->sin_addr.s_addr = *(uint32_t*)&buf[32];
        if(request && *server_conf_receiver)
            saddr4->sin_port = 0;
        else
            saddr4->sin_port = *(uint16_t*)&buf[14];

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

    tspec->packet_size_padding = ntohl(*(uint32_t*)&buf[64]);

    _OWPDecodeTimeStamp(&tstamp,(uint8_t *)&buf[68]);
    tspec->start_time = tstamp.owptime;
    _OWPDecodeTimeStamp(&tstamp,(uint8_t *)&buf[76]);
    tspec->loss_timeout = tstamp.owptime;

    /*
     * Rely on implementation in endpoint.c to verify bits.
     * (This allows typeP to be expanded in the future for
     * implementations that understand it.)
     */
    tspec->typeP = ntohl(*(uint32_t*)&buf[84]);

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
        uint32_t   msg[4], /* 1 block 32bit aligned */
        OWPSlot     *slot
        )
{
    char            *buf = (char *)msg;
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
    _OWPEncodeTimeStamp((uint8_t *)&buf[8],&tstamp);

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
        uint32_t   msg[4] /* 1 block 32bit aligned */
        )
{
    char            *buf = (char *)msg;
    OWPTimeStamp    tstamp;

    _OWPDecodeTimeStamp(&tstamp,(uint8_t *)&buf[8]);
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
        int             *retn_on_intr,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        OWPBoolean      server_conf_sender,
        OWPBoolean      server_conf_receiver,
        OWPSID          sid,
        OWPTestSpec     *test_spec
        )
{
    char        *buf = (char *)cntrl->msg;
    uint32_t    buf_len = sizeof(cntrl->msg);
    uint32_t    i;

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
                    server_conf_receiver,cntrl->twoway,sid,test_spec) != 0) ||
            (buf_len != 112)){
        return OWPErrFATAL;
    }

    /* Add everything up to the HMAC block into the HMAC */
    _OWPSendHMACAdd(cntrl,buf,6);
    /* Fetch the digest out into the final HMAC block   */
    _OWPSendHMACDigestClear(cntrl,&buf[96]);

    /*
     * Now - send the request! 112 octets == 7 blocks.
     */
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,7,retn_on_intr) != 7){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * Send slots
     */
    if (!cntrl->twoway) {
        for(i=0;i<test_spec->nslots;i++){
            if(_OWPEncodeSlot(cntrl->msg,&test_spec->slots[i]) != OWPErrOK){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                         "_OWPWriteTestRequest: Invalid slot record");
                cntrl->state = _OWPStateInvalid;
                return OWPErrFATAL;
            }
            _OWPSendHMACAdd(cntrl,buf,1);
            if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
                cntrl->state = _OWPStateInvalid;
                return OWPErrFATAL;
            }
        }
        /*
         * Send HMAC digest block
         */
        _OWPSendHMACDigestClear(cntrl,buf);
        if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
            cntrl->state = _OWPStateInvalid;
            return OWPErrFATAL;
        }
    }

    cntrl->state |= _OWPStateAcceptSession;

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
        uint32_t   nslots,
        OWPSlot     *slots
        )
{
    char        *buf = (char *)cntrl->msg;
    uint32_t    i;
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
        if((len =_OWPReceiveBlocksIntr(cntrl,(uint8_t *)&buf[0],1,intr)) != 1){
            cntrl->state = _OWPStateInvalid;
            if((len < 0) && *intr && (errno==EINTR)){
                return OWPErrFATAL;
            }
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "_OWPReadTestRequestSlots: Read Error: %M");
            return OWPErrFATAL;
        }
        _OWPRecvHMACAdd(cntrl,buf,1);

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
     * Now read slot HMAC digest
     */
    if((len=_OWPReceiveBlocksIntr(cntrl,(uint8_t *)&buf[0],1,intr)) != 1){
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
    if(!_OWPRecvHMACCheckClear(cntrl,buf)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadTestRequestSlots: Invalid HMAC");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * TestRequestSlots are read, now ready to send AcceptSession message.
     */
    cntrl->state &= ~_OWPStateTestRequestSlots;

    return OWPErrOK;
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
    char                    *buf = (char *)cntrl->msg;
    OWPErrSeverity          err_ret=OWPErrOK;
    struct sockaddr_storage sendaddr_rec;
    struct sockaddr_storage recvaddr_rec;
    socklen_t               addrlen = sizeof(sendaddr_rec);
    I2Addr                  SendAddr=NULL;
    I2Addr                  RecvAddr=NULL;
    uint8_t                 ipvn;
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

    if(!_OWPStateIs(cntrl->twoway ? _OWPStateTestRequestTW : _OWPStateTestRequest,cntrl)){
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
    if(!accept_ret && (_OWPReceiveBlocksIntr(cntrl,(uint8_t *)&buf[0],1,intr) != 1)){
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
    if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)&buf[16],_OWP_TEST_REQUEST_BLK_LEN-1,
                intr) != (_OWP_TEST_REQUEST_BLK_LEN-1)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadTestRequest: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        *accept_ptr = OWP_CNTRL_INVALID;
        return OWPErrFATAL;
    }

    /*
     * Add data to HMAC and verify digest before decoding message
     */
    _OWPRecvHMACAdd(cntrl,buf,6);
    if(!_OWPRecvHMACCheckClear(cntrl,&buf[96])){
        OWPError(cntrl->ctx,OWPErrFATAL,EACCES,
                "_OWPReadTestRequest: Invalid HMAC");
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
                    cntrl->twoway,
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
    SendAddr = I2AddrBySAddr(OWPContextErrHandle(cntrl->ctx),
            (struct sockaddr*)&sendaddr_rec,addrlen,SOCK_DGRAM,IPPROTO_UDP);
    RecvAddr = I2AddrBySAddr(OWPContextErrHandle(cntrl->ctx),
            (struct sockaddr*)&recvaddr_rec,addrlen,SOCK_DGRAM,IPPROTO_UDP);

    /*
     * Allocate a record for this test.
     */
    if( !(tsession = _OWPTestSessionAlloc(cntrl,SendAddr,conf_sender,
                    RecvAddr,conf_receiver,&tspec))){
        err_ret = OWPErrWARNING;
        *accept_ptr = OWP_CNTRL_FAILURE;
        goto error;
    }

    if(!cntrl->twoway){
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
    }

    /*
     * In the server context, we are going to _OWPStateAcceptSession.
     * In the client "fetching" context we are ready to read the
     * record header and the records.
     */
    if(accept_ret){
        cntrl->state |= _OWPStateAcceptSession;
    }else{
        cntrl->state |= _OWPStateFetching;
    }

    *test_session = tsession;

    return OWPErrOK;

error:
    if(tsession){
        _OWPTestSessionFree(tsession,OWP_CNTRL_FAILURE);
    }else{
        I2AddrFree(SendAddr);
        I2AddrFree(RecvAddr);
    }

    return err_ret;
}

/*
 *
 *         AcceptSession message format:
 *
 *         size: 48 octets
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
 *        24|                        MBZ (12 octets)                        |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        32|                                                               |
 *        36|                       HMAC (16 octets)                        |
 *        40|                                                               |
 *        44|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteAcceptSession(
        OWPControl      cntrl,
        int             *intr,
        OWPAcceptType   acceptval,
        uint16_t       port,
        OWPSID          sid
        )
{
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIs(_OWPStateAcceptSession,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteAcceptSession called in wrong state.");
        return OWPErrFATAL;
    }

    memset(&buf[0],0,_OWP_MAX_MSG_SIZE);
    buf[0] = acceptval & 0xff;
    *(uint16_t *)&buf[2] = htons(port);
    if(sid)
        memcpy(&buf[4],sid,16);

    /*
     * Add this block to HMAC, and then put the digest in the message.
     */
    _OWPSendHMACAdd(cntrl,buf,2);
    _OWPSendHMACDigestClear(cntrl,&buf[32]);

    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,3,intr) != 3){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    cntrl->state &= ~_OWPStateAcceptSession;

    return OWPErrOK;
}

OWPErrSeverity
_OWPReadAcceptSession(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval,
        uint16_t        *port,
        OWPSID          sid
        )
{
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIs(_OWPStateAcceptSession,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadAcceptSession called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Get the servers response.
     */
    if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,3,retn_on_intr) != 3){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadAcceptSession:Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * Add blocks to HMAC, then check digest.
     */
    _OWPRecvHMACAdd(cntrl,buf,2);
    if(!_OWPRecvHMACCheckClear(cntrl,&buf[32])){
        cntrl->state = _OWPStateInvalid;
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid HMAC in Accept-Session message");
        return OWPErrFATAL;
    }

    *acceptval = GetAcceptType(cntrl,buf[0]);
    if(*acceptval == OWP_CNTRL_INVALID){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(port)
        *port = ntohs(*(uint16_t*)&buf[2]);

    if(sid)
        memcpy(sid,&buf[4],16);

    cntrl->state &= ~_OWPStateAcceptSession;

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
 *          +-+-+-+-+-+-+-+-+                                               |
 *        04|                         MBZ (15 octets)                       |
 *        08|                                                               |
 *        12|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                                                               |
 *        20|                        HMAC (16 octets)                       |
 *        24|                                                               |
 *        28|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteStartSessions(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIsRequest(cntrl) || _OWPStateIsPending(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteStartSessions:called in wrong state.");
        return OWPErrFATAL;
    }

    buf[0] = OWPReqStartSessions;
#ifndef        NDEBUG
    memset(&buf[1],0,15);        /* Unused        */
#endif
    memset(&buf[16],0,16);        /* Zero padding */

    /*
     * Add text to HMAC and put digest in second block of message
     */
    _OWPSendHMACAdd(cntrl,buf,1);
    _OWPSendHMACDigestClear(cntrl,&buf[16]);

    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,2,retn_on_intr) != 2){
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
    int     n;
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIs(_OWPStateStartSessions,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartSessions: called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Already read the first block - read the rest for this message
     * type.
     */
    n = _OWPReceiveBlocksIntr(cntrl,(uint8_t *)&buf[16],
            _OWP_STOP_SESSIONS_BLK_LEN-1,retn_on_intr);

    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != (_OWP_STOP_SESSIONS_BLK_LEN-1)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadStartSessions: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * Put first block in HMAC, then check to see if the digest matches
     * the second block.
     */
    _OWPRecvHMACAdd(cntrl,buf,1);
    if(!_OWPRecvHMACCheckClear(cntrl,&buf[16])){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartSessions: Invalid HMAC");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(buf[0] != OWPReqStartSessions){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartSessions: Not a StartSessions message...");
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
 *        20|                        HMAC (16 octets)                       |
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
    int     n;
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIs(_OWPStateStartAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteStartAck called in wrong state.");
        return OWPErrFATAL;
    }

    buf[0] = acceptval & 0xff;
    memset(&buf[1],0,15);        /* MBZ        */

    _OWPSendHMACAdd(cntrl,buf,1);
    _OWPSendHMACDigestClear(cntrl,&buf[16]);

    n = _OWPSendBlocksIntr(cntrl,(uint8_t *)buf,2,retn_on_intr);

    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != 2){
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
        int             *retn_on_intr,
        OWPAcceptType   *acceptval
        )
{
    char    *buf = (char *)cntrl->msg;

    *acceptval = OWP_CNTRL_INVALID;

    if(!_OWPStateIs(_OWPStateStartAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartAck: called in wrong state.");
        return OWPErrFATAL;
    }

    if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)&buf[0],2,retn_on_intr) != 
            (_OWP_START_ACK_BLK_LEN)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadStartAck: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    /*
     * Put first block in HMAC, then check to see if the digest matches
     * the second block.
     */
    _OWPRecvHMACAdd(cntrl,buf,1);
    if(!_OWPRecvHMACCheckClear(cntrl,&buf[16])){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStartAck: Invalid HMAC");
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
 *        04|                       HMAC (16 octets)                        |
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
        uint32_t       num_sessions
        )
{
    OWPTestSession  sptr;
    char            *buf = (char *)cntrl->msg;

    if(!(_OWPStateIs(_OWPStateRequest,cntrl) &&
                _OWPStateIs(_OWPStateTest,cntrl))){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteStopSessions: called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * StopSessions header
     */
    memset(&buf[0],0,16);

    buf[0] = OWPReqStopSessions;
    buf[1] = acceptval & 0xff;
    *(uint32_t*)&buf[4] = htonl(num_sessions);

    /*
     * Add 'header' into HMAC and send
     */
    _OWPSendHMACAdd(cntrl,buf,1);
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }


    if (!cntrl->twoway) {
        /*
         * Loop through each session, write out a session description
         * record for each "send" session.
         */
        for(sptr=cntrl->tests; sptr; sptr = sptr->next){
            off_t       sd_size;

            /*
             * Check for invalid sessions
             */
            if(!sptr->endpoint){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                         "_OWPWriteStopSessions: invalid session information.");
                continue;
            }

            /*
             * Receive sessions don't need more work here.
             */
            if(!sptr->endpoint->send) continue;

            _OWPSendHMACAdd(cntrl,(char *)sptr->sid,1);
            if(_OWPSendBlocksIntr(cntrl,(uint8_t *)sptr->sid,1,retn_on_intr) != 1){
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
                _OWPSendHMACAdd(cntrl,buf,1);
                if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
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
                /* pad with 0 */
                memset(&buf[8],0,8);
                _OWPSendHMACAdd(cntrl,buf,1);
                if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
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
    }

    /*
     * Complete WriteStopSessions by sending HMAC.
     */
    _OWPSendHMACDigestClear(cntrl,buf);
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
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
        uint8_t buf[_OWP_SKIPREC_SIZE],
        OWPSkip skip
        )
{
    uint32_t        nlbuf;

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
 *         place the values in the given _OWPSkipRec.
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
        OWPSkip skip,
        char    buf[_OWP_SKIPREC_SIZE]
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
 *              there are possible race-conditions. (This is done by the
 *              recv process - a control process could potentially be
 *              reading the file at any time.) Therefore, it is imperative
 *              that things be done in the correct order to avoid this.
 *
 *              Correct order:
 *                  No skip records can be added into the file until
 *                  after the number of data records in the fil has
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
 *
 *              TODO: Eventually should probably read this message into a temp
 *              buffer of some sort, and check the HMAC BEFORE modifying
 *              the recv files.
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
    char            *buf = (char *)cntrl->msg;
    OWPAcceptType   aval;
    uint32_t        i,j,num_sessions;
    OWPTestSession  *sptr,tptr;
    OWPTestSession  receivers = NULL;
    off_t           toff;
    int             actual_num_sessions;

    if(!(_OWPStateIs(_OWPStateRequest,cntrl) &&
                _OWPStateIs(_OWPStateTest,cntrl))){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStopSessions called in wrong state.");
        return OWPErrFATAL;
    }

    /*
     * Decode first block of StopSessions message.
     */
    aval = GetAcceptType(cntrl,buf[1]);
    if(acceptval)
        *acceptval = aval;

    if(aval == OWP_CNTRL_INVALID){
        goto err;
    }

    num_sessions = ntohl(*(uint32_t*)&buf[4]);

    _OWPRecvHMACAdd(cntrl,buf,1);

    actual_num_sessions = 0;

    if (cntrl->twoway) {
        /*
         * Count number of active sessions
         */
        for (tptr = cntrl->tests; tptr != NULL; tptr = tptr->next) {
            actual_num_sessions++;
        }

        if (num_sessions != actual_num_sessions) {
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                     "_OWPReadStopSessions: Message does not account "
                     "for all two-way sessions: %u vs. %u actual",
                     num_sessions, actual_num_sessions);
            goto err;
        }

        /*
         * Put receivers back into tests list.
         */
        while(receivers){
            tptr = receivers;
            receivers = receivers->next;

            tptr->next = cntrl->tests;
            cntrl->tests = tptr;
        }
    } else {
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
            actual_num_sessions++;
        }

        /*
         * Now read and decode the variable length portion of the
         * StopSessions message.
         */
        for(i=0;i<num_sessions;i++){
            FILE                        *rfp;
            char                        sid_name[sizeof(OWPSID)*2+1];
            _OWPSessionHeaderInitialRec fhdr;
            struct flock                flk;
            OWPSkipRec                  prev_skip, curr_skip;
            uint32_t                    next_seqno;
            uint32_t                    num_skips;

            /*
             * Read sid from session description record
             */
            n = _OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,intr);
            if(n != 1){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                         "_OWPReadStopSessions: Unable to read session record (%d)",
                         i);
                goto err;
            }
            _OWPRecvHMACAdd(cntrl,buf,1);

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

            /*
             * Read next_seqno, num_skips from SessionDescription record
             */
            n = _OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,intr);
            if(n != 1){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                         "_OWPReadStopSessions: Unable to read session record (%d)",
                         i);
                goto err;
            }
            _OWPRecvHMACAdd(cntrl,buf,1);
            next_seqno = ntohl(*(uint32_t*)&buf[0]);
            num_skips = ntohl(*(uint32_t*)&buf[4]);

            I2HexEncode(sid_name,tptr->sid,sizeof(OWPSID));

            rfp = tptr->endpoint->datafile;

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

            if( !_OWPCleanDataRecs(cntrl->ctx,tptr,next_seqno,stoptime,NULL,NULL)){
                OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                         "_OWPReadStopSessions: Unable to clean data sid(%s): %M",
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
             * Advance fp beyond datarecords, write skip records and write
             * NumSkipRecords
             */
            if(!num_skips) goto done_skips;
            toff = fhdr.oset_datarecs + (fhdr.num_datarecs * fhdr.rec_size);
            if(fseeko(rfp,toff,SEEK_SET) != 0){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
                goto err;
            }

            prev_skip.begin = prev_skip.end = 0;
            for(j=0; j < num_skips; j++){
                uint8_t bufi;

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
                    n = _OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,intr);
                    if(n != 1){
                        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                                 "_OWPReadStopSessions: Unable to read skip record sid(%s)",
                                 sid_name);
                        goto err;
                    }
                    _OWPRecvHMACAdd(cntrl,buf,1);
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
                    goto err;
                }
                if(prev_skip.end && (curr_skip.begin < prev_skip.end)){
                    OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                             "_OWPReadStopSessions: Invalid skip record sid(%s): skips out of order",
                             sid_name);
                    goto err;
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

            if( !_OWPWriteDataHeaderFinished(cntrl->ctx,rfp,OWP_SESSION_FINISHED_NORMAL,
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

        if(*sptr){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                     "_OWPReadStopSessions: Message does not account for all recv sessions");
            goto err;
        }
    }

    /*
     * HMAC completes the StopSessions message.
     */
    n = _OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,intr);
    if(n != 1){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStopSessions: Unable to read final HMAC block");
        goto err;
    }
    if(!_OWPRecvHMACCheckClear(cntrl,buf)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadStopSessions: Invalid HMAC");
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
    while(receivers){
        tptr = receivers;
        receivers = receivers->next;

        tptr->next = cntrl->tests;
        cntrl->tests = tptr;
    }

    if(acceptval){
        *acceptval = OWP_CNTRL_FAILURE;
    }
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
 *        36|                        HMAC (16 octets)                       |
 *        40|                                                               |
 *        44|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
OWPErrSeverity
_OWPWriteFetchSession(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint32_t    begin,
        uint32_t    end,
        OWPSID      sid
        )
{
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIs(_OWPStateRequest,cntrl) || _OWPStateIsTest(cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteFetchSession called in wrong state.");
        return OWPErrFATAL;
    }

    if (cntrl->twoway) {
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteFetchSession: not valid for twoway connection");
        return OWPErrFATAL;
    }

    buf[0] = OWPReqFetchSession;
#ifndef        NDEBUG
    memset(&buf[1],0,7);        /* Unused        */
#endif
    *(uint32_t*)&buf[8] = htonl(begin);
    *(uint32_t*)&buf[12] = htonl(end);
    memcpy(&buf[16],sid,16);

    _OWPSendHMACAdd(cntrl,buf,2);
    _OWPSendHMACDigestClear(cntrl,&buf[32]);

    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,3,retn_on_intr) != 3)
        return OWPErrFATAL;

    cntrl->state |= (_OWPStateFetchAck | _OWPStateFetchSession);
    cntrl->state &= ~(_OWPStateRequest);
    return OWPErrOK;
}

OWPErrSeverity
_OWPReadFetchSession(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint32_t   *begin,
        uint32_t   *end,
        OWPSID      sid
        )
{
    int     n;
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIs(_OWPStateFetchSession,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchSession: called in wrong state.");
        return OWPErrFATAL;
    }

    if (cntrl->twoway) {
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteFetchSession: not valid for twoway connection");
        return OWPErrFATAL;
    }

    /*
     * Already read the first block - read the rest for this message
     * type.
     */
    n = _OWPReceiveBlocksIntr(cntrl,(uint8_t *)&buf[16],_OWP_FETCH_SESSION_BLK_LEN-1,
            retn_on_intr);

    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != (_OWP_FETCH_SESSION_BLK_LEN-1)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadFetchSession: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    _OWPRecvHMACAdd(cntrl,buf,2);
    if(!_OWPRecvHMACCheckClear(cntrl,&buf[32])){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchSession: Invalid HMAC");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    if(buf[0] != OWPReqFetchSession){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchSession: Invalid message...");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    *begin = ntohl(*(uint32_t*)&buf[8]);
    *end = ntohl(*(uint32_t*)&buf[12]);
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
 *        20|                       HMAC (16 octets)                        |
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
        uint8_t        finished,
        uint32_t       next_seqno,
        uint32_t       num_skiprecs,
        uint32_t       num_datarecs
        )
{
    int     n;
    char    *buf = (char *)cntrl->msg;

    if(!_OWPStateIs(_OWPStateFetchAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPWriteFetchAck called in wrong state.");
        return OWPErrFATAL;
    }

    /* initialize */
    memset(&buf[0],0,32);

    buf[0] = acceptval & 0xff;
    buf[1] = finished & 0xff;


    if(finished){
        *(uint32_t*)&buf[4] = htonl(next_seqno);
        *(uint32_t*)&buf[8] = htonl(num_skiprecs);
    }

    *(uint32_t*)&buf[12] = htonl(num_datarecs);

    _OWPSendHMACAdd(cntrl,buf,1);
    _OWPSendHMACDigestClear(cntrl,&buf[16]);

    n = _OWPSendBlocksIntr(cntrl,(uint8_t *)buf,2,retn_on_intr);

    /*
     * Return control to a higher level on interrupt.
     */
    if((n < 0) && *retn_on_intr && (errno == EINTR)){
        return OWPErrFATAL;
    }

    if(n != 2){
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
        int             *retn_on_intr,
        OWPAcceptType   *acceptval,
        uint8_t         *finished,
        uint32_t        *next_seqno,
        uint32_t        *num_skiprecs,
        uint32_t        *num_datarecs
        )
{
    char    *buf = (char *)cntrl->msg;

    *acceptval = OWP_CNTRL_INVALID;

    if(!_OWPStateIs(_OWPStateFetchAck,cntrl)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchAck: called in wrong state.");
        return OWPErrFATAL;
    }

    if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,2,retn_on_intr) != 2){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,
                "_OWPReadFetchAck: Unable to read from socket.");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    _OWPRecvHMACAdd(cntrl,buf,1);
    if(!_OWPRecvHMACCheckClear(cntrl,&buf[16])){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "_OWPReadFetchAck: Invalid HMAC");
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    *acceptval = GetAcceptType(cntrl,buf[0]);
    if(*acceptval == OWP_CNTRL_INVALID){
        cntrl->state = _OWPStateInvalid;
        return OWPErrFATAL;
    }

    *finished = buf[1];
    *next_seqno = ntohl(*(uint32_t*)&buf[4]);
    *num_skiprecs = ntohl(*(uint32_t*)&buf[8]);
    *num_datarecs = ntohl(*(uint32_t*)&buf[12]);

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
        cntrl->state |= (cntrl->twoway ? _OWPStateTestRequestTW :
                         _OWPStateTestRequest);
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
        char        buf[25],
        OWPDataRec  *rec
        )
{
    uint32_t   nlbuf;

    memset(buf,0,25);
    nlbuf = htonl(rec->seq_no);

    /* seq no */
    memcpy(&buf[0],&nlbuf,4);

    /* send stamp */
    _OWPEncodeTimeStamp((uint8_t *)&buf[8],&rec->send);

    /* send err */
    if(!_OWPEncodeTimeStampErrEstimate((uint8_t *)&buf[4],&rec->send)){
        return False;
    }

    /* recv err */
    if(!_OWPEncodeTimeStampErrEstimate((uint8_t *)&buf[6],&rec->recv)){
        return False;
    }

    /* recv stamp */
    _OWPEncodeTimeStamp((uint8_t *)&buf[16],&rec->recv);

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
        uint32_t    file_version,
        OWPDataRec  *rec,
        char        *buf
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
            _OWPDecodeTimeStamp(&rec->send,(uint8_t *)&buf[4]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->send,(uint8_t *)&buf[12])){
                return False;
            }

            _OWPDecodeTimeStamp(&rec->recv,(uint8_t *)&buf[14]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->recv,(uint8_t *)&buf[22])){
                return False;
            }

            rec->ttl = 255;
            break;
        case 3:
            _OWPDecodeTimeStamp(&rec->send,(uint8_t *)&buf[8]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->send,(uint8_t *)&buf[4])){
                return False;
            }

            _OWPDecodeTimeStamp(&rec->recv,(uint8_t *)&buf[16]);
            if(!_OWPDecodeTimeStampErrEstimate(&rec->recv,(uint8_t *)&buf[6])){
                return False;
            }

            rec->ttl = buf[24];
            break;
        default:
            return False;
    }

    return True;
}

/*
 * Function:        _OWPTWEncodeDataRecord
 *
 * Description:
 *         This function is used to encode the 50 octet "packet record" from
 *         the values in the given OWPTWDataRec. It returns false if the
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
_OWPEncodeTWDataRecord(
        char        buf[50],
        OWPTWDataRec  *rec
        )
{
    if (!_OWPEncodeDataRecord(&buf[0], &rec->sent)) {
        return False;
    }
    if (!_OWPEncodeDataRecord(&buf[25], &rec->reflected)) {
        return False;
    }

    return True;
}

/*
 * Function:        OWPDecodeTWDataRecord
 *
 * Description:
 *         This function is used to decode the "packet record" and
 *         place the values in the given OWPTWDataRec. It returns false if the
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
_OWPDecodeTWDataRecord(
        uint32_t    file_version,
        OWPTWDataRec *rec,
        char        *buf
        )
{
    switch(file_version){
    case _OWP_VERSION_TWOWAY|3:
        if (!_OWPDecodeDataRecord(3, &rec->sent, &buf[0])) {
            return False;
        }
        if (!_OWPDecodeDataRecord(3, &rec->reflected, &buf[25])) {
            return False;
        }
        break;
    default:
        return False;
    }

    return True;
}
