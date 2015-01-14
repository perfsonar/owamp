/*
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
 *        File:         sapi.c
 *
 *        Author:       Anatoly Karp
 *                      Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Sun Jun 02 11:40:27 MDT 2002
 *
 *        Description:        
 *
 *        This file contains the api functions typically called from an
 *        owamp server application.
 */
#include <owamp/owampP.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>


static int
OpenSocket(
        OWPContext  ctx,
        int         family,
        I2Addr      addr,
        char        *def_serv
        )
{
    struct addrinfo *fai;
    struct addrinfo *ai;
    int             on;
    int             fd=-1;

    if( !(fai = I2AddrAddrInfo(addr,NULL,def_serv))){
        return -2;
    }

    for(ai = fai;ai;ai = ai->ai_next){
        if(ai->ai_family != family)
            continue;

        fd =socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);

        if(fd < 0)
            continue;

        on=1;
        if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) != 0){
            goto failsock;
        }

        /*
         * TODO Check for the superseded IPV6_BINDV6ONLY sockopt too?
         * (No - not unless someone complains.)
         */
#if        defined(AF_INET6) && defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
        on=0;
        if((ai->ai_family == AF_INET6) &&
                setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&on,sizeof(on)) != 0){
            goto failsock;
        }
#endif

        if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){

            if( !I2AddrSetSAddr(addr,ai->ai_addr,ai->ai_addrlen) ||
                    !I2AddrSetProtocol(addr,ai->ai_protocol) ||
                    !I2AddrSetSocktype(addr,ai->ai_socktype) ||
                    !I2AddrSetFD(addr,fd,True)){
                OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "OpenSocket: Unable to set saddr in address record");
                return -1;
            }

            break;
        }

        if(errno == EADDRINUSE)
            return -2;

failsock:
        while((close(fd) < 0) && (errno == EINTR));
        fd = -1;
    }

    return fd;
}

/*
 * Function:        OWPServerSockCreate
 *
 * Description:        
 *                 Used by server to create the initial listening socket.
 *                 (It is not required that the server use this interface,
 *                 but it will be kept up-to-date and in sync with the
 *                 client OWPControlOpen function. For example, both of
 *                 these functions currently give priority to IPV6 addresses
 *                 over IPV4.)
 *
 *                 The addr should be NULL for a wildcard socket, or bound to
 *                 a specific interface using OWPAddrByNode or
 *                 OWPAddrByAddrInfo.
 *
 *                 This function will create the socket, bind it, and set the
 *                 "listen" backlog length.
 *
 *                 If addr is set using OWPAddrByFD, it will cause an error.
 *                 (It doesn't really make much sense to call this function at
 *                 all if you are going to create and bind your own socket -
 *                 the only thing left is to call "listen"...)
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
static I2Addr
OWPServerSockCreateCommon(
        OWPContext      ctx,
        I2Addr          addr,
        char            *def_serv,
        OWPErrSeverity  *err_ret
        )
{
    int fd = -1;

    *err_ret = OWPErrOK;

    /*
     * AddrByFD is invalid.
     */
    if(addr && (I2AddrFD(addr) > -1)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid I2Addr record - fd already specified.");
        goto error;
    }

    /*
     * If no addr specified, then use wildcard address.
     */
    if((!addr) &&
            !(addr = I2AddrByWildcard(OWPContextErrHandle(ctx),SOCK_STREAM,
                    def_serv))){
        goto error;
    }

    if( !I2AddrSetPassive(addr,True)){
        goto error;
    }

#ifdef        AF_INET6
    /*
     * First try IPv6 addrs only
     */
    fd = OpenSocket(ctx,AF_INET6,addr,def_serv);

    /*
     * Fall back to IPv4 addrs if necessary.
     */
    if(fd == -1)
#endif
        fd = OpenSocket(ctx,AF_INET,addr,def_serv);

    /*
     * if we failed to find any IPv6 or IPv4 addresses... punt.
     */
    if(fd < 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"OWPServerSockCreate: %M");
        goto error;
    }

    /*
     * We have a bound socket - set the listen backlog.
     */
    if(listen(fd,OWP_LISTEN_BACKLOG) < 0){
        OWPError(ctx,OWPErrFATAL,errno,"listen(%d,%d): %s",
                fd,OWP_LISTEN_BACKLOG,strerror(errno));
        goto error;
    }

    return addr;

error:
    I2AddrFree(addr);
    *err_ret = OWPErrFATAL;
    return NULL;

}

I2Addr
OWPServerSockCreate(
        OWPContext      ctx,
        I2Addr          addr,
        OWPErrSeverity  *err_ret
        )
{
    return OWPServerSockCreateCommon(ctx, addr, OWP_CONTROL_SERVICE_NAME,
                                     err_ret);
}

I2Addr
TWPServerSockCreate(
        OWPContext      ctx,
        I2Addr          addr,
        OWPErrSeverity  *err_ret
        )
{
    return OWPServerSockCreateCommon(ctx, addr, TWP_CONTROL_SERVICE_NAME,
                                     err_ret);
}

/*
 * Function:        OWPControlAcceptCommon
 *
 * Description:        
 *                 This function is used to initialize the xWAMP communication
 *                 to the peer.
 *           
 * In Args:        
 *                 connfd,connsaddr, and connsaddrlen are all returned
 *                 from "accept".
 *
 * Returns:        Valid OWPControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
static OWPControl
OWPControlAcceptCommon(
        OWPContext      ctx,            /* library context              */
        int             connfd,         /* connected socket             */
        struct sockaddr *connsaddr,     /* connected socket addr        */
        socklen_t       connsaddrlen,   /* connected socket addr len    */
        uint32_t        mode_offered,   /* advertised server mode       */
        OWPNum64        uptime,         /* uptime for server            */
        OWPBoolean      twoway,
        int             *retn_on_intr,  /* if *retn_on_intr return      */
        OWPErrSeverity  *err_ret        /* err - return                 */
        )
{
    OWPControl      cntrl;
    uint8_t         challenge[16];
    uint8_t         salt[16];
    uint8_t         rawtoken[64];
    uint8_t         token[64];
    uint8_t         *pf=NULL;
    void            *pf_free=NULL;
    size_t          pf_len=0;
    int             rc;
    OWPTimeStamp    timestart,timeend;
    int             ival=1;
    int             *intr = &ival;
    char            remotenode[NI_MAXHOST],remoteserv[NI_MAXSERV];
    size_t          remotenodelen = sizeof(remotenode);
    size_t          remoteservlen = sizeof(remoteserv);
    char            localnode[NI_MAXHOST],localserv[NI_MAXSERV];
    size_t          localnodelen = sizeof(localnode);
    size_t          localservlen = sizeof(localserv);

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    *err_ret = OWPErrOK;

    if ( !(cntrl = _OWPControlAlloc(ctx,twoway,err_ret)))
        goto error;

    cntrl->sockfd = connfd;
    cntrl->server = True;

    /*
     * set up remote_addr for policy decisions, and log reporting.
     *
     * If connsaddr is non-existant, than create the I2Addr using
     * the socket.
     */
    if(!connsaddr || !connsaddrlen){
        if( !(cntrl->remote_addr = I2AddrBySockFD(
                    OWPContextErrHandle(ctx),connfd,True))){
            goto error;
        }
    }
    else{
        if( !(cntrl->remote_addr = I2AddrBySAddr(
                    OWPContextErrHandle(ctx),
                    connsaddr,connsaddrlen,SOCK_STREAM,0)) ||
                !I2AddrSetFD(cntrl->remote_addr,connfd,True)){
            goto error;
        }
    }

    /*
     * set up local_addr for policy decisions, and log reporting.
     */
    if( !(cntrl->local_addr = I2AddrByLocalSockFD(
                    OWPContextErrHandle(ctx),connfd,False))){
        *err_ret = OWPErrFATAL;
        goto error;
    }

    if( !I2AddrNodeName(cntrl->remote_addr,remotenode,&remotenodelen) ||
            !I2AddrServName(cntrl->remote_addr,remoteserv,&remoteservlen) ||
            !I2AddrNodeName(cntrl->local_addr,localnode,&localnodelen) ||
            !I2AddrServName(cntrl->local_addr,localserv,&localservlen)){
        goto error;
    }

    OWPError(ctx,OWPErrINFO,OWPErrPOLICY,
            "Connection to ([%s]:%s) from ([%s]:%s)",
            localnode,localserv,remotenode,remoteserv);

    /* generate 16 random bytes of challenge and salt. */
    if((I2RandomBytes(ctx->rand_src,challenge,sizeof(challenge)) != 0) ||
            (I2RandomBytes(ctx->rand_src,salt, sizeof(salt)) != 0)){
        *err_ret = OWPErrFATAL;
        goto error;
    }

    if(!OWPGetTimeOfDay(ctx,&timestart)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"OWPGetTimeOfDay(): %M");
        *err_ret = OWPErrFATAL;
        goto error;
    }
    if( (rc = _OWPWriteServerGreeting(cntrl,intr,mode_offered,
                    challenge,salt,ctx->pbkdf2_count)) < OWPErrOK){
        *err_ret = (OWPErrSeverity)rc;
        goto error;
    }

    /*
     * If no mode offered, immediately close socket after sending
     * server greeting.
     */
    if(!mode_offered){
        OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                "Control request to ([%s]:%s) denied from ([%s]:%s): mode == 0",
                localnode,localserv,remotenode,remoteserv);
        goto error;
    }

    if((rc = _OWPReadSetupResponse(cntrl,intr,&cntrl->mode,rawtoken,
                    cntrl->readIV)) < OWPErrOK){
        *err_ret = (OWPErrSeverity)rc;
        goto error;
    }

    if(!OWPGetTimeOfDay(ctx,&timeend)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"OWPGetTimeOfDay(): %M");
        *err_ret = OWPErrFATAL;
        goto error;
    }
    cntrl->rtt_bound = OWPNum64Sub(timeend.owptime,timestart.owptime);

    /* insure that exactly one mode is chosen */
    if((cntrl->mode != OWP_MODE_OPEN) &&
            (cntrl->mode != OWP_MODE_AUTHENTICATED) &&
            (cntrl->mode != OWP_MODE_ENCRYPTED)){
        *err_ret = OWPErrFATAL;
        goto error;
    }

    if(!(cntrl->mode | mode_offered)){ /* can't provide requested mode */
        OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                "Control request to ([%s]:%s) denied from ([%s]:%s): mode not offered (%u)",
                localnode,localserv,remotenode,remoteserv,cntrl->mode);
        if( (rc = _OWPWriteServerStart(cntrl,intr,OWP_CNTRL_REJECT,0)) <
                OWPErrOK){
            *err_ret = (OWPErrSeverity)rc;
        }
        goto error;
    }

    if(cntrl->mode & (OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)){
        OWPBoolean  getkey_success;

        /*
         * go through the motions of decrypting token even if
         * getkey fails to find username to minimize vulnerability
         * to timing attacks.
         */
        getkey_success = _OWPCallGetPF(cntrl->ctx,cntrl->userid_buffer,
                &pf,&pf_len,&pf_free, err_ret);
        if(!getkey_success && (*err_ret != OWPErrOK)){
            (void)_OWPWriteServerStart(cntrl,intr,OWP_CNTRL_FAILURE,0);
            goto error;
        }

        if(OWPDecryptToken(pf,pf_len,salt,ctx->pbkdf2_count,
                    rawtoken,token) < 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Encryption state problem?!?!");
            (void)_OWPWriteServerStart(cntrl,intr,OWP_CNTRL_FAILURE,0);
            *err_ret = OWPErrFATAL;
            goto error;
        }

        /* Decrypted challenge is in the first 16 bytes */
        if((memcmp(challenge,token,16) != 0) || !getkey_success){
            if(!getkey_success){
                OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                        "Unknown userid (%s) from ([%s]:%s)",
                        cntrl->userid_buffer,remotenode,remoteserv);
            }
            else{
                OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                        "Control request to ([%s]:%s) denied from ([%s]:%s):Invalid challenge encryption",
                        localnode,localserv,remotenode,remoteserv);
            }
            (void)_OWPWriteServerStart(cntrl,intr,OWP_CNTRL_REJECT,0);
            goto error;
        }

        /* Authentication ok - set encryption fields */
        cntrl->userid = cntrl->userid_buffer;
        if(I2RandomBytes(cntrl->ctx->rand_src,cntrl->writeIV,16) != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to fetch randomness...");
            (void)_OWPWriteServerStart(cntrl,intr,OWP_CNTRL_FAILURE,0);
            goto error;
        }

        memcpy(cntrl->aessession_key,&token[16],16);
        _OWPMakeKey(cntrl,cntrl->aessession_key); 

        memcpy(cntrl->hmac_key,&token[32],32);
        I2HMACSha1Init(cntrl->send_hmac_ctx,cntrl->hmac_key,
                sizeof(cntrl->hmac_key));
        I2HMACSha1Init(cntrl->recv_hmac_ctx,cntrl->hmac_key,
                sizeof(cntrl->hmac_key));

        if(pf_free){
            /* clean-up */
            memset(pf,0,pf_len);
            free(pf_free);
            pf_free = NULL;
            pf = NULL;
            pf_len = 0;
        }
    }

    if(!_OWPCallCheckControlPolicy(cntrl,cntrl->mode,cntrl->userid, 
                I2AddrSAddr(cntrl->local_addr,NULL),
                I2AddrSAddr(cntrl->remote_addr,NULL),err_ret)){
        if(*err_ret > OWPErrWARNING){
            OWPError(ctx,OWPErrWARNING,OWPErrPOLICY,
                    "ControlSession request to ([%s]:%s) denied from userid(%s):([%s]:%s)",
                    localnode,localserv,
                    (cntrl->userid)?cntrl->userid:(char*)"nil",
                    remotenode,remoteserv);
            /*
             * send mode of 0 to client, and then close.
             */
            (void)_OWPWriteServerStart(cntrl,intr,OWP_CNTRL_REJECT,0);
        }
        else{
            OWPError(ctx,*err_ret,OWPErrUNKNOWN,
                    "Policy function failed.");
            (void)_OWPWriteServerStart(cntrl,intr,OWP_CNTRL_FAILURE,0);
        }
        goto error;
    }

    /*
     * Made it through the gauntlet - accept the control session!
     */
    if( (rc = _OWPWriteServerStart(cntrl,intr,OWP_CNTRL_ACCEPT,uptime)) <
            OWPErrOK){
        *err_ret = (OWPErrSeverity)rc;
        goto error;
    }
    OWPError(ctx,OWPErrWARNING,OWPErrPOLICY,
            "ControlSession([%s]:%s) accepted from userid(%s):([%s]:%s)",
            localnode,localserv,
            (cntrl->userid)?cntrl->userid:(char*)"nil",
            remotenode,remoteserv);

    return cntrl;

error:
    if(pf_free)
        free(pf_free);
    OWPControlClose(cntrl);
    return NULL;
}

/*
 * Function:        OWPControlAccept
 *
 * Description:
 *                 This function is used to initialize the OWAMP communication
 *                 to the peer.
 *
 * In Args:
 *                 connfd,connsaddr, and connsaddrlen are all returned
 *                 from "accept".
 *
 * Returns:        Valid OWPControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 *
 * Side Effect:
 */
OWPControl
OWPControlAccept(
        OWPContext      ctx,            /* library context              */
        int             connfd,         /* connected socket             */
        struct sockaddr *connsaddr,     /* connected socket addr        */
        socklen_t       connsaddrlen,   /* connected socket addr len    */
        uint32_t        mode_offered,   /* advertised server mode       */
        OWPNum64        uptime,         /* uptime for server            */
        int             *retn_on_intr,  /* if *retn_on_intr return      */
        OWPErrSeverity  *err_ret        /* err - return                 */
        )
{
    return OWPControlAcceptCommon(ctx,connfd,connsaddr,connsaddrlen,
                                  mode_offered,uptime,False,retn_on_intr,
                                  err_ret);
}

/*
 * Function:        TWPControlAccept
 *
 * Description:
 *                 This function is used to initialize the TWAMP communication
 *                 to the peer.
 *
 * In Args:
 *                 connfd,connsaddr, and connsaddrlen are all returned
 *                 from "accept".
 *
 * Returns:        Valid OWPControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 *
 * Side Effect:
 */
OWPControl
TWPControlAccept(
        OWPContext      ctx,            /* library context              */
        int             connfd,         /* connected socket             */
        struct sockaddr *connsaddr,     /* connected socket addr        */
        socklen_t       connsaddrlen,   /* connected socket addr len    */
        uint32_t        mode_offered,   /* advertised server mode       */
        OWPNum64        uptime,         /* uptime for server            */
        int             *retn_on_intr,  /* if *retn_on_intr return      */
        OWPErrSeverity  *err_ret        /* err - return                 */
        )
{
    return OWPControlAcceptCommon(ctx,connfd,connsaddr,connsaddrlen,
                                  mode_offered,uptime,True,retn_on_intr,
                                  err_ret);
}

OWPErrSeverity
OWPProcessTestRequest(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    OWPTestSession  tsession = NULL;
    OWPErrSeverity  err_ret=OWPErrOK;
    uint16_t       port;
    int             rc;
    OWPAcceptType   acceptval = OWP_CNTRL_FAILURE;
    int             ival=1;
    int             *intr = &ival;
    struct sockaddr *rsaddr;
    struct sockaddr *ssaddr;
    socklen_t       saddrlen;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    /*
     * Read the TestRequest and alloate tsession to hold the information.
     */
    if((rc = _OWPReadTestRequest(cntrl,intr,&tsession,&acceptval)) !=
            OWPErrOK){
        if(acceptval < 0)
            return OWPErrFATAL;
        return OWPErrWARNING;
    }

    assert(tsession);

    /*
     * Get local copies of saddr's.
     */
    rsaddr = I2AddrSAddr(tsession->receiver,&saddrlen);
    ssaddr = I2AddrSAddr(tsession->sender,&saddrlen);
    if(!rsaddr || !ssaddr){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Invalid addresses from ReadTestRequest");
        err_ret = OWPErrFATAL;
        goto error;
    }

    if(tsession->conf_receiver && (_OWPCreateSID(tsession) != 0)){
        err_ret = OWPErrWARNING;
        acceptval = OWP_CNTRL_FAILURE;
        goto error;
    }

    /*
     * Now that we know the SID we can create the schedule
     * context.
     */
    if(!(tsession->sctx = OWPScheduleContextCreate(cntrl->ctx,
                    tsession->sid,&tsession->test_spec))){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to init schedule generator");
        err_ret = OWPErrWARNING;
        acceptval = OWP_CNTRL_FAILURE;
        goto error;
    }

    /*
     * if conf_receiver - open port and get SID.
     */
    if(tsession->conf_receiver){
        if(tsession->conf_sender){
            /*
             * NOTE:
             * This implementation only configures "local" test
             * endpoints. For a more distributed implementation
             * where a single control server could manage multiple
             * endpoints - this check would be removed, and
             * conf_sender and conf_receiver could make
             * sense together.
             */
            acceptval = OWP_CNTRL_UNSUPPORTED;
            err_ret = OWPErrWARNING;
            goto error;
        }

        if(!_OWPCallCheckTestPolicy(cntrl,False,
                    rsaddr,ssaddr,saddrlen,
                    &tsession->test_spec,&tsession->closure,
                    &err_ret)){
            if(err_ret < OWPErrOK)
                goto error;
            OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                    "Test not allowed");
            acceptval = OWP_CNTRL_REJECT;
            err_ret = OWPErrWARNING;
            goto error;
        }

        /* receiver first */
        if(!_OWPEndpointInit(cntrl,tsession,tsession->receiver,NULL,
                    &acceptval,&err_ret)){
            goto error;
        }
    }

    if(tsession->conf_sender){
        /*
         * Check for possible DoS as advised in Section 7 of owdp
         * spec.
         * (control-client MUST be receiver if openmode.)
         */

        if(!(cntrl->mode & OWP_MODE_DOCIPHER)){
            struct sockaddr *csaddr;
            socklen_t       csaddrlen;
            char            remotenode[NI_MAXHOST];
            size_t          remotenodelen = sizeof(remotenode);
            char            recvnode[NI_MAXHOST];
            size_t          recvnodelen = sizeof(recvnode);

            if( !(csaddr = I2AddrSAddr(cntrl->remote_addr,&csaddrlen)) ||
                    !I2AddrNodeName(cntrl->remote_addr,remotenode,
                        &remotenodelen) ||
                    !I2AddrNodeName(tsession->receiver,recvnode,&recvnodelen)){
                OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                        "Unable to determine sockaddr information");
                err_ret = OWPErrFATAL;
                goto error;
            }
            if(I2SockAddrEqual(csaddr,csaddrlen,rsaddr,saddrlen,
                        I2SADDR_ADDR) <= 0){
                OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                        "Test Denied: OpenMode recieve_addr(%s) != control_client(%s)",
                        recvnode,remotenode);
                acceptval = OWP_CNTRL_REJECT;
                err_ret = OWPErrWARNING;
                goto error;
            }
        }

        if(!_OWPCallCheckTestPolicy(cntrl,True,
                    ssaddr,rsaddr,saddrlen,
                    &tsession->test_spec,
                    &tsession->closure,&err_ret)){
            if(err_ret < OWPErrOK)
                goto error;
            OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,"Test not allowed");
            acceptval = OWP_CNTRL_REJECT;
            err_ret = OWPErrWARNING;
            goto error;
        }
        if(!_OWPEndpointInit(cntrl,tsession,tsession->sender,NULL,
                    &acceptval,&err_ret)){
            goto error;
        }
        if(!_OWPEndpointInitHook(cntrl,tsession,&acceptval,&err_ret)){
            goto error;
        }
        port = I2AddrPort(tsession->sender);
    }

    /*
     * This portion could technically be above with the rest
     * of the conf_receiver portion since this implementation
     * does not currently support (conf_receiver && conf_sender),
     * but is broken out so the logic is preserved.
     */
    if(tsession->conf_receiver){
        if(!_OWPEndpointInitHook(cntrl,tsession,&acceptval,&err_ret)){
            goto error;
        }
        port = I2AddrPort(tsession->receiver);
    }

    if( (rc = _OWPWriteAcceptSession(cntrl,intr,OWP_CNTRL_ACCEPT,
                    port,tsession->sid)) < OWPErrOK){
        err_ret = (OWPErrSeverity)rc;
        goto err2;
    }

    /*
     * Add tsession to list of tests managed by this control connection.
     */
    tsession->next = cntrl->tests;
    cntrl->tests = tsession;

    return OWPErrOK;

error:
    /*
     * If it is a non-fatal error, communication should continue, so
     * send negative accept.
     */
    if(err_ret >= OWPErrWARNING)
        (void)_OWPWriteAcceptSession(cntrl,intr,acceptval,0,NULL);

err2:
    if(tsession)
        _OWPTestSessionFree(tsession,acceptval);

    return err_ret;
}

OWPErrSeverity
OWPProcessTestRequestTW(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    OWPTestSession  tsession = NULL;
    OWPErrSeverity  err_ret=OWPErrOK;
    uint16_t       port;
    int             rc;
    OWPAcceptType   acceptval = OWP_CNTRL_FAILURE;
    int             ival=1;
    int             *intr = &ival;
    struct sockaddr *rsaddr;
    struct sockaddr *ssaddr;
    socklen_t       saddrlen;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    /*
     * Read the TestRequest and alloate tsession to hold the information.
     */
    if((rc = _OWPReadTestRequest(cntrl,intr,&tsession,&acceptval)) !=
            OWPErrOK){
        if(acceptval < 0)
            return OWPErrFATAL;
        return OWPErrWARNING;
    }

    assert(tsession);

    /*
     * Get local copies of saddr's.
     */
    rsaddr = I2AddrSAddr(tsession->receiver,&saddrlen);
    ssaddr = I2AddrSAddr(tsession->sender,&saddrlen);
    if(!rsaddr || !ssaddr){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Invalid addresses from ReadTestRequest");
        err_ret = OWPErrFATAL;
        goto error;
    }

    if(_OWPCreateSID(tsession) != 0){
        err_ret = OWPErrWARNING;
        acceptval = OWP_CNTRL_FAILURE;
        goto error;
    }

    /*
     * open port and get SID. For the purposes of policy, we are a
     * local sender - we don't require any disk space.
     */
    if(!_OWPCallCheckTestPolicy(cntrl,True,
                                rsaddr,ssaddr,saddrlen,
                                &tsession->test_spec,&tsession->closure,
                                &err_ret)){
        if(err_ret < OWPErrOK)
            goto error;
        OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                 "Test not allowed");
        acceptval = OWP_CNTRL_REJECT;
        err_ret = OWPErrWARNING;
        goto error;
    }

    /*
     * Use the receiver address for the endpoint - we'll use sendto to
     * actually send the reflected packet
     */
    if(!_OWPEndpointInit(cntrl,tsession,tsession->receiver,NULL,
                         &acceptval,&err_ret)){
        goto error;
    }

    if(!_OWPEndpointInitHook(cntrl,tsession,&acceptval,&err_ret)){
        goto error;
    }
    port = I2AddrPort(tsession->receiver);

    if( (rc = _OWPWriteAcceptSession(cntrl,intr,OWP_CNTRL_ACCEPT,
                    port,tsession->sid)) < OWPErrOK){
        err_ret = (OWPErrSeverity)rc;
        goto err2;
    }

    /*
     * Add tsession to list of tests managed by this control connection.
     */
    tsession->next = cntrl->tests;
    cntrl->tests = tsession;

    return OWPErrOK;

error:
    /*
     * If it is a non-fatal error, communication should continue, so
     * send negative accept.
     */
    if(err_ret >= OWPErrWARNING)
        (void)_OWPWriteAcceptSession(cntrl,intr,acceptval,0,NULL);

err2:
    if(tsession)
        _OWPTestSessionFree(tsession,acceptval);

    return err_ret;
}

OWPErrSeverity
OWPProcessStartSessions(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    int             rc;
    OWPTestSession  tsession;
    OWPErrSeverity  err,err2=OWPErrOK;
    int             ival=1;
    int             *intr = &ival;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    if( (rc = _OWPReadStartSessions(cntrl,intr)) < OWPErrOK)
        return _OWPFailControlSession(cntrl,rc);

    for(tsession = cntrl->tests;tsession;tsession = tsession->next){
        if(tsession->endpoint){
            if(!_OWPEndpointStart(tsession->endpoint,&err)){
                (void)_OWPWriteStartAck(cntrl,intr,
                                        OWP_CNTRL_FAILURE);
                return _OWPFailControlSession(cntrl,err);
            }
            err2 = MIN(err,err2);
        }
    }

    if( (rc = _OWPWriteStartAck(cntrl,intr,OWP_CNTRL_ACCEPT)) < OWPErrOK)
        return _OWPFailControlSession(cntrl,rc);


    return err2;
}

struct DoDataState{
    OWPControl      cntrl;
    OWPErrSeverity  err;
    uint32_t       rec_size;
    OWPBoolean      send;
    uint32_t       begin;
    uint32_t       end;
    uint32_t       inbuf;
    uint64_t       count;
    uint32_t       maxiseen;
    int             *intr;
};

static int
DoDataRecords(
        OWPDataRec  *rec,
        void        *udata
        )
{
    struct DoDataState  *dstate = (struct DoDataState *)udata;
    OWPControl          cntrl = dstate->cntrl;
    char                *buf = (char *)cntrl->msg;

    /*
     * Save largest index seen that is not lost.
     * (This allows this data to be parsed again to count only those
     * records before this index for the purposes of fetching a
     * partial valid session even if it was unable to terminate
     * properly.)
     */
    if((rec->seq_no > dstate->maxiseen) && !OWPIsLostRecord(rec)){
        dstate->maxiseen = rec->seq_no;
    }

    /*
     * If this record is not in range - return 0 to continue on.
     */
    if((rec->seq_no < dstate->begin) || (rec->seq_no > dstate->end)){
        return 0;
    }

    dstate->count++;

    if(dstate->send){
        /*
         * Encode this record into cntrl->msg buffer.
         */
        if(!_OWPEncodeDataRecord(&buf[dstate->inbuf*dstate->rec_size],
                    rec)){
            return -1;
        }
        dstate->inbuf++;

        /*
         * If the buffer is full enough to send, do so.
         */
        if(dstate->inbuf == _OWP_FETCH_DATAREC_BLOCKS){
            _OWPSendHMACAdd(cntrl,buf,_OWP_FETCH_AES_BLOCKS);
            if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,_OWP_FETCH_AES_BLOCKS,
                        dstate->intr) != _OWP_FETCH_AES_BLOCKS){
                dstate->err = OWPErrFATAL;
                _OWPFailControlSession(cntrl,OWPErrFATAL);
                return -1;
            }
            dstate->inbuf = 0;
        }
        else if(dstate->inbuf > _OWP_FETCH_DATAREC_BLOCKS){
            dstate->err = OWPErrFATAL;
            _OWPFailControlSession(cntrl,OWPErrFATAL);
            return -1;
        }
    }

    return 0;
}

OWPErrSeverity
OWPProcessFetchSession(
        OWPControl  cntrl,
        int         *retn_on_intr
        )
{
    char                        *buf = (char *)cntrl->msg;
    OWPErrSeverity              err;
    OWPAcceptType               acceptval = OWP_CNTRL_REJECT;
    void                        *closure = NULL;
    struct sockaddr             *lsaddr;
    struct sockaddr             *rsaddr;
    socklen_t                   saddrlen;
    uint32_t                    begin;
    uint32_t                    end;
    OWPSID                      sid;

    FILE                        *fp;
    char                        fname[PATH_MAX];

    _OWPSessionHeaderInitialRec fhdr;
    struct flock                flk;
    int                         lock_tries=0;
    int                         finish_tries=0;

    uint32_t                    sendrecs;
    uint32_t                    next_seqno = 0;
    uint32_t                    num_skiprecs = 0;
    off_t                       tr_size;

    struct DoDataState          dodata;

    int                         ival=1;
    int                         *intr = &ival;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    /*
     * Read the complete FetchSession request.
     */
    if((err = _OWPReadFetchSession(cntrl,intr,&begin,&end,sid)) < OWPErrOK){
        return _OWPFailControlSession(cntrl, err);
    }

    lsaddr = I2AddrSAddr(cntrl->local_addr,&saddrlen);
    rsaddr = I2AddrSAddr(cntrl->remote_addr,&saddrlen);
    if(!_OWPCallCheckFetchPolicy(cntrl,
                    lsaddr,rsaddr,saddrlen,begin,end,sid,&closure,&err)){
        if(err < OWPErrOK){
            return _OWPFailControlSession(cntrl,err);
        }
        OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,"Fetch not allowed");
        goto reject;
    }
    
    /*
     * Try and open the file containing sid information.
     */
    if( !(fp = _OWPCallOpenFile(cntrl,closure,sid,fname))){
        goto reject;
    }

    /*
     * Read the file header - fp will end up at beginning of
     * TestRequest record.
     */
read_file:
    if( !_OWPReadDataHeaderInitial(cntrl->ctx,fp,&fhdr)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "_OWPReadDataHeaderInitial(\"%s\"): %M",fname);
        goto failed;
    }

    /*
     * Only version 3 files are supported for "fetch session"
     * response messages.
     */
    if(fhdr.version != 3){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPProcessFetchSession(\"%s\"): Invalid file version: %d",
                fname,fhdr.version);
        goto failed;
    }

    if(fhdr.finished == OWP_SESSION_FINISHED_ERROR){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPProcessFetchSession(\"%s\"): Invalid file!",
                fname);
        goto failed;
    }

    /*
     * If the session is not complete, then the file needs be locked before
     * trusting headers. If num_datarecs is still 0 when it is locked, then use
     * the filesize to determine the number of records. Read the file
     * as is - closing the fd will automatically unlock it.
     *
     * If num_datarecs is set, the data up to that point can be trusted.
     */
    if(fhdr.finished != OWP_SESSION_FINISHED_NORMAL){
        memset(&flk,0,sizeof(flk));
        flk.l_start = 0;
        flk.l_len = 0;
        flk.l_whence = SEEK_SET;
        flk.l_type = F_RDLCK;

        if( fcntl(fileno(fp), F_SETLK, &flk) < 0){
            /*
             * If there is currently a lock, go back and reread the
             * header - hopefully the session is being finalized.
             * (Counter here to give up after 5 tries - escalating
             * wait times.)
             */
            if((errno == EACCES) || (errno == EAGAIN)){
                if(lock_tries > 4){
                    OWPError(cntrl->ctx,OWPErrFATAL,errno,
                            "Repeat lock failures: fcntl(\"%s\"): %M",fname);
                    goto failed;
                }
                fflush(fp);
                sleep(1<<lock_tries);
                lock_tries++;
                goto read_file;
            }

            /*
             * any other error is fatal.
             */
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "Unable to lock session file: fcntl(\"%s\"): %M",fname);
            goto failed;
        }

        /*
         * Lock obtained, reread the file header.
         */
        if( !_OWPReadDataHeaderInitial(cntrl->ctx,fp,&fhdr)){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "_OWPReadDataHeaderInitial(\"%s\"): %M",fname);
            goto failed;
        }

        /*
         * If a "complete" session was requested, and the test did not
         * terminate normally - we MUST deny here.
         * Add a delay in to handle possible race conditions.
         */
        if((begin == 0) && (end == 0xFFFFFFFF) &&
                (fhdr.finished != OWP_SESSION_FINISHED_NORMAL)){
            if(finish_tries > 4){
                OWPError(cntrl->ctx,OWPErrFATAL,EBUSY,
                        "OWPProcessFetchSession(\"%s\"): Request for complete session, but session not yet terminated!",
                        fname);
                goto reject;
            }
            fflush(fp);

            // unlock the file since we'll need to retry
            memset(&flk,0,sizeof(flk));
            flk.l_start = 0;
            flk.l_len = 0;
            flk.l_whence = SEEK_SET;
            flk.l_type = F_UNLCK;
            fcntl(fileno(fp), F_SETLK, &flk);

            sleep(1<<finish_tries);
            finish_tries++;

            goto read_file;
        }


        /*
         * If the file doesn't have the number of recs set, then records
         * continue to the end of the file.
         */
        if(!fhdr.num_datarecs){
            fhdr.num_datarecs = (fhdr.sbuf.st_size - fhdr.oset_datarecs) / 
                fhdr.rec_size;
        }
    }

    /*
     * setup the state record for parsing the records.
     */
    dodata.cntrl = cntrl;
    dodata.intr = intr;
    dodata.err = OWPErrOK;
    dodata.rec_size = fhdr.rec_size;
    dodata.send = False;
    dodata.begin = begin;
    dodata.end = end;
    dodata.inbuf = 0;
    dodata.count = 0;
    dodata.maxiseen = 0;

    /*
     * Now - count the number of records that will be sent.
     * short-cut the count if full session is requested.
     */
    if((fhdr.finished == OWP_SESSION_FINISHED_NORMAL) &&
            (begin == 0) && (end == 0xFFFFFFFF)){
        sendrecs = fhdr.num_datarecs;
    }
    else{
        /* forward pointer to data records for counting */
        if(fseeko(fp,fhdr.oset_datarecs,SEEK_SET)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
            goto failed;
        }
        /*
         * Now, count the records in range.
         */
        if(OWPParseRecords(cntrl->ctx,fp,fhdr.num_datarecs,fhdr.version,
                    DoDataRecords,&dodata) != OWPErrOK){
            goto failed;
        }
        sendrecs = dodata.count;
        dodata.count = 0;

        /*
         * If the session did not complete normally, redo the
         * count ignoring all "missing" packets after the
         * last seen one.
         */
        if((fhdr.finished != OWP_SESSION_FINISHED_NORMAL) &&
                (dodata.maxiseen < end)){
            dodata.end = dodata.maxiseen;

            /* set pointer to beginning of data recs */
            if(fseeko(fp,fhdr.oset_datarecs,SEEK_SET)){
                OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
                goto failed;
            }

            if(OWPParseRecords(cntrl->ctx,fp,fhdr.num_datarecs,fhdr.version,
                        DoDataRecords,&dodata) != OWPErrOK){
                goto failed;
            }
            sendrecs = dodata.count;
            dodata.count = 0;
        }

    }

    if(fhdr.finished){
        next_seqno = fhdr.next_seqno;
        num_skiprecs = fhdr.num_skiprecs;
    }

    /* set file pointer to beginning of TestReq */
    if(fseeko(fp,_OWP_TESTREC_OFFSET,SEEK_SET)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
        goto failed;
    }

    /*
     * Now accept the FetchRequest.
     */
    acceptval = OWP_CNTRL_ACCEPT;
    if((err = _OWPWriteFetchAck(cntrl,intr,acceptval,fhdr.finished,next_seqno,
                    num_skiprecs,sendrecs)) < OWPErrOK){
        _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
        return _OWPFailControlSession(cntrl,err);
    }

    /*
     * Determine how large TestReq is including "slots"
     */
    if(fhdr.oset_skiprecs){
        tr_size = fhdr.oset_skiprecs;
    }
    else{
        tr_size = fhdr.oset_datarecs;
    }

    if(fhdr.oset_datarecs){
        tr_size = MIN(tr_size,fhdr.oset_datarecs);
    }

    tr_size -= _OWP_TESTREC_OFFSET;

    if(tr_size % _OWP_RIJNDAEL_BLOCK_SIZE){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPProcessFetchSession: Invalid TestReq in file \"%s\"",
                fname);
    }

    /*
     * Read the TestRequestPreamble from the file, modify the HMAC
     * then send.
     * TestRequestPreamble is 7 blocks long (last one is HMAC).
     */
    if(fread(buf,7*_OWP_RIJNDAEL_BLOCK_SIZE,1,fp) != 1){
        _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }
    _OWPSendHMACAdd(cntrl,buf,6);
    _OWPSendHMACDigestClear(cntrl,&buf[96]);
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,7,intr) != 7){
        _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }
    tr_size -= (_OWP_RIJNDAEL_BLOCK_SIZE*7);

    /*
     * Read the TestReq slots from the file and write it to the socket.
     * Ignore last block (it holds original HMAC - recompute the last
     * block of HMAC and send).
     * (after this loop - fp is positioned at hdr_off.
     */
    while(tr_size > _OWP_RIJNDAEL_BLOCK_SIZE){
        if(fread(buf,1,_OWP_RIJNDAEL_BLOCK_SIZE,fp) !=
                _OWP_RIJNDAEL_BLOCK_SIZE){
            _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
            return _OWPFailControlSession(cntrl,OWPErrFATAL);
        }
        _OWPSendHMACAdd(cntrl,buf,1);
        if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,intr) != 1){
            _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
            return _OWPFailControlSession(cntrl,OWPErrFATAL);
        }
        tr_size -= _OWP_RIJNDAEL_BLOCK_SIZE;
    }
    _OWPSendHMACDigestClear(cntrl,buf);
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,intr) != 1){
        _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }

    if(fhdr.finished && fhdr.num_skiprecs){

        /* set file pointer to beginning of skips */
        if(fseeko(fp,fhdr.oset_skiprecs,SEEK_SET)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
            _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
            return _OWPFailControlSession(cntrl,OWPErrFATAL);
        }

        /*
         * size for all skip records
         */
        tr_size = fhdr.num_skiprecs * _OWP_SKIPREC_SIZE;

        /*
         * First deal with complete blocks of skips
         */
        while(tr_size > _OWP_RIJNDAEL_BLOCK_SIZE){
            if(fread(buf,1,_OWP_RIJNDAEL_BLOCK_SIZE,fp) !=
                    _OWP_RIJNDAEL_BLOCK_SIZE){
                _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
            _OWPSendHMACAdd(cntrl,buf,1);
            if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,intr) != 1){
                _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
            tr_size -= _OWP_RIJNDAEL_BLOCK_SIZE;
        }

        /*
         * Now deal with "partial" skips
         */
        if(tr_size > 0){
            /* zero block so extra space will be 0 padded */
            memset(buf,0,_OWP_RIJNDAEL_BLOCK_SIZE);

            if(fread(buf,1,tr_size,fp) != (size_t)tr_size){
                _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
            _OWPSendHMACAdd(cntrl,buf,1);
            if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,intr) != 1){
                _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
                return _OWPFailControlSession(cntrl,OWPErrFATAL);
            }
        }

    }

    /* now send HMAC Block (between skips & data */
    _OWPSendHMACDigestClear(cntrl,buf);
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,intr) != 1){
        _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
        return _OWPFailControlSession(cntrl,err);
    }


    /*
     * Shortcut for no data.
     */
    if(!sendrecs) goto final;

    /* set file pointer to beginning of data */
    if(fseeko(fp,fhdr.oset_datarecs,SEEK_SET)){
        OWPError(cntrl->ctx,OWPErrFATAL,errno,"fseeko(): %M");
        _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
        return _OWPFailControlSession(cntrl,err);
    }

    /*
     * Now, send the data!
     */
    dodata.send = True;
    if( (OWPParseRecords(cntrl->ctx,fp,fhdr.num_datarecs,fhdr.version,
                    DoDataRecords,&dodata) != OWPErrOK) ||
            (dodata.count != sendrecs)){
        _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
        return _OWPFailControlSession(cntrl,err);
    }

    if(dodata.inbuf){
        /*
         * Set "blks" to number of AES blocks that need to be sent to
         * hold all "leftover" records.
         */
        int blks = (dodata.inbuf*fhdr.rec_size/_OWP_RIJNDAEL_BLOCK_SIZE) + 1;

        /* zero out any partial data blocks */
        memset(&buf[dodata.inbuf*fhdr.rec_size],0,
                (blks*_OWP_RIJNDAEL_BLOCK_SIZE)-
                (dodata.inbuf*fhdr.rec_size));

        /*
         * Write enough AES blocks to get remaining records.
         */
        _OWPSendHMACAdd(cntrl,buf,blks);
        if( (_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,blks,intr) != blks)){
            _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_FAILURE);
            return _OWPFailControlSession(cntrl,err);
        }
    }

final:
    /*
     * We are done reading from the file - close it.
     */
    _OWPCallCloseFile(cntrl,closure,fp,OWP_CNTRL_ACCEPT);

    /* now send final HMAC Block */
    _OWPSendHMACDigestClear(cntrl,buf);
    if(_OWPSendBlocksIntr(cntrl,(uint8_t *)buf,1,intr) != 1){
        return _OWPFailControlSession(cntrl,err);
    }

    /*
     * reset state to request.
     */
    cntrl->state &= ~_OWPStateFetching;
    cntrl->state |= _OWPStateRequest;

    return OWPErrOK;

failed:
    acceptval = OWP_CNTRL_FAILURE;
reject:
    if(fp){
        _OWPCallCloseFile(cntrl,closure,fp,acceptval);
    }

    if( (err = _OWPWriteFetchAck(cntrl,intr,acceptval,0,0,0,0)) < OWPErrOK){
        return _OWPFailControlSession(cntrl,err);
    }

    return OWPErrWARNING;

}

OWPErrSeverity
OWPUnexpectedRequestType(
    OWPControl cntrl
    )
{
    int             ival=1;
    OWPErrSeverity  rc;

    /*
     * OWAMP doesn't specify any behaviour on unexpected requests, so
     * return fatal to cause the server to close the control session.
     */
    if (!cntrl->twoway) {
        return OWPErrFATAL;
    }

    cntrl->state |= _OWPStateAcceptSession;

    rc = _OWPWriteAcceptSession(cntrl,&ival,OWP_CNTRL_UNSUPPORTED,
                                0,NULL);

    /*
     * Reset state
     */
    cntrl->state = _OWPStateRequest;

    return rc;
}
