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
 *        File:         capi.c
 *
 *        Author:       Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Sun Jun 02 11:37:38 MDT 2002
 *
 *        Description:        
 *
 *        This file contains the api functions that are typically called from
 *        an owamp client application.
 */
#include <owamp/owampP.h>
#include <I2util/util.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

/*
 * Function:        _OWPClientBind
 *
 * Description:        
 *         This function attempts to bind the fd to a local address allowing
 *         the client socket to have the source addr bound.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 *         True if successful, False if unsuccessful.
 *         Additionally err_ret will be set to OWPErrFATAL if there was a
 *         problem with the local_addr.
 * Side Effect:        
 */
static OWPBoolean
_OWPClientBind(
        OWPControl      cntrl,
        int             fd,
        I2Addr          local_addr,
        struct addrinfo *remote_addrinfo,
        OWPErrSeverity  *err_ret
        )
{
    struct addrinfo *fai;
    struct addrinfo *ai;

    *err_ret = OWPErrOK;

    if( !I2AddrSetSocktype(local_addr,SOCK_STREAM) ||
            !I2AddrSetProtocol(local_addr,IPPROTO_TCP) ||
            !(fai = I2AddrAddrInfo(local_addr,NULL,NULL))){
        *err_ret = OWPErrFATAL;
        return False;
    }

    /*
     * Now that we have a valid addrinfo list for this address, go
     * through each of those addresses and try to bind the first
     * one that matches addr family and socktype.
     */
    for(ai=fai;ai;ai = ai->ai_next){
        if(ai->ai_family != remote_addrinfo->ai_family)
            continue;
        if(ai->ai_socktype != remote_addrinfo->ai_socktype)
            continue;

        if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
            if( I2AddrSetSAddr(local_addr,ai->ai_addr,ai->ai_addrlen)){
                return True;
            }
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "I2AddrSetSAddr(): failed to set saddr");
            return False;
        }else{
            switch(errno){
                /* report these errors */
                case EAGAIN:
                case EBADF:
                case ENOTSOCK:
                case EADDRNOTAVAIL:
                case EADDRINUSE:
                case EACCES:
                case EFAULT:
                    OWPError(cntrl->ctx,OWPErrFATAL,errno,
                            "bind(): %M");
                    break;
                    /* ignore all others */
                default:
                    break;
            }
            return False;
        }

    }

    /*
     * None found.
     */
    return False;
}

/*
 * Function:        TryAddr
 *
 * Description:        
 *         This function attempts to connect to the given ai description of
 *         the "server" addr possibly binding to "local" addr.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 *        -1: error - future trys are unlikely to succeed - terminate upward.
 *         0: success - wahoo!
 *         1: keep trying - this one didn't work, probably addr mismatch.
 * Side Effect:        
 */
/*
 */
static int
TryAddr(
        OWPControl      cntrl,
        struct addrinfo *ai,
        I2Addr          local_addr,
        I2Addr          server_addr
       )
{
    OWPErrSeverity  addr_ok=OWPErrOK;
    int             fd;

    fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
    if(fd < 0)
        return 1;

    if(local_addr){
        if(!_OWPClientBind(cntrl,fd,local_addr,ai,&addr_ok)){
            if(addr_ok != OWPErrOK){
                return -1;
            }
            goto cleanup;
        }
    }

    /*
     * Call connect - if it succeeds, return else try again.
     */
    if(connect(fd,ai->ai_addr,ai->ai_addrlen) == 0){

        /*
         * Connected, set the fields in the addr records
         */
        if(I2AddrSetSAddr(server_addr,ai->ai_addr,ai->ai_addrlen) &&
                I2AddrSetSocktype(server_addr,ai->ai_socktype) &&
                I2AddrSetProtocol(server_addr,ai->ai_protocol) &&
                I2AddrSetFD(server_addr,fd,True)){

            cntrl->remote_addr = server_addr;
            cntrl->local_addr = local_addr;
            cntrl->sockfd = fd;
            return 0;
        }

        /*
         * Connected, but addr record stuff failed.
         */
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "I2Addr functions failed after successful connection");
    }

cleanup:
    while((close(fd) < 0) && (errno == EINTR));
    return 1;
}

/*
 * Function:        _OWPClientConnect
 *
 * Description:        
 *         This function attempts to create a socket connection between
 *         the local client and the server. Each specified with OWPAddr
 *         records. If the local_addr is not specified, then the source
 *         addr is not bound. The server_addr is used to get a valid list
 *         of addrinfo records and each addrinfo description record is
 *         tried until one succeeds. (IPV6 is prefered over IPV4)
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
_OWPClientConnect(
        OWPControl      cntrl,
        I2Addr          local_addr,
        I2Addr          server_addr,
        OWPErrSeverity  *err_ret
        )
{
    int             rc;
    struct addrinfo *fai=NULL;
    struct addrinfo *ai=NULL;
    char            nodename[NI_MAXHOST];
    size_t          nodename_len = sizeof(nodename);
    char            servname[NI_MAXSERV];
    size_t          servname_len = sizeof(servname);
    char            *node,*serv;

    if(!server_addr)
        goto error;

    /*
     * Easy case - application provided socket directly.
     */
    if((cntrl->sockfd = I2AddrFD(server_addr)) > -1){
        cntrl->remote_addr = server_addr;
        return 0;
    }

    /*
     * Initialize addrinfo portion of server_addr record.
     */
    if( !(fai = I2AddrAddrInfo(server_addr,NULL,OWP_CONTROL_SERVICE_NAME))){
        goto error;
    }

    /*
     * Now that we have addresses - see if it is valid by attempting
     * to create a socket of that type, and binding(if wanted).
     * Also check policy for allowed connection before calling
     * connect.
     */
#ifdef        AF_INET6
    for(ai=fai;ai;ai=ai->ai_next){

        if(ai->ai_family != AF_INET6) continue;

        if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
            return 0;
        if(rc < 0)
            goto error;
    }
#endif
    /*
     * Now try IPv4 addresses.
     */
    for(ai=fai;ai;ai=ai->ai_next){

        if(ai->ai_family != AF_INET) continue;

        if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
            return 0;
        if(rc < 0)
            goto error;
    }

error:
    /*
     * ifdef out for now... This should be detected by client tools
     * that call OWPControlOpen and reported from there - otherwise
     * retries put out too many error messages.
     */
#if NOT
    /*
     * Unable to connect! If we have a server name report it in
     * the error message.
     */
    if(I2AddrNodeName(server_addr,nodename,&nodename_len)){
        node = nodename;
    }
    else
        node = "**unknown**";

    if(I2AddrServName(server_addr,servname,&servname_len)){
        serv = servname;
    }
    else
        serv = OWP_CONTROL_SERVICE_NAME;

    OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "Unable to connect to \"[%s]:%s\"",node,serv);
#endif

    *err_ret = OWPErrFATAL;

    return -1;
}

/*
 * Function:        OWPControlOpen
 *
 * Description:        
 *                 Opens a connection to an owamp server. Returns after complete
 *                 control connection setup is complete. This means that encrytion
 *                 has been intialized, and the client is authenticated to the
 *                 server if that is necessary. However, the client has not
 *                 verified the server at this point.
 *
 * Returns:        
 *                 A valid OWPControl pointer or NULL.
 * Side Effect:        
 */
OWPControl
OWPControlOpen(
        OWPContext      ctx,            /* control context      */
        I2Addr          local_addr,     /* local addr or null   */
        I2Addr          server_addr,    /* server addr          */
        uint32_t        mode_req_mask,  /* requested modes      */
        OWPUserID       userid,         /* userid or NULL       */
        OWPNum64        *uptime_ret,    /* server uptime - ret  */
        OWPErrSeverity  *err_ret        /* err - return         */
        )
{
    int             rc;
    OWPControl      cntrl;
    uint32_t        mode_avail;
    uint8_t         challenge[16];
    uint8_t         salt[_OWP_SALT_SIZE];
    uint32_t        count;
    uint8_t         token[_OWP_TOKEN_SIZE];
    uint8_t         *pf=NULL;
    void            *pf_free=NULL;
    size_t          pf_len=0;
    OWPAcceptType   acceptval;
    OWPTimeStamp    timestart,timeend;
    OWPNum64        uptime;
    int             intr=1;
    int             *retn_on_intr = &intr;

    *err_ret = OWPErrOK;

    /*
     * First allocate memory for the control state.
     */
    if( !(cntrl = _OWPControlAlloc(ctx,err_ret)))
        goto error;

    /*
     * Use application defined I/O interrupt signal if available.
     * (Default is to fail I/O if it is interrupted.)
     */
    if(cntrl->retn_on_intr){
        retn_on_intr = cntrl->retn_on_intr;
    }

    /*
     * Initialize server record for address we are connecting to.
     */
    if(!server_addr){
        goto error;
    }

    /*
     * Connect to the server.
     * Address policy check happens in here.
     */
    if(_OWPClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
        goto error;

    if(!cntrl->local_addr){
        if( !(cntrl->local_addr = I2AddrByLocalSockFD(
                        OWPContextErrHandle(cntrl->ctx),
                        cntrl->sockfd,False))){
            goto error;
        }
    }

    /*
     * Read the server greating.
     */
    if((rc=_OWPReadServerGreeting(cntrl,retn_on_intr,&mode_avail,
                    challenge,salt,&count)) < OWPErrOK){
        *err_ret = (OWPErrSeverity)rc;
        goto error;
    }

    /*
     * Select mode wanted...
     */
    mode_avail &= mode_req_mask;        /* mask out unwanted modes */

    /*
     * retrieve pf if needed
     */
    if(userid && (mode_avail & OWP_MODE_DOCIPHER)){
        strncpy(cntrl->userid_buffer,userid,
                sizeof(cntrl->userid_buffer)-1);
        if(_OWPCallGetPF(cntrl->ctx,cntrl->userid_buffer,
                    &pf,&pf_len,&pf_free,err_ret)){
            cntrl->userid = cntrl->userid_buffer;
        }
        else{
            if(*err_ret != OWPErrOK)
                goto error;
        }
    }
    /*
     * If no pf, then remove auth/crypt modes
     */
    if(!pf)
        mode_avail &= ~OWP_MODE_DOCIPHER;

    /*
     * Pick "highest" level mode still available to this server.
     */
    if((mode_avail & OWP_MODE_ENCRYPTED) &&
            _OWPCallCheckControlPolicy(cntrl,OWP_MODE_ENCRYPTED,
                cntrl->userid,
                I2AddrSAddr(cntrl->local_addr,NULL),
                I2AddrSAddr(cntrl->remote_addr,NULL),
                err_ret)){
        cntrl->mode = OWP_MODE_ENCRYPTED;
    }
    else if((*err_ret == OWPErrOK) &&
            (mode_avail & OWP_MODE_AUTHENTICATED) &&
            _OWPCallCheckControlPolicy(cntrl,OWP_MODE_AUTHENTICATED,
                cntrl->userid,
                I2AddrSAddr(cntrl->local_addr,NULL),
                I2AddrSAddr(cntrl->remote_addr,NULL),
                err_ret)){
        cntrl->mode = OWP_MODE_AUTHENTICATED;
    }
    else if((*err_ret == OWPErrOK) &&
            (mode_avail & OWP_MODE_OPEN) &&
            _OWPCallCheckControlPolicy(cntrl,OWP_MODE_OPEN,cntrl->userid,
                I2AddrSAddr(cntrl->local_addr,NULL),
                I2AddrSAddr(cntrl->remote_addr,NULL),
                err_ret)){
        cntrl->mode = OWP_MODE_OPEN;
    }
    else if(*err_ret != OWPErrOK){
        goto error;
    }
    else{
        OWPError(ctx,OWPErrWARNING,OWPErrPOLICY,
                "OWPControlOpen: No Common Modes");
        goto denied;
    }

    /*
     * Initialize all the encryption values as necessary.
     */
    if(cntrl->mode & OWP_MODE_DOCIPHER){
        /*
         * Create "token" for SetUpResponse message.
         * Section 3.1 of owamp spec:
         *         AES(concat(challenge(16),aessession_key(16),hmackey(32)))
         */
        uint8_t   buf[_OWP_TOKEN_SIZE];

        /*
         * Create random aes session key. Use rand data to
         * initialize AES structures for use with this
         * key. (ReadBlock/WriteBlock functions will automatically
         * use this key for this cntrl connection.
         */
        if(I2RandomBytes(ctx->rand_src,cntrl->aessession_key,16) != 0)
            goto error;
        _OWPMakeKey(cntrl,cntrl->aessession_key);

        /*
         * Create random HMAC Session-key
         * Initialize hmac structures with this key.
         */
        if(I2RandomBytes(ctx->rand_src,cntrl->hmac_key,
                    sizeof(cntrl->hmac_key)) != 0){
            goto error;
        }
        I2HMACSha1Init(cntrl->send_hmac_ctx,cntrl->hmac_key,
                sizeof(cntrl->hmac_key));
        I2HMACSha1Init(cntrl->recv_hmac_ctx,cntrl->hmac_key,
                sizeof(cntrl->hmac_key));

        /*
         * copy challenge
         * concat session key to buffer
         * concat hmac key to buffer
         */
        memcpy(buf,challenge,16);
        memcpy(&buf[16],cntrl->aessession_key,16);
        memcpy(&buf[32],cntrl->hmac_key,32);

        /*
         * Encrypt the token as specified by Section 3.1
         * (AES CBC, IV=0, key=pbkdf2(pf))
         */
        if(OWPEncryptToken(pf,pf_len,salt,count,buf,token) != 0)
            goto error;

        /*
         * Create random writeIV
         */
        if(I2RandomBytes(ctx->rand_src,cntrl->writeIV,16) != 0)
            goto error;
    }

    if(pf_free){
        /* clean-up */
        memset(pf,0,pf_len);
        free(pf_free);
        pf_free = NULL;
        pf = NULL;
        pf_len = 0;
    }

    /*
     * Get current time before sending client greeting - used
     * for very rough estimate of RTT. (upper bound)
     */
    if(!OWPGetTimeOfDay(ctx,&timestart))
        goto error;

    /*
     * Write the client greeting, and see if the Server agree's to it.
     */
    if( ((rc=_OWPWriteSetupResponse(cntrl,retn_on_intr,token)) < OWPErrOK) ||
            ((rc=_OWPReadServerStart(cntrl,retn_on_intr,&acceptval,
                                     &uptime)) < OWPErrOK)){
        *err_ret = (OWPErrSeverity)rc;
        goto error;
    }

    /*
     * TODO: enumerate reason for rejection
     */
    if(acceptval != OWP_CNTRL_ACCEPT){
        char nodename_buf[255];
        size_t nodename_buflen;

        nodename_buflen = sizeof(nodename_buf);
        OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY,
                "Server denied access: %s", I2AddrNodeName(server_addr, nodename_buf, &nodename_buflen));
        goto denied;
    }

    /*
     * Get current time after response from server and set the RTT
     * in the "rtt_bound" field of cntrl.
     */
    if(!OWPGetTimeOfDay(ctx,&timeend))
        goto error;

    cntrl->rtt_bound = OWPNum64Sub(timeend.owptime,timestart.owptime);

    if(uptime_ret){
        *uptime_ret = uptime;
    }

    /*
     * Done - return!
     */
    return cntrl;

    /*
     * If there was an error - set err_ret, then cleanup memory and return.
     */
error:
    *err_ret = OWPErrFATAL;

    /*
     * If access was denied - cleanup memory and return.
     */
denied:
    if(pf_free)
        free(pf_free);
    if(cntrl->local_addr != local_addr)
        I2AddrFree(local_addr);
    if(cntrl->remote_addr != server_addr)
        I2AddrFree(server_addr);
    OWPControlClose(cntrl);
    return NULL;
}

/*
 * Function:        _OWPClientRequestTestReadResponse
 *
 * Description:        
 *         This function is used to request a test from the server and
 *         return the response.
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
static int
_OWPClientRequestTestReadResponse(
        OWPControl      cntrl,
        int             *retn_on_intr,
        I2Addr          sender,
        OWPBoolean      server_conf_sender,
        I2Addr          receiver,
        OWPBoolean      server_conf_receiver,
        OWPTestSpec     *test_spec,
        OWPSID          sid,                /* ret iff conf_receiver else set */
        OWPErrSeverity  *err_ret
        )
{
    int             rc;
    OWPAcceptType   acceptval;
    uint16_t        port_ret=0;
    uint8_t         *sid_ret=NULL;
    char            nodename_buf[255];
    size_t          nodename_buflen;

    if( (rc = _OWPWriteTestRequest(cntrl,retn_on_intr,
                    I2AddrSAddr(sender,NULL),
                    I2AddrSAddr(receiver,NULL),
                    server_conf_sender, server_conf_receiver,
                    sid, test_spec)) < OWPErrOK){
        *err_ret = (OWPErrSeverity)rc;
        return 1;
    }

    if(server_conf_receiver)
        sid_ret = sid;

    if((rc = _OWPReadAcceptSession(cntrl,retn_on_intr,&acceptval,
                    &port_ret,sid_ret)) < OWPErrOK){
        *err_ret = (OWPErrSeverity)rc;
        return 1;
    }

    /*
     * Figure out if the server will be returning Port field.
     * If so - set set_addr to the sockaddr that needs to be set.
     */
    if(server_conf_sender && !server_conf_receiver){
        if( !I2AddrSetPort(sender,port_ret)){
            return 1;
        }
    }
    else if(!server_conf_sender && server_conf_receiver){
        if( !I2AddrSetPort(receiver,port_ret)){
            return 1;
        }
    }

    if(acceptval == OWP_CNTRL_ACCEPT)
        return 0;

    /*
     * TODO: enumerate failure reasons
     */
    nodename_buflen = sizeof(nodename_buf);
    OWPError(cntrl->ctx,OWPErrWARNING,OWPErrPOLICY, "Server denied test: %s", I2AddrNodeName(cntrl->remote_addr, nodename_buf, &nodename_buflen));

    *err_ret = OWPErrOK;
    return 1;
}

/*
 * Function:        OWPSessionRequest
 *
 * Description:        
 *         Public function used to request a test from the server.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 *         True/False based upon acceptance from server. If False is returned
 *         check err_ret to see if an error condition exists. (If err_ret is
 *         not OWPErrOK, the control connection is probably no longer valid.)
 * Side Effect:        
 */
OWPBoolean
OWPSessionRequest(
        OWPControl      cntrl,
        I2Addr          sender,
        OWPBoolean      server_conf_sender,
        I2Addr          receiver,
        OWPBoolean      server_conf_receiver,
        OWPTestSpec     *test_spec,
        FILE            *fp,
        OWPSID          sid_ret,
        OWPErrSeverity  *err_ret
        )
{
    struct addrinfo *frai=NULL;
    struct addrinfo *rai=NULL;
    struct addrinfo *fsai=NULL;
    struct addrinfo *sai=NULL;
    OWPTestSession  tsession = NULL;
    int             rc=0;
    OWPAcceptType   aval = OWP_CNTRL_ACCEPT;
    struct sockaddr *rsaddr;
    struct sockaddr *ssaddr;
    socklen_t       saddrlen;
    int             intr=1;
    int             *retn_on_intr=&intr;

    *err_ret = OWPErrOK;

    /*
     * Check cntrl state is appropriate for this call.
     * (this would happen as soon as we tried to call the protocol
     * function - but it saves a lot of misplaced work to check now.)
     */
    if(!cntrl || !_OWPStateIsRequest(cntrl)){
        *err_ret = OWPErrFATAL;
        OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
                "OWPSessionRequest: called with invalid cntrl record");
        goto error;
    }

    /*
     * Use application defined intr semantics if available.
     * (Default is to fail on intrupted I/O.)
     */
    if(cntrl->retn_on_intr){
        retn_on_intr = cntrl->retn_on_intr;
    }

    /*
     * If NULL passed in for recv address - fill it in with local
     */
    if(!receiver){
        if(server_conf_receiver){
            OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
                    "OWPSessionRequest: called with invalid receiver address");
            goto error;
        }
        else{
            rsaddr = I2AddrSAddr(cntrl->local_addr,&saddrlen);
            if( !(receiver = I2AddrBySAddr(OWPContextErrHandle(cntrl->ctx),
                            rsaddr,saddrlen,SOCK_DGRAM,IPPROTO_UDP))){
                goto error;
            }
        }
    }
    if( !I2AddrSetSocktype(receiver,SOCK_DGRAM) ||
            !I2AddrSetProtocol(receiver,IPPROTO_UDP) ||
            !I2AddrSetPort(receiver,0)){
        goto error;
    }

    /*
     * If NULL passed in for send address - fill it in with local
     */
    if(!sender){
        if(server_conf_sender){
            OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
                    "OWPSessionRequest: called with invalid sender address");
            goto error;
        }
        else{
            ssaddr = I2AddrSAddr(cntrl->local_addr,&saddrlen);
            if( !(sender = I2AddrBySAddr(OWPContextErrHandle(cntrl->ctx),
                            ssaddr,saddrlen,SOCK_DGRAM,IPPROTO_UDP))){
                goto error;
            }
        }
    }
    if( !I2AddrSetSocktype(sender,SOCK_DGRAM) ||
            !I2AddrSetProtocol(sender,IPPROTO_UDP) ||
            !I2AddrSetPort(sender,0)){
        goto error;
    }

    /*
     * Get addrinfo for address spec's so we can choose between
     * the different address possiblities in the next step.
     */
    if( !(frai = I2AddrAddrInfo(receiver,NULL,NULL)) ||
            !(fsai = I2AddrAddrInfo(sender,NULL,NULL))){
        goto error;
    }

    /*
     * Determine proper address specifications for send/recv.
     * Loop on ai values to find a match and use that.
     * (We prefer IPV6 over others, so loop over IPv6 addrs first...)
     * We only support AF_INET and AF_INET6.
     */
#ifdef        AF_INET6
    for(rai = frai;rai;rai = rai->ai_next){
        if(rai->ai_family != AF_INET6) continue;
        for(sai = fsai;sai;sai = sai->ai_next){
            if(rai->ai_family != sai->ai_family) continue;
            if(rai->ai_socktype != sai->ai_socktype) continue;
            goto foundaddr;
        }
    }
#endif
    for(rai = frai;rai;rai = rai->ai_next){
        if(rai->ai_family != AF_INET) continue;
        for(sai = fsai;sai;sai = sai->ai_next){
            if(rai->ai_family != sai->ai_family) continue;
            if(rai->ai_socktype != sai->ai_socktype) continue;
            goto foundaddr;
        }
    }

    /*
     * Didn't find compatible addrs - return error.
     */
    *err_ret = OWPErrWARNING;
    OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
            "OWPSessionRequest called with incompatible addresses");
    goto error;

foundaddr:
    /*
     * Fill I2Addr records with "selected" addresses for test.
     */
    if( !I2AddrSetSAddr(receiver,rai->ai_addr,rai->ai_addrlen) ||
            !I2AddrSetSAddr(sender,sai->ai_addr,sai->ai_addrlen)){

        OWPError(cntrl->ctx,*err_ret,OWPErrINVALID,
                "OWPSessionRequest: Unable to set socket information");
        goto error;
    }

    /*
     * Save direct pointers to the recv/send saddr's for later.
     */
    rsaddr = rai->ai_addr;
    ssaddr = sai->ai_addr;
    saddrlen = sai->ai_addrlen;

    /*
     * Create a structure to store the stuff we need to keep for
     * later calls.
     */
    if( !(tsession = _OWPTestSessionAlloc(cntrl,sender,server_conf_sender,
                    receiver,server_conf_receiver,test_spec)))
        goto error;

    /*
     * This section initializes the two endpoints for the test.
     * EndpointInit is used to create a local socket and allocate
     * a port for the local side of the test.
     *
     * EndpointInitHook is used to set the information for the
     * remote side of the test and then the Endpoint process
     * is forked off.
     *
     * The request to the server is interwoven in based upon which
     * side needs to happen first. (The receiver needs to be initialized
     * first because the SID comes from there - so, if conf_receiver
     * then the request is sent to the server, and then other work
     * happens. If the client is the receiver, then the local
     * initialization needs to happen before sending the request.)
     */

    /*
     * Configure receiver first since the sid comes from there.
     */
    if(server_conf_receiver){
        /*
         * If send local, check local policy for sender
         */
        if(!server_conf_sender){
            /*
             * create the local sender
             */
            if(!_OWPEndpointInit(cntrl,tsession,sender,NULL,
                        &aval,err_ret)){
                goto error;
            }
        }
        else{
            /*
             * This request will fail with the sample implementation
             * owampd. owampd is not prepared to configure both
             * endpoints - but let the test request go through
             * here anyway.  It will allow a client of the
             * sample implementation to be used with a possibly
             * more robust server.
             */
            ;
        }

        /*
         * Request the server create the receiver & possibly the
         * sender.
         */
        if((rc = _OWPClientRequestTestReadResponse(cntrl,retn_on_intr,
                        sender,server_conf_sender,
                        receiver,server_conf_receiver,
                        test_spec,tsession->sid,err_ret)) != 0){
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
            goto error;
        }

        /*
         * If sender is local, complete it's initialization now that
         * we know the receiver port number.
         */
        if(!server_conf_sender){
            /*
             * check local policy for this sender
             * (had to call policy check after initialize
             * because schedule couldn't be computed until
             * we got the SID from the server.)
             */


            if(!_OWPCallCheckTestPolicy(cntrl,True,
                        ssaddr,rsaddr,saddrlen,
                        test_spec,&tsession->closure,err_ret)){
                OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
                        "Test not allowed");
                goto error;
            }

            if(!_OWPEndpointInitHook(cntrl,tsession,&aval,err_ret)){
                goto error;
            }
        }
    }
    else{
        /*
         * local receiver - create SID and compute schedule.
         */
        if(_OWPCreateSID(tsession) != 0){
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
            goto error;
        }

        /*
         * Local receiver - first check policy, then create.
         */
        if(!_OWPCallCheckTestPolicy(cntrl,False,
                    rsaddr,ssaddr,saddrlen,
                    test_spec,&tsession->closure,err_ret)){
            OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
                    "Test not allowed");
            goto error;
        }
        if(!_OWPEndpointInit(cntrl,tsession,receiver,fp,&aval,err_ret)){
            goto error;
        }


        /*
         * If conf_sender - make request to server
         */
        if(server_conf_sender){
            if((rc = _OWPClientRequestTestReadResponse(cntrl,retn_on_intr,
                            sender,server_conf_sender,
                            receiver,server_conf_receiver,
                            test_spec,tsession->sid,err_ret)) != 0){
                goto error;
            }
        }
        else{
            /*
             * This is a VERY strange situation - the
             * client is setting up a test session without
             * making a request to the server...
             *
             * Just return an error here...
             */
            OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
                    "Test not allowed");
            goto error;
        }
        if(!_OWPEndpointInitHook(cntrl,tsession,&aval,err_ret)){
            goto error;
        }
    }

    /*
     * Server accepted our request, and we were able to initialize our
     * side of the test. Add this "session" to the tests list for this
     * control connection.
     */
    tsession->next = cntrl->tests;
    cntrl->tests = tsession;

    /*
     * return the SID for this session to the caller.
     */
    memcpy(sid_ret,tsession->sid,sizeof(OWPSID));

    return True;

error:
    switch(aval){
        case OWP_CNTRL_ACCEPT:
            break;
        case OWP_CNTRL_REJECT:
            OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,"Test not allowed");
            break;
        case OWP_CNTRL_UNSUPPORTED:
            OWPError(cntrl->ctx,*err_ret,OWPErrUNKNOWN,
                    "Test type unsupported");
            break;
        case OWP_CNTRL_UNAVAILABLE_PERM:
            OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
                    "Test denied: resources unavailable");
            break;
        case OWP_CNTRL_UNAVAILABLE_TEMP:
            OWPError(cntrl->ctx,*err_ret,OWPErrPOLICY,
                    "Test denied: resource temporarily unavailable");
            break;
        case OWP_CNTRL_FAILURE:
        default:
            OWPError(cntrl->ctx,*err_ret,OWPErrUNKNOWN,"Test failed");
            break;
    }

    if(tsession){
        _OWPTestSessionFree(tsession,OWP_CNTRL_FAILURE);
    }
    else{
        /*
         * If tsession exists - the addr's will be free'd as part
         * of it - otherwise, do it here.
         */
        I2AddrFree(receiver);
        I2AddrFree(sender);
    }

    return False;
}

/*
 * Function:        OWPStartSessions
 *
 * Description:        
 *         This function is used by applications to send the StartSessions
 *         message to the server and to kick of it's side of all sessions.
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
OWPStartSessions(
        OWPControl  cntrl
        )
{
    int             rc;
    OWPErrSeverity  err,err2=OWPErrOK;
    OWPTestSession  tsession;
    OWPAcceptType   acceptval;
    int             intr=1;
    int             *retn_on_intr=&intr;

    /*
     * Must pass valid cntrl record.
     */
    if(!cntrl){
        OWPError(NULL,OWPErrFATAL,OWPErrINVALID,
                "OWPStartSessions called with invalid cntrl record");
        return OWPErrFATAL;
    }

    /*
     * Use application defined intrrupt semantics if avail.
     * (Default is to fail on intrrupted I/O.)
     */
    if(cntrl->retn_on_intr){
        retn_on_intr = cntrl->retn_on_intr;
    }

    /*
     * Send the StartSessions message to the server
     */
    if((rc = _OWPWriteStartSessions(cntrl,retn_on_intr)) < OWPErrOK){
        return _OWPFailControlSession(cntrl,rc);
    }

    /*
     * Small optimization... - start local receivers while waiting for
     * the server to respond. (should not start senders - don't want
     * to send packets unless control-ack comes back positive.)
     */
    for(tsession = cntrl->tests;tsession;tsession = tsession->next){
        if(tsession->endpoint && !tsession->endpoint->send){
            if(!_OWPEndpointStart(tsession->endpoint,&err)){
                return _OWPFailControlSession(cntrl,err);
            }
            err2 = MIN(err,err2);
        }
    }

    /*
     * Read the server response.
     */
    if(((rc = _OWPReadStartAck(cntrl,retn_on_intr,&acceptval)) < OWPErrOK) ||
            (acceptval != OWP_CNTRL_ACCEPT)){
        return _OWPFailControlSession(cntrl,OWPErrFATAL);
    }

    /*
     * Now start local senders.
     */
    for(tsession = cntrl->tests;tsession;tsession = tsession->next){
        if(tsession->endpoint && tsession->endpoint->send){
            if(!_OWPEndpointStart(tsession->endpoint,&err)){
                return _OWPFailControlSession(cntrl,err);
            }
            err2 = MIN(err,err2);
        }
    }

    return err2;
}

/*
 * Function:        OWPDelay
 *
 * Description:        
 *         Compute delay between two timestamps.
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
OWPDelay(
        OWPTimeStamp    *send_time,
        OWPTimeStamp    *recv_time
        )
{
    return OWPNum64ToDouble(recv_time->owptime) -
        OWPNum64ToDouble(send_time->owptime);
}

/*
 * Function:        OWPFetchSession
 *
 * Description:        
 *        This function is used to request that the data for the TestSession
 *        identified by sid be fetched from the server and copied to the
 *        file pointed at by fp. This function assumes fp is currently pointing
 *        at an open file, and that fp is ready to write at the begining of the
 *        file.
 *
 *        To request an entire session set begin = 0, and end = 0xFFFFFFFF.
 *        (This is only valid if the session is complete - otherwise the server
 *        should deny this request.)
 *        Otherwise, "begin" and "end" refer to sequence numbers in the test
 *        session.
 *        The number of records returned will not necessarily be end-begin due
 *        to possible loss and/or duplication.
 *
 *      There is a full description of the owp file format in the comments
 *      in api.c.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 *        The number of data records in the file. If < 1, check err_ret to
 *        find out if it was an error condition: ErrOK just means the request
 *        was denied by the server. ErrWARNING means there was a local
 *        problem (fp not writeable etc...) and the control connection is
 *        still valid.
 * Side Effect:        
 */
uint32_t
OWPFetchSession(
        OWPControl      cntrl,
        FILE            *fp,
        uint32_t       begin,
        uint32_t       end,
        OWPSID          sid,
        OWPErrSeverity  *err_ret
        )
{
    OWPAcceptType       acceptval;
    uint8_t             finished;
    uint32_t            n;
    OWPTestSession      tsession = NULL;
    OWPSessionHeaderRec hdr;
    off_t               toff;
    char                buf[_OWP_FETCH_BUFFSIZE];
    OWPBoolean          dowrite = True;
    struct sockaddr     *saddr;
    socklen_t           saddrlen;
    int                 intr=1;
    int                 *retn_on_intr=&intr;

    *err_ret = OWPErrOK;

    if(!fp){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPFetchSession: Invalid fp");
        *err_ret = OWPErrFATAL;
        return 0;
    }

    /*
     * Use application defined intrrupt semantics if avail.
     * (Default is to fail on intrrupted I/O.)
     */
    if(cntrl->retn_on_intr){
        retn_on_intr = cntrl->retn_on_intr;
    }

    /*
     * Initialize file header record.
     */
    memset(&hdr,0,sizeof(hdr));

    /*
     * Make the request of the server.
     */
    if((*err_ret = _OWPWriteFetchSession(cntrl,retn_on_intr,
                    begin,end,sid)) < OWPErrWARNING){
        goto failure;
    }

    /*
     * Read the response
     */
    if((*err_ret = _OWPReadFetchAck(cntrl,retn_on_intr,
                    &acceptval,&finished,&hdr.next_seqno,
                    &hdr.num_skiprecs,&hdr.num_datarecs)) < OWPErrWARNING){
        goto failure;
    }
    /* store 8 bit finished in 32 bit hdr.finished field. */
    hdr.finished = finished;

    /*
     * If the server didn't accept, the fetch response is complete.
     */
    if(acceptval != OWP_CNTRL_ACCEPT){
        return 0;
    }

    /*
     * Representation of original TestReq is first.
     */
    if((*err_ret = _OWPReadTestRequest(cntrl,retn_on_intr,
                    &tsession,NULL)) != OWPErrOK){
        goto failure;
    }

    /*
     * Write the file header now. First encode the tsession into
     * a SessionHeader.
     */
    if( !(saddr = I2AddrSAddr(tsession->sender,&saddrlen))){
        goto failure;
    }
    assert(sizeof(hdr.addr_sender) >= saddrlen);
    memcpy(&hdr.addr_sender,saddr,saddrlen);

    if( !(saddr = I2AddrSAddr(tsession->receiver,&saddrlen))){
        goto failure;
    }
    assert(sizeof(hdr.addr_receiver) >= saddrlen);
    memcpy(&hdr.addr_receiver,saddr,saddrlen);

    hdr.conf_sender = tsession->conf_sender;
    hdr.conf_receiver = tsession->conf_receiver;

    memcpy(hdr.sid,tsession->sid,sizeof(hdr.sid));
    /* hdr.test_spec will now point at same slots memory. */
    hdr.test_spec = tsession->test_spec;

    /*
     * Now, actually write the header
     */
    if( !OWPWriteDataHeader(cntrl->ctx,fp,&hdr)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPFetchSession: OWPWriteDataHeader(): %M");
        *err_ret = OWPErrWARNING;
        dowrite = False;
    }

    /*
     * Done with tsession
     * (Make sure hdr.test_spec->slots is not accessed - mem is freed!)
     */
    (void)_OWPTestSessionFree(tsession,OWP_CNTRL_INVALID);
    hdr.test_spec.slots = NULL;

    /*
     * Skip records:
     *
     * How many octets of skip records?
     */
    toff = hdr.num_skiprecs * _OWP_SKIPREC_SIZE;

    /*
     * Read even AES blocks of skips first
     */
    while(toff > _OWP_RIJNDAEL_BLOCK_SIZE){
        if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        _OWPRecvHMACAdd(cntrl,buf,1);
        if(dowrite && ( fwrite(buf,1,_OWP_RIJNDAEL_BLOCK_SIZE,fp) !=
                    _OWP_RIJNDAEL_BLOCK_SIZE)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
        toff -= _OWP_RIJNDAEL_BLOCK_SIZE;
    }
    /*
     * Finish incomplete block
     */
    if(toff){
        if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        _OWPRecvHMACAdd(cntrl,buf,1);
        if(dowrite && ( fwrite(buf,1,toff,fp) != (size_t)toff)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
    }

    /*
     * Read sent HMAC digest and compare
     */
    if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
        *err_ret = OWPErrFATAL;
        goto failure;
    }
    if(!_OWPRecvHMACCheckClear(cntrl,buf)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPFetchSession: Invalid HMAC");
        *err_ret = OWPErrFATAL;
        goto failure;
    }

    /*
     * Data records are next (fp is already positioned correctly).
     */

    for(n=hdr.num_datarecs;
            n >= _OWP_FETCH_DATAREC_BLOCKS;
            n -= _OWP_FETCH_DATAREC_BLOCKS){
        if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,_OWP_FETCH_AES_BLOCKS,
                    retn_on_intr) != _OWP_FETCH_AES_BLOCKS){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        _OWPRecvHMACAdd(cntrl,buf,_OWP_FETCH_AES_BLOCKS);
        if(dowrite && (fwrite(buf,_OWP_DATAREC_SIZE,
                        _OWP_FETCH_DATAREC_BLOCKS,fp) !=
                    _OWP_FETCH_DATAREC_BLOCKS)){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
    }

    if(n){
        /*
         * Read enough AES blocks to get remaining records.
         */
        int        blks = n*_OWP_DATAREC_SIZE/_OWP_RIJNDAEL_BLOCK_SIZE + 1;

        if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,
                    blks,retn_on_intr) != blks){
            *err_ret = OWPErrFATAL;
            goto failure;
        }
        _OWPRecvHMACAdd(cntrl,buf,blks);
        if(dowrite && (fwrite(buf,_OWP_DATAREC_SIZE,n,fp) != n)){
            OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPFetchSession: fwrite(): %M");
            dowrite = False;
        }
    }

    fflush(fp);

    /*
     * Read final block of HMAC
     */
    if(_OWPReceiveBlocksIntr(cntrl,(uint8_t *)buf,1,retn_on_intr) != 1){
        *err_ret = OWPErrFATAL;
        goto failure;
    }
    if(!_OWPRecvHMACCheckClear(cntrl,buf)){
        OWPError(cntrl->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPFetchSession: Invalid HMAC");
        *err_ret = OWPErrFATAL;
        goto failure;
    }

    /*
     * reset state to request.
     */
    cntrl->state &= ~_OWPStateFetching;
    cntrl->state |= _OWPStateRequest;

    if(!dowrite){
        *err_ret = OWPErrWARNING;
        hdr.num_datarecs = 0;
    }

    return hdr.num_datarecs;

failure:
    (void)_OWPFailControlSession(cntrl,*err_ret);
    return 0;
}

/*
 * Function:        OWPParsePortRange
 *
 * Description:        
 *         Fills in the passed OWPPortRangeRec with the values from the passed
 *         in port range string. A valid port range string consists of either
 *         "0", a specific port or a range like "min-max". It returns False on
 *         failure and True on success. If failure is returned, the contents of
 *         the OWPPortRangeRec are unspecified.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
I2Boolean
OWPParsePortRange (
        char    *pspec,
        OWPPortRangeRec   *portspec
        )
{
    char    *tstr,*endptr;
    long    tint;

    if(!pspec) return False;

    tstr = pspec;
    endptr = NULL;

    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    portspec->low = (uint16_t)tint;

    while(isspace((int)*endptr)) endptr++;

    switch(*endptr){
        case '\0':
            /* only allow a single value if it is 0 */
            if(!portspec->low){
                goto failed;
            }
            portspec->high = portspec->low;
            goto done;
            break;
        case '-':
            endptr++;
            break;
        default:
            goto failed;
    }

    tstr = endptr;
    endptr = NULL;
    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    portspec->high = (uint16_t)tint;

    if(portspec->high < portspec->low){
        goto failed;
    }

done:
    /*
     * If ephemeral is specified, shortcut by not setting.
     */
    if(!portspec->high && !portspec->low)
        return True;

    return True;

failed:
    return False;
}
