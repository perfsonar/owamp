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
 **        File:        context.c
 **
 **        Author:      Jeff W. Boote
 **                     Anatoly Karp
 **
 **        Date:        Fri Apr 12 09:11:31  2002
 **
 **        Description:        
 */
#include "owampP.h"

#include <assert.h>
#include <signal.h>


/*
 * Function:        notmuch
 *
 * Description:        
 *                 "do nothing" signal handler. Put in place to ensure
 *                 SIGCHLD events are received.
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
notmuch(
        int signo
       )
{
    switch(signo){
        case SIGCHLD:
            break;
        default:
            abort();
            raise(SIGFPE);
    }
}

/*
 * Function:        OWPContextCreate
 *
 * Description:        
 *         This function is used to initialize a "context" for the owamp
 *         library. The context is used to define how error reporting
 *         and other semi-global state should be defined.
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
OWPContextCreate(
        I2ErrHandle eh
        )
{
    struct sigaction    act;
    I2LogImmediateAttr  ia;
    OWPContext          ctx = calloc(1,sizeof(OWPContextRec));

    if(!ctx){
        OWPError(eh,
                OWPErrFATAL,ENOMEM,":calloc(1,%d):%M",
                sizeof(OWPContextRec));
        return NULL;
    }

    if(!eh){
        ctx->lib_eh = True;
        ia.line_info = (I2NAME|I2MSG);
        ia.fp = stderr;
        ctx->eh = I2ErrOpen("libowamp",I2ErrLogImmediate,&ia,
                NULL,NULL);
        if(!ctx->eh){
            OWPError(NULL,OWPErrFATAL,OWPErrUNKNOWN,
                    "Cannot init error module");
            free(ctx);
            return NULL;
        }
    }
    else{
        ctx->lib_eh = False;
        ctx->eh = eh;
    }

    if(_OWPInitNTP(ctx) != 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to initialize clock interface.");
        OWPContextFree(ctx);
        return NULL;
    }

    if( !(ctx->table = I2HashInit(ctx->eh,_OWP_CONTEXT_TABLE_SIZE,
                    NULL,NULL))){
        OWPContextFree(ctx);
        return NULL;
    }

    if( !(ctx->rand_src = I2RandomSourceInit(ctx->eh,I2RAND_DEV,NULL))){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Failed to initialize randomness sources");
        OWPContextFree(ctx);
        return NULL;
    }

    if( !OWPContextConfigGetU32(ctx,OWPKeyDerivationCount,&ctx->pbkdf2_count)){
        ctx->pbkdf2_count = _OWP_DEFAULT_PBKDF2_COUNT;
    }

    /*
     * Do NOT exit on SIGPIPE. To defeat this in the least intrusive
     * way only set SIG_IGN if SIGPIPE is currently set to SIG_DFL.
     * Presumably if someone actually set a SIGPIPE handler, they
     * knew what they were doing...
     */
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    if(sigaction(SIGPIPE,NULL,&act) != 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"sigaction(): %M");
        OWPContextFree(ctx);
        return NULL;
    }
    if(act.sa_handler == SIG_DFL){
        act.sa_handler = SIG_IGN;
        if(sigaction(SIGPIPE,&act,NULL) != 0){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "sigaction(): %M");
            OWPContextFree(ctx);
            return NULL;
        }
    }

    /*
     * This library uses calls to select that are intended to
     * interrupt select in the case of SIGCHLD, so I must
     * ensure that the process is getting SIGCHLD events.
     */
    memset(&act,0,sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    /* fetch current handler */
    if(sigaction(SIGCHLD,NULL,&act) != 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"sigaction(): %M");
        OWPContextFree(ctx);
        return NULL;
    }
    /* If there is no current handler - set a "do nothing" one. */
    if(act.sa_handler == SIG_DFL){
        act.sa_handler = notmuch;
        if(sigaction(SIGCHLD,&act,NULL) != 0){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "sigaction(): %M");
            OWPContextFree(ctx);
            return NULL;
        }
    }

    return ctx;
}

/*
 * Function:        OWPContextErrHandle
 *
 * Description:        
 *         Returns the ErrHandle that was set for this context upon creation.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
extern I2ErrHandle
OWPContextErrHandle(
        OWPContext  ctx
        )
{
    return ctx->eh;
}

typedef union _OWPContextHashValue{
    void        *value;
    void        (*func)(void);
    uint32_t    u32;
} _OWPContextHashValue;

struct _OWPContextHashRecord{
    char                    key[_OWP_CONTEXT_MAX_KEYLEN+1];
    _OWPContextHashValue    val;
};

struct _OWPFreeHashRecord{
    OWPContext  ctx;
    I2Table     table;
};

static I2Boolean
free_hash_entries(
        I2Datum key,
        I2Datum value,
        void    *app_data
        )
{
    struct _OWPFreeHashRecord   *frec = (struct _OWPFreeHashRecord*)app_data;

    /*
     * Delete hash so key.dptr will not be referenced again.
     * (key.dptr is part of value.dptr alloc)
     */
    if(I2HashDelete(frec->table,key) != 0){
        OWPError(frec->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to clean out Context hash?");
        return False;
    }

    free(value.dptr);

    return True;
}


void
OWPContextFree(
        OWPContext  ctx
        )
{
    struct _OWPFreeHashRecord   frec; 

    while(ctx->cntrl_list){
        OWPControlClose(ctx->cntrl_list);
    }

    frec.ctx = ctx;
    frec.table = ctx->table;

    if(ctx->table){
        I2HashIterate(ctx->table,free_hash_entries,(void*)&frec);
        I2HashClose(ctx->table);
        ctx->table = NULL;
    }

    if(ctx->rand_src){
        I2RandomSourceClose(ctx->rand_src);
        ctx->rand_src = NULL;
    }

    if(ctx->lib_eh && ctx->eh){
        I2ErrClose(ctx->eh);
        ctx->eh = NULL;
    }

    free(ctx);

    return;
}

OWPErrSeverity
OWPControlClose(
        OWPControl  cntrl
        )
{
    OWPErrSeverity              err = OWPErrOK;
    OWPErrSeverity              lerr = OWPErrOK;
    struct _OWPFreeHashRecord   frec; 
    OWPControl                  *list = &cntrl->ctx->cntrl_list;

    /*
     * remove all test sessions
     */
    while(cntrl->tests){
        lerr = _OWPTestSessionFree(cntrl->tests,OWP_CNTRL_FAILURE);
        err = MIN(err,lerr);
    }

    frec.ctx = cntrl->ctx;
    frec.table = cntrl->table;

    if(cntrl->table){
        I2HashIterate(cntrl->table,free_hash_entries,(void*)&frec);
        I2HashClose(cntrl->table);
    }

    if(cntrl->send_hmac_ctx){
        I2HMACSha1Free(cntrl->send_hmac_ctx);
        cntrl->send_hmac_ctx = NULL;
    }
    if(cntrl->recv_hmac_ctx){
        I2HMACSha1Free(cntrl->recv_hmac_ctx);
        cntrl->recv_hmac_ctx = NULL;
    }

    /*
     * Remove cntrl from ctx list.
     */
    while(*list && (*list != cntrl))
        list = &(*list)->next;
    if(*list == cntrl)
        *list = cntrl->next;

    /*
     * these functions will close the control socket if it is open.
     */
    I2AddrFree(cntrl->remote_addr);
    I2AddrFree(cntrl->local_addr);

    free(cntrl->interface);

    free(cntrl);

    return err;
}

OWPControl
_OWPControlAlloc(
        OWPContext      ctx,
        OWPBoolean      twoway,
        OWPErrSeverity  *err_ret
        )
{
    OWPControl  cntrl;

    /*
     * Use calloc to alloc memory so it will be initialized to 0.
     */
    if( !(cntrl = calloc(1,sizeof(OWPControlRec)))){
        OWPError(ctx,OWPErrFATAL,errno,
                ":calloc(1,%d)",sizeof(OWPControlRec));
        *err_ret = OWPErrFATAL;
        return NULL;
    }

    /*
     * Init state fields
     */
    cntrl->ctx = ctx;
    cntrl->twoway = twoway;

    /*
     * Initialize control policy state hash.
     */
    if( !(cntrl->table = I2HashInit(ctx->eh,_OWP_CONTEXT_TABLE_SIZE,
                    NULL,NULL))){
        goto error;
    }

    /*
     * Init addr fields
     */
    cntrl->sockfd = -1;

    /*
     * Init I/O fields
     */
    cntrl->retn_on_intr = (int *)OWPContextConfigGetV(ctx,OWPInterruptIO);

    /*
     * Init encryption fields
     */
    memset(cntrl->userid_buffer,'\0',sizeof(cntrl->userid_buffer));

    if( !(cntrl->send_hmac_ctx = I2HMACSha1Alloc(ctx->eh))){
        goto error;
    }
    if( !(cntrl->recv_hmac_ctx = I2HMACSha1Alloc(ctx->eh))){
        goto error;
    }

    /*
     * Put this control record on the ctx list.
     */
    cntrl->next = ctx->cntrl_list;
    ctx->cntrl_list = cntrl;

    return cntrl;

error:
    *err_ret = OWPErrFATAL;
    if(cntrl){
        if(cntrl->send_hmac_ctx){
            I2HMACSha1Free(cntrl->send_hmac_ctx);
        }
        if(cntrl->recv_hmac_ctx){
            I2HMACSha1Free(cntrl->recv_hmac_ctx);
        }
        free(cntrl);
    }
    return NULL;
}

static OWPBoolean
ConfigSetU(
        I2Table                 table,
        const char              *key,
        _OWPContextHashValue    val
        )
{
    struct _OWPContextHashRecord    *rec,*trec;
    I2Datum                         k,v,t;

    assert(table);
    assert(key);

    if(!(rec = calloc(1,sizeof(struct _OWPContextHashRecord)))){
        return False;
    }
    /* ensure nul byte */
    rec->key[_OWP_CONTEXT_MAX_KEYLEN] = '\0';

    /* set key datum */
    strncpy(rec->key,key,_OWP_CONTEXT_MAX_KEYLEN);
    rec->val = val;

    k.dptr = rec->key;
    k.dsize = strlen(rec->key);

    /* set value datum */
    v.dptr = rec;
    v.dsize = sizeof(rec);

    /*
     * If there is already a key by this entry - free that record.
     */
    if(I2HashFetch(table,k,&t)){
        trec = (struct _OWPContextHashRecord*)t.dptr;
        I2HashDelete(table,k);
        free(trec);
    }

    if(I2HashStore(table,k,v) == 0){
        return True;
    }

    free(rec);
    return False;
}

static OWPBoolean
ConfigSetV(
        I2Table     table,
        const char  *key,
        void        *value
        )
{
    _OWPContextHashValue    val;

    val.value = value;
    return ConfigSetU(table,key,val);
}

static OWPBoolean
ConfigSetU32(
        I2Table     table,
        const char  *key,
        uint32_t    u32
        )
{
    _OWPContextHashValue    val;

    val.u32 = u32;
    return ConfigSetU(table,key,val);
}

static OWPBoolean
ConfigSetF(
        I2Table     table,
        const char  *key,
        void        (*func)(void)
        )
{
    _OWPContextHashValue    val;

    val.func = func;
    return ConfigSetU(table,key,val);
}

static OWPBoolean
ConfigGetU(
        I2Table                 table,
        const char              *key,
        _OWPContextHashValue    *val
        )
{
    struct _OWPContextHashRecord    *rec;
    I2Datum                         k,v;
    char                            kval[_OWP_CONTEXT_MAX_KEYLEN+1];

    assert(key);

    kval[_OWP_CONTEXT_MAX_KEYLEN] = '\0';
    strncpy(kval,key,_OWP_CONTEXT_MAX_KEYLEN);
    k.dptr = kval;
    k.dsize = strlen(kval);

    if(!I2HashFetch(table,k,&v)){
        return False;
    }

    rec = (struct _OWPContextHashRecord*)v.dptr;
    *val = rec->val;

    return True;
}

static void *
ConfigGetV(
        I2Table     table,
        const char  *key
        )
{
    _OWPContextHashValue    val;
   
    if( !ConfigGetU(table,key,&val)){
        return NULL;
    }

    return val.value;
}

static OWPBoolean
ConfigGetU32(
        I2Table     table,
        const char  *key,
        uint32_t    *u32
        )
{
    _OWPContextHashValue    val;

    if( !ConfigGetU(table,key,&val)){
        return False;
    }

    *u32 = val.u32;

    return True;
}

static OWPFunc ConfigGetF(
        I2Table     table,
        const char  *key
        )
{
    _OWPContextHashValue    val;

    if( !ConfigGetU(table,key,&val)){
        return NULL;
    }

    return val.func;
}

static OWPBoolean
ConfigDelete(
        I2Table     table,
        const char  *key
        )
{
    I2Datum k;
    char    kval[_OWP_CONTEXT_MAX_KEYLEN+1];

    assert(key);

    kval[_OWP_CONTEXT_MAX_KEYLEN] = '\0';
    strncpy(kval,key,_OWP_CONTEXT_MAX_KEYLEN);
    k.dptr = kval;
    k.dsize = strlen(kval);

    if(I2HashDelete(table,k) == 0){
        return True;
    }

    return False;
}

/*
 * Function:        OWPContextSet
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
OWPBoolean
OWPContextConfigSetV(
        OWPContext  ctx,
        const char  *key,
        void        *value
        )
{
    assert(ctx);

    return ConfigSetV(ctx->table,key,value);
}

OWPBoolean
OWPContextConfigSetF(
        OWPContext  ctx,
        const char  *key,
        OWPFunc     func
        )
{
    assert(ctx);

    return ConfigSetF(ctx->table,key,func);
}

OWPBoolean
OWPContextConfigSetU32(
        OWPContext  ctx,
        const char  *key,
        uint32_t    u32
        )
{
    assert(ctx);

    return ConfigSetU32(ctx->table,key,u32);
}

void *
OWPContextConfigGetV(
        OWPContext  ctx,
        const char  *key
        )
{
    assert(ctx);

    return ConfigGetV(ctx->table,key);
}

OWPBoolean
OWPContextConfigGetU32(
        OWPContext  ctx,
        const char  *key,
        uint32_t    *u32
        )
{
    assert(ctx);

    return ConfigGetU32(ctx->table,key,u32);
}

OWPFunc
OWPContextConfigGetF(
        OWPContext  ctx,
        const char  *key
        )
{
    assert(ctx);

    return ConfigGetF(ctx->table,key);
}

OWPBoolean
OWPContextConfigDelete(
        OWPContext  ctx,
        const char  *key
        )
{
    assert(ctx);

    return ConfigDelete(ctx->table,key);
}

/*
 * Function:        OWPControlSet
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
OWPBoolean
OWPControlConfigSetV(
        OWPControl  cntrl,
        const char  *key,
        void        *value
        )
{
    assert(cntrl);

    return ConfigSetV(cntrl->table,key,value);
}

OWPBoolean
OWPControlConfigSetU32(
        OWPControl  cntrl,
        const char  *key,
        uint32_t    u32
        )
{
    assert(cntrl);

    return ConfigSetU32(cntrl->table,key,u32);
}

OWPBoolean
OWPControlConfigSetF(
        OWPControl  cntrl,
        const char  *key,
        OWPFunc     func
        )
{
    assert(cntrl);

    return ConfigSetF(cntrl->table,key,func);
}

void *
OWPControlConfigGetV(
        OWPControl  cntrl,
        const char  *key
        )
{
    assert(cntrl);

    return ConfigGetV(cntrl->table,key);
}

OWPBoolean
OWPControlConfigGetU32(
        OWPControl  cntrl,
        const char  *key,
        uint32_t    *u32
        )
{
    assert(cntrl);

    return ConfigGetU32(cntrl->table,key,u32);
}

OWPFunc
OWPControlConfigGetF(
        OWPControl  cntrl,
        const char  *key
        )
{
    assert(cntrl);

    return ConfigGetF(cntrl->table,key);
}

OWPBoolean
OWPControlConfigDelete(
        OWPControl  cntrl,
        const char  *key
        )
{
    assert(cntrl);

    return ConfigDelete(cntrl->table,key);
}

/*
 * Function:        _OWPCallGetPF
 *
 * Description:
 *         Calls the get_pf function that is defined by the application.
 *         If the application didn't define the get_pf function, then provide
 *         the default response of False.
 */
OWPBoolean
_OWPCallGetPF(
        OWPContext      ctx,        /* library context  */
        const OWPUserID userid,     /* identifies user  */
        uint8_t         **pf_ret,   /* pf - return      */
        size_t          *pf_len,    /* pf_len - return  */
        void            **pf_free,  /* pf_free - return */
        OWPErrSeverity  *err_ret    /* error - return   */
        )
{
    OWPGetPFFunc    func;

    *err_ret = OWPErrOK;

    func = (OWPGetPFFunc)OWPContextConfigGetF(ctx,OWPGetPF);

    /*
     * Default action is no encryption support.
     */
    if(!func){
        return False;
    }

    return func(ctx,userid,pf_ret,pf_len,pf_free,err_ret);
}

/*
 * Function:        _OWPCallCheckControlPolicy
 *
 * Description:
 *         Calls the check_control_func that is defined by the application.
 *         If the application didn't define the check_control_func, then provide
 *         the default response of True(allowed).
 */
OWPBoolean
_OWPCallCheckControlPolicy(
        OWPControl      cntrl,              /* control record       */
        OWPSessionMode  mode,               /* requested mode       */
        const OWPUserID userid,             /* key identity         */
        struct sockaddr *local_sa_addr,     /* local addr or NULL   */
        struct sockaddr *remote_sa_addr,    /* remote addr          */
        OWPErrSeverity  *err_ret            /* error - return       */
        )
{
    OWPCheckControlPolicyFunc   func;

    *err_ret = OWPErrOK;

    func = (OWPCheckControlPolicyFunc)OWPContextConfigGetF(cntrl->ctx,
            OWPCheckControlPolicy);

    /*
     * Default action is to allow anything.
     */
    if(!func){
        return True;
    }

    return func(cntrl,mode,userid,local_sa_addr,remote_sa_addr,err_ret);
}

/*
 * Function:        _OWPCallCheckTestPolicy
 *
 * Description:
 *         Calls the check_test_func that is defined by the application.
 *         If the application didn't define the check_test_func, then provide
 *         the default response of True(allowed).
 */
OWPBoolean
_OWPCallCheckTestPolicy(
        OWPControl      cntrl,          /* control handle           */
        OWPBoolean      local_sender,   /* Is local send or recv    */
        struct sockaddr *local,         /* local endpoint           */
        struct sockaddr *remote,        /* remote endpoint          */
        socklen_t       sa_len,         /* saddr lens               */
        OWPTestSpec     *test_spec,     /* test requested           */
        void            **closure,
        OWPErrSeverity  *err_ret        /* error - return           */
        )
{
    OWPCheckTestPolicyFunc  func;

    *err_ret = OWPErrOK;

    func = (OWPCheckTestPolicyFunc)OWPContextConfigGetF(cntrl->ctx,
            OWPCheckTestPolicy);
    /*
     * Default action is to allow anything.
     */
    if(!func){
        return True;
    }

    return func(cntrl,local_sender,local,remote,sa_len,test_spec,closure,
            err_ret);
}

/*
 * Function:        _OWPCallCheckFetchPolicy
 *
 * Description:
 *         Calls the check_test_func that is defined by the application.
 *         If the application didn't define the check_test_func, then provide
 *         the default response of True(allowed).
 */
OWPBoolean
_OWPCallCheckFetchPolicy(
        OWPControl      cntrl,          /* control handle           */
        struct sockaddr *local,         /* local endpoint           */
        struct sockaddr *remote,        /* remote endpoint          */
        socklen_t       sa_len,         /* saddr lens               */
        uint32_t        begin,
        uint32_t        end,
        OWPSID          sid,
        void            **closure,
        OWPErrSeverity  *err_ret        /* error - return           */
        )
{
    OWPCheckFetchPolicyFunc  func;

    *err_ret = OWPErrOK;

    func = (OWPCheckFetchPolicyFunc)OWPContextConfigGetF(cntrl->ctx,
            OWPCheckFetchPolicy);
    /*
     * Default action is to allow anything.
     */
    if(!func){
        return True;
    }

    return func(cntrl,local,remote,sa_len,begin,end,sid,closure,err_ret);
}

/*
 * Function:        _OWPCallTestComplete
 *
 * Description:
 *         Calls the "OWPTestComplete" that is defined by the application.
 *         If the application didn't define the "OWPTestComplete" function, then
 *         this is a no-op.
 *
 *         The primary use for this hook is to free memory and other resources
 *         (bandwidth etc...) allocated on behalf of this test.
 */
void
_OWPCallTestComplete(
        OWPTestSession  tsession,
        OWPAcceptType   aval
        )
{
    OWPTestCompleteFunc func;

    func = (OWPTestCompleteFunc)OWPContextConfigGetF(tsession->cntrl->ctx,
            OWPTestComplete);
    /*
     * Default action is nothing...
     */
    if(!func){
        return;
    }

    func(tsession->cntrl,tsession->closure,aval);

    return;
}

/*
 * Function:        _OWPCallOpenFile
 *
 * Description:
 *         Calls the "OWPOpenFile" that is defined by the application.
 *         If the application didn't define the "OWPOpenFile" function, then
 *         it won't be able to implement the "FetchSession" functionality or
 *         run a "receive" endpoint from a "server" point-of-view.
 *
 *         (This is not needed from the client point-of-view since it passes
 *         a FILE* into the retrieve/receiver functions directly.)
 *
 *         (basically - this is a hook to allow relatively simple changes
 *         to the way owampd saves/fetches session data.)
 *
 *         The "closure" pointer is a pointer to the value that is returned
 *         from the CheckTestPolicy or CheckFetchPolicy function. This is
 *         the way resource requests/releases can be adjusted based upon
 *         actual use.
 *
 *         (keeping policy separate from function is challenging... I hope
 *         it is worth it...)
 *
 */
FILE *
_OWPCallOpenFile(
        OWPControl  cntrl,              /* control handle   */
        void        *closure,           /* null if r/o      */
        OWPSID      sid,                /* sid              */
        char        fname_ret[PATH_MAX] /* return name      */
        )
{
    OWPOpenFileFunc func;

    func = (OWPOpenFileFunc)OWPContextConfigGetF(cntrl->ctx,
            OWPOpenFile);
    /*
     * Default action is nothing...
     */
    if(!func){
        return NULL;
    }

    return func(cntrl,closure,sid,fname_ret);
}

/*
 * Function:        _OWPCallCloseFile
 *
 * Description:
 *         Calls the "OWPCloseFile" that is defined by the application.
 *         If the application didn't define the "OWPCloseFile" function, then
 *         fclose will be called on the fp.
 *
 *         (The primary use for this hook is to implement the delete-on-fetch
 *         functionality. i.e. once this is called on a file with that policy
 *         setting, unlink can be called on the file.)
 */
void
_OWPCallCloseFile(
        OWPControl      cntrl,      /* control handle   */
        void            *closure,
        FILE            *fp,
        OWPAcceptType   aval
        )
{
    OWPCloseFileFunc    func;

    func = (OWPCloseFileFunc)OWPContextConfigGetF(cntrl->ctx,
            OWPCloseFile);
    /*
     * Default action is nothing...
     */
    if(!func){
        int rc;

        while(((rc = fclose(fp)) != 0) && (errno == EINTR));
        if(rc != 0){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"fclose(): %M");
        }
        return;
    }

    func(cntrl,closure,fp,aval);

    return;
}
