/*
 *      $Id$
 */
/************************************************************************
*                                                                        *
*                             Copyright (C)  2002                        *
*                                Internet2                                *
*                             All Rights Reserved                        *
*                                                                        *
************************************************************************/
/*
 *        File:                powstream.c
 *
 *        Authors:        Jeff Boote
 *                      Anatoly Karp
 *                        Internet2
 *
 *        Date:                Tue Sep  3 15:47:26 MDT 2002
 *
 *        Description:        
 *
 *        Initial implementation of powstream commandline application. This
 *        application will measure active one-way udp latencies. And it will
 *        set up perpetual tests and keep them going until this application
 *        is killed.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <assert.h>
#include <syslog.h>
#include <math.h>

#include <owamp/owamp.h>


#if defined HAVE_DECL_OPTRESET && !HAVE_DECL_OPTRESET
int optreset;
#endif

#include "./powstreamP.h"

/*
 * This just ensures the padding requested fits in the "type" used to
 * make the request from the command-line options. (If the padding requested
 * is larger than is possible due to IP/UDP/OWAMP headers - then the
 * TestRequest will be denied, but this isn't easily checked during
 * initial command-line option parsing because of the dependancies involved.)
 */
#define        MAX_PADDING_SIZE        0xFFFF


/*
 * The powstream context
 */
static powapp_trec      appctx;
static I2ErrHandle      eh;
static pow_cntrl_rec    pcntrl[2];
static OWPTestSpec      tspec;
static OWPSlot          slot;
static u_int32_t        sessionTime;
static double           inf_delay;
static u_int8_t         aesbuff[16];

/*
 * signal catching vars
 */
static int              pow_reset = 0;
static int              pow_exit = 0;
static int              pow_intr = 0;
static int              pow_error = SIGCONT;

/*
 * pathname variables used throughout:
 *
 * /dirpath/STIME_ETIME.ext
 * ^        ^    ^     ^
 * |        |    |     |__ ext_offset
 * |        |    |
 * |        |    |__ tstamp_offset
 * |        |
 * |        |__ file_offset
 * |
 * |__ dirpath
 */
static char             dirpath[PATH_MAX];
static u_int32_t        file_offset,tstamp_offset,ext_offset;

static void
print_conn_args(){
        fprintf(stderr,"              [Connection Args]\n\n"
"   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen\n"
"   -k keyfile     AES keyfile to use with Authenticated/Encrypted modes\n"
"   -u username    username to use with Authenticated/Encrypted modes\n"
"   -S srcaddr     use this as a local address for control connection and tests\n"
        );
}

static void
print_test_args(){
        fprintf(stderr,
"              [Test Args]\n\n"
"   -c count       number of test packets (per file)\n"
"   -i wait        mean average time between packets (seconds)\n"
"   -L timeout     maximum time to wait for a packet (seconds)\n"
"   -s padding     size of the padding added to each packet (bytes)\n");
}

static void
print_output_args()
{
    fprintf(stderr,
"              [Output Args]\n\n"
"   -d dir         directory to save session file in\n"
"   -N count       number of test packets (per summary)\n"
"   -p             print filenames to stdout, and summarize sessions\n"
"   -b bucketWidth create summary files with buckets(seconds)\n"
"   -h             print this message and exit\n"
"   -e             syslog facility to log to\n"
"   -r             syslog facility to STDERR\n"
           );
}

static void
usage(
        const char *progname,
        const char *msg)
{
    if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
    fprintf(stderr,"usage: %s %s\n",progname,
            "[arguments] testaddr [servaddr]");
    fprintf(stderr, "\n");
    print_conn_args();

    fprintf(stderr, "\n");
    print_test_args();

    fprintf(stderr, "\n");
    print_output_args();

    fprintf(stderr, "Distribution: %s\n", PACKAGE_STRING);

    return;
}

static OWPBoolean
getclientkey(
        OWPContext      ctx __attribute__((unused)),
        const OWPUserID userid __attribute__((unused)),
        OWPKey          key_ret,
        OWPErrSeverity  *err_ret __attribute__((unused))
        )
{
    memcpy(key_ret,aesbuff,sizeof(aesbuff));

    return True;
}

/*
 ** Initialize authentication and policy data (used by owping and owfetch)
 */
void
owp_set_auth(
        OWPContext  ctx,
        char        *progname,
        powapp_trec *pctx
        )
{
    if(pctx->opt.identity){
        u_int8_t        *aes = NULL;

        /*
         * If keyfile specified, attempt to get key from there.
         */
        if(pctx->opt.keyfile){
            /* keyfile */
            FILE        *fp;
            int        rc = 0;
            char        *lbuf=NULL;
            size_t        lbuf_max=0;

            if(!(fp = fopen(pctx->opt.keyfile,"r"))){
                I2ErrLog(eh,"Unable to open %s: %M",pctx->opt.keyfile);
                goto DONE;
            }

            rc = I2ParseKeyFile(eh,fp,0,&lbuf,&lbuf_max,NULL,
                    pctx->opt.identity,NULL,aesbuff);
            if(lbuf){
                free(lbuf);
            }
            lbuf = NULL;
            lbuf_max = 0;
            fclose(fp);

            if(rc > 0){
                aes = aesbuff;
            }
            else{
                I2ErrLog(eh,
                        "Unable to find key for id=\"%s\" from keyfile=\"%s\"",
                        pctx->opt.identity,pctx->opt.keyfile);
            }
        }else{
            /*
             * Do passphrase:
             *         open tty and get passphrase.
             *        (md5 the passphrase to create an aes key.)
             */
            char                *passphrase;
            char                ppbuf[MAX_PASSPHRASE];
            char                prompt[MAX_PASSPROMPT];
            I2MD5_CTX        mdc;
            size_t                pplen;

            if(snprintf(prompt,MAX_PASSPROMPT,
                        "Enter passphrase for identity '%s': ",
                        pctx->opt.identity) >= MAX_PASSPROMPT){
                I2ErrLog(eh,"ip_set_auth: Invalid identity");
                goto DONE;
            }

            if(!(passphrase = I2ReadPassPhrase(prompt,ppbuf,
                            sizeof(ppbuf),I2RPP_ECHO_OFF))){
                I2ErrLog(eh,"I2ReadPassPhrase(): %M");
                goto DONE;
            }
            pplen = strlen(passphrase);

            I2MD5Init(&mdc);
            I2MD5Update(&mdc,(unsigned char *)passphrase,pplen);
            I2MD5Final(aesbuff,&mdc);
            aes = aesbuff;
        }
DONE:
        if(aes){
            /*
             * install getaeskey func (key is in aesbuff)
             */
            OWPGetAESKeyFunc        getaeskey = getclientkey;

            if(!OWPContextConfigSetF(ctx,OWPGetAESKey,
                        (OWPFunc)getaeskey)){
                I2ErrLog(eh,"Unable to set AESKey for context: %M");
                aes = NULL;
                goto DONE;
            }
        }
        else{
            free(pctx->opt.identity);
            pctx->opt.identity = NULL;
        }
    }

    /*
     * Verify/decode auth options.
     */
    if(pctx->opt.authmode){
        char        *s = appctx.opt.authmode;
        pctx->auth_mode = 0;
        while(*s != '\0'){
            switch (toupper(*s)){
                case 'O':
                    pctx->auth_mode |= OWP_MODE_OPEN;
                    break;
                case 'A':
                    pctx->auth_mode |= OWP_MODE_AUTHENTICATED;
                    break;
                case 'E':
                    pctx->auth_mode |= OWP_MODE_ENCRYPTED;
                    break;
                default:
                    I2ErrLogP(eh,EINVAL,"Invalid -authmode %c",*s);
                    usage(progname, NULL);
                    exit(1);
            }
            s++;
        }
    }else{
        /*
         * Default to all modes.
         * If identity not set - library will ignore A/E.
         */
        pctx->auth_mode = OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|
            OWP_MODE_ENCRYPTED;
    }
}

static int
mmap_copy_file(
        int tofd,
        int fromfd
        )
{
    struct stat sbuf;
    int         rc;
    void        *fptr,*tptr;

    if((rc = fstat(fromfd,&sbuf)) != 0){
        I2ErrLog(eh,"fstat: %M, copying session file");
        return rc;
    }

    if((rc = ftruncate(tofd,sbuf.st_size)) != 0){
        I2ErrLog(eh,"ftruncate(%llu): %M, creating session file",sbuf.st_size);
        return rc;
    }

    if(!(fptr = mmap(NULL,sbuf.st_size,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,fromfd,0))){
        I2ErrLog(eh,"mmap(FROM session file): %M");
        return -1;
    }
    if(!(tptr = mmap(NULL,sbuf.st_size,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,tofd,0))){
        I2ErrLog(eh,"mmap(TO session file): %M");
        return -1;
    }

    memcpy(tptr,fptr,sbuf.st_size);

    if((rc = munmap(fptr,sbuf.st_size)) != 0){
        I2ErrLog(eh,"munmap(FROM session file): %M");
        return -1;
    }
    if((rc = munmap(tptr,sbuf.st_size)) != 0){
        I2ErrLog(eh,"munmap(TO session file): %M");
        return -1;
    }

    return 0;
}

typedef struct pow_maxsend_rec{
    OWPSessionHeader    hdr;
    u_int32_t           index;
    OWPNum64            sendtime;
    OWPSkip             skips;
} pow_maxsend_rec;

static int
GetMaxSend(
        OWPDataRec  *rec,
        void        *data
        )
{
    pow_maxsend_rec     *sndrec = (pow_maxsend_rec *)data;
    u_int32_t           iskip =0;

    if(sndrec->skips){
        /*
         * Look for first skip range with "end" greater than seq_no
         */
        while((iskip < sndrec->hdr->num_skiprecs) &&
                (rec->seq_no > sndrec->skips[iskip].end)){
            iskip++;
        }
        /*
         * If seq_no is within this range, it is not available
         * as a max end time.
         */
        if((iskip < sndrec->hdr->num_skiprecs) &&
                (rec->seq_no > sndrec->skips[iskip].begin)){
            return 0;
        }
    }

    if(rec->seq_no > sndrec->index){
        sndrec->index = rec->seq_no;
        sndrec->sendtime = rec->send.owptime;
    }

    return 0;
}

/*
 * Function:    write_session
 *
 * Description:    
 *              Takes a completed session and copies it from the
 *              unlinked file - possibly computing a new endtime
 *              based on the last "valid" record in the file.
 *              (Technically, it should probably be based on the
 *              scheduled sendtime
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
write_session(
        pow_cntrl   p,
        OWPBoolean  newend
        )
{
    OWPNum64        endnum;
    char            tfname[PATH_MAX];
    char            fname[PATH_MAX];
    char            startname[PATH_MAX];
    char            endname[PATH_MAX];
    int             tofd;

    /*
     * If this session does not have a started session, there is no
     * reason to continue.
     */
    if(!p->fp || !p->session_started)
        return;

    if(newend){
        OWPSessionHeaderRec hdr;
        struct flock        flk;
        pow_maxsend_rec     sndrec;
        u_int32_t           i;

        /*
         * This section reads the packet records
         * in the time period of this sum-session.
         */
        (void)OWPReadDataHeader(p->ctx,p->fp,&hdr);
        if( !hdr.header){
            I2ErrLog(eh,"OWPReadDataHeader(session data [%llu,%llu])",
                    p->currentSessionStartNum,p->currentSessionEndNum);
            return;
        }

        /*
         * Determine offset to last datarec
         */
        if(hdr.finished != OWP_SESSION_FINISHED_NORMAL){
            /*
             * Don't worry about unlocking, closing the file
             * after the copy during session reset will do that
             * automatically.
             */
            memset(&flk,0,sizeof(flk));
            flk.l_start = 0;
            flk.l_len = 0;
            flk.l_whence = SEEK_SET;
            flk.l_type = F_RDLCK;

            if( fcntl(fileno(p->fp), F_SETLK, &flk) < 0){
                I2ErrLog(eh,"Lock failure: fcntl(session data): %M");
                return;
            }

            /*
             * Re-read after lock.
             */
            (void)OWPReadDataHeader(p->ctx,p->fp,&hdr);
            if( !hdr.header){
                I2ErrLog(eh,"OWPReadDataHeader(session data [%llu,%llu])",
                        p->currentSessionStartNum,p->currentSessionEndNum);
                return;
            }

            /*
             * If the session did not complete, then num_datarecs
             * can be determined from the filesize.
             */
            if(!hdr.num_datarecs){
                hdr.num_datarecs = (hdr.sbuf.st_size - hdr.oset_datarecs) /
                    hdr.rec_size;
            }
        }

        if(!hdr.num_datarecs){
            if(appctx.opt.verbose > 1){
                I2ErrLog(eh,"No data - skip writing session (%llu,%llu)",
                        p->currentSessionStartNum,p->currentSessionEndNum);
            }
            return;
        }

        /*
         * Read all records and find the "last" one in the file.
         */
        if(fseeko(p->fp,hdr.oset_datarecs,SEEK_SET) != 0){
            I2ErrLog(eh,"fseeko(): %M");
            return;
        }

        /*
         * Find the last index in the file so it can be used to compute
         * the assumed "send" time for the "end" time of the session.
         */
        memset(&sndrec,0,sizeof(sndrec));
        sndrec.hdr = &hdr;
        if(hdr.num_skiprecs){
            if( !(sndrec.skips = calloc(hdr.num_skiprecs,sizeof(OWPSkipRec)))){
                I2ErrLog(eh,"calloc: %M");
                return;
            }
            if( !OWPReadDataSkips(p->ctx,p->fp,hdr.num_skiprecs,
                        sndrec.skips)){
                I2ErrLog(eh,"OWPReadDataSkips: %M");
                free(sndrec.skips);
                return;
            }
        }

        if(OWPParseRecords(p->ctx,p->fp,hdr.num_datarecs,hdr.version,GetMaxSend,
                    (void*)&sndrec) != OWPErrOK){
            if(sndrec.skips) free(sndrec.skips);
            I2ErrLog(eh,"GetMaxIndex: %M");
            return;
        }
        if(sndrec.skips) free(sndrec.skips);

        /*
         * Compute endnum based on the send schedule and the index of the
         * last valid packet in the file.
         */
        (void)OWPScheduleContextReset(p->sctx,NULL,NULL);
        endnum = p->currentSessionStartNum;
        for(i=0;i<sndrec.index+1;i++){
            endnum = OWPNum64Add(endnum,
                    OWPScheduleContextGenerateNextDelta(p->sctx));
        }
    }
    else{
        endnum = p->currentSessionEndNum;
    }

    /*
     * Make a temporary session filename to hold data.
     */
    strcpy(tfname,dirpath);
    sprintf(startname,OWP_TSTAMPFMT,p->currentSessionStartNum);
    sprintf(endname,OWP_TSTAMPFMT,endnum);
    sprintf(&tfname[file_offset],"%s%s%s%s%s",
            startname,OWP_NAME_SEP,endname,
            OWP_FILE_EXT,POW_INC_EXT);

    while(((tofd = open(tfname,O_RDWR|O_CREAT|O_EXCL,
                        S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) && errno==EINTR);
    if(tofd < 0){

        I2ErrLog(eh,"open(%s): %M",tfname);

        /*
         * Can't open the file.
         */
        switch(errno){
            /*
             * reasons to go to the next
             * session
             * (Temporary resource problems.)
             */
            case EMFILE:
            case ENFILE:
            case ENOSPC:
            case EDQUOT:
                break;
                /*
                 * Everything else is a reason to exit
                 * (Probably permissions.)
                 */
            default:
                exit(1);
                break;
        }

        /*
         * Skip to next session.
         */
        return;
    }

    /*
     * stat the "from" file, ftruncate the to file,
     * mmap both of them, then do a memcpy between them.
     */
    if(mmap_copy_file(tofd,fileno(p->fp)) == 0){
        /*
         * Relink the incomplete file as a complete one.
         */
        strcpy(fname,tfname);
        sprintf(&fname[ext_offset],"%s",OWP_FILE_EXT);
        if(link(tfname,fname) != 0){
            /* note, but ignore the error */
            I2ErrLog(eh,"link(%s,%s): %M",tfname,fname);
        } else if(appctx.opt.printfiles){
            /* Now print the filename to stdout */
            fprintf(stdout,"%s\n",fname);
            fflush(stdout);
        }
    }
    if(unlink(tfname) != 0){
        /* note, but ignore the error */
        I2ErrLog(eh,"unlink(%s): %M",tfname);
    }

    return;
}

static void
ResetSession(
        pow_cntrl        p,        /* connection we are configuring        */
        pow_cntrl        q        /* other connection                        */
        )
{
    OWPAcceptType   aval = OWP_CNTRL_ACCEPT;
    int             intr=1;

    if(p->numPackets && p->call_stop && p->cntrl &&
            (OWPStopSessions(p->cntrl,&intr,&aval)<OWPErrWARNING)){
        OWPControlClose(p->cntrl);
        p->cntrl = NULL;
    }

    /*
     * Output "early-terminated" owp file
     */
    write_session(p,True);

    if(p->fp){
        fclose(p->fp);
        p->fp = NULL;
    }
    if(p->testfp){
        fclose(p->testfp);
        p->testfp = NULL;
    }
    p->numPackets = 0;
    p->call_stop = False;
    p->session_started = False;
    p->nextSessionStart = NULL;
    q->nextSessionStart = NULL;

    return;
}

static void
CloseSessions()
{
    ResetSession(&pcntrl[0],&pcntrl[1]);
    ResetSession(&pcntrl[1],&pcntrl[0]);
    if(pcntrl[0].cntrl)
        OWPControlClose(pcntrl[0].cntrl);
    if(pcntrl[1].cntrl)
        OWPControlClose(pcntrl[1].cntrl);
    pcntrl[0].cntrl = NULL;
    pcntrl[1].cntrl = NULL;

    return;
}

static void
sig_catch(
        int signo
        )
{
    switch(signo){
        case SIGINT:
        case SIGTERM:
            pow_exit++;
            pow_intr++;
            break;
        case SIGHUP:
            pow_reset++;
            pow_intr++;
            break;
        default:
            pow_error = signo;
            break;
    }

    return;
}

static int
sig_check()
{
    if(pow_error != SIGCONT){
        I2ErrLog(eh,"sig_check(%d):UNEXPECTED SIGNAL NUMBER",pow_error);
        exit(1);
    }

    if(pow_exit || pow_reset){
        CloseSessions();
    }
    if(pow_exit){
        I2ErrLog(eh,"SIGTERM/SIGINT: Exiting.");
        exit(0);
    }
    if(pow_reset){
        pow_reset = 0;
        pow_intr = 0;
        I2ErrLog(eh,"SIGHUP: Re-opening connections.");
        return 1;
    }

    return 0;
}

static int
SetupSession(
        OWPContext  ctx,
        pow_cntrl   p,      /* connection we are configuring    */
        pow_cntrl   q,      /* other connection                 */
        OWPNum64    *stop   /* return by this time              */
        )
{
    OWPErrSeverity  err;
    OWPTimeStamp    currtime;
    unsigned int    stime;
    int             fd;
    u_int64_t       i;
    char            fname[PATH_MAX];

    if(p->numPackets)
        return 0;

    /*
     * First open a connection if we don't have one.
     */
    while(!p->cntrl){

        if(stop){
            if(!OWPGetTimeOfDay(ctx,&currtime)){
                I2ErrLog(eh,"OWPGetTimeOfDay:%M");
                exit(1);
            }

            if(OWPNum64Cmp(currtime.owptime,*stop) > 0){
                if(p->nextSessionStart){
                    q->nextSessionStart = &q->nextSessionStartNum;
                    *q->nextSessionStart = *p->nextSessionStart;
                }else
                    q->nextSessionStart = NULL;
                return 0;
            }
        }

        if(!p->sctx){
            if(!(p->sctx = OWPScheduleContextCreate(ctx,p->sid,&tspec))){
                I2ErrLog(eh,"OWPScheduleContextCreate: %M");
                while((stime = sleep(stime))){
                    if(sig_check())
                        return 1;
                }
                continue;
            }
        }


        if(!(p->cntrl = OWPControlOpen(ctx,
                        OWPAddrByNode(ctx, appctx.opt.srcaddr),
                        OWPAddrByNode(ctx, appctx.remote_serv),
                        appctx.auth_mode,appctx.opt.identity,
                        NULL,&err))){
            if(sig_check()) return 1;
            stime = MIN(sessionTime,SETUP_ESTIMATE);
            I2ErrLog(eh,"OWPControlOpen():%M:Retry in-%d seconds",
                    stime);
            while((stime = sleep(stime))){
                if(sig_check()) return 1;
            }
            if(sig_check()) return 1;
        }
    }
    if(sig_check())
        return 1;

    if(!OWPGetTimeOfDay(ctx,&currtime)){
        I2ErrLogP(eh,errno,"OWPGetTimeOfDay:%M");
        exit(1);
    }
    currtime.owptime = OWPNum64Add(currtime.owptime,
            OWPULongToNum64(SETUP_ESTIMATE));

    if(p->nextSessionStart){
        if(OWPNum64Cmp(currtime.owptime,*p->nextSessionStart) > 0){
            p->nextSessionStart = NULL;
        }
    }

    if(!p->nextSessionStart){
        p->nextSessionStartNum = currtime.owptime;
        p->nextSessionStart = &p->nextSessionStartNum;
    }

    /*
     * Create a tmpfile to hold session data - this file will be
     * in an unlinked state to make "cleanup" easier.
     */
    strcpy(fname,dirpath);
    strcpy(&fname[file_offset],POWTMPFILEFMT);

    /*
     * use mkstemp to avoid race condition (downside, fd - not fp)
     */
    if((fd = mkstemp(fname)) < 0){
        I2ErrLog(eh,"mkstemp(%s):%M",fname);
        return 0;
    }

    /*
     * Wrap the fd in a file pointer.
     */
    if(!(p->fp = fdopen(fd,"wb+"))){
        I2ErrLog(eh,"fdopen(%s:(%d)):%M",fname,fd);
        while((close(fd) != 0) && errno==EINTR);
        return 0;
    }

    /*
     * Create a second fp for the actual test endpoint to use.
     * This creates a completely different fd under the fp so
     * updates of the "fp" do not disturb the ongoing test.
     */
    if(!(p->testfp = fopen(fname,"wb+"))){
        I2ErrLog(eh,"fopen(%s): %M",fname);
        while((fclose(p->fp) != 0) && errno==EINTR);
        p->fp = NULL;
        return 0;
    }

    /*
     * Unlinke the filename so interrupt resets don't have
     * as much work to do. (This does mean the data needs
     * to be copied into a new file upon completion of the
     * test.)
     */
    if(unlink(fname) != 0){
        I2ErrLog(eh,"unlink():%M");
        goto file_clean;
    }

    if(sig_check())
        return 1;
    /*
     * Make the actual request for the test specifying the testfp
     * to hold the results.
     */
    tspec.start_time = *p->nextSessionStart;
    if(!OWPSessionRequest(p->cntrl,OWPAddrByNode(ctx,appctx.remote_test),
                True, NULL, False,(OWPTestSpec*)&tspec,p->testfp,p->sid,&err)){
        I2ErrLog(eh,"OWPSessionRequest: Failed");
        if(err == OWPErrFATAL){
            OWPControlClose(p->cntrl);
            p->cntrl = NULL;
        }
        goto file_clean;
    }
    if(sig_check())
        return 1;

    /*
     * Start the session
     */
    if(OWPStartSessions(p->cntrl) < OWPErrINFO){
        I2ErrLog(eh,"OWPStartSessions: Failed");
        goto cntrl_clean;
    }
    if(sig_check())
        return 1;
    /*
     * session_started will be set to true when the loop that parses this
     * session data begins.
     */
    p->call_stop = True;
    p->session_started = False;

    /*
     * Assign new sid to schedule context for computing new schedule.
     */
    if(OWPScheduleContextReset(p->sctx,p->sid,&tspec) != OWPErrOK){
        I2ErrLog(eh,"Schedule Initialization Failed");
        goto cntrl_clean;
    }

    p->numPackets = tspec.npackets;

    /*
     * Compute end of session
     */
    p->nextSessionEndNum = p->nextSessionStartNum;
    for(i=0;i<p->numPackets;i++){
        p->nextSessionEndNum = OWPNum64Add(p->nextSessionEndNum,
                OWPScheduleContextGenerateNextDelta(p->sctx));
    }

    /*
     * Reset the schedule index's. (shouldn't be possible to fail that
     * part...)
     */
    (void)OWPScheduleContextReset(p->sctx,NULL,NULL);

    /*
     * Set q->nextSessionStartNum to end of p's session.
     * (Used when this function is called for the "other" connection.)
     */
    q->nextSessionStartNum = p->nextSessionEndNum;
    q->nextSessionStart = &q->nextSessionStartNum;

    return 0;

cntrl_clean:
    OWPControlClose(p->cntrl);
    p->cntrl = NULL;

file_clean:
    while((fclose(p->fp) != 0) && errno==EINTR);
    p->fp = NULL;
    while((fclose(p->testfp) != 0) && errno==EINTR);
    p->testfp = NULL;
    return 0;
}

static int
IterateSumSession(
        OWPDataRec  *rec,
        void        *data
        )
{
    struct pow_parse_rec    *parse = (struct pow_parse_rec*)data;

    /*
     * Mark the first offset that has a record greater than this
     * sum-session so the next sum-session can start searching here.
     */
    if(!parse->next && (rec->seq_no > parse->last))
        parse->next = parse->begin + parse->i * parse->hdr->rec_size;

    /* increase file index */
    parse->i++;

    /* return if this record is not part of this sum-session */
    if((rec->seq_no < parse->first) || (rec->seq_no > parse->last) ||
            OWPIsLostRecord(rec)){
        return 0;
    }

    /*
     * Record is a good one, notice and count it.
     */
    rec->seq_no -= parse->first;
    parse->seen[rec->seq_no].seen++;

    /*
     * If doing summary, and this is not a duplicate packet, bucket
     * this delay.
     */
    if(parse->buckets && (parse->seen[rec->seq_no].seen == 1)){
        I2Datum key,val;
        double  d;
        int     b;

        /*
         * If either side is unsynchronized, record that.
         */
        if(!rec->send.sync || !rec->recv.sync){
            parse->sync = 0;
        }
        /*
         * Comute error from send/recv.
         */
        d = OWPGetTimeStampError(&rec->send) + OWPGetTimeStampError(&rec->recv);
        parse->maxerr = MAX(parse->maxerr,d);

        d = OWPDelay(&rec->send,&rec->recv);

        /*
         * Save max/min delays
         */
        parse->max_delay = MAX(parse->max_delay,d);
        parse->min_delay = MIN(parse->min_delay,d);

        /*
         * Compute bucket index value.
         */
        d /= appctx.opt.bucketWidth;
        b = (d<0)?floor(d):ceil(d);

        key.dsize = b;
        key.dptr = &key.dsize;
        if(I2HashFetch(parse->buckets,key,&val)){
            (*(u_int32_t*)val.dptr)++;
        }
        else{
            val.dsize = sizeof(u_int32_t);
            val.dptr = &parse->bucketvals[parse->nbuckets];
            parse->bucketvals[parse->nbuckets++] = 1;

            if(I2HashStore(parse->buckets,key,val) != 0){
                I2ErrLog(eh,"I2HashStore(): Unable to store bucket!");
                return -1;
            }

        }
    }

    /*
     * Save ttl info
     */
    parse->ttl_count[rec->ttl]++;
    if(rec->ttl != 255){
        parse->max_ttl = MAX(parse->max_ttl,rec->ttl);
    }
    parse->min_ttl = MIN(parse->min_ttl,rec->ttl);

    return 0;
}

static void
IterateSumSessionLost(
        struct pow_parse_rec        *parse
        )
{
    u_int32_t   i,n;

    n = parse->last - parse->first + 1;

    for(i=0;i<n;i++){
        if(parse->seen[i].seen){
            parse->dups += (parse->seen[i].seen - 1);
            continue;
        }
        parse->lost++;
    }

    return;
}

static u_int32_t
inthash(
        I2Datum        key
       )
{
    return (u_int32_t)key.dsize;
}

static int
intcmp(
        const I2Datum        x,
        const I2Datum        y
      )
{
    return(x.dsize != y.dsize);
}

static I2Boolean
PrintBuckets(
        I2Datum key,
        I2Datum value,
        void    *data
        )
{
    struct pow_parse_rec    *parse = (struct pow_parse_rec*)data;
    int rc;

    fprintf(parse->fp,"\t%d\t%u\n",(int)key.dsize,*(u_int32_t*)value.dptr);
    rc = I2HashDelete(parse->buckets,key);
    assert(rc==0);

    return True;
}


int
main(
        int     argc,
        char    **argv
)
{
    char                    *progname;
    int                     lockfd;
    char                    lockpath[PATH_MAX];
    int                     rc;
    OWPErrSeverity          err_ret = OWPErrOK;
    I2ErrLogSyslogAttr      syslogattr;
    OWPContext              ctx;

    int                     fname_len;
    int                     ch;
    char                    *endptr = NULL;
    char                    optstring[128];
    static char             *conn_opts = "A:S:k:u:";
    static char             *test_opts = "c:i:s:L:";
    static char             *out_opts = "d:N:pe:rb:v";
    static char             *gen_opts = "hw";
    static char             *posixly_correct="POSIXLY_CORRECT=True";

    int                     which=0;        /* which cntrl connect used */
    u_int32_t               numSummaries;
    u_int32_t               iotime;
    struct pow_parse_rec    parse;
    struct flock            flk;
    struct sigaction        act;

    progname = (progname = strrchr(argv[0], '/')) ? progname+1 : *argv;

    /* Create options strings for this program. */
    strcpy(optstring, conn_opts);
    strcat(optstring, test_opts);
    strcat(optstring, out_opts);
    strcat(optstring, gen_opts);


    syslogattr.ident = progname;
    syslogattr.logopt = LOG_PID;
    syslogattr.facility = LOG_USER;
    syslogattr.priority = LOG_ERR;
    syslogattr.line_info = I2MSG;

    /* Set default options. */
    memset(&appctx,0,sizeof(appctx));
    appctx.opt.numPackets = 300;
    appctx.opt.lossThreshold = 10.0;
    appctx.opt.meanWait = (float)0.1;
    appctx.opt.bucketWidth = (float)0.0001; /* 100 usecs */

    /*
     * Fix getopt if the brain-dead GNU version is being used.
     */
    if(putenv(posixly_correct) != 0){
        fprintf(stderr,"Unable to set POSIXLY_CORRECT getopt mode");
        exit(1);
    }
    opterr = 0;
    while((ch = getopt(argc, argv, optstring)) != -1){
        int fac;
        switch (ch){
            case 'e':
                if((fac = I2ErrLogSyslogFacility(optarg)) == -1){
                    fprintf(stderr,
                            "Invalid -e: Syslog facility \"%s\" unknown\n",
                            optarg);
                    exit(1);
                }
                syslogattr.facility = fac;
                break;
            case 'v':
                appctx.opt.verbose++;
                /* fallthrough */
            case 'r':
                syslogattr.logopt |= LOG_PERROR;
                break;
            default:
                break;
        }
    }
    opterr = optreset = optind = 1;

    /*
     * Start an error logging session for reporing errors to the
     * standard error
     */
    if(appctx.opt.verbose > 1){
        syslogattr.logopt |= LOG_PID;
        syslogattr.line_info |= I2FILE | I2LINE;
    }
    eh = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);
    if(! eh) {
        fprintf(stderr, "%s : Couldn't init error module\n", progname);
        exit(1);
    }


    while ((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch) {
            /* Connection options. */
            case 'A':
                if (!(appctx.opt.authmode = strdup(optarg))) {
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'S':
                if (!(appctx.opt.srcaddr = strdup(optarg))) {
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'u':
                if (!(appctx.opt.identity = strdup(optarg))) {
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'k':
                if (!(appctx.opt.keyfile = strdup(optarg))) {
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'c':
                appctx.opt.numPackets = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname,"Invalid value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'i':
                appctx.opt.meanWait = strtod(optarg, &endptr);
                if (*endptr != '\0') {
                    usage(progname, 
                            "Invalid value. Positive float expected");
                    exit(1);
                }
                break;
            case 's':
                appctx.opt.padding = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname, 
                            "Invalid value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'L':
                appctx.opt.lossThreshold = strtod(optarg, &endptr);
                if((*endptr != '\0') ||
                        (appctx.opt.lossThreshold <= 0.0)){
                    usage(progname, 
                            "Invalid (-L) value. Positive float expected");
                    exit(1);
                }
                break;
#ifndef        NDEBUG
            case 'w':
                appctx.opt.childwait = True;
                break;
#endif
            case 'd':
                if (!(appctx.opt.savedir = strdup(optarg))) {
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'p':
                appctx.opt.printfiles = True;
                break;
            case 'b':
                appctx.opt.bucketWidth = strtod(optarg, &endptr);
                if((*endptr != '\0') || (appctx.opt.bucketWidth <= 0.0)){
                    usage(progname, 
                            "Invalid (-b) value. Positive float expected");
                    exit(1);
                }
                break;
            case 'N':
                appctx.opt.numBucketPackets =
                    strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname,"Invalid value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'e':
            case 'r':
            case 'v':
                /* handled in prior getopt call... */
                break;
                /* Generic options.*/
            case 'h':
            case '?':
            default:
                usage(progname, "");
                exit(0);
                /* UNREACHED */
        }
    }
    argc -= optind;
    argv += optind;

    if((argc < 1) || (argc > 2)){
        usage(progname, NULL);
        exit(1);
    }

    appctx.remote_test = argv[0];
    if(argc > 1)
        appctx.remote_serv = argv[1];
    else
        appctx.remote_serv = appctx.remote_test;

    /*
     * This is in reality dependent upon the actual protocol used
     * (ipv4/ipv6) - it is also dependent upon the auth mode since
     * authentication implies 128bit block sizes.
     */
    if(appctx.opt.padding > MAX_PADDING_SIZE)
        appctx.opt.padding = MAX_PADDING_SIZE;

    /*
     * Check savedir option. Make sure it will not make fnames
     * exceed PATH_MAX even with the nul byte.
     * Also set file_offset and tstamp_offset to the lengths needed.
     */
    fname_len = (2 * OWP_TSTAMPCHARS) + strlen(OWP_NAME_SEP) +
        MAX(strlen(OWP_FILE_EXT),strlen(POW_SUM_EXT)) + strlen(POW_INC_EXT);
    assert((fname_len+1)<PATH_MAX);
    if(appctx.opt.savedir){
        if((strlen(appctx.opt.savedir) + strlen(OWP_PATH_SEPARATOR) +
                    fname_len + 1) > PATH_MAX){
            usage(progname,"-d: pathname too long.");
            exit(1);
        }
        strcpy(dirpath,appctx.opt.savedir);
        strcat(dirpath,OWP_PATH_SEPARATOR);
    }
    else{
        dirpath[0] = '\0';
    }
    file_offset = strlen(dirpath);
    tstamp_offset = file_offset + OWP_TSTAMPCHARS;
    ext_offset = tstamp_offset + OWP_TSTAMPCHARS + strlen(OWP_NAME_SEP);

    /*
     * Lock the directory for powstream.
     * (May need a more complex mutex eventually - but for now, just
     * try and lock it, and fail completely if can't.)
     *         could read pid out of file, etc...
     */
    strcpy(lockpath,dirpath);
    strcat(lockpath,POWLOCK);
    lockfd = open(lockpath,O_RDWR|O_CREAT,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if(lockfd < 0){
        I2ErrLog(eh,"open(%s):%M",lockpath);
        exit(1);
    }

    flk.l_start = 0;
    flk.l_len = 0;
    flk.l_type = F_WRLCK;
    flk.l_whence = SEEK_SET;
    while((rc = fcntl(lockfd,F_SETLK,&flk)) < 0 && errno == EINTR);
    if(rc < 0){
        I2ErrLog(eh,"Unable to lock file %s:%M",lockpath);
        if(I2Readn(lockfd,&ch,sizeof(ch)) == sizeof(ch)){
            I2ErrLog(eh,"Possibly locked by pid(%d)",ch);
        }
        exit(1);
    }

    ch = getpid();
    if(I2Writen(lockfd,&ch,sizeof(ch)) != sizeof(ch)){
        I2ErrLog(eh,"Unable to write to lockfile:%M");
        exit(1);
    }

    /*
     * Determine how many packets are in each sum-session.
     * Verify that summary sessions are an even divisor of full
     * sessions.
     */
    if(!appctx.opt.numBucketPackets){
        appctx.opt.numBucketPackets = appctx.opt.numPackets;
        appctx.opt.bucketWidth = 0.0;
        numSummaries = 0;
    }
    else{
        if((appctx.opt.numPackets < appctx.opt.numBucketPackets) ||
                (appctx.opt.numPackets % appctx.opt.numBucketPackets)){
            I2ErrLog(eh,"Number of summary packets (-N %d) must be a divisor of the number of session packets (-c %d).",
                    appctx.opt.numBucketPackets,appctx.opt.numPackets);
            exit(1);
        }
        numSummaries = appctx.opt.numPackets/appctx.opt.numBucketPackets;

        memset(&parse,0,sizeof(struct pow_parse_rec));
        if(!(parse.seen = malloc(sizeof(pow_seen_rec)*
                        appctx.opt.numBucketPackets))){
            I2ErrLog(eh,"malloc(): %M");
            exit(1);
        }

        /*
         * NOTE:
         * Will use the dsize of the key datum to actually hold
         * the bucket index, therefore I need to install the cmp
         * and hash functions. The "actual" datatype is 'unsigned'
         * so be careful to cast appropriately.
         */
        if(!(parse.buckets = I2HashInit(eh,0,intcmp,inthash))){
            I2ErrLog(eh,"I2HashInit(): %M");
            exit(1);
        }
        /*
         * Can't use more buckets than we have packets, so this is
         * definitely enough memory.
         */
        if(!(parse.bucketvals = malloc(sizeof(u_int32_t) *
                        appctx.opt.numBucketPackets))){
            I2ErrLog(eh,"malloc(): %M");
            exit(1);
        }
        parse.nbuckets = 0;
    }

    /*
     * Warn if it will take longer to setup sessions than the
     * actual session duration...
     */
    sessionTime = appctx.opt.numPackets * appctx.opt.meanWait;
    if(sessionTime < SETUP_ESTIMATE + appctx.opt.lossThreshold){
        I2ErrLog(eh,
                "Warning: Holes in data are likely because"
                " lossThreshold(%g) is too large a fraction"
                " of approx file session duration(%lu)",
                appctx.opt.lossThreshold,sessionTime);
    }

    /*
     * Setup Test Session record.
     */
    /* skip start_time - set per/test */
    tspec.loss_timeout = OWPDoubleToNum64(appctx.opt.lossThreshold);
    tspec.typeP = 0;
    tspec.packet_size_padding = appctx.opt.padding;
    tspec.npackets = appctx.opt.numPackets;

    /*
     * inf_delay is used as the next largest number over lossThreshold
     * in our time resolution.
     */
    inf_delay = OWPNum64ToDouble(tspec.loss_timeout + 1);

    /*
     * powstream uses a single slot with exp distribution.
     */
    slot.slot_type = OWPSlotRandExpType;
    slot.rand_exp.mean = OWPDoubleToNum64(appctx.opt.meanWait);
    tspec.nslots = 1;
    tspec.slots = &slot;


    /*
     * Initialize library with configuration functions.
     */
    if( !(appctx.lib_ctx = OWPContextCreate(eh))){
        I2ErrLog(eh, "Unable to initialize OWP library.");
        exit(1);
    }
    ctx = appctx.lib_ctx;
    parse.ctx = ctx;


    owp_set_auth(ctx,progname,&appctx); 

    memset(&pcntrl,0,2*sizeof(pow_cntrl_rec));
    strcpy(pcntrl[0].fname,dirpath);
    strcpy(pcntrl[1].fname,dirpath);
    pcntrl[0].ctx = pcntrl[1].ctx = ctx;

    /*
     * Add time for file buffering. 
     * Add 2 seconds to the max of (1,mu). file io is optimized to
     * try and only buffer 1 second of data - but if mu is > one
     * second, then we have to wait mu, because each record will
     * be flushed individually in this case.
     * (2 seconds is because the recv process waits 1 after the end
     * of the test before it does it's clean-up, and we want to wait
     * until it is done with it's clean-up. It should definitely not
     * take longer than 1 second to clean-up.)
     */
    iotime = MAX(appctx.opt.meanWait,1) + 2;

    /*
     * Setup signal handlers.
     */
    pow_reset = 0;
    pow_exit = 0;
    pow_intr = 0;
    act.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if((sigaction(SIGUSR1,&act,NULL) != 0) ||
            (sigaction(SIGUSR2,&act,NULL) != 0)){
        I2ErrLog(eh,"sigaction():%M");
        exit(1);
    }

    act.sa_handler = sig_catch;

    if((sigaction(SIGTERM,&act,NULL) != 0) ||
            (sigaction(SIGINT,&act,NULL) != 0) ||
            (sigaction(SIGHUP,&act,NULL) != 0)){
        I2ErrLog(eh,"sigaction():%M");
        exit(1);
    }

    /*
     * Set the retn_on_intr flag.
     */
    if(!OWPContextConfigSetV(ctx,OWPInterruptIO,(void*)&pow_intr)){
        I2ErrLog(eh,"Unable to set Context var: %M");
        exit(1);
    }

    /*
     * Main loop - loop over two connections collecting the data
     * and placing a summary in the directory when the sum-session
     * is complete.
     *
     */
    while(1){
        pow_cntrl       p,q;
        OWPAcceptType   aval;
        u_int32_t       sum;
        OWPNum64        stopnum;
        OWPNum64        startnum,lastnum;
        char            tfname[PATH_MAX];
        char            fname[PATH_MAX];
        char            startname[PATH_MAX];
        char            endname[PATH_MAX];

NextConnection:
        sig_check();

        /*
         * p is the "connection" we are dealing with this loop
         * iteration. We need a pointer to q to tell it what series
         * start time to use based upon the end of the p series.
         */
        p = &pcntrl[which++];
        which %= 2;
        q = &pcntrl[which];

        if(!p->numPackets){
            (void)SetupSession(ctx,q,p,NULL);
            goto NextConnection;
        }

        /* init vars for loop */
        parse.begin=0;
        lastnum=OWPULongToNum64(0);

        /*
         * Make local copies of start/end - SetupSession modifies
         * them.
         */
        p->currentSessionStartNum = p->nextSessionStartNum;
        p->currentSessionEndNum = p->nextSessionEndNum;

        if(appctx.opt.verbose > 1){
            sprintf(startname,OWP_TSTAMPFMT,p->currentSessionStartNum);
            sprintf(endname,OWP_TSTAMPFMT,p->currentSessionEndNum);
            fprintf(stderr,"Starting session [%s - %s] v=%d\n",startname,endname,appctx.opt.verbose);
        }
            
        /*
         * Call StopSessionsWait (blocking) if no summaries
         * are wanted.
         */
        if(!numSummaries){
            /*
             * Now try and setup the next full session (q).
             * SetupSession checks for reset signals, and returns
             * non-zero if one happend.
             */
            if(SetupSession(ctx,q,p,NULL))
                goto NextConnection;
            p->session_started = True;
wait_again:
            rc = OWPStopSessionsWait(p->cntrl,NULL,&pow_intr,&aval,&err_ret);
            if(rc<0){
                /* error - reset sessions and start over. */
                CloseSessions();
                goto NextConnection;
            }
            else if(rc==2){
                /*
                 * system event
                 */
                if(sig_check()){
                    /* cleanup resources */
                    goto NextConnection;
                }
                goto wait_again;
            }
            p->call_stop = False;

        }

        /*
         * This loops on each "sum" session - it completes when
         * there are no more sum-sessions to fetch - i.e. the real
         * test session is complete.
         */
        for(sum=0;sum<numSummaries;sum++){
            u_int32_t           arecs,nrecs;
            off_t               fileend;
            OWPSessionHeaderRec hdr;
            OWPNum64            localstop;

            if(sig_check())
                goto NextConnection;

            parse.first = appctx.opt.numBucketPackets*sum;
            parse.last = (appctx.opt.numBucketPackets*(sum+1))-1;
            parse.i = 0;
            parse.next = 0;
            parse.sync = 1;
            parse.maxerr = 0.0;
            parse.dups = parse.lost = 0;
            parse.min_delay = inf_delay;
            parse.max_delay = -inf_delay;
            memset(&parse.ttl_count,0,sizeof(parse.ttl_count));
            parse.min_ttl = 255;
            parse.max_ttl = 0;
            parse.nbuckets = 0;
            parse.fp = NULL;
            assert(!parse.buckets || (I2HashNumEntries(parse.buckets)==0));

            /*
             * lastnum contains offset for previous sum.
             * So - currentSessionStart + lastnum is new
             * startnum.
             */
            startnum = OWPNum64Add(p->currentSessionStartNum,lastnum);

            /*
             * This loop sets lastnum to the relative lastnum
             * of this sum-session. (It starts at the relative
             * offset of the lastnum from the previous session.)
             * It also initializes the "seen" array for this
             * sum-session. This array saves the presumed sendtimes
             * in the event "lost" records for those packets
             * need to be generated.
             */
            for(nrecs=0;nrecs<appctx.opt.numBucketPackets;nrecs++){

                lastnum = OWPNum64Add(lastnum,
                        OWPScheduleContextGenerateNextDelta(p->sctx));

                parse.seen[nrecs].sendtime =
                    OWPNum64Add(p->currentSessionStartNum,lastnum);

                parse.seen[nrecs].seen = 0;
            }
            /*
             * set localstop to absolute time of final packet.
             */
            localstop = OWPNum64Add(p->currentSessionStartNum,lastnum);

            /*
             * set stopnum to the time we should collect this
             * session.
             * sumsession can't be over until after
             * lossThresh, then add iotime.
             */
            stopnum = OWPNum64Add(localstop,OWPNum64Add(tspec.loss_timeout,
                        OWPULongToNum64(iotime)));

            /*
             * Now try and setup the next full session (q).
             * SetupSession checks for reset signals, and returns
             * non-zero if one happend.
             */
            if(SetupSession(ctx,q,p,&stopnum))
                goto NextConnection;
AGAIN:
            /*
             * Wait until this "sumsession" is complete.
             */
            if(p->call_stop){
                rc = OWPStopSessionsWait(p->cntrl,&stopnum,NULL,&aval,&err_ret);
            }
            else{
                rc=1; /* no more data coming */
            }

            if(rc<0){
                /* error */
                OWPControlClose(p->cntrl);
                p->cntrl = NULL;
                break;
            }
            if(rc==0){
                /* session over */
                p->call_stop = False;
                /*
                 * If aval non-zero, session data is invalid.
                 */
                if(aval)
                    break;
            }
            if(rc==2){
                /*
                 * system event
                 */
                if(sig_check())
                    goto NextConnection;

                if(OWPSessionsActive(p->cntrl,NULL)){
                    goto AGAIN;
                }
            }
            /* Else - time's up! Get to work.        */
            p->session_started = True;

            /*
             * If not doing buckets, then the loop is
             * complete.
             */
            if(!parse.buckets){
                continue;
            }

            /*
             * This section reads the packet records
             * in the time period of this sum-session.
             */
            (void)OWPReadDataHeader(ctx,p->fp,&hdr);
            parse.hdr = &hdr;

            /*
             * If no data, then skip.
             */
            if(!hdr.header){
                I2ErrLog(eh,"OWPReadDataHeader failed");
                break;
            }

            /*
             * Determine offset to end of datarecs
             */
            if(hdr.oset_skiprecs > hdr.oset_datarecs){
                fileend = hdr.oset_skiprecs;
            }
            else{
                if(fseeko(p->fp,0,SEEK_END) != 0){
                    I2ErrLog(eh,"fseeko(): %M");
                    break;
                }
                if((fileend = ftello(p->fp)) < 0){
                    I2ErrLog(eh,"ftello(): %M");
                    break;
                }
            }

            /* Determine first position of first record we need to look at. */
            if(parse.begin < hdr.oset_datarecs){
                parse.begin = hdr.oset_datarecs;
            }
            if(fseeko(p->fp,parse.begin,SEEK_SET) != 0){
                I2ErrLog(eh,"fseeko(): %M");
                break;
            }

            /*
             * How many records from "begin" to end of file.
             */
            nrecs = (fileend - parse.begin) / hdr.rec_size;

            /*
             * No more data to parse.
             */
            if(!p->call_stop && !nrecs)
                break;

            /*
             * Iterate over the records in the file and
             * calculate summary statistics.
             */
            if(OWPParseRecords(ctx,p->fp,nrecs,hdr.version,IterateSumSession,
                        (void*)&parse) != OWPErrOK){
                I2ErrLog(eh,
                        "IterateSumSession: sum=%d,arecs=%lu,nrecs=%lu,begin=%lld,first=%lu,last=%lu,oset_datarecs=%llu,fileend=%lld: %M",
                        sum,arecs,nrecs,parse.begin,
                        parse.first,parse.last,
                        hdr.oset_datarecs,fileend);
                goto cleanup;
            }
            IterateSumSessionLost(&parse);

            /*
             * If we have read to the end of the stream, we need
             * to clear the eof flag so the stream will work
             * if the child process adds more records.
             */
            if(feof(p->fp)){
                clearerr(p->fp);
            }

            /*
             * Make a temporary sum-session file.
             */
            strcpy(tfname,dirpath);
            sprintf(startname,OWP_TSTAMPFMT,startnum);
            sprintf(endname,OWP_TSTAMPFMT,localstop);
            sprintf(&tfname[file_offset],"%s%s%s%s%s",
                    startname,OWP_NAME_SEP,endname,POW_SUM_EXT,POW_INC_EXT);

            while(!(parse.fp = fopen(tfname,"w")) && errno==EINTR){
                if(sig_check())
                    goto NextConnection;
            }
            if(!parse.fp){

                I2ErrLog(eh,"fopen(%s): %M",tfname);

                /*
                 * Can't open the file.
                 */
                switch(errno){
                    /*
                     * reasons to go to the next sum-session.
                     * (Temporary resource problems.)
                     */
                    case ENOMEM:
                    case EMFILE:
                    case ENFILE:
                    case ENOSPC:
                        break;
                        /*
                         * Everything else is a reason to exit
                         * (Probably permissions.)
                         */
                    default:
                        exit(1);
                        break;
                }

                /*
                 * Skip to next sum-session.
                 */
                goto cleanup;
            }

            /*
             * File is good, write to it.
             */

            /* PRINT version 1 STATS */
            fprintf(parse.fp,"SUMMARY\t2.0\n");
            fprintf(parse.fp,"SENT\t%u\n",appctx.opt.numBucketPackets);
            fprintf(parse.fp,"MAXERR\t%g\n",parse.maxerr);
            fprintf(parse.fp,"SYNC\t%u\n",parse.sync);
            fprintf(parse.fp,"DUPS\t%u\n",parse.dups);
            fprintf(parse.fp,"LOST\t%u\n",parse.lost);

            /*
             * PRINT out the delay information/BUCKETS
             */
            if(parse.min_delay < inf_delay){
                fprintf(parse.fp,"MIN\t%g\n",parse.min_delay);
            }
            if(parse.max_delay > -inf_delay){
                fprintf(parse.fp,"MAX\t%g\n",parse.max_delay);
            }
            fprintf(parse.fp,"BUCKETWIDTH\t%g\n",appctx.opt.bucketWidth);
            fprintf(parse.fp,"<BUCKETS>\n");
            I2HashIterate(parse.buckets,PrintBuckets,&parse);
            fprintf(parse.fp,"</BUCKETS>\n");

            /*
             * PRINT out the ttl information/buckets
             * (255 is reported if ttl is not reported, so do not
             * report any ttl info if all packets report in this bin.)
             */
            if(parse.ttl_count[255] < appctx.opt.numBucketPackets+parse.lost){
                if(parse.min_ttl < 255){
                    fprintf(parse.fp,"MINTTL\t%u\n",parse.min_ttl);
                }
                if(parse.max_ttl > 0){
                    fprintf(parse.fp,"MAXTTL\t%u\n",parse.max_ttl);
                }

                /*
                 * PRINT out the TTLBUCKETS
                 */
                fprintf(parse.fp,"<TTLBUCKETS>\n");
                for(nrecs=0;nrecs<255;nrecs++){
                    if(!parse.ttl_count[nrecs])
                        continue;
                    fprintf(parse.fp,"\t%u\t%u\n",nrecs,parse.ttl_count[nrecs]);
                }
                fprintf(parse.fp,"</TTLBUCKETS>\n");
            }

            fclose(parse.fp);
            parse.fp = NULL;

            /*
             * Relink the incomplete file as a complete one.
             */
            strcpy(fname,tfname);
            sprintf(&fname[ext_offset],"%s",POW_SUM_EXT);
            if(link(tfname,fname) != 0){
                /* note, but ignore the error */
                I2ErrLog(eh,"link(%s,%s): %M",tfname,fname);
            }

            if(appctx.opt.printfiles){
                /* Now print the filename to stdout */
                fprintf(stdout,"%s\n",fname);
                fflush(stdout);
            }

cleanup:
            /* unlink old name */
            if(unlink(tfname) != 0){
                /* note, but ignore the error */
                I2ErrLog(eh,"unlink(%s): %M",tfname);
            }

            if(parse.buckets)
                I2HashClean(parse.buckets);

            /*
             * Setup begin offset for next time around.
             */
            if(parse.next)
                parse.begin = parse.next;
            else
                parse.begin += parse.i * hdr.rec_size;

            if(!p->cntrl)
                break;
        }

        if(p->cntrl && p->call_stop){
            if(OWPStopSessions(p->cntrl,NULL,&aval)<OWPErrWARNING){
                OWPControlClose(p->cntrl);
                p->cntrl = NULL;
            }
        }

        /*
         * TODO: Write out complete session summary
         */

        /*
         * Write out the complete owp session file.
         */
        write_session(p,False);

        /*
         * This session is complete - reset p.
         */
        p->numPackets = 0;
        while(p->fp && (fclose(p->fp) != 0) && errno==EINTR);
        while(p->testfp && (fclose(p->testfp) != 0) && errno==EINTR);
        p->fp = p->testfp = NULL;

        if(sum < numSummaries){
            /*
             * This session ended prematurely - q needs to
             * be reset for an immediate start time!.
             */
            ResetSession(q,p);
        }
    }

    exit(0);
}
