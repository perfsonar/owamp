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
 *        File:         powstream.c
 *
 *        Authors:      Jeff Boote
 *                      Internet2
 *
 *        Date:         Tue Sep  3 15:47:26 MDT 2002
 *
 *        Description:        
 *
 *        Initial implementation of powstream commandline application. This
 *        application will measure active one-way udp latencies. And it will
 *        set up perpetual tests and keep them going until this application
 *        is killed.
 */
#include <owamp/owamp.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <assert.h>
#include <syslog.h>
#include <math.h>
#include <net/if.h>


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

#define debug(fmt, ...) \
  fprintf(stdout, "debug: %s:%s:%d: " fmt "\n", __FILE__, __func__,  __LINE__, ##__VA_ARGS__)

/*
 * The powstream context
 */
static powapp_trec      appctx;
static I2ErrHandle      eh;
static pow_cntrl_rec    pcntrl[2];
static OWPTestSpec      tspec;
static OWPSlot          slot;
static uint32_t         sessionTime;
static double           inf_delay;
static uint8_t          *pfbuff;
static size_t           pfbuff_len;

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
static uint32_t        file_offset,tstamp_offset,ext_offset;

static uint32_t FetchSession(
        pow_cntrl       p,
        uint32_t        begin,
        uint32_t        end,
        OWPErrSeverity  *err_ret
        );

static int sig_check();

static void
print_conn_args(){
        fprintf(stderr,"              [Connection Args]\n\n"
"   -4             use IPv4 only\n"
"   -6             use IPv6 only\n"
"   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen\n"
"   -k pffile      pass-phrase file to use with Authenticated/Encrypted modes\n"
"   -S srcaddr     specify the local address or interface for control connection and tests\n"
"   -B interface   specify the interface to use for control connection and tests\n"
"   -u username    username to use with Authenticated/Encrypted modes\n"
"   -I retryDelay  time to wait between failed connections (default: 60 seconds)\n"
        );
}

static void
print_test_args(){
        fprintf(stderr,
"              [Test Args]\n\n"
"   -t             sets the tests direction from client to server\n"
"   -c count       number of test packets (per complete session)\n"
"   -E endDelay    time to wait before sending stop-session message\n"
"   -i wait        mean average time between packets (seconds)\n"
"   -L timeout     maximum time to wait for a packet (seconds)\n"
"   -P portrange   test port range to use (must contain at least 2 ports)\n"
"   -s padding     size of the padding added to each packet (bytes)\n"
"   -z delayStart  time to wait before starting first test (seconds)\n"
        );
}

static void
print_output_args()
{
    fprintf(stderr,
"              [Output Args]\n\n"
"   -b bucketWidth create summary files with buckets(seconds)\n"
"   -d dir         directory to save session file in\n"
"   -e facility    syslog facility to log to\n"
"   -g loglevel    severity log messages to report to syslog Valid values: NONE, FATAL, WARN, INFO, DEBUG, ALL\n"
"   -N count       number of test packets (per sub-session)\n"
"   -p             print filenames to stdout\n"
"   -R             Only send messages to syslog (not STDERR)\n"
"   -v             include more verbose output\n"
"   -U             Adds UNIX timestamps to summary results\n"
"   -j             JSON output"
           );
}

static void
usage(
        const char *progname,
        const char *msg)
{
    if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
    fprintf(stderr,"usage: %s %s\n%s\n",progname,
            "[arguments] testaddr [servaddr]",
            "[arguments] are as follows: "
            );

    fprintf(stderr, "\n%s\n",
"   -h             print this message and exit\n"
            );

    fprintf(stderr, "\n");
    print_test_args();

    fprintf(stderr, "\n");
    print_conn_args();

    fprintf(stderr, "\n");
    print_output_args();

    if (PATCH_LEVEL) {
        fprintf(stderr, "\nVersion: %s-%d\n\n", PACKAGE_VERSION, PATCH_LEVEL);
    }
    else {
        fprintf(stderr, "\nVersion: %s\n\n", PACKAGE_VERSION);
    }

    return;
}

static OWPBoolean
getclientpf(
        OWPContext      ctx __attribute__((unused)),
        const OWPUserID userid __attribute__((unused)),
        uint8_t         **pf,
        size_t          *pf_len,
        void            **pf_free,
        OWPErrSeverity  *err_ret __attribute__((unused))
        )
{
    *pf = pfbuff;
    *pf_len = pfbuff_len;
    *pf_free = NULL;

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
        char    *lbuf=NULL;
        size_t  lbuf_max=0;
        char    *passphrase;

        /*
         * If pffile specified, attempt to get key from there.
         */
        if(pctx->opt.pffile){
            /* pffile */
            FILE    *filep;
            int     rc = 0;

            if(!(filep = fopen(pctx->opt.pffile,"r"))){
                I2ErrLog(eh,"Unable to open %s: %M",pctx->opt.pffile);
                goto DONE;
            }

            rc = I2ParsePFFile(eh,filep,NULL,0,pctx->opt.identity,NULL,
                    &passphrase,&pfbuff_len,&lbuf,&lbuf_max);
            if(rc < 1){
                I2ErrLog(eh,
                        "Unable to find pass-phrase for id=\"%s\" from pffile=\"%s\"",
                        pctx->opt.identity,pctx->opt.pffile);
            }

            fclose(filep);
        }
        else{
            /*
             * Do passphrase:
             *         open tty and get passphrase.
             */
            char                prompt[MAX_PASSPROMPT];

            if(snprintf(prompt,MAX_PASSPROMPT,
                        "Enter passphrase for identity '%s': ",
                        pctx->opt.identity) >= MAX_PASSPROMPT){
                I2ErrLog(eh,"ip_set_auth: Invalid identity");
                goto DONE;
            }

            if(!(passphrase = I2ReadPassPhraseAlloc(prompt,I2RPP_ECHO_OFF,
                            &lbuf,&lbuf_max))){
                I2ErrLog(eh,"I2ReadPassPhraseAlloc(): %M");
                goto DONE;
            }
            pfbuff_len = strlen(passphrase);
        }

        /* copy pass-phrase */
        if(passphrase){
            if( !(pfbuff = malloc(pfbuff_len))){
                I2ErrLog(eh,"malloc: %M");
                exit(1);
            }
            memcpy(pfbuff,passphrase,pfbuff_len);
        }

DONE:

        if(lbuf){
            free(lbuf);
        }
        lbuf = NULL;
        lbuf_max = 0;

        if(pfbuff){
            /*
             * install getpf func (passphrase is in pfbuff)
             */
            OWPGetPFFunc    getpf = getclientpf;

            if(!OWPContextConfigSetF(ctx,OWPGetPF,(OWPFunc)getpf)){
                I2ErrLog(eh,"Unable to set AESKey for context: %M");
                exit(1);
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
    }
    else{
        /*
         * Default to all modes.
         * If identity not set - library will ignore A/E.
         */
        pctx->auth_mode = OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|
            OWP_MODE_ENCRYPTED;
    }

    return;
}

typedef struct pow_maxsend_rec{
    OWPSessionHeader    hdr;
    uint32_t           index;
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
    uint32_t           iskip =0;

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

    assert(rec->seq_no < sndrec->hdr->test_spec.npackets);
    assert(sndrec->index < sndrec->hdr->test_spec.npackets);
    if(rec->seq_no > sndrec->index){
        sndrec->index = rec->seq_no;
        sndrec->sendtime = rec->send.owptime;
    }

    return 0;
}

static uint32_t
FetchSession(
        pow_cntrl       p,
        uint32_t        begin,
        uint32_t        end,
        OWPErrSeverity  *err_ret
        )
{
    OWPErrSeverity err;
    uint32_t       num_rec;

    if (p->fetch == NULL) {
        p->fetch = OWPControlOpenInterface(p->ctx,
                        appctx.opt.srcaddr,
                        appctx.opt.interface,
                        I2AddrByNode(eh, appctx.remote_serv),
                        appctx.auth_mode,appctx.opt.identity,
                        NULL,&err);
        if (!p->fetch) {
            I2ErrLog(eh,"OWPControlOpen(%s): Couldn't open 'fetch' connection to server: %M",
                    appctx.remote_serv);
            goto error_out;
        }

        if(sig_check()) {
            *err_ret = OWPErrINVALID;
            return 0;
        }
    }

    num_rec = OWPFetchSession(p->fetch,p->testfp,
                begin, end,p->sid,err_ret);
    if (!num_rec) {
        goto error_out;
    }
 
    return num_rec;

error_out:
    if (p->fetch)
        OWPControlClose(p->fetch);

    p->fetch = NULL;

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
        pow_cntrl       p,
        OWPAcceptType   aval,
        OWPBoolean      newend
        )
{
    OWPSessionHeaderRec hdr;
    OWPNum64            endnum;
    char                tfname[PATH_MAX];
    char                ofname[PATH_MAX];
    char                ofname_json[PATH_MAX];
    char                sfname[PATH_MAX];
    char                sfname_json[PATH_MAX];
    char                startname[PATH_MAX];
    char                endname[PATH_MAX];
    int                 tofd = -1;
    FILE                *fp = NULL;
    OWPBoolean          dotf = False;
    OWPStats            stats = NULL;
    int                 rc;
    OWPErrSeverity      ec;
    // TODO
    FILE *              owp_json_file = NULL;
    FILE *              sum_json_file = NULL;

    /*
     * If this session does not have a started session, or the
     * data is corrupt there is no reason to save it.
     */
    if(!p->fp || !p->session_started || (aval != OWP_CNTRL_ACCEPT))
        return;

    /*
     * If sender session - data needs to be fetched from the remote server.
     */
    if(appctx.opt.sender){
        uint32_t    num_rec;

        /*
         * If there is no file to fetch the data give up.
         */
        if(!p->testfp)
            return;

        /*
         * Move file pointer to beginning and set file size to zero
         * before Fetching data.
         */
        if(fseeko(p->testfp,0,SEEK_SET) != 0){
            I2ErrLog(eh,"fseeko(): %M");
            return;
        }
        if((rc = ftruncate(fileno(p->testfp),0)) != 0){
            I2ErrLog(eh,"write_session(): ftruncate(): %M");
            return;
        }

        /*
         * Fetch the data and put it in testfp
         */
        num_rec = FetchSession(p,0,(uint32_t)0xFFFFFFFF,&ec);
        if(!num_rec){
            if(ec >= OWPErrWARNING){
                /*
                 * Server denied request - report error
                 */
                I2ErrLog(eh,"write_session(): OWPFetchSession(): Server denied request for full session data");
            }

            return;
        }
    }

    (void)OWPReadDataHeader(p->ctx,p->fp,&hdr);
    if( !hdr.header){
        I2ErrLog(eh,"OWPReadDataHeader(session data [%" PRIu64 ",%" PRIu64 ")",
                p->currentSessionStartNum,p->currentSessionEndNum);
        return;
    }


    if(newend){
        struct flock        flk;
        pow_maxsend_rec     sndrec;
        uint32_t           i;

        /*
         * This section reads the packet records
         * in the time period of this sum-session.
         */
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
                I2ErrLog(eh,
                        "OWPReadDataHeader(session data [%" PRIu64
                        ",%" PRIu64 ")",
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
                I2ErrLog(eh,"No data - skip writing session (%" PRIu64
                        ",%" PRIu64 ")",
                        p->currentSessionStartNum,p->currentSessionEndNum);
            }
            return;
        }

        /*
         * Read in skip recs
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

        /*
         * Find the last index in the file so it can be used to compute
         * the assumed "send" time for the "end" time of the session.
         *
         * Read all records and find the "last" one in the file.
         */
        if(fseeko(p->fp,hdr.oset_datarecs,SEEK_SET) != 0){
            if(sndrec.skips) free(sndrec.skips);
            I2ErrLog(eh,"fseeko(): %M");
            return;
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
        assert(sndrec.index < hdr.test_spec.npackets);
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
            case ENOMEM:
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
        goto skip_data;
    }
    dotf=True;

    /*
     * stat the "from" file, ftruncate the to file,
     * mmap both of them, then do a memcpy between them.
     */
    if(I2CopyFile(eh,tofd,fileno(p->fp),0) == 0){
        /*
         * Relink the incomplete file as a complete one.
         */
        strcpy(ofname,tfname);
        sprintf(&ofname[ext_offset],"%s",OWP_FILE_EXT);
        if(link(tfname,ofname) != 0){
            /* note, but ignore the error */
            I2ErrLog(eh,"link(%s,%s): %M",tfname,ofname);
            ofname[0]='\0';
        }
    }

skip_data:

    while((close(tofd) != 0) && errno==EINTR);
    if(dotf && (unlink(tfname) != 0)){
        /* note, but ignore the error */
        I2ErrLog(eh,"unlink(%s): %M",tfname);
    }
    dotf=False;

    /*
     * Write out complete session summary
     */

    /*
     * Create the stats record if empty. (Did not go through
     * subsession loop.)
     */
    if( !(stats = OWPStatsCreate(p->ctx,p->fp,&hdr,NULL,NULL,'m',
                    appctx.opt.bucketWidth))){
        I2ErrLog(eh,"OWPStatsCreate failed");
        goto skip_sum;
    }
    
    /* Set the timestamp flag here */
    if (appctx.opt.display_unix_ts == True)
        stats->display_unix_ts = True;

    // Set json output and create the files
    if (appctx.opt.is_json_format == True)
    {
        stats->is_json_format = True;
        // TODO Testing
        if (!stats->owp_json)
        {
            stats->owp_json = cJSON_CreateObject();
        }
        if (!stats->owp_histogram_ttl_json)
        {
            stats->owp_histogram_ttl_json = cJSON_CreateArray();
        }
        if (!stats->owp_histogram_latency_json)
        {
            stats->owp_histogram_latency_json = cJSON_CreateArray();
        }
        if (!stats->owp_raw_packets)
        {
            stats->owp_raw_packets = cJSON_CreateArray();
        }
        strcpy(ofname_json,ofname);
        sprintf(&ofname_json[ext_offset],"%s%s",OWP_FILE_EXT, JSON_FILE_EXT);
        debug("ofname_json: %s", ofname_json);
    }

    // TODO
    if (appctx.opt.is_json_format)
    {
        strcpy(sfname_json,tfname);
        sprintf(&sfname_json[ext_offset],"%s%s",POW_SUM_EXT, JSON_FILE_EXT);
        debug("sfname_json: %s", sfname_json);
    }

    /*
     * Parse the data and compute the statistics
     */
    if( !OWPStatsParse(stats,NULL,0,0,~0)){
        I2ErrLog(eh,"OWPStatsParse failed");
        goto skip_sum;
    }

    /*
     * Make a temporary session filename to hold data.
     */
    strcpy(tfname,dirpath);
    sprintf(startname,OWP_TSTAMPFMT,p->currentSessionStartNum);
    sprintf(endname,OWP_TSTAMPFMT,endnum);
    sprintf(&tfname[file_offset],"%s%s%s%s%s",
            startname,OWP_NAME_SEP,endname,
            POW_SUM_EXT,POW_INC_EXT);

    while(!(fp = fopen(tfname,"w")) && errno==EINTR);
    if(!fp){

        I2ErrLog(eh,"fopen(%s): %M",tfname);

        /*
         * Can't open the file.
         */
        switch(errno){
            /*
             * reasons to go to the next
             * session
             * (Temporary resource problems.)
             */
            case ENOMEM:
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
        goto skip_sum;
    }
    dotf=True;


    /*
     * Actually print out stats
     */
    if(!OWPStatsPrintMachine(stats,fp)){
        goto skip_sum;
    }

    /*
     * Relink the incomplete file as a complete one.
     */
    strcpy(sfname,tfname);
    sprintf(&sfname[ext_offset],"%s",POW_SUM_EXT);
    if(link(tfname,sfname) != 0){
        /* note, but ignore the error */
        I2ErrLog(eh,"link(%s,%s): %M",tfname,sfname);
        sfname[0] = '\0';
    }
    // open JSON format files
    if (appctx.opt.is_json_format)
    {
        owp_json_file = fopen(ofname_json, "w+");
        sum_json_file = fopen(sfname_json, "w+");
    }

    if (appctx.opt.is_json_format)
    {
        char * owp_json_str = NULL;
        char * sum_json_str = NULL;

        if (stats->owp_json)
        {
            cJSON * results = cJSON_CreateObject();
            cJSON_AddItemToObject(results, "raw-packets", stats->owp_raw_packets);
            cJSON_AddItemToObject(results, "histogram-latency", stats->owp_histogram_latency_json);
            cJSON_AddItemToObject(results, "histogram-ttl", stats->owp_histogram_ttl_json);
            //cJSON_AddItemToObject(stats->owp_json, "results", results);
            //owp_json_str = cJSON_Print(stats->owp_raw_packets);
            owp_json_str = cJSON_Print(results);
        }

        OWPStatsPrintMachineJSON(stats, sum_json_file);

        // TODO might need to remove
        if (stats->sum_json)
        {
            sum_json_str = cJSON_Print(stats->sum_json);
        }
        if (owp_json_str)
        {
            fprintf(owp_json_file, "%s", owp_json_str);
        }
        if (sum_json_str)
        {
            fprintf(sum_json_file, "%s", sum_json_str);
        }
    }
skip_sum:
    if(dotf && (unlink(tfname) != 0)){
        /* note, but ignore the error */
        I2ErrLog(eh,"unlink(%s): %M",tfname);
    }

    if(fp){
        fclose(fp);
    }

    // close JSON format files
    if (appctx.opt.is_json_format)
    {
        if (owp_json_file)
        {
            fclose(owp_json_file);
            owp_json_file = NULL;
        }
        if (sum_json_file)
        {
            fclose(sum_json_file);
            sum_json_file = NULL;
        }
    }

    if(stats){
        OWPStatsFree(stats);
    }

    /* Print complete filenames to stdout */
    if(appctx.opt.printfiles){
        if(strlen(ofname) > 0){
            fprintf(stdout,"%s\n",ofname);
        }
        if(strlen(sfname) > 0){
            fprintf(stdout,"%s\n",sfname);
        }
        if (appctx.opt.is_json_format)
        {
            if(strlen(ofname_json) > 0){
                fprintf(stdout,"%s\n",ofname_json);
            }
            if(strlen(sfname_json) > 0){
                fprintf(stdout,"%s\n",sfname_json);
            }
        }
        fflush(stdout);
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

    if(p->numPackets && p->call_stop && p->cntrl){
            (void)OWPStopSessions(p->cntrl,&pow_intr,&aval);
    }

    /*
     * Output "early-terminated" owp file - must be before the ControlClose
     * for 'sender' sessions so OWPFetchSession can be called.
     */
    write_session(p,aval,True);

    if(p->fetch){
        OWPControlClose(p->fetch);
        p->fetch = NULL;
    }

    if(p->cntrl){
        OWPControlClose(p->cntrl);
        p->cntrl = NULL;
    }

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
        /*
         * reset pow_intr to allow file i/o to complete. If the user
         * is impatient, a second signal will interrupt this.
         */
        pow_intr = 0;
        CloseSessions();
    }
    if(pow_exit){
        I2ErrLog(eh,"SIGTERM/SIGINT Caught: Exiting.");
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
    int             fd;
    uint64_t        i;
    char            fname[PATH_MAX];
    static int      first_time=1;

    if(p->numPackets)
        return 0;

    // reset the session if we're here.
    if(p->fetch){
        OWPControlClose(p->fetch);
        p->fetch = NULL;
    }

    if(p->cntrl){
        OWPControlClose(p->cntrl);
        p->cntrl = NULL;
    }

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


    if(appctx.opt.retryDelay > 0 && OWPNum64Cmp(p->prev_runtime.owptime, OWPULongToNum64(0)) > 0) {
        struct timespec ts, nts;
        OWPNum64 next_runtime;

        if(!OWPGetTimeOfDay(ctx,&currtime)){
            I2ErrLog(eh,"OWPGetTimeOfDay: %M");
            exit(1);
        }

        next_runtime = OWPNum64Add(p->prev_runtime.owptime, OWPULongToNum64(appctx.opt.retryDelay));
        if (OWPNum64Cmp(next_runtime, currtime.owptime) > 0) {
            OWPNum64ToTimespec(&ts, OWPNum64Sub(next_runtime, currtime.owptime));

            I2ErrLog(eh,"OWPControlOpen(%s): Waiting %d.%d seconds before retrying",
                    appctx.remote_serv,ts.tv_sec,ts.tv_nsec);
            while (nanosleep(&ts, &nts) == -1 && errno == EINTR) {
                if (sig_check()) return 1;

                ts.tv_sec  = nts.tv_sec;
                ts.tv_nsec = nts.tv_nsec;
            }
        }

    }

    if(!OWPGetTimeOfDay(ctx,&currtime)){
        I2ErrLog(eh,"OWPGetTimeOfDay: %M");
        exit(1);
    }

    if(stop != NULL && OWPNum64Cmp(currtime.owptime,*stop) > 0){
        if(p->nextSessionStart){
            q->nextSessionStart = &q->nextSessionStartNum;
            *q->nextSessionStart = *p->nextSessionStart;
        }else
            q->nextSessionStart = NULL;
        return 0;
    }

    OWPGetTimeOfDay(ctx,&p->prev_runtime);

    if(sig_check())
        return 1;

#if 0
        // XXX: we may need to be able to force an end by a certain time.
        if(stop){
            if(!OWPGetTimeOfDay(ctx,&currtime)){
                I2ErrLog(eh,"OWPGetTimeOfDay: %M");
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
#endif

    /*
     * First open a connection if we don't have one. XXX: we should now always
     * create a new connection, but need to verify that fact.
     */
    if(!p->sctx){
        if(!(p->sctx = OWPScheduleContextCreate(ctx,p->sid,&tspec))){
            I2ErrLog(eh,"OWPScheduleContextCreate: %M");
            goto fetch_clean;
        }
    }


    if(!(p->cntrl = OWPControlOpenInterface(ctx,
                    appctx.opt.srcaddr,
                    appctx.opt.interface,
                    I2AddrByNode(eh, appctx.remote_serv),
                    appctx.auth_mode,appctx.opt.identity,
                    NULL,&err))){
        if(sig_check()) return 1;

        I2ErrLog(eh,"OWPControlOpen(%s): Couldn't open 'control' connection to server: %M",
                appctx.remote_serv);
        goto sctx_clean;
    }

    if(sig_check())
        return 1;

    if(!OWPGetTimeOfDay(ctx,&currtime)){
        I2ErrLogP(eh,errno,"OWPGetTimeOfDay: %M");
        goto cntrl_clean;
    }
    currtime.owptime = OWPNum64Add(currtime.owptime,
            OWPULongToNum64(SETUP_ESTIMATE));
    if(first_time){
        currtime.owptime = OWPNum64Add(currtime.owptime,
                OWPULongToNum64(appctx.opt.delayStart));
        first_time=0;
    }

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
        I2ErrLog(eh,"mkstemp(%s): %M",fname);
        goto cntrl_clean;
    }

    /*
     * Wrap the fd in a file pointer.
     */
    if(!(p->fp = fdopen(fd,"wb+"))){
        I2ErrLog(eh,"fdopen(%s:(%d)): %M",fname,fd);
        while((close(fd) != 0) && errno==EINTR);
        (void)unlink(fname);
        goto cntrl_clean;
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
        (void)unlink(fname);
        goto cntrl_clean;
    }

    /*
     * Unlink the filename so interrupt resets don't have
     * as much work to do. (This does mean the data needs
     * to be copied into a new file upon completion of the
     * test.)
     */
    if(unlink(fname) != 0){
        I2ErrLog(eh,"unlink(): %M");
        goto file_clean;
    }

    // XXX: this could be bad?
    if(sig_check())
        return 1;

    /*
     * Make the actual request for the test specifying the testfp
     * to hold the results if receiver. (testfp still used to hold
     * data that is fetched using OWPFetchSession for sender sessions)
     */
    tspec.start_time = *p->nextSessionStart;
    if(appctx.opt.sender){
        if(!OWPSessionRequest(p->cntrl,NULL,(OWPBoolean)False,
                    I2AddrByNode(eh,appctx.remote_test),(OWPBoolean)True,
                    (OWPBoolean)False,(OWPTestSpec*)&tspec,NULL,p->sid,&err)){
            I2ErrLog(eh,"OWPSessionRequest: Failed");
            /*
            if(err == OWPErrFATAL){
                OWPControlClose(p->cntrl);
                p->cntrl = NULL;
            }
            */
            goto file_clean;
        }
    }
    else{
        if(!OWPSessionRequest(p->cntrl,I2AddrByNode(eh,appctx.remote_test),
                    True, NULL, False, False, (OWPTestSpec*)&tspec, p->testfp,
                    p->sid,&err)){
            I2ErrLog(eh,"OWPSessionRequest: Failed");
            /*
            if(err == OWPErrFATAL){
                OWPControlClose(p->cntrl);
                p->cntrl = NULL;
            }
            */
            goto file_clean;
        }
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
    /*
     * session_started will be set to true when the loop that parses this
     * session data begins.
     */
    p->call_stop = True;
    p->session_started = False;

    if(sig_check())
        return 1;

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

file_clean:
    while((fclose(p->fp) != 0) && errno==EINTR);
    p->fp = NULL;
    while((fclose(p->testfp) != 0) && errno==EINTR);
    p->testfp = NULL;

cntrl_clean:
    OWPControlClose(p->cntrl);
    p->cntrl = NULL;

sctx_clean:
    OWPScheduleContextFree(p->sctx);
    p->sctx = NULL;

fetch_clean:
    if (p->fetch){
        OWPControlClose(p->fetch);
	p->fetch = NULL;
    }

    return -1;
}

int
main(
        int     argc,
        char    **argv
)
{
    char                *progname;
    int                 lockfd;
    char                lockpath[PATH_MAX];
    int                 rc;
    OWPErrSeverity      err_ret = OWPErrOK;
    I2ErrLogSyslogAttr  syslogattr;
    OWPContext          ctx;

    int                 fname_len;
    int                 ch;
    char                *endptr = NULL;
    char                optstring[128];
    static char         *conn_opts = "46A:k:S:B:u:I:";
    static char         *test_opts = "c:E:i:L:s:tz:P:";
    static char         *out_opts = "b:d:e:g:N:pRvUj";
    static char         *gen_opts = "hw";
    static char         *posixly_correct="POSIXLY_CORRECT=True";

    int                 which=0;        /* which cntrl connect used */
    uint32_t            numSummaries;
    uint32_t            iotime;
    struct flock        flk;
    struct sigaction    act;
    OWPStats            stats = NULL;

    progname = (progname = strrchr(argv[0], '/')) ? progname+1 : *argv;

    /* Create options strings for this program. */
    strcpy(optstring, conn_opts);
    strcat(optstring, test_opts);
    strcat(optstring, out_opts);
    strcat(optstring, gen_opts);


    syslogattr.ident = progname;
    syslogattr.logopt = LOG_PID | LOG_PERROR;
    syslogattr.facility = LOG_USER;
    syslogattr.priority = LOG_ERR;
    syslogattr.line_info = I2MSG;
    syslogattr.report_level = OWPErrINFO;
    
    /* Set default options. */
    memset(&appctx,0,sizeof(appctx));
    appctx.opt.numPackets = 300;
    appctx.opt.retryDelay = 60;
    appctx.opt.lossThreshold = 10.0;
    appctx.opt.meanWait = 0.1;
    appctx.opt.bucketWidth = 0.0001; /* 100 usecs */
    appctx.opt.port_range.low  = 8760;
    appctx.opt.port_range.high = 9960;

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
        int report_level;
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
            case 'g':
                report_level = OWPReportLevelByName(optarg);
                if(report_level == -1){
                         fprintf(stderr,
                                "Log level \"%s\" invalid\n",
                                optarg);
                        exit(1);
                }
                syslogattr.report_level = report_level;
                break;
            case 'v':
                appctx.opt.verbose++;
                break;
            case 'R':
                syslogattr.logopt &= ~LOG_PERROR;
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
            case '4':
                appctx.opt.v4only = True;
                break;
            case '6':
                appctx.opt.v6only = True;
                break;
            /* test options */
            case 'c':
                appctx.opt.numPackets = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname,"Invalid value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'E':
                appctx.opt.endDelay = strtod(optarg, &endptr);
                if((*endptr != '\0') ||
                        (appctx.opt.endDelay <= 0.0)){
                    usage(progname, 
                            "Invalid (-E) value. Positive float expected");
                    exit(1);
                }
                break;
            case 'I':
                appctx.opt.retryDelay = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname,"Invalid (-I) value. Positive integer expected");
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
            case 'L':
                appctx.opt.lossThreshold = strtod(optarg, &endptr);
                if((*endptr != '\0') ||
                        (appctx.opt.lossThreshold <= 0.0)){
                    usage(progname, 
                            "Invalid (-L) value. Positive float expected");
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
            case 't':
                appctx.opt.sender = True;
                break;
            case 'z':
                appctx.opt.delayStart = strtoul(optarg,&endptr,10);
                if(*endptr != '\0'){
                    usage(progname,
                            "Invalid (-z) value. Positive integer expected");
                    exit(1);
                }
                break;
            /* Connection options. */
            case 'A':
                if (!(appctx.opt.authmode = strdup(optarg))) {
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'k':
                if (!(appctx.opt.pffile = strdup(optarg))) {
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'S':
                if (!(appctx.opt.srcaddr = strdup(optarg))) {
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'B':
                if(appctx.opt.interface){
                    usage(progname,"-B can only be used once");
                    exit(1);
                }
                if(!(appctx.opt.interface = strndup(optarg, IFNAMSIZ))){
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'u':
                if (!(appctx.opt.identity = strdup(optarg))) {
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'P':
                if (strcmp(optarg, "0") == 0) {
                    appctx.opt.port_range.high = appctx.opt.port_range.low = 0; /* Ephemeral Ports */
                }
                else {
                    if(!OWPParsePortRange(optarg, &appctx.opt.port_range)){
                        I2ErrLog(eh,
                                "Invalid test port range specified.");
                        exit(1);
                    }
                    if (appctx.opt.port_range.high && appctx.opt.port_range.low) {
                            if ((appctx.opt.port_range.high - appctx.opt.port_range.low + 1) < 2) {
                                I2ErrLog(eh,
                                        "Invalid test port range specified: must contain at least 2 ports.");
                                exit(1);
                            }
                    }
                }
                break;
            /* Output options */
            case 'b':
                appctx.opt.bucketWidth = strtod(optarg, &endptr);
                if((*endptr != '\0') || (appctx.opt.bucketWidth <= 0.0)){
                    usage(progname, 
                            "Invalid (-b) value. Positive float expected");
                    exit(1);
                }
                break;
            case 'd':
                if (!(appctx.opt.savedir = strdup(optarg))) {
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'N':
                appctx.opt.numBucketPackets =
                    strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname,
                            "Invalid (-N) value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'p':
                appctx.opt.printfiles = True;
                break;
            case 'U':
                appctx.opt.display_unix_ts = True;
                break;
            case 'j':
                appctx.opt.is_json_format = True;
                break;
            /* undocumented debug options */
#ifdef DEBUG
            case 'w':
                appctx.opt.childwait = True;
                break;
#endif
            /* handled in prior getopt call... */
            case 'e':
            case 'g':
            case 'R':
            case 'v':
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
        I2ErrLog(eh,"open(%s): %M",lockpath);
        exit(1);
    }

    flk.l_start = 0;
    flk.l_len = 0;
    flk.l_type = F_WRLCK;
    flk.l_whence = SEEK_SET;
    while((rc = fcntl(lockfd,F_SETLK,&flk)) < 0 && errno == EINTR);
    if(rc < 0){
        I2ErrLog(eh,"Unable to lock file %s: %M",lockpath);
        if(I2Readn(lockfd,&ch,sizeof(ch)) == sizeof(ch)){
            I2ErrLog(eh,"Possibly locked by pid(%d)",ch);
        }
        exit(1);
    }

    ch = getpid();
    if(I2Writen(lockfd,&ch,sizeof(ch)) != sizeof(ch)){
        I2ErrLog(eh,"Unable to write to lockfile: %M");
        exit(1);
    }

    /*
     * Determine how many packets are in each sum-session.
     * Verify that summary sessions are an even divisor of full
     * sessions.
     */
    if(!appctx.opt.numBucketPackets){
        appctx.opt.numBucketPackets = appctx.opt.numPackets;
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
                " of approx summary session duration(%lu)",
                appctx.opt.lossThreshold,sessionTime);
    }

    if(sessionTime < appctx.opt.retryDelay) {
        appctx.opt.retryDelay = sessionTime;
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

    owp_set_auth(ctx,progname,&appctx); 

    memset(&pcntrl,0,2*sizeof(pow_cntrl_rec));
    strcpy(pcntrl[0].fname,dirpath);
    strcpy(pcntrl[1].fname,dirpath);
    pcntrl[0].ctx = pcntrl[1].ctx = ctx;

    /*
     * Restrict INET address families
     */
    if(appctx.opt.v4only){
        if(appctx.opt.v6only){
            I2ErrLog(eh,"-4 and -6 flags cannot be set together");
            exit(1);
        }
        if( !OWPContextConfigSetV(ctx,OWPIPv4Only,(void*)True)){
            I2ErrLog(eh,
                    "OWPContextConfigSetV(): Unable to set OWPIPv4Only?!");
            exit(1);
        }
    }
    if(appctx.opt.v6only){
        if( !OWPContextConfigSetV(ctx,OWPIPv6Only,(void*)True)){
            I2ErrLog(eh,
                    "OWPContextConfigSetV(): Unable to set OWPIPv6Only?!");
            exit(1);
        }
    }

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
        I2ErrLog(eh,"sigaction(): %M");
        exit(1);
    }

    act.sa_handler = sig_catch;

    if((sigaction(SIGTERM,&act,NULL) != 0) ||
            (sigaction(SIGINT,&act,NULL) != 0) ||
            (sigaction(SIGHUP,&act,NULL) != 0)){
        I2ErrLog(eh,"sigaction(): %M");
        exit(1);
    }

    /*
     * Setup portrange
     */
    if(!OWPContextConfigSetV(ctx,OWPTestPortRange,
                (void*) &appctx.opt.port_range)){
        I2ErrLog(eh,
                "OWPContextConfigSetV(): Unable to set OWPTestPortRange.");
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
     * Set OWPEndDelay
     */
    if(appctx.opt.setEndDelay &&
            !OWPContextConfigSetV(ctx,OWPEndDelay,
                (void*)&appctx.opt.endDelay)){
        I2ErrLog(eh,"Unable to set Context var: %M");
        exit(1);
    }

    /*
     * Set the detach processes flag.
     */
    if(!OWPContextConfigSetV(ctx,OWPDetachProcesses,(void*)True)){
        I2ErrLog(eh,"Unable to set Context var: %M");
        exit(1);
    }

#ifdef DEBUG
    /*
     * Setup debugging of child prcesses.
     */
    if(appctx.opt.childwait &&
            !OWPContextConfigSetV(ctx,OWPChildWait,
                (void*)appctx.opt.childwait)){
        I2ErrLog(eh,"Unable to set Context var: %M");
        exit(1);
    }
#endif

    /*
     * Main loop - loop over two connections collecting the data
     * and placing a summary in the directory when the sum-session
     * is complete.
     *
     */
    while(1){
        pow_cntrl       p,q;
        OWPAcceptType   aval;
        uint32_t        sum;
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

	/* If the sessions haven't been initialized, do the init phase */
        if(!p->numPackets){
            (void)SetupSession(ctx,q,p,NULL);
            goto NextConnection;
        }

        /* init vars for loop */
        lastnum=OWPULongToNum64(0);
        aval = OWP_CNTRL_ACCEPT;

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
                p->call_stop = False;
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
         *
         * stats structures are specific to the file - so any previous
         * one is no longer valid when we get back here.
         */
        if(stats){
            OWPStatsFree(stats);
            stats = NULL;
        }

        for(sum=0;sum<numSummaries;sum++){
            uint32_t            nrecs;
            OWPSessionHeaderRec hdr;
            OWPNum64            localstop;
            FILE                *fp=NULL;
            OWPBoolean          dotf = False;

            if(sig_check())
                goto NextConnection;

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
             */
            for(nrecs=0;nrecs<appctx.opt.numBucketPackets;nrecs++){
                lastnum = OWPNum64Add(lastnum,
                        OWPScheduleContextGenerateNextDelta(p->sctx));

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
                rc = OWPStopSessionsWait(p->cntrl,&stopnum,&pow_intr,
                        &aval,&err_ret);
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

            /* Time's up! Get to work.        */
            p->session_started = True;

            /*
             * If "sender" then Fetch records for
             * just this sub-session from remote side into the file.
             * -- initialize special 'send' control pointer if needed
             * (if can't - don't fail on the error. This allows long-lived
             * sessions to survive temporary network problems and show
             * the loss! - just goto 'cleanup')
             */
            if(appctx.opt.sender){
                /*
                 * Delete the stats record if it exists - this will
                 * effectively create a new file, so the stats record
                 * is no longer valid.
                 */
                if(stats){
                    OWPStatsFree(stats);
                    stats = NULL;
                }

                /*
                 * Move file pointer to beginning and set file size to zero
                 * before Fetching data.
                 */
                if(fseeko(p->testfp,0,SEEK_SET) != 0){
                    I2ErrLog(eh,"fseeko(): %M");
                    break;
                }
                if((rc = ftruncate(fileno(p->testfp),0)) != 0){
                    I2ErrLog(eh,"write_session(): ftruncate(): %M");
                    break;
                }
                /*
                 * Refresh read-only file pointer due to above trunc
                 */
                if(fflush(p->fp) != 0){
                    I2ErrLog(eh,"fflush(): %M");
                    break;
                }

                /*
                 * Fetch the data and put it in testfp
                 */
                nrecs = FetchSession(p,
                        appctx.opt.numBucketPackets*sum,
                        (appctx.opt.numBucketPackets*(sum+1))-1,
                        &err_ret);
                if(!nrecs){
                    if(err_ret >= OWPErrWARNING){
                        /*
                         * Server denied request - report error
                         */
                        I2ErrLog(eh,"write_session(): OWPFetchSession(): Server denied request for session data seq_no[%llu-%llu]",
                                appctx.opt.numBucketPackets*sum,
                                appctx.opt.numBucketPackets*(sum+1));
                    }
                    /*
                     * If this fails - continue to next summary
                     * so we see packet loss during temporary network
                     * failures.
                     */
                    continue;
                }

            }

            /*
             * This section reads the packet records
             * in the time period of this sum-session.
             */
            (void)OWPReadDataHeader(ctx,p->fp,&hdr);

            /*
             * If no data, then skip.
             */
            if(!hdr.header){
                I2ErrLog(eh,"OWPReadDataHeader failed");
                break;
            }

            /*
             * Create the stats record if empty. (first time in loop)
             */
            if(!stats){
                if( !(stats = OWPStatsCreate(ctx,p->fp,&hdr,NULL,NULL,'m',
                                appctx.opt.bucketWidth))){
                    I2ErrLog(eh,"OWPStatsCreate failed");
                    break;
                }
            }
            
            /* Set the timestamp flag here */
            if (appctx.opt.display_unix_ts == True)
                stats->display_unix_ts = True;

            if (appctx.opt.is_json_format == True)
                stats->is_json_format = True;

            /*
             * Parse the data and compute the statistics
             */
            if( !OWPStatsParse(stats,NULL,stats->next_oset,
                        appctx.opt.numBucketPackets*sum,
                        (appctx.opt.numBucketPackets*(sum+1)))){
                I2ErrLog(eh,"OWPStatsParse failed");
                break;
            }

            /*
             * No more data to parse.
             */
            if(!p->call_stop && !stats->sent)
                break;

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

            while(!(fp = fopen(tfname,"w")) && errno==EINTR){
                if(sig_check())
                    goto NextConnection;
            }
            if(!fp){

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
                 * Skip to next sum-session.
                 */
                goto cleanup;
            }
            dotf=True;

            /*
             * File is good, write to it.
             */
            if(!OWPStatsPrintMachine(stats,fp)){
                goto cleanup;
            }

            /*
             * Relink the incomplete file as a complete one.
             */
            strcpy(fname,tfname);
            sprintf(&fname[ext_offset],"%s",POW_SUM_EXT);
            if(link(tfname,fname) != 0){
                /* note, but ignore the error */
                I2ErrLog(eh,"link(%s,%s): %M",tfname,fname);
            }
            if (appctx.opt.is_json_format == True)
            {
                 // open files
                 // write stats
            }


            if(appctx.opt.printfiles){
                /* Make sure file is complete */
                fflush(fp);
                /* Now print the filename to stdout */
                fprintf(stdout,"%s\n",fname);
                fflush(stdout);
            }

cleanup:
            if(fp){
                fclose(fp);
            }
            fp = NULL;

            /* unlink old name */
            if(dotf && (unlink(tfname) != 0)){
                /* note, but ignore the error */
                I2ErrLog(eh,"unlink(%s): %M",tfname);
            }
            dotf=False;

            if(!p->cntrl)
                break;
        }

        if(p->cntrl && p->call_stop){
            if(OWPStopSessions(p->cntrl,&pow_intr,&aval)<OWPErrWARNING){
                OWPControlClose(p->cntrl);
                p->cntrl = NULL;
            }
        }

        /*
         * Write out the complete owp session file.
         */
        write_session(p,aval,False);

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
