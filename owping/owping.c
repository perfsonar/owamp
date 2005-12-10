/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabls-mode: nil -*-
 *      $Id$
 */
/************************************************************************
 *                                                                       *
 *                           Copyright (C)  2002                         *
 *                               Internet2                               *
 *                           All Rights Reserved                         *
 *                                                                       *
 ************************************************************************/
/*
 *    File:         owping.c
 *
 *    Author:       Jeff Boote
 *                  Anatoly Karp
 *                  Internet2
 *
 *    Date:         Thu Apr 25 12:22:31  2002
 *
 *    Description:    
 *
 *    Initial implementation of owping commandline application. This
 *    application will measure active one-way udp latencies.
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <I2util/util.h>
#include <owamp/owamp.h>

#include "./owpingP.h"

/*
 * The owping context
 */
static  ow_ping_trec    ping_ctx;
static  I2ErrHandle     eh;
static  char            tmpdir[PATH_MAX+1];
static  u_int8_t        aesbuff[16];

    static void
print_conn_args()
{
    fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n",
            "              [Connection Args]",
            "   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen",
            "   -k keyfile     AES keyfile to use with Authenticated/Encrypted modes",
            "   -u username    username to use with Authenticated/Encrypted modes",
            "   -S srcaddr     use this as a local address for control connection and tests");
}

    static void
print_test_args()
{
    fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
            "              [Test Args]",
            "   -f | -F file   perform one-way test from testhost [and save results to file]",
            "   -t | -T file   perform one-way test to testhost [and save results to file]",
            "   -c count       number of test packets",
            "   -i wait        mean average time between packets (seconds)",
            "   -L timeout     maximum time to wait for a packet before declaring it lost (seconds)",
            "   -s padding     size of the padding added to each packet (bytes)",
            "   -z delayStart  time to wait before executing test (seconds)"
            );
}

    static void
print_output_args()
{
    fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n%s\n%s\n",
            "              [Output Args]",
            "   -h             print this message and exit",
            "   -Q             run the test and exit without reporting statistics",
            "   -M             print machine (perl) readable summary",
            "   -R             print RAW data: \"SEQNO STIME SS SERR RTIME RS RERR TTL\\n\"",
            "   -v             print out individual delays",
            "   -a alpha       report an additional percentile level for the delays"
           );
}

    static void
usage(const char *progname, const char *msg)
{
    if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
    if (!strcmp(progname, "owping")) {
        fprintf(stderr,
                "usage: %s %s\n%s\n", 
                progname, "[arguments] testaddr [servaddr]",
                "[arguments] are as follows: "
               );
        fprintf(stderr, "\n");
        print_conn_args();

        fprintf(stderr, "\n");
        print_test_args();

        fprintf(stderr, "\n");
        print_output_args();

    } else if (!strcmp(progname, "owstats")) {
        fprintf(stderr,
                "usage: %s %s\n%s\n",
                progname, "[arguments] sessionfile",
                "[arguments] are as follows: "
               );
        fprintf(stderr, "\n");
        print_output_args();
    } else if (!strcmp(progname, "owfetch")) {
        fprintf(stderr,
                "usage: %s %s\n%s\n",
                progname, "[arguments] servaddr [SID savefile]+",
                "[arguments] are as follows: "
               );
        fprintf(stderr, "\n");
        print_conn_args();
        fprintf(stderr, "\n");
        print_output_args();
    }
    else{
        fprintf(stderr,
                "usage: %s is not a known name for this program.\n",progname);
    }

    fprintf(stderr, "Distribution: %s\n", PACKAGE_STRING);

    return;
}

static void
    FailSession(
            OWPControl    control_handle    __attribute__((unused))
            )
{
    /*
     * Session denied - report error, close connection, and exit.
     */
    I2ErrLog(eh, "Session Failed!");
    fflush(stderr);

    /* TODO: determine "reason" for denial and report */
    (void)OWPControlClose(ping_ctx.cntrl);
    exit(1);
}

/*
 * RAW ascii format is:
 * "SEQ STIME SS SERR RTIME RS RERR\n"
 * name     desc                type
 * SEQ      sequence number     unsigned long
 * STIME    sendtime            owptimestamp (%020llu)
 * SS       send synchronized   boolean unsigned
 * SERR     send err estimate   float (%g)
 * RTIME    recvtime            owptimestamp (%020llu)
 * RS       recv synchronized   boolean unsigned
 * RERR     recv err estimate   float (%g)
 * TTL      ttl                 unsigned short
 */
#define RAWFMT "%lu %020llu %u %g %020llu %u %g %u\n"
static int
printraw(
        OWPDataRec    *rec,
        void        *udata
        )
{
    FILE        *out = (FILE*)udata;

    fprintf(out,RAWFMT,(unsigned long)rec->seq_no,
            rec->send.owptime,rec->send.sync,
            OWPGetTimeStampError(&rec->send),
            rec->recv.owptime,rec->recv.sync,
            OWPGetTimeStampError(&rec->recv),
            rec->ttl);
    return 0;
}

/*
 * Does statistical output parsing.
 */
int
do_stats(
        OWPContext    ctx,
        FILE        *output,
        FILE        *fp,
        char        *from,
        char        *to
        )
{
    u_int32_t           num_rec;
    OWPSessionHeaderRec hdr;
    OWPStats            stats;

    if(!(num_rec = OWPReadDataHeader(ctx,fp,&hdr))){
        I2ErrLog(eh, "OWPReadDataHeader:Empty file?");
        return -1;
    }

    /*
     * If raw data is requested, no summary information is needed.
     */
    if(ping_ctx.opt.raw){
        if(OWPParseRecords(ctx,fp,num_rec,hdr.version,printraw,output)
                < OWPErrWARNING){
            I2ErrLog(eh,"OWPParseRecords(): %M");
            return -1;
        }
        return 0;
    }

    /*
     * Create a "stats" object to hold the aggregate statistics
     */
    if( !(stats = OWPStatsCreate(ctx,fp,&hdr,from,to,
                    ping_ctx.opt.units,ping_ctx.opt.bucket_width))){
        I2ErrLog(eh,"OWPStatsCreate: failed");
        return -1;
    }

    /*
     * Parse the file to fill it.
     */
    if( !OWPStatsParse(stats,(ping_ctx.opt.records)?output:NULL,0,0,~0)){
        I2ErrLog(eh,"OWPStatsParse: failed");
        OWPStatsFree(stats);
        return -1;
    }

    /*
     * Print out summary info
     */
    if(ping_ctx.opt.machine){
        OWPStatsPrintMachine(stats,output);
    }
    else{
        OWPStatsPrintSummary(stats,output,
                ping_ctx.opt.percentiles,
                ping_ctx.opt.npercentiles);
    }

    OWPStatsFree(stats);

    return 0;
}


static FILE *
tfile(
        OWPContext    eh
     )
{
    char    fname[PATH_MAX+1];
    int    fd;
    FILE    *fp;

    strcpy(fname,tmpdir);
    strcat(fname,_OWPING_PATH_SEPARATOR);
    strcat(fname,_OWPING_TMPFILEFMT);

    if((fd = mkstemp(fname)) < 0){
        I2ErrLog(eh,"mkstemp(%s): %M",fname);
        return NULL;
    }

    if( !(fp = fdopen(fd,"w+b"))){
        I2ErrLog(eh,"fdopen(%s:(%d)): %M",fname,fd);
        return NULL;
    }

    if(unlink(fname) != 0){
        I2ErrLog(eh,"unlink(%s): %M",fname);
        while((fclose(fp) != 0) && (errno == EINTR));
        return NULL;
    }

    return fp;
}

/*
 ** Fetch a session with the given <sid> from the remote server.
 ** It is assumed that control connection has been opened already.
 */
FILE *
owp_fetch_sid(
        char        *savefile,
        OWPControl    cntrl,
        OWPSID        sid
        )
{
    char        *path;
    FILE        *fp;
    u_int32_t    num_rec;
    OWPErrSeverity    rc=OWPErrOK;

    /*
     * Prepare paths for datafiles. Unlink if not keeping data.
     */
    if(savefile){
        path = savefile;
        if( !(fp = fopen(path,"w+b"))){
            I2ErrLog(eh,"owp_fetch_sid:fopen(%s):%M",path);
            return NULL;
        }
    }
    else if( !(fp = tfile(eh))){
        return NULL;
    }

    /*
     * Ask for complete session 
     */
    num_rec = OWPFetchSession(cntrl,fp,0,(u_int32_t)0xFFFFFFFF,sid,&rc);
    if(!num_rec){
        if(path)
            (void)unlink(path);
        if(rc < OWPErrWARNING){
            I2ErrLog(eh,"owp_fetch_sid:OWPFetchSession error?");
            return NULL;
        }
        /*
         * server denied request...
         */
        I2ErrLog(eh,
                "owp_fetch_sid:Server denied request for to session data");
        return NULL;
    }

    return fp;
}

static OWPBoolean
getclientkey(
        OWPContext    ctx __attribute__((unused)),
        const OWPUserID    userid    __attribute__((unused)),
        OWPKey        key_ret,
        OWPErrSeverity    *err_ret __attribute__((unused))
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
        OWPContext    ctx,
        char        *progname,
        ow_ping_trec    *pctx
        )
{
    if(pctx->opt.identity){
        u_int8_t    *aes = NULL;

        /*
         * If keyfile specified, attempt to get key from there.
         */
        if(pctx->opt.keyfile){
            /* keyfile */
            FILE    *fp;
            int    rc = 0;
            char    *lbuf=NULL;
            size_t    lbuf_max=0;

            if(!(fp = fopen(pctx->opt.keyfile,"r"))){
                I2ErrLog(eh,"Unable to open %s: %M",
                        pctx->opt.keyfile);
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
             *     open tty and get passphrase.
             *    (md5 the passphrase to create an aes key.)
             */
            char        *passphrase;
            char        ppbuf[MAX_PASSPHRASE];
            char        prompt[MAX_PASSPROMPT];
            I2MD5_CTX    mdc;
            size_t        pplen;

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
            OWPGetAESKeyFunc    getaeskey = getclientkey;

            if(!OWPContextConfigSetF(ctx,OWPGetAESKey,(OWPFunc)getaeskey)){
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
        char    *s = ping_ctx.opt.authmode;
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

static OWPBoolean
parse_percentile(
        char        *str,
        float       **alpha_ret,
        u_int32_t   *nalpha_ret
        )
{
    u_int32_t    i,nalpha;
    char        *tstr;
    float       *alpha;

    if(!str) return False;

    /*
     * count number of alpha specified.
     */
    nalpha=1;
    tstr=str;
    while((tstr=strchr(tstr,','))){
        nalpha++;
        tstr++;
    }

    /*
     * Allocate alpha array.
     */
    if(!(alpha = calloc(nalpha,sizeof(float)))){
        I2ErrLogP(eh,errno,"Can't alloc float[%d] for alpha list: %M",
                nalpha);
        return False;
    }

    /*
     * parse string with strtok to grab each float
     */
    i=0;
    for(i=0,tstr = strtok(str,",");
            (i<nalpha) && tstr;
            tstr = strtok(NULL,","),i++){
        char    *endptr;
        double    dval;

        dval = strtod(tstr,&endptr);
        if((endptr == tstr) || (dval < 0.0) || (dval > 100.0)){
            I2ErrLogP(eh,errno,
                    "Invalid numeric value (%s) for percentile",
                    tstr);
            goto FAILED;
        }
        alpha[i] = dval;
    }

    if(i != nalpha){
        I2ErrLogP(eh,errno,"Unable to parse percentiles specification");
        goto FAILED;
    }

    *alpha_ret = alpha;
    *nalpha_ret = nalpha;
    return True;

FAILED:
    free(alpha);
    return False;
}

/*
 * TODO: Find real max padding sizes based upon size of headers
 */
#define    MAX_PADDING_SIZE    65000

static OWPBoolean
parse_slots(
        char        *sched,
        OWPSlot        **slots_ret,
        u_int32_t    *nslots_ret
        )
{
    u_int32_t    i,nslots;
    char        *tstr;
    OWPSlot        *slots = NULL;

    if(!sched) return False;

    /*
     * count number of slots specified.
     */
    nslots=1;
    tstr=sched;
    while((tstr=strchr(tstr,','))){
        nslots++;
        tstr++;
    }

    /*
     * Allocate slot array.
     */
    if(!(slots = calloc(nslots,sizeof(OWPSlot)))){
        I2ErrLogP(eh,errno,"Can't alloc %d slots for schedule: %M",
                nslots);
        return False;
    }

    /*
     * parse string with strtok to grab each slot and fill the record
     */
    i=0;
    for(i=0,tstr = strtok(sched,",");
            (i<nslots) && tstr;
            tstr = strtok(NULL,","),i++){
        char    *endptr;
        double    dval;

        dval = strtod(tstr,&endptr);
        if(endptr == tstr){
            I2ErrLogP(eh,errno,
                    "Invalid numeric value (%s) for schedule",
                    tstr);
            goto FAILED;
        }
        if(strlen(endptr) > 1){
            I2ErrLogP(eh,errno,
                    "Invalid slot type (%s) for schedule",
                    endptr);
            goto FAILED;
        }
        switch(tolower(*endptr)){
            case '\0':
            case 'e':
                /* exponential slot */
                slots[i].slot_type = OWPSlotRandExpType;
                slots[i].rand_exp.mean = OWPDoubleToNum64(dval);
                break;
            case 'f':
                /* fixed offset slot */
                slots[i].slot_type = OWPSlotLiteralType;
                slots[i].literal.offset =OWPDoubleToNum64(dval);
                break;
            default:
                I2ErrLogP(eh,errno,
                        "Invalid slot type (%s) for schedule",
                        endptr);
                goto FAILED;
                break;
        }
    }

    if(i != nslots){
        I2ErrLogP(eh,errno,"Unable to parse schedule specification");
        goto FAILED;
    }

    *slots_ret = slots;
    *nslots_ret = nslots;
    return True;

FAILED:
    free(slots);
    return False;
}

static OWPBoolean
parse_ports(
        char        *pspec
        )
{
    char        *tstr,*endptr;
    long        tint;

    if(!pspec) return False;

    tstr = pspec;
    endptr = NULL;
    while(isspace(*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto FAILED;
    }
    ping_ctx.portrec.low = (u_int16_t)tint;

    while(isspace(*endptr)) endptr++;

    switch(*endptr){
        case '\0':
            /* only allow a single value if it is 0 */
            if(ping_ctx.portrec.low){
                goto FAILED;
            }
            ping_ctx.portrec.high = ping_ctx.portrec.low;
            goto DONE;
            break;
        case '-':
            endptr++;
            break;
        default:
            goto FAILED;
    }

    tstr = endptr;
    endptr = NULL;
    while(isspace(*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto FAILED;
    }
    ping_ctx.portrec.high = (u_int16_t)tint;

    if(ping_ctx.portrec.high < ping_ctx.portrec.low){
        goto FAILED;
    }

DONE:
    /*
     * If ephemeral is specified, shortcut but not setting.
     */
    if(!ping_ctx.portrec.high && !ping_ctx.portrec.low)
        return True;

    /*
     * Set.
     */
    ping_ctx.opt.portspec = &ping_ctx.portrec;
    return True;

FAILED:
    I2ErrLogP(eh,EINVAL,"Invalid port-range (-P): \"%s\": %M",pspec);
    return False;
}

int
main(
        int     argc,
        char    **argv
    )
{
    char                *progname;
    OWPErrSeverity      err_ret = OWPErrOK;
    I2LogImmediateAttr  ia;
    OWPContext          ctx;
    OWPTimeStamp        curr_time;
    OWPTestSpec         tspec;
    OWPSlot             slot;
    OWPNum64            rtt_bound;
    OWPNum64            delayStart;
    OWPSID              tosid, fromsid;
    OWPAcceptType       acceptval;
    OWPErrSeverity      err;
    FILE                *fromfp=NULL;
    char                localbuf[NI_MAXHOST+1+NI_MAXSERV+1];
    char                remotebuf[NI_MAXHOST+1+NI_MAXSERV+1];
    char                *local, *remote;

    int                 ch;
    char                *endptr = NULL;
    char                optstring[128];
    static char         *conn_opts = "A:k:S:u:";
    static char         *test_opts = "c:D:fF:H:i:L:P:s:tT:z:";
    static char         *out_opts = "a:b:Mn:QRv";
    static char         *gen_opts = "h";
#ifndef    NDEBUG
    static char         *debug_opts = "w";
#endif

    ia.line_info = (I2NAME | I2MSG);
#ifndef    NDEBUG
    ia.line_info |= (I2LINE | I2FILE);
#endif
    ia.fp = stderr;

    progname = (progname = strrchr(argv[0], '/')) ? progname+1 : *argv;

    /*
     * Start an error logging session for reporing errors to the
     * standard error
     */
    eh = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
    if(! eh) {
        fprintf(stderr, "%s : Couldn't init error module\n", progname);
        exit(1);
    }

    if( (endptr = getenv("TMPDIR")))
        strncpy(tmpdir,endptr,PATH_MAX);
    else
        strncpy(tmpdir,_OWPING_DEF_TMPDIR,PATH_MAX);

    if(strlen(tmpdir) + strlen(_OWPING_PATH_SEPARATOR) +
            strlen(_OWPING_TMPFILEFMT) > PATH_MAX){
        I2ErrLog(eh, "TMPDIR too long");
        exit(1);
    }

    memset(&ping_ctx,0,sizeof(ping_ctx));

    /*
     * Initialize library with configuration functions.
     */
    if( !(ping_ctx.lib_ctx = OWPContextCreate(eh))){
        I2ErrLog(eh, "Unable to initialize OWP library.");
        exit(1);
    }
    ctx = ping_ctx.lib_ctx;

    /* Set default options. */
    ping_ctx.opt.records = ping_ctx.opt.childwait 
        = ping_ctx.opt.from = ping_ctx.opt.to = ping_ctx.opt.quiet
        = ping_ctx.opt.raw = ping_ctx.opt.machine = False;
    ping_ctx.opt.save_from_test = ping_ctx.opt.save_to_test 
        = ping_ctx.opt.identity = ping_ctx.opt.keyfile 
        = ping_ctx.opt.srcaddr = ping_ctx.opt.authmode = NULL;
    ping_ctx.opt.numPackets = 100;
    ping_ctx.opt.lossThreshold = 0.0;
    ping_ctx.opt.delayStart = 0.0;
    ping_ctx.opt.percentiles = NULL;
    ping_ctx.opt.padding = 0;
    ping_ctx.mean_wait = (float)0.1;
    ping_ctx.opt.units = 'm';
    ping_ctx.opt.bucket_width = 0.0001;

    /* Create options strings for this program. */
    if (!strcmp(progname, "owping")) {
        strcpy(optstring, conn_opts);
        strcat(optstring, test_opts);
        strcat(optstring, out_opts);
    } else if (!strcmp(progname, "owstats")) {
        strcpy(optstring, out_opts);
    } else if (!strcmp(progname, "owfetch")) {
        strcpy(optstring, conn_opts);
        strcat(optstring, out_opts);
    }
    else{
        usage(progname, "Invalid program name.");
        exit(1);
    }

    strcat(optstring, gen_opts);
#ifndef    NDEBUG
    strcat(optstring,debug_opts);
#endif

    while((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch) {
            u_int32_t   tlng;

            /* Connection options. */

            case 'A':
                if(!(ping_ctx.opt.authmode = strdup(optarg))){
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'k':
                if (!(ping_ctx.opt.keyfile = strdup(optarg))){
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'S':
                if(!(ping_ctx.opt.srcaddr = strdup(optarg))){
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;
            case 'u':
                if(!(ping_ctx.opt.identity = strdup(optarg))){
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                break;

                /* Test options. */

            case 'c':
                ping_ctx.opt.numPackets = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname,
                            "Invalid value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'D':
                if(ping_ctx.typeP){
                    usage(progname,
                            "Invalid option \'-D\'. Can only set one \'-D\' or \'-H\'.");
                    exit(1);
                }
                tlng = strtoul(optarg,&endptr,0);
                /*
                 * Validate int conversion and verify user only sets
                 * last 6 bits (DSCP must fit in 6 bits - RFC 2474.)
                 */
                if((*endptr != '\0') || (tlng & ~0x3F)){
                    usage(progname,
                            "Invalid value for option \'-D\'. DSCP value expected");
                    exit(1);
                }
                ping_ctx.typeP = tlng << 24;
                break;
            case 'F':
                if (!(ping_ctx.opt.save_from_test = strdup(optarg))){
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                /* fall through */
            case 'f':
                ping_ctx.opt.from = True;
                break;
            case 'H':
                if(ping_ctx.typeP){
                    usage(progname,
                            "Invalid option \'-H\'. Can only set one \'-H\' or \'-D\'.");
                    exit(1);
                }
                tlng = strtoul(optarg,&endptr,0);
                /*
                 * Validate int conversion and verify user only sets
                 * last 16 bits (PHB must fit in 16 bits - RFC 2836.)
                 */
                if((*endptr != '\0') || (tlng & ~0xFFFF)){
                    usage(progname,
                            "Invalid value for option \'-H\'. PHB value expected");
                    exit(1);
                }
                /* set second bit to specify PHB per owamp spec. */
                ping_ctx.typeP = 0x40000000;
                /* copy 16 bit PHB into next 16 bits of typeP. */
                ping_ctx.typeP |= (tlng << 14);
                break;
            case 'T':
                if (!(ping_ctx.opt.save_to_test = strdup(optarg))) {
                    I2ErrLog(eh,"malloc:%M");
                    exit(1);
                }
                /* fall through */
            case 't':
                ping_ctx.opt.to = True;
                break;
            case 'i':
                if(!parse_slots(optarg,&ping_ctx.slots,
                            &ping_ctx.nslots)){
                    usage(progname, "Invalid Schedule.");
                    exit(1);
                }
                break;
            case 's':
                ping_ctx.opt.padding = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname, 
                            "Invalid value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'L':
                ping_ctx.opt.lossThreshold = strtod(optarg,&endptr);
                if((*endptr != '\0') ||
                        (ping_ctx.opt.lossThreshold < 0.0)){
                    usage(progname, 
                            "Invalid \'-L\' value. Positive float expected");
                    exit(1);
                }
                break;
            case 'P':
                if(!parse_ports(optarg)){
                    usage(progname,
                            "Invalid test port range specified.");
                    exit(1);
                }
                break;
            case 'z':
                ping_ctx.opt.delayStart = strtod(optarg,&endptr);
                if((*endptr != '\0') ||
                        (ping_ctx.opt.delayStart < 0.0)){
                    usage(progname, 
                            "Invalid \'-z\' value. Positive float expected");
                    exit(1);
                }
                break;

                /* Output options */

            case 'b':
                ping_ctx.opt.bucket_width = strtod(optarg,&endptr);
                if((*endptr != '\0') ||
                        (ping_ctx.opt.bucket_width <= 0.0)){
                    usage(progname, 
                            "Invalid \'-b\' value. Positive float expected");
                    exit(1);
                }
                break;
            case 'v':
                ping_ctx.opt.records = True;
                break;
            case 'M':
                ping_ctx.opt.machine = True;
                break;
            case 'n':
                if(OWPStatsScaleFactor(optarg[0],NULL,NULL) == 0.0){
                    usage(progname,"Invalid \'-n\' value.");
                    exit(1);
                }
                ping_ctx.opt.units = optarg[0];
                break;
            case 'Q':
                ping_ctx.opt.quiet = True;
                break;
            case 'R':
                ping_ctx.opt.raw = True;
                break;
            case 'a':
                if(!parse_percentile(optarg,&ping_ctx.opt.percentiles,
                            &ping_ctx.opt.npercentiles)){
                    usage(progname, "Invalid \'-a\' alpha list .");
                    exit(1);
                }
                break;
#ifndef    NDEBUG
            case 'w':
                ping_ctx.opt.childwait = True;
                break;
#endif

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

    if(ping_ctx.opt.raw || ping_ctx.opt.machine){
        ping_ctx.opt.quiet = True;
    }

    if(ping_ctx.opt.records && ping_ctx.opt.quiet){
        I2ErrLog(eh,"Ignoring \'-v\'");
        ping_ctx.opt.records = False;
    }


    /*
     * Handle 3 possible cases (owping, owfetch, owstats) one by one.
     */
    if (!strcmp(progname, "owping")){

        if((argc < 1) || (argc > 2)){
            usage(progname, NULL);
            exit(1);
        }

        if(!ping_ctx.opt.to && !ping_ctx.opt.from)
            ping_ctx.opt.to = ping_ctx.opt.from = True;

        ping_ctx.remote_test = argv[0];
        if(argc > 1)
            ping_ctx.remote_serv = argv[1];
        else
            ping_ctx.remote_serv = ping_ctx.remote_test;

        /*
         * This is in reality dependent upon the actual protocol used
         * (ipv4/ipv6) - it is also dependent upon the auth mode since
         * authentication implies 128bit block sizes.
         */
        if(ping_ctx.opt.padding > MAX_PADDING_SIZE)
            ping_ctx.opt.padding = MAX_PADDING_SIZE;

        owp_set_auth(ctx, progname, &ping_ctx); 

        /*
         * Determine schedule.
         */
        if(!ping_ctx.slots){
            tspec.nslots = 1;
            slot.slot_type = OWPSlotRandExpType;
            slot.rand_exp.mean = OWPDoubleToNum64(
                    ping_ctx.mean_wait);
            tspec.slots = &slot;
        }
        else{
            tspec.nslots = ping_ctx.nslots;
            tspec.slots = ping_ctx.slots;
        }

        /*
         * Setup test port range if specified.
         */
        if(ping_ctx.opt.portspec &&
                !OWPContextConfigSetV(ctx,OWPTestPortRange,
                    (void*)ping_ctx.opt.portspec)){
            I2ErrLog(eh,
                    "OWPContextConfigSetV(): Unable to set OWPTestPortRange?!");
            exit(1);
        }
#ifndef    NDEBUG
        /*
         * Setup debugging of child processes.
         */
        if(ping_ctx.opt.childwait &&
                !OWPContextConfigSetV(ctx,
                    OWPChildWait,
                    (void*)ping_ctx.opt.childwait)){
            I2ErrLog(eh,
                    "OWPContextConfigSetV(): Unable to set OWPChildWait?!");
        }
#endif

        /*
         * Open connection to owampd.
         */

        ping_ctx.cntrl = OWPControlOpen(ctx, 
                OWPAddrByNode(ctx, ping_ctx.opt.srcaddr),
                OWPAddrByNode(ctx, ping_ctx.remote_serv),
                ping_ctx.auth_mode,ping_ctx.opt.identity,
                NULL,&err_ret);
        if (!ping_ctx.cntrl){
            I2ErrLog(eh, "Unable to open control connection.");
            exit(1);
        }

        rtt_bound = OWPGetRTTBound(ping_ctx.cntrl);
        /*
         * Set the loss threshold to 2 seconds longer then the
         * rtt delay estimate. 2 is just a guess for a good number
         * based upon how impatient this command-line user gets for
         * results. Caveat: For the results to have any statistical
         * relevance the lossThreshold should be specified on the
         * command line. (You have to wait until this long after
         * the end of a test to declare the test over in order to
         * be confident that you have accepted all "duplicates"
         * that could come in during the test.)
         */
        if(ping_ctx.opt.lossThreshold <= 0.0){
            ping_ctx.opt.lossThreshold =
                OWPNum64ToDouble(rtt_bound) + 2.0;
        }

        if(ping_ctx.opt.lossThreshold < ping_ctx.opt.bucket_width){
            I2ErrLog(eh,
                        "Invalid test specification: LossThreshold(%f) \'-L\' < BucketWidth (%f) \'-b\'",
                        ping_ctx.opt.lossThreshold,ping_ctx.opt.bucket_width);
            exit(1);
        }

        /*
         * Compute a "min" start time.
         *
         * For now estimate a start time that allows both sides to
         * setup the session before that time:
         *     num_rtt * rtt_est + 1sec from now
         *
         *  There will be a rtt delay for the start sessions message
         *  and for each test request. For the default case, this
         *  will be 3 rtt's.
         */
        if(!OWPGetTimeOfDay(ctx,&curr_time)){
            I2ErrLogP(eh,errno,"Unable to get current time:%M");
            exit(1);
        }
        /* using ch to hold num_rtt */
        ch = 1;    /* startsessions command */
        if(ping_ctx.opt.to) ch++;
        if(ping_ctx.opt.from) ch++;
        tspec.start_time = OWPNum64Add(OWPNum64Mult(rtt_bound,
                                        OWPULongToNum64(ch)),
                                    OWPULongToNum64(1));

        /*
         * If the specified start time is greater than the "min"
         * start time, then use it.
         */
        if(ping_ctx.opt.delayStart > 0.0){
            delayStart = OWPDoubleToNum64(ping_ctx.opt.delayStart);
        }else{
            delayStart = OWPULongToNum64(0);
        }
        if(OWPNum64Cmp(delayStart,tspec.start_time) > 0){
            tspec.start_time = delayStart;
        }

        /*
         * Turn "relative" start time into an absolute time.
         */
        tspec.start_time = OWPNum64Add(tspec.start_time,curr_time.owptime);


        tspec.loss_timeout =
            OWPDoubleToNum64(ping_ctx.opt.lossThreshold);

        tspec.typeP = ping_ctx.typeP;
        tspec.packet_size_padding = ping_ctx.opt.padding;
        tspec.npackets = ping_ctx.opt.numPackets;


        /*
         * Prepare paths for datafiles. Unlink if not keeping data.
         */
        if(ping_ctx.opt.to) {
            if (!OWPSessionRequest(ping_ctx.cntrl, NULL, False,
                        OWPAddrByNode(ctx,ping_ctx.remote_test),
                        True,(OWPTestSpec*)&tspec,
                        NULL,tosid,&err_ret))
                FailSession(ping_ctx.cntrl);
        }

        if(ping_ctx.opt.from) {

            if (ping_ctx.opt.save_from_test) {
                fromfp = fopen(ping_ctx.opt.save_from_test,
                        "w+b");
                if(!fromfp){
                    I2ErrLog(eh,"fopen(%s):%M", 
                            ping_ctx.opt.save_from_test);
                    exit(1);
                }
            } else if( !(fromfp = tfile(eh))){
                exit(1);
            }

            if (!OWPSessionRequest(ping_ctx.cntrl,
                        OWPAddrByNode(ctx,ping_ctx.remote_test),
                        True, NULL, False,(OWPTestSpec*)&tspec,
                        fromfp,fromsid,&err_ret))
                FailSession(ping_ctx.cntrl);
        }


        if(OWPStartSessions(ping_ctx.cntrl) < OWPErrINFO)
            FailSession(ping_ctx.cntrl);

        /*
         * Give an estimate for when session data will be available.
         */
        if(!ping_ctx.opt.quiet){
            double  duration;
            double  rate;
            double  endtime;

            /*
             * First estimate duration of actual test session.
             */
            rate = OWPTestPacketRate(ctx,&tspec); 

            if(rate <= 0){
                duration = 0.0;
            }
            else{
                duration = (double)tspec.npackets / rate; 
            }

            /*
             * Now wait lossThreshold for duplicate packet detection.
             */
            duration += ping_ctx.opt.lossThreshold;

            /*
             * Now wait for StopSessions messages to be exchanged.
             */
            duration += OWPNum64ToDouble(rtt_bound);

            /*
             * Compute "endtime" based on starttime and duration
             */
            endtime = OWPNum64ToDouble(tspec.start_time) + duration;

            /*
             * Compute a relative time from "endtime" and curr_time.
             */
            if(!OWPGetTimeOfDay(ctx,&curr_time)){
                I2ErrLogP(eh,errno,"Unable to get current time:%M");
                exit(1);
            }

            endtime -= OWPNum64ToDouble(curr_time.owptime);

            fprintf(stdout,
                    "Approximately %.1f seconds until results available\n",
                    endtime);
        }

        /*
         * TODO install sig handler for keyboard interupt - to send 
         * stop sessions. (Currently SIGINT causes everything to be 
         * killed and lost - might be reasonable to keep it that
         * way...)
         */
        if(OWPStopSessionsWait(ping_ctx.cntrl,NULL,NULL,&acceptval,
                    &err)){
            exit(1);
        }

        if (acceptval != 0) {
            I2ErrLog(eh, "Test session(s) Failed...");

            exit(0);
        }

        /*
         * Get "local" and "remote" names for pretty printing
         * if we need them.
         */
        local = remote = NULL;
        if(!ping_ctx.opt.quiet){
            OWPAddr    laddr;
            size_t    lsize;

            /*
             * First determine local address.
             */
            if(ping_ctx.opt.srcaddr){
                laddr = OWPAddrByNode(ctx,
                        ping_ctx.opt.srcaddr);
            }
            else{
                laddr = OWPAddrByLocalControl(
                        ping_ctx.cntrl);
            }
            lsize = sizeof(localbuf);
            OWPAddrNodeName(laddr,localbuf,&lsize);
            if(lsize > 0){
                local = localbuf;
            }
            OWPAddrFree(laddr);

            /*
             * Now determine remote address.
             */
            laddr = OWPAddrByNode(ctx,ping_ctx.remote_test);
            lsize = sizeof(remotebuf);
            OWPAddrNodeName(laddr,remotebuf,&lsize);
            if(lsize > 0){
                remote = remotebuf;
            }
            OWPAddrFree(laddr);
        }

        if(ping_ctx.opt.to && (ping_ctx.opt.save_to_test ||
                    !ping_ctx.opt.quiet || ping_ctx.opt.raw ||
                    ping_ctx.opt.machine)){
            FILE    *tofp;

            tofp = owp_fetch_sid(ping_ctx.opt.save_to_test,
                    ping_ctx.cntrl,tosid);
            if(tofp && (!ping_ctx.opt.quiet || ping_ctx.opt.raw ||
                        ping_ctx.opt.machine) &&
                    do_stats(ctx,stdout,tofp,local,remote)){
                I2ErrLog(eh, "do_stats(\"to\" session): %M");
            }
            if(tofp && fclose(tofp)){
                I2ErrLog(eh,"close(): %M");
            }
        }

        if(fromfp && (!ping_ctx.opt.quiet || ping_ctx.opt.raw ||
                    ping_ctx.opt.machine)){
            if( do_stats(ctx,stdout,fromfp,remote,local)){
                I2ErrLog(eh, "do_stats(\"from\" session): %M");
            }
        }

        if(fromfp && fclose(fromfp)){
            I2ErrLog(eh,"close(): %M");
        }

        exit(0);

    }

    if (!strcmp(progname, "owstats")) {
        FILE        *fp;

        if(!(fp = fopen(argv[0],"rb"))){
            I2ErrLog(eh,"fopen(%s):%M",argv[0]);
            exit(1);
        }

        if ( do_stats(ctx,stdout,fp,NULL,NULL)){
            I2ErrLog(eh,"do_stats() failed.");
            exit(1);
        }

        fclose(fp);

        exit(0);
    }

    if (!strcmp(progname, "owfetch")) {
        int i;
        if((argc%2 == 0) || (argc < 3)){
            usage(progname, NULL);
            exit(1);
        }

        ping_ctx.remote_serv = argv[0];
        argv++;
        argc--;

        owp_set_auth(ctx, progname, &ping_ctx); 

        /*
         * Open connection to owampd.
         */
        ping_ctx.cntrl = OWPControlOpen(ctx, 
                OWPAddrByNode(ctx, ping_ctx.opt.srcaddr),
                OWPAddrByNode(ctx, ping_ctx.remote_serv),
                ping_ctx.auth_mode,ping_ctx.opt.identity,
                NULL,&err_ret);
        if (!ping_ctx.cntrl){
            I2ErrLog(eh, "Unable to open control connection.");
            exit(1);
        }

        for (i = 0; i < argc/2; i++) {
            OWPSID    sid;
            FILE    *fp;
            char    *sname;
            char    *fname;

            sname = *argv++;
            fname = *argv++;
            I2HexDecode(sname, sid, 16);
            if(!(fp = owp_fetch_sid(fname,ping_ctx.cntrl,sid))){
                I2ErrLog(eh,"Unable to fetch sid(%s)",sname);
            }
            else if((!ping_ctx.opt.quiet || ping_ctx.opt.raw ||
                    ping_ctx.opt.machine) &&
                    do_stats(ctx,stdout,fp,NULL,NULL)){
                I2ErrLog(eh,"do_stats() failed.");
            }
            else if(fclose(fp)){
                I2ErrLog(eh,"fclose(): %M");
            }
        }

        exit(0);
    }

    exit(0);
}
