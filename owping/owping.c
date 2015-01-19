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
#include <owamp/owamp.h>
#include <I2util/util.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <signal.h>

#include "./owpingP.h"

/*
 * The owping context
 */
static ow_ping_trec ping_ctx;
static I2ErrHandle  eh;
static char         tmpdir[PATH_MAX+1];
static uint8_t      *pfbuff = NULL;
static size_t       pfbuff_len = 0;
static int          owp_intr = 0;

static char         dirpath[PATH_MAX];
static uint32_t     file_oset,tstamp_oset,ext_oset;

#ifdef TWAMP
#define NWPControlOpen TWPControlOpen
#else
#define NWPControlOpen OWPControlOpen
#endif

#define OWP_PADDING_UNSET (~0)

static void
print_conn_args(
        void
        )
{
    fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n%s\n%s\n",
            "              [Connection Args]",
            "   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen",
            "   -k passphrasefile     passphrasefile to use with Authenticated/Encrypted modes",
            "   -S srcaddr     specify the local address or interface for control connection and tests",
            "   -u username    username to use with Authenticated/Encrypted modes",
            "   -4             connect using IPv4 addresses only",
            "   -6             connect using IPv6 addresses only"
           );
}

static void
print_test_args(
        void
        )
{
    fprintf(stderr,
            "              [Test Args]\n"
            "   -c count       number of test packets\n"
            "   -D DSCP        RFC 2474 style DSCP value for TOS byte\n"
#ifdef TWAMP
            "   -F file        save results to file\n"
#else
            "   -f | -F file   perform one-way test from testhost [and save results to file]\n"
#endif
            "   -i wait        mean average time between packets (seconds)\n"
            "   -L timeout     maximum time to wait for a packet before declaring it lost (seconds)\n"
            "   -P portrange   port range to use during the test\n"
            "   -s padding     size of the padding added to each packet (bytes)\n"
#ifndef TWAMP
            "   -t | -T file   perform one-way test to testhost [and save results to file]\n"
#endif
            "   -z delayStart  time to wait before executing test (seconds)\n"
           );
}

static void
print_output_args(
        void
        )
{
    fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
            "              [Output Args]",
            "   -a alpha       report an additional percentile level for the delays",
            "   -b bucketwidth bin size for histogram calculations",
            "   -M             print machine (perl) readable summary",
            "   -n units       \'n\',\'u\',\'m\', or \'s\'",
            "   -N count       number of test packets (to summarize per sub-session)\n"
            "   -Q             run the test and exit without reporting statistics",
            "   -R             print RAW data: \"SEQNO STIME SS SERR RTIME RS RERR TTL\\n\"",
            "   -v[N]          print out individual delays. You can supply an optional N here to limit the print to the first N packets",
            "   -U             Adds UNIX timestamps when printing individual delays"
           );
}

static void
usage(
        const char *progname,
        const char *msg
        )
{
    if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
    if (!strcmp(progname, "owping") || !strcmp(progname, "twping")) {
        fprintf(stderr,
                "usage: %s %s\n%s\n", 
                progname, "[arguments] testaddr [servaddr]",
                "[arguments] are as follows: "
               );

        fprintf(stderr,"\n%s\n",
                "   -h             print this message and exit"
               );

        fprintf(stderr, "\n");
        print_test_args();

        fprintf(stderr, "\n");
        print_conn_args();

        fprintf(stderr, "\n");
        print_output_args();

    } else if (!strcmp(progname, "owstats")) {
        fprintf(stderr,
                "usage: %s %s\n%s\n",
                progname, "[arguments] sessionfile [sessionfile]*",
                "[arguments] are as follows: "
               );
        fprintf(stderr,"\n%s\n",
                "   -h             print this message and exit"
               );

        fprintf(stderr, "\n");
        print_output_args();
    } else if (!strcmp(progname, "owfetch")) {
        fprintf(stderr,
                "usage: %s %s\n%s\n",
                progname, "[arguments] servaddr [SID savefile]+",
                "[arguments] are as follows: "
               );
        fprintf(stderr,"\n%s\n",
                "   -h             print this message and exit"
               );

        fprintf(stderr, "\n");
        print_conn_args();
        fprintf(stderr, "\n");
        print_output_args();
    } else if (!strcmp(progname, "owup")) {
        fprintf(stderr,
                "usage: %s %s\n%s\n",
                progname, "[arguments] servaddr",
                "[arguments] are as follows: "
               );
        fprintf(stderr,"\n%s\n",
                "   -h             print this message and exit"
               );

        fprintf(stderr, "\n");
        print_conn_args();
    }
    else{
        fprintf(stderr,
                "usage: %s is not a known name for this program.\n",progname);
    }

    if (PATCH_LEVEL) {
        fprintf(stderr, "\nVersion: %s-%d\n\n", PACKAGE_VERSION, PATCH_LEVEL);
    }
    else {
        fprintf(stderr, "\nVersion: %s\n\n", PACKAGE_VERSION);
    }

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
 * STIME    sendtime            owptimestamp (%020 PRIu64)
 * SS       send synchronized   boolean unsigned
 * SERR     send err estimate   float (%g)
 * RTIME    recvtime            owptimestamp (%020 PRIu64)
 * RS       recv synchronized   boolean unsigned
 * RERR     recv err estimate   float (%g)
 * TTL      ttl                 unsigned short
 */
#define RAWFMT "%lu " OWP_TSTAMPFMT " %u %g " OWP_TSTAMPFMT " %u %g %u\n"
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
        FILE        *fp,
        char        *from,
        char        *to
        )
{
    OWPSessionHeaderRec hdr;
    OWPStats            stats;
    uint32_t            num_rec;
    uint32_t            num_sum;
    uint32_t            sum;
    char                tfname[PATH_MAX];
    char                sfname[PATH_MAX];
    char                startname[PATH_MAX];
    char                endname[PATH_MAX];
    FILE                *tfp;
    char                *ext;

    if(!(num_rec = OWPReadDataHeader(ctx,fp,&hdr)) && !hdr.header){
        I2ErrLog(eh, "OWPReadDataHeader: Invalid file?");
        return -1;
    }

    /*
     * If raw data is requested, no summary information is needed.
     */
    if(ping_ctx.opt.raw){
        if(OWPParseRecords(ctx,fp,num_rec,hdr.version,printraw,stdout)
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

    /* Set the limits here */
    if (ping_ctx.opt.rec_limit > 0)
      stats->rec_limit = ping_ctx.opt.rec_limit;

    /* Set the timestamp flag here */
    if (ping_ctx.opt.display_unix_ts == True)
      stats->display_unix_ts = True;

    /*
     * How many summaries?
     */
    if(!ping_ctx.opt.numBucketPackets ||
            (ping_ctx.opt.numBucketPackets >= hdr.test_spec.npackets)){
        num_sum = 0;
    }
    else{
        num_sum = hdr.test_spec.npackets / ping_ctx.opt.numBucketPackets;
        if(hdr.test_spec.npackets % ping_ctx.opt.numBucketPackets){
            num_sum++;
        }
    }

    /*
     * Parse the data, and generate the summaries.
     */
    if(!num_sum){
        /*
         * Create temporary sum-session file.
         */
        if(ping_ctx.opt.printfiles){
            strcpy(tfname,dirpath);
            sprintf(startname,OWP_TSTAMPFMT,hdr.test_spec.start_time);
            sprintf(&tfname[file_oset],"%s%s",startname,_OWPING_INC_EXT);
            if( !(tfp = fopen(tfname,"w"))){
                I2ErrLog(eh,"OWStatsParse: fopen(%s): %M",tfname);
                return -1;
            }
        }
        else{
            tfp = stdout;
        }

        if( !OWPStatsParse(stats,(ping_ctx.opt.records?tfp:NULL),0,0,~0)){
            I2ErrLog(eh,"OWPStatsParse: failed");
            OWPStatsFree(stats);
            if(ping_ctx.opt.printfiles){
                /* ignore errors */
                fclose(tfp);
                unlink(tfname);
            }
            return -1;
        }

        /*
         * Print out summary info
         */
        if(ping_ctx.opt.machine){
            OWPStatsPrintMachine(stats,tfp);
            ext = _OWPING_SUM_EXT;
        }
        else{
            OWPStatsPrintSummary(stats,tfp,
                    ping_ctx.opt.percentiles,
                    ping_ctx.opt.npercentiles);
            ext = _OWPING_DEF_EXT;
        }

        sprintf(startname,OWP_TSTAMPFMT,stats->start_time);
        sprintf(endname,OWP_TSTAMPFMT,stats->end_time);

        /*
         * relink output file to correct name
         */
        if(ping_ctx.opt.printfiles){
            fclose(tfp);
            strcpy(sfname,dirpath);
            sprintf(&sfname[file_oset],"%s%s%s%s",
                    startname,OWP_NAME_SEP,endname,ext);

            if(link(tfname,sfname) != 0){
                I2ErrLog(eh,"OWStatsParse: link(%s,%s): %M",tfname,sfname);
                OWPStatsFree(stats);
                unlink(tfname);
                return -1;
            }
            unlink(tfname);
            fprintf(stdout,"%s\n",sfname);
            fflush(stdout);
        }
    }
    else{
        for(sum=0;sum<num_sum;sum++){
            uint32_t    begin,end;

            begin = ping_ctx.opt.numBucketPackets * sum;
            end = ping_ctx.opt.numBucketPackets * (sum+1);
            if(end > hdr.test_spec.npackets){
                end = ~0;
            }

            /*
             * Create temporary sum-session file.
             */
            if(ping_ctx.opt.printfiles){
                strcpy(tfname,dirpath);
                sprintf(startname,OWP_TSTAMPFMT,hdr.test_spec.start_time);
                sprintf(&tfname[file_oset],"%s%s",startname,_OWPING_INC_EXT);
                if( !(tfp = fopen(tfname,"w"))){
                    I2ErrLog(eh,"OWStatsParse: fopen(%s): %M",tfname);
                    return -1;
                }
            }
            else{
                tfp = stdout;
            }

            if( !OWPStatsParse(stats,(ping_ctx.opt.records?tfp:NULL),
                        stats->next_oset,begin,end)){
                I2ErrLog(eh,"OWPStatsParse: failed");
                OWPStatsFree(stats);
                return -1;
            }

            /*
             * Print out summary info
             */
            if(ping_ctx.opt.machine){
                OWPStatsPrintMachine(stats,tfp);
                ext = _OWPING_SUM_EXT;
            }
            else{
                OWPStatsPrintSummary(stats,tfp,
                        ping_ctx.opt.percentiles,
                        ping_ctx.opt.npercentiles);
                ext = _OWPING_DEF_EXT;
            }

            sprintf(startname,OWP_TSTAMPFMT,stats->start_time);
            sprintf(endname,OWP_TSTAMPFMT,stats->end_time);

            /*
             * relink output file to correct name
             */
            if(ping_ctx.opt.printfiles){
                fclose(tfp);
                strcpy(sfname,dirpath);
                sprintf(&sfname[file_oset],"%s%s%s%s",
                        startname,OWP_NAME_SEP,endname,ext);

                if(link(tfname,sfname) != 0){
                    I2ErrLog(eh,"OWStatsParse: link(%s,%s): %M",tfname,sfname);
                    OWPStatsFree(stats);
                    unlink(tfname);
                    return -1;
                }
                unlink(tfname);
                fprintf(stdout,"%s\n",sfname);
                fflush(stdout);
            }
        }
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
    uint32_t    num_rec;
    OWPErrSeverity    rc=OWPErrOK;

    /*
     * Prepare paths for datafiles. Unlink if not keeping data.
     */
    if(savefile){
        path = savefile;
        if( !(fp = fopen(path,"w+b"))){
            I2ErrLog(eh,"owp_fetch_sid:fopen(%s): %M",path);
            return NULL;
        }
    }
    else if( !(fp = tfile(eh))){
        return NULL;
    }

    /*
     * Ask for complete session 
     */
    num_rec = OWPFetchSession(cntrl,fp,0,(uint32_t)0xFFFFFFFF,sid,&rc);
    if(!num_rec){
        if(path)
            (void)unlink(path);
        if(rc < OWPErrWARNING){
            return NULL;
        }
        /*
         * server denied request...
         */
        I2ErrLog(eh,
                "owp_fetch_sid:Server denied request for to session data - is your clock synchronized via NTP properly?");
        return NULL;
    }

    return fp;
}

static OWPBoolean
getclientpf(
        OWPContext      ctx __attribute__((unused)),
        const OWPUserID userid    __attribute__((unused)),
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
        OWPContext    ctx,
        char        *progname,
        ow_ping_trec    *pctx
        )
{
    if(pctx->opt.identity){
        char        *lbuf=NULL;
        size_t      lbuf_max=0;
        char        *passphrase;

        /*
         * If pffile specified, attempt to get key from there.
         */
        if(pctx->opt.pffile){
            /* pffile */
            FILE        *filep;
            int         rc = 0;

            if(!(filep = fopen(pctx->opt.pffile,"r"))){
                I2ErrLog(eh,"Unable to open %s: %M",
                        pctx->opt.pffile);
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

        }else{
            /*
             * Do passphrase:
             *     open tty and get passphrase.
             */
            char        prompt[MAX_PASSPROMPT];

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

        /* copy passphrase */
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
             * install getpf func (pf is in pfbuff)
             */
            OWPGetPFFunc    getpf = getclientpf;

            if(!OWPContextConfigSetF(ctx,OWPGetPF,(OWPFunc)getpf)){
                I2ErrLog(eh,"Unable to set pass-phrase func for context: %M");
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
    }
    else{
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
        uint32_t   *nalpha_ret
        )
{
    uint32_t    i,nalpha;
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
        uint32_t    *nslots_ret
        )
{
    uint32_t    i,nslots;
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
parse_typeP(
        char        *tspec
        )
{
    char            *tstr,*endptr;
    unsigned long   tlng;
    uint8_t         tosbyte = 0;

    if(!tspec) return False;

    tstr = tspec;
    endptr = NULL;
    while(isspace((int)*tstr)) tstr++;
    tlng = strtoul(optarg,&endptr,0);

    /*
     * Try interpreting as hex DSCP value.
     * Verify user only sets
     * last 6 bits (DSCP must fit in 6 bits - RFC 2474.)
     */
    if((*endptr == '\0') && !(tlng & ~0x3F)){
        /* save in tosbyte - uses high-order 6 bits instead of low */
        tosbyte = tlng << 2;
        tstr = endptr;
    }

    /*
     * It is useful to define some symbolic constants for the -D (DSCP)
     * value. RFC 4594 seemed a reasonable collection of these useful
     * constants.
     *
     * Table of constants from RFC 4594:
     *
     *
   *********************************************************************

    ------------------------------------------------------------------
   |   Service     |  DSCP   |    DSCP     |       Application        |
   |  Class Name   |  Name   |    Value    |        Examples          |
   |===============+=========+=============+==========================|
   |Network Control|  CS6    |   110000    | Network routing          |
   |---------------+---------+-------------+--------------------------|
   | Telephony     |   EF    |   101110    | IP Telephony bearer      |
   |---------------+---------+-------------+--------------------------|
   |  Signaling    |  CS5    |   101000    | IP Telephony signaling   |
   |---------------+---------+-------------+--------------------------|
   | Multimedia    |AF41,AF42|100010,100100|   H.323/V2 video         |
   | Conferencing  |  AF43   |   100110    |  conferencing (adaptive) |
   |---------------+---------+-------------+--------------------------|
   |  Real-Time    |  CS4    |   100000    | Video conferencing and   |
   |  Interactive  |         |             | Interactive gaming       |
   |---------------+---------+-------------+--------------------------|
   | Multimedia    |AF31,AF32|011010,011100| Streaming video and      |
   | Streaming     |  AF33   |   011110    |   audio on demand        |
   |---------------+---------+-------------+--------------------------|
   |Broadcast Video|  CS3    |   011000    |Broadcast TV & live events|
   |---------------+---------+-------------+--------------------------|
   | Low-Latency   |AF21,AF22|010010,010100|Client/server transactions|
   |   Data        |  AF23   |   010110    | Web-based ordering       |
   |---------------+---------+-------------+--------------------------|
   |     OAM       |  CS2    |   010000    |         OAM&P            |
   |---------------+---------+-------------+--------------------------|
   |High-Throughput|AF11,AF12|001010,001100|  Store and forward       |
   |    Data       |  AF13   |   001110    |     applications         |
   |---------------+---------+-------------+--------------------------|
   |    Standard   | DF (CS0)|   000000    | Undifferentiated         |
   |               |         |             | applications             |
   |---------------+---------+-------------+--------------------------|
   | Low-Priority  |  CS1    |   001000    | Any flow that has no BW  |
   |     Data      |         |             | assurance                |
    ------------------------------------------------------------------

                Figure 3. DSCP to Service Class Mapping
   *********************************************************************
     *
     * Mapping this to the full binary tos byte, and including CS? and
     * EF symbolic names...
     *
     *
     * Symbolic constants           6-bit DSCP
     *
     * none/default/CS0             000 000
     * CS1                          001 000
     * AF11                         001 010
     * AF12                         001 100
     * AF13                         001 110
     * CS2                          010 000
     * AF21                         010 010
     * AF22                         010 100
     * AF23                         010 110
     * CS3                          011 000
     * AF31                         011 010
     * AF32                         011 100
     * AF33                         011 110
     * CS4                          100 000
     * AF41                         100 010
     * AF42                         100 100
     * AF43                         100 110
     * CS5                          101 000
     * EF                           101 110
     * CS6                          110 000
     * CS7                          111 000
     */

    else if(!strncasecmp(tstr,"none",5)){
        /* standard */
        tstr += 4;
    }
    else if(!strncasecmp(tstr,"default",8)){
        /* standard */
        tstr += 7;
    }
    else if(!strncasecmp(tstr,"df",3)){
        /* standard */
        tstr += 2;
    }
    else if(!strncasecmp(tstr,"ef",3)){
        /* Expedited Forwarding */
        tosbyte = 0xB8;
        tstr += 2;
    }
    else if((toupper(tstr[0]) == 'C') && (toupper(tstr[1]) == 'S')){
        switch(tstr[2]){
            case '0':
                break;
            case '1':
                tosbyte = 0x20;
                break;
            case '2':
                tosbyte = 0x40;
                break;
            case '3':
                tosbyte = 0x60;
                break;
            case '4':
                tosbyte = 0x80;
                break;
            case '5':
                tosbyte = 0xA0;
                break;
            case '6':
                tosbyte = 0xC0;
                break;
            case '7':
                tosbyte = 0xE0;
                break;
            default:
                goto FAILED;
                break;
        }
        /* forward tstr to end of accepted pattern */
        tstr += 3;
    }
    else if(toupper(tstr[0] == 'A') && (toupper(tstr[1]) == 'F')){
        switch(tstr[2]){
            case '1':
                tosbyte = 0x20;
                break;
            case '2':
                tosbyte = 0x40;
                break;
            case '3':
                tosbyte = 0x60;
                break;
            case '4':
                tosbyte = 0x80;
                break;
            default:
                goto FAILED;
                break;
        }
        switch(tstr[3]){
            case '1':
                tosbyte |= 0x08;
                break;
            case '2':
                tosbyte |= 0x10;
                break;
            case '3':
                tosbyte |= 0x18;
                break;
            default:
                goto FAILED;
                break;
        }
        /* forward tstr to end of accepted pattern */
        tstr += 4;
    }

    /*
     * Forward past any whitespace and make sure arg is clean.
     */
    while(isspace((int)*tstr)) tstr++;
    if(*tstr != '\0'){
        goto FAILED;
    }

    /*
     * Set pType - only 6 bits should be set in tosbyte (high-order)
     * pType of OWAMP expects them in the low-order 6 bits of the
     * high-order byte. So, shift 24 left, and 2 right == 22.
     */
    ping_ctx.typeP = tosbyte << 22;
    return True;

FAILED:
    I2ErrLogP(eh,EINVAL,"Invalid DSCP value (-D): \"%s\": %M",tspec);
    return False;
}

/*
 * Signal handler installed so HUP/TERM signals will be noticed.
 */
static void
signal_catch(
        int signo
        )
{
    switch(signo){
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
            break;
        default:
            I2ErrLogP(eh,EINVAL,"signal_catch(): Invalid signal(%d)",signo);
            _exit(-1);
    }

    owp_intr++;

    return;
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
    OWPSID              tosid;
    OWPAcceptType       acceptval;
    OWPErrSeverity      err;
    FILE                *fromfp=NULL;
    char                localbuf[NI_MAXHOST+1+NI_MAXSERV+1];
    char                remotebuf[NI_MAXHOST+1+NI_MAXSERV+1];
    char                *local, *remote;
    struct sigaction    setact;

    int                 ch;
    char                *endptr = NULL;
    char                optstring[128];
    static char         *conn_opts = "64A:k:S:u:";
    static char         *test_opts = "c:D:E:F:i:L:P:s:z:";
    static char         *out_opts = "a:b:d:Mn:N:pQRv::U";
    static char         *gen_opts = "h";
#ifndef TWAMP
    static char         *ow_opts = "ftT:";
#endif
#ifndef    NDEBUG
    static char         *debug_opts = "w";
#endif
    int                 fname_len;

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
    ping_ctx.opt.v4only = ping_ctx.opt.v6only =
    ping_ctx.opt.records = ping_ctx.opt.from = ping_ctx.opt.to =
    ping_ctx.opt.quiet = ping_ctx.opt.raw = ping_ctx.opt.machine = False;
    ping_ctx.opt.childwait = NULL;
    ping_ctx.opt.save_from_test = ping_ctx.opt.save_to_test 
        = ping_ctx.opt.identity = ping_ctx.opt.pffile 
        = ping_ctx.opt.srcaddr = ping_ctx.opt.authmode = NULL;
    ping_ctx.opt.numPackets = 100;
    ping_ctx.opt.lossThreshold = 0.0;
    ping_ctx.opt.delayStart = 0.0;
    ping_ctx.opt.percentiles = NULL;
    ping_ctx.opt.padding = OWP_PADDING_UNSET;
    ping_ctx.mean_wait = (float)0.1;
    ping_ctx.opt.units = 'm';
    ping_ctx.opt.numBucketPackets = 0;
    ping_ctx.opt.bucket_width = 0.0001;

    ping_ctx.opt.portspec = &ping_ctx.portrec;

    ping_ctx.opt.portspec->low  = 8760;
    ping_ctx.opt.portspec->high = 9960;

    /* Create options strings for this program. */
    if (!strcmp(progname, "owping") || !strcmp(progname, "twping")) {
        strcpy(optstring, conn_opts);
        strcat(optstring, test_opts);
        strcat(optstring, out_opts);
    } else if (!strcmp(progname, "owstats")) {
        strcpy(optstring, out_opts);
    } else if (!strcmp(progname, "owfetch")) {
        strcpy(optstring, conn_opts);
        strcat(optstring, out_opts);
    } else if (!strcmp(progname, "owup")) {
        strcpy(optstring, conn_opts);
    }
    else{
        usage(progname, "Invalid program name.");
        exit(1);
    }

    strcat(optstring, gen_opts);
#ifndef    NDEBUG
    strcat(optstring,debug_opts);
#endif
#ifndef TWAMP
    strcat(optstring, ow_opts);
#endif

    while((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch) {
            /* Connection options. */

            case '4':
                ping_ctx.opt.v4only = True;
                break;
            case '6':
                ping_ctx.opt.v6only = True;
                break;
            case 'A':
                if(!(ping_ctx.opt.authmode = strdup(optarg))){
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'k':
                if (!(ping_ctx.opt.pffile = strdup(optarg))){
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'S':
                if(!(ping_ctx.opt.srcaddr = strdup(optarg))){
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'u':
                if(!(ping_ctx.opt.identity = strdup(optarg))){
                    I2ErrLog(eh,"malloc: %M");
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
                            "Invalid option \'-D\'. Can only set one \'-D\'");
                    exit(1);
                }
                if(!parse_typeP(optarg)){
                    exit(1);
                }
                break;
            case 'E':
                ping_ctx.opt.endDelay = strtod(optarg,&endptr);
                if((*endptr != '\0') ||
                        (ping_ctx.opt.endDelay < 0.0)){
                    usage(progname, 
                            "Invalid \'-E\' value. Positive float expected");
                    exit(1);
                }
                ping_ctx.opt.setEndDelay = True;
                break;
            case 'F':
                if (!(ping_ctx.opt.save_from_test = strdup(optarg))){
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                /* fall through */
            case 'f':
                ping_ctx.opt.from = True;
                break;
            case 'T':
                if (!(ping_ctx.opt.save_to_test = strdup(optarg))) {
                    I2ErrLog(eh,"malloc: %M");
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
                if (strcmp(optarg, "0") == 0) {
                    ping_ctx.opt.portspec->low  = 0;
                    ping_ctx.opt.portspec->high = 0;
                }
                else {
                    if(!OWPParsePortRange(optarg, &ping_ctx.portrec)){
                        usage(progname,
                                "Invalid test port range specified.");
                        exit(1);
                    }

                    if (ping_ctx.portrec.high && ping_ctx.portrec.low) {
                            //if ((ping_ctx.portrec.high - ping_ctx.portrec.low + 1) < 2) {
                            if ((ping_ctx.portrec.high - ping_ctx.portrec.low + 1) < 1) {
                                I2ErrLog(eh,
                                        "Invalid test port range specified: must contain at least 2 ports.");
                                exit(1);
                            }
                    }
    
                    ping_ctx.opt.portspec = &ping_ctx.portrec;
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
            case 'd':
                if (!(ping_ctx.opt.savedir = strdup(optarg))) {
                    I2ErrLog(eh,"malloc: %M");
                    exit(1);
                }
                break;
            case 'v':
                ping_ctx.opt.records = True;

		if (optarg != NULL) {
		  ping_ctx.opt.rec_limit = strtoul(optarg, &endptr, 10);
		  if (*endptr != '\0') {
                    usage(progname,
			  "Invalid \"-v\" value. Positive integer expected");
                    exit(1);
		  }
		};
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
            case 'N':
                ping_ctx.opt.numBucketPackets = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    usage(progname,
                            "Invalid \"-N\" value. Positive integer expected");
                    exit(1);
                }
                break;
            case 'p':
                ping_ctx.opt.printfiles = True;
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
	case 'U':
	  ping_ctx.opt.display_unix_ts = True;
	  break;
#ifndef    NDEBUG
            case 'w':
                ping_ctx.opt.childwait = (void*)True;
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
        if(owp_intr) exit(2);
    }
    argc -= optind;
    argv += optind;

    /*
     * Restrict INET address families
     */
    if(ping_ctx.opt.v4only){
        if(ping_ctx.opt.v6only){
            I2ErrLog(eh,"-4 and -6 flags cannot be set together");
            exit(1);
        }
        if( !OWPContextConfigSetV(ctx,OWPIPv4Only,(void*)True)){
            I2ErrLog(eh,
                    "OWPContextConfigSetV(): Unable to set OWPIPv4Only?!");
            exit(1);
        }
    }
    if(ping_ctx.opt.v6only){
        if( !OWPContextConfigSetV(ctx,OWPIPv6Only,(void*)True)){
            I2ErrLog(eh,
                    "OWPContextConfigSetV(): Unable to set OWPIPv6Only?!");
            exit(1);
        }
    }

    if(ping_ctx.opt.raw){
        ping_ctx.opt.quiet = True;
    }

    if(ping_ctx.opt.records && ping_ctx.opt.quiet){
        I2ErrLog(eh,"Ignoring \'-v\', \'-Q\' set");
        ping_ctx.opt.records = False;
    }

    if(ping_ctx.opt.machine && ping_ctx.opt.quiet){
        I2ErrLog(eh,"Ignoring \'-M\', \'-Q\' set");
        ping_ctx.opt.machine = False;
    }


    if(ping_ctx.opt.records && ping_ctx.opt.machine){
        I2ErrLog(eh,"Ignoring \'-v\', \'-M\' set");
        ping_ctx.opt.records = False;
    }

    /*
     * Check savedir option. make sure it will not make fnames
     * exceed PATH_MAX. Also set file_oset, tstamp_oset, and ext_oset
     * to the appropriate values.
     */
    fname_len = (2 * OWP_TSTAMPCHARS) + strlen(OWP_NAME_SEP) +
        MAX(strlen(_OWPING_DEF_EXT),strlen(_OWPING_SUM_EXT)) +
        strlen(_OWPING_INC_EXT);
    assert((fname_len+1)<PATH_MAX);
    if(ping_ctx.opt.savedir){
        if((strlen(ping_ctx.opt.savedir) + strlen(OWP_PATH_SEPARATOR) +
                    fname_len + 1) > PATH_MAX){
            usage(progname,"-d: pathname too long.");
            exit(1);
        }
        strcpy(dirpath,ping_ctx.opt.savedir);
        strcat(dirpath,OWP_PATH_SEPARATOR);
    }
    else{
        dirpath[0] = '\0';
    }
    file_oset = strlen(dirpath);
    tstamp_oset = file_oset + OWP_TSTAMPCHARS;
    ext_oset = tstamp_oset + OWP_TSTAMPCHARS + strlen(OWP_NAME_SEP);

    memset(&setact,0,sizeof(setact));
    setact.sa_handler = signal_catch;
    sigemptyset(&setact.sa_mask);
    if(     (sigaction(SIGTERM,&setact,NULL) != 0) ||
            (sigaction(SIGHUP,&setact,NULL) != 0) ||
            (sigaction(SIGINT,&setact,NULL) != 0)){
        I2ErrLog(eh,"sigaction(): %M");
        exit(1);
    }

    /*
     * Handle 3 possible cases (owping, owfetch, owstats) one by one.
     */
    if (!strcmp(progname, "owping") || !strcmp(progname, "twping")){

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

        if(ping_ctx.opt.padding == OWP_PADDING_UNSET){
#ifdef TWAMP
            /*
             * If padding hasn't been set explicitly then set it to
             * the difference between the sender payload size and the
             * response payload size (i.e. such that the sending
             * payload has enough space that the reflector generates a
             * packet with the same size, albeit with no padding).
             */
            ping_ctx.opt.padding = OWPTestTWPayloadSize(ping_ctx.auth_mode,0) -
                OWPTestPayloadSize(ping_ctx.auth_mode,0);
#else
            ping_ctx.opt.padding = 0;
#endif
        }

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

        /*
         * Set OWPEndDelay
         */
        if(ping_ctx.opt.setEndDelay &&
                !OWPContextConfigSetV(ctx,OWPEndDelay,
                    (void*)&ping_ctx.opt.endDelay)){
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

#ifndef    NDEBUG
        /*
         * Setup debugging of child processes.
         */
        if(ping_ctx.opt.childwait &&
                !OWPContextConfigSetV(ctx,
                    OWPChildWait,
                    ping_ctx.opt.childwait)){
            I2ErrLog(eh,
                    "OWPContextConfigSetV(): Unable to set OWPChildWait?!");
        }
#endif

        /*
         * Open connection to owampd.
         */

        ping_ctx.cntrl = NWPControlOpen(ctx,
                ping_ctx.opt.srcaddr,
                I2AddrByNode(eh, ping_ctx.remote_serv),
                ping_ctx.auth_mode,ping_ctx.opt.identity,
                NULL,&err_ret);
        if (!ping_ctx.cntrl){
            I2ErrLog(eh, "Unable to open control connection to %s.",
                    ping_ctx.remote_serv);
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
            I2ErrLogP(eh,errno,"Unable to get current time: %M");
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

        if(owp_intr) exit(2);

#ifdef TWAMP
        if (ping_ctx.opt.save_from_test) {
            fromfp = fopen(ping_ctx.opt.save_from_test,
                           "w+b");
            if(!fromfp){
                I2ErrLog(eh,"fopen(%s): %M",
                         ping_ctx.opt.save_from_test);
                exit(1);
            }
        } else if( !(fromfp = tfile(eh))){
            exit(1);
        }

        if (!OWPSessionRequest(ping_ctx.cntrl, NULL, False,
                               I2AddrByNode(eh,ping_ctx.remote_test),
                               True,(OWPTestSpec*)&tspec,
                               fromfp,tosid,&err_ret))
            FailSession(ping_ctx.cntrl);
#else
        /*
         * Prepare paths for datafiles. Unlink if not keeping data.
         */
        if(ping_ctx.opt.to) {
            if (!OWPSessionRequest(ping_ctx.cntrl, NULL, False,
                        I2AddrByNode(eh,ping_ctx.remote_test),
                        True,(OWPTestSpec*)&tspec,
                        NULL,tosid,&err_ret))
                FailSession(ping_ctx.cntrl);
        }

        if(owp_intr) exit(2);

        if(ping_ctx.opt.from) {
            OWPSID fromsid;

            if (ping_ctx.opt.save_from_test) {
                fromfp = fopen(ping_ctx.opt.save_from_test,
                        "w+b");
                if(!fromfp){
                    I2ErrLog(eh,"fopen(%s): %M", 
                            ping_ctx.opt.save_from_test);
                    exit(1);
                }
            } else if( !(fromfp = tfile(eh))){
                exit(1);
            }

            if (!OWPSessionRequest(ping_ctx.cntrl,
                        I2AddrByNode(eh,ping_ctx.remote_test),
                        True, NULL, False,(OWPTestSpec*)&tspec,
                        fromfp,fromsid,&err_ret))
                FailSession(ping_ctx.cntrl);
        }
#endif

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
                I2ErrLogP(eh,errno,"Unable to get current time: %M");
                exit(1);
            }

            endtime -= OWPNum64ToDouble(curr_time.owptime);

            fprintf(stdout,
                    "Approximately %.1f seconds until results available\n",
                    endtime);
        }
        if(owp_intr) exit(2);

        /*
         * If ch == 2, it is possible to continue parsing partial data.
         */
        ch = OWPStopSessionsWait(ping_ctx.cntrl,NULL,&owp_intr,&acceptval,&err);
        if((ch < 0) || (acceptval != OWP_CNTRL_ACCEPT)){
            I2ErrLog(eh, "Test session(s) Failed...");
            if(ping_ctx.opt.save_from_test){
                (void)unlink(ping_ctx.opt.save_from_test);
            }
            exit(1);
        }

        if(ch == 2){
            /* early termination request (signal) */
            (void)OWPStopSessions(ping_ctx.cntrl,&owp_intr,&acceptval);
            if(acceptval != OWP_CNTRL_ACCEPT){
                I2ErrLog(eh, "Test session(s) Failed...");
                if(ping_ctx.opt.save_from_test){
                    (void)unlink(ping_ctx.opt.save_from_test);
                }
                exit(2);
            }
        }
        if(owp_intr > 1) exit(2);

        /*
         * Get "local" and "remote" names for pretty printing
         * if we need them.
         */
        local = remote = NULL;
        if(!ping_ctx.opt.quiet){
            I2Addr    laddr;
            size_t    lsize;

            /*
             * First determine local address.
             */
            laddr = I2AddrByLocalSockFD(eh,OWPControlFD(ping_ctx.cntrl), False);

            lsize = sizeof(localbuf);
            I2AddrNodeName(laddr,localbuf,&lsize);
            if(lsize > 0){
                local = localbuf;
            }
            I2AddrFree(laddr);

            /*
             * Now determine remote address.
             */
            laddr = I2AddrByNode(eh,ping_ctx.remote_test);
            lsize = sizeof(remotebuf);
            I2AddrNodeName(laddr,remotebuf,&lsize);
            if(lsize > 0){
                remote = remotebuf;
            }
            I2AddrFree(laddr);
        }

#ifndef TWAMP
        if(ping_ctx.opt.to && (ping_ctx.opt.save_to_test ||
                    !ping_ctx.opt.quiet || ping_ctx.opt.raw)){
            FILE    *tofp;

            if( !(tofp = owp_fetch_sid(ping_ctx.opt.save_to_test,
                            ping_ctx.cntrl,tosid))){
                char    sname[sizeof(OWPSID)*2 + 1];
                I2HexEncode(sname,tosid,sizeof(OWPSID));
                I2ErrLog(eh,"Unable to fetch data for sid(%s)",sname);
            }
            else if(!ping_ctx.opt.quiet || ping_ctx.opt.raw){
                if( do_stats(ctx,tofp,local,remote)){
                    I2ErrLog(eh, "do_stats(\"to\" session): %M");
                }
            }
            if(tofp && fclose(tofp)){
                I2ErrLog(eh,"close(): %M");
            }
        }
#endif

        if(owp_intr > 1) exit(2);

        if(fromfp && (!ping_ctx.opt.quiet || ping_ctx.opt.raw)){
            if( do_stats(ctx,fromfp,remote,local)){
                I2ErrLog(eh, "do_stats(\"from\" session): %M");
            }
        }

        if(fromfp && fclose(fromfp)){
            I2ErrLog(eh,"close(): %M");
        }

    }

    else if (!strcmp(progname, "owstats")) {
        int i;

        for(i = 0; i < argc; i++) {
            FILE        *fp;

            if(!(fp = fopen(argv[i],"rb"))){
                I2ErrLog(eh,"fopen(%s): %M",argv[0]);
                exit(1);
            }

            if ( do_stats(ctx,fp,NULL,NULL)){
                I2ErrLog(eh,"do_stats() failed.");
                exit(1);
            }

            fclose(fp);
        }

    }

    else if (!strcmp(progname, "owfetch")) {
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
                ping_ctx.opt.srcaddr,
                I2AddrByNode(eh, ping_ctx.remote_serv),
                ping_ctx.auth_mode,ping_ctx.opt.identity,
                NULL,&err_ret);
        if (!ping_ctx.cntrl){
            I2ErrLog(eh, "Unable to open control connection to %s.",
                    ping_ctx.remote_serv);
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
            else if((!ping_ctx.opt.quiet || ping_ctx.opt.raw) &&
                    do_stats(ctx,fp,NULL,NULL)){
                I2ErrLog(eh,"do_stats() failed.");
            }
            else if(fclose(fp)){
                I2ErrLog(eh,"fclose(): %M");
            }

            if(owp_intr) exit(2);
        }

    }

    else if (!strcmp(progname, "owup")) {
        struct timeval  tval;
        OWPTimeStamp    tstamp;
        struct tm       trec,*tptr;
        char            buf[PATH_MAX];

        if(argc != 1){
            usage(progname, NULL);
            exit(1);
        }

        ping_ctx.remote_serv = argv[0];

        owp_set_auth(ctx, progname, &ping_ctx); 

        /*
         * Open connection to owampd.
         */
        ping_ctx.cntrl = OWPControlOpen(ctx, 
                ping_ctx.opt.srcaddr,
                I2AddrByNode(eh, ping_ctx.remote_serv),
                ping_ctx.auth_mode,ping_ctx.opt.identity,
                &tstamp.owptime,&err_ret);
        if (!ping_ctx.cntrl){
            I2ErrLog(eh, "Unable to open control connection to %s.",
                    ping_ctx.remote_serv);
            exit(1);
        }
        (void)OWPControlClose(ping_ctx.cntrl);

        /* TimestampToTimeval, localtime, strftime */

        if(!OWPTimestampToTimeval(&tval,&tstamp)){
            I2ErrLog(eh, "Unable to convert timestamp to timeval.");
            exit(1);
        }
        
        if( !(tptr = localtime_r(&tval.tv_sec,&trec))){
            I2ErrLog(eh, "Unable to convert time_t to struct tm.");
            exit(1);
        }

        if( !strftime(buf,sizeof(buf),"Server Up Since: %Y-%m-%dT%H:%M:%S.%%03d%Z\n",tptr)){
            I2ErrLog(eh, "Unable to convert time_t to struct tm.");
            exit(1);
        }

        /* %03d format string used - need to convert usec's to msec's */
        fprintf(stderr,buf,tval.tv_usec/1000);

    }

    /* Free all free-able memory and close open sockets. */
    OWPContextFree(ctx);

    exit(0);
}
