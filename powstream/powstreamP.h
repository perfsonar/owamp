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
 *        File:         powstreamP.h
 *
 *        Author:       Jeff Boote
 *                      Internet2
 *
 *        Date:         Tue Sep  3 15:44:17 MDT 2002
 *
 *        Description:        
 */
#ifndef        _powstreamp_h_
#define        _powstreamp_h_

#include <I2util/table.h>

/*
 * Bound of the RTT in seconds. This application needs an estimate of how
 * long it takes to request a test session. It uses this estimate to make
 * sure that it has enough time to make the test requests before those
 * tests actually need to start. (It times the first connection to get
 * a good idea, but does not dynamically modifiy the number of sessions
 * per series based on changes to the RTT over time.) This constant
 * is used to bound that estimate. i.e. we hope that the RTT never gets
 * worse then this value, or the initial value retrieved dynamically.
 * If the RTT gets worse than this, there will be breaks between the
 * sessions.
 */
#define SETUP_ESTIMATE  10

/*
 * Lock file name. This file is created in the output directory to ensure
 * there is not more than one powstream process writing there.
 */
#define POWLOCK         ".powlock"
#define POWTMPFILEFMT   "pow.XXXXXX"
#define POW_INC_EXT     ".i"
#define POW_SUM_EXT     ".sum"

/*
 * Reasonable limits on these so dynamic memory is not needed.
 */
#define MAX_PASSPROMPT  256
#define MAX_PASSPHRASE  256

/*
 * Application "context" structure
 */
typedef        struct {
    /*
     **        Command line options
     */
    struct  {
        /* Flags */

        OWPBoolean  v4only;             /* -4 */
        OWPBoolean  v6only;             /* -6 */

        char        *srcaddr;           /* -S */
        char        *interface;         /* -B */
        char        *authmode;          /* -A */
        char        *identity;          /* -u */
        char        *pffile;            /* -k */
#ifndef        NDEBUG
        I2Boolean   childwait;          /* -w */
#endif

        uint32_t    numPackets;         /* -c */
        double      lossThreshold;      /* -L (seconds) */
        double      meanWait;           /* -i  (seconds) */
        uint32_t    padding;            /* -s */
        OWPBoolean  sender;             /* -t */
        OWPPortRangeRec port_range;     /* -P */

        char        *savedir;           /* -d */
        I2Boolean   printfiles;         /* -p */
        I2Boolean   display_unix_ts;    /* -U */
        int         facility;           /* -e */
                                        /* -r stderr too */
        int         verbose;            /* -v verbose */
        double      bucketWidth;        /* -b (seconds) */
        uint32_t    numBucketPackets;   /* -N */
        uint32_t    delayStart;         /* -z */

        uint32_t    retryDelay;         /* -I */

        I2Boolean   setEndDelay;
        double      endDelay;           /* -E */

    } opt;

    char            *remote_test;
    char            *remote_serv;

    uint32_t        auth_mode;

    OWPContext      lib_ctx;
} powapp_trec, *powapp_t;

typedef struct pow_cntrl_rec{
    OWPContext          ctx;
    OWPControl          cntrl;
    OWPControl          fetch;
    OWPScheduleContext  sctx;
    OWPSID              sid;
    OWPNum64            *nextSessionStart;
    OWPNum64            nextSessionStartNum;
    OWPNum64            nextSessionEndNum;
    OWPNum64            currentSessionStartNum;
    OWPNum64            currentSessionEndNum;
    OWPTimeStamp        prev_runtime;

    FILE                *fp;
    FILE                *testfp;
    char                fname[PATH_MAX];
    uint32_t           numPackets;
    OWPBoolean          call_stop;
    OWPBoolean          session_started;
} pow_cntrl_rec, *pow_cntrl;

#endif
