/*
 *      $Id$
 */
/************************************************************************
 *                                                                      *
 *                             Copyright (C)  2003                      *
 *                                Internet2                             *
 *                             All Rights Reserved                      *
 *                                                                      *
 ************************************************************************/
/*
 *        File:         owtvec.c
 *
 *        Author:       Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Mon Oct 20 13:55:38 MDT 2003
 *
 *        Description:        
 */
#include <owamp/owamp.h>
#include <I2util/util.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

int
main(
        int     argc    __attribute__((unused)),
        char    **argv
    ) {
    char                *progname;
    I2LogImmediateAttr  ia;
    I2ErrHandle         eh;
    OWPContext          ctx;
    uint8_t             seed[16];
    char                *seedvals[4] = {
        "2872979303ab47eeac028dab3829dab2",
        "0102030405060708090a0b0c0d0e0f00",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "feed0feed1feed2feed3feed4feed5ab"};
    unsigned int        nice[] = {1,10,100,1000,100000,1000000};
    unsigned int        i,j,n;
    OWPExpContext       exp;
    OWPNum64            eval;
    OWPNum64            sum;


    ia.line_info = (I2NAME | I2MSG);
#ifndef        NDEBUG
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

    /*
     * Initialize library with configuration functions.
     */
    if( !(ctx = OWPContextCreate(eh))){
        I2ErrLog(eh, "Unable to initialize OWP library.");
        exit(1);
    }

    for(i=0;i<I2Number(seedvals);i++){
        assert(I2HexDecode(seedvals[i],seed,16));
        assert((exp = OWPExpContextCreate(ctx,(uint8_t *)seed)));
        fprintf(stdout,"SEED = 0x%s\n",seedvals[i]);
        n = 0;
        sum = OWPULongToNum64(0);
        for(j=1;j<=1000000;j++){
            eval = OWPExpContextNext(exp);
            sum = OWPNum64Add(sum,eval);
            if((n < I2Number(nice)) && (j == nice[n])){
                /* local copies of eval and sum */
                OWPNum64    te,ts;
                /* big-endian versions of eval and sum */
                uint8_t     e[8];
                uint8_t     s[8];
                /* hex encoded big-endian ov eval and sum */
                char                ve[17];
                char                vs[17];

                te = eval;
                ts = sum;

                /*
                 * Copy low-order 32 bits
                 */
                *(uint32_t*)&e[4] = htonl((te&0xffffffffUL));
                *(uint32_t*)&s[4] = htonl((ts&0xffffffffUL));
                /*
                 * Copy high-order 32 bits
                 */
                te >>= 32;
                ts >>= 32;
                *(uint32_t*)&e[0] = htonl((te&0xffffffffUL));
                *(uint32_t*)&s[0] = htonl((ts&0xffffffffUL));

                I2HexEncode(ve,e,8);
                I2HexEncode(vs,s,8);
                ve[16] = vs[16] = '\0';

                fprintf(stdout,
                        "EXP[%d] = 0x%s (%f)\tSUM[%d] = 0x%s (%f)\n",
                        j,ve,OWPNum64ToDouble(eval),
                        j,vs,OWPNum64ToDouble(sum));
                n++;
            }
        }
        OWPExpContextFree(exp);
        exp = NULL;
        fprintf(stdout,"\n");
    }

    exit(0);
}
