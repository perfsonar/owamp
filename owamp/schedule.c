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
 *        File:         schedule.c
 *
 *        Author:       Jeff Boote
 *                      Internet2
 *
 *        Date:         Fri Jan 17 09:33:02  2003
 *
 *        Description:        
 */
#include <stdlib.h>
#include <string.h>
#include <owamp/owamp.h>

struct OWPExpContextRec{
    /* AES random number generator fields */
    keyInstance key;            /* key used to encrypt the counter */
    u_int8_t    counter[16];    /* 128-bit counter (network order) */
    u_int8_t    out[16];        /* encrypted block buffer.         */
};


struct OWPScheduleContextRec {
    OWPContext              ctx;

    struct OWPExpContextRec exp;

    u_int64_t               i;        /* current index for generation */
    u_int64_t               maxi;
    u_int32_t               nslots;
    OWPSlot                 *slots;
};

/*
 * Function:        OWPUnifRand64
 *
 * Description:        
 *        Generate and return a 32-bit uniform random string (saved in the lower
 *        half of the OWPNum64.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
static OWPNum64
OWPUnifRand64(
        OWPExpContext   ectx
        )
{
    u_int8_t    forth = ectx->counter[15] & (u_int8_t)3;
    u_int8_t    *buf;
    int         j;
    OWPNum64    ret = 0;

    /*
     * Only generate a new AES number every 4'th UnifRand.
     * The (out) buffer holds 128 random bits - enough for 4 x 32bit
     * random numbers for the algorithm.
     */
    if (!forth){
        rijndaelEncrypt(ectx->key.rk,ectx->key.Nr,
                ectx->counter,ectx->out);
    }

    /*
     * Increment the counter as a 128-bit single quantity in
     * network byte order for AES counter mode.
     */
    for (j = 15; j >= 0; j--){
        if (++ectx->counter[j]){
            break;
        }
    }

    /*
     * Point buf to correct 1/4th of the out buffer.
     */
    buf = &ectx->out[4*forth];

    /*
     * Convert the "raw" buffer to an unsigned integer.
     * (i.e. The last 4 bytes of ret will contain the random
     * integer in network byte order after this loop.)
     *
     * (If OWPNum64 changes from a 32.32 format u_int64_t, this will
     * need to be modified. It is expecting to set the .32 portion.)
     */
    for(j=0;j<4;j++){
        ret <<= 8;
        ret += *buf++;
    }

    return ret;
}

/*
 * Function:        OWPExpContextNext
 *
 * Description:        
 *
 * Generate an exponential deviate using a 32-bit binary string as an input
 * This is algorithm 3.4.1.S from Knuth's v.2 of "Art of Computer Programming" 
 * (1998), p.133.
 *
 * It produces exponential (mean mu) random deviates.
 * 
 * Algorithm S: the constants
 * 
 * Q[k] = (ln2)/(1!) + (ln2)^2/(2!) + ... + (ln2)^k/(k!),    1 <= k <= 18
 * 
 * are precomputed. NOTE: all scalar quantities and arithmetical
 * operations are in fixed-precision 64-bit arithmetic (32 bits before
 * and after the decimal point). All 32-bit uniform random strings are
 * obtained by applying AES in counter mode to a 128-bit unsigned integer
 * (initialized to be zero) written in network byte order, then picking the
 * i_th quartet of bytes of the encrypted block, where i is equal to
 * the value of the counter modulo 4. (Thus, one encrypted block gives
 * rise to four 32-bit random strings)
 * 
 * S1. [Get U and shift.] Generate a 32-bit uniform random binary fraction
 * 
 *               U = (.b0 b1 b2 ... b31)    [note the decimal point]
 * 
 *     Locate the first zero bit b_j, and shift off the leading (j+1) bits,
 *     setting U <- (.b_{j+1} ... b31)
 * 
 *     NOTE: in the rare case that the zero has not been found it is prescribed
 *     that the algorithm return (mu*32*ln2).
 * 
 * S2. [Immediate acceptance?] If U < ln2, set X <- mu*(j*ln2 + U) and terminate
 *     the algorithm. (Note that Q[1] = ln2.)
 * 
 * S3. [Minimize.] Find the least k >= 2 sich that U < Q[k]. Generate
 *     k new uniform random binary fractions U1,...,Uk and set
 *     V <- min(U1,...,Uk).
 * 
 * S4. [Deliver the answer.] Set X <- mu*(j + V)*ln2.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
/*
 * This array has been computed according to the formula:
 *
 *       Q[k] = (ln2)/(1!) + (ln2)^2/(2!) + ... + (ln2)^k/(k!)
 *
 * as described in the Knuth algorithm. (The values below have been
 * multiplied by 2^32 and rounded to the nearest integer.)
 */
static OWPNum64 Q[] = {
    0,          /* Placeholder. */
    0xB17217F8,
    0xEEF193F7,
    0xFD271862,
    0xFF9D6DD0,
    0xFFF4CFD0,
    0xFFFEE819,
    0xFFFFE7FF,
    0xFFFFFE2B,
    0xFFFFFFE0,
    0xFFFFFFFE,
    0xFFFFFFFF
};

#define BIT31       (0x80000000UL)
#define MASK32(n)   (n & 0xFFFFFFFFUL)
#define LN2         Q[1] /* this element represents ln2 */

OWPNum64 
OWPExpContextNext(
        OWPExpContext   ectx
        )
{
    u_int32_t   i, k, j = 0;
    OWPNum64    U, V, tmp; 

    /*
     * S1. [Get U and shift.] Generate a (t+1)-bit
     */
    /* Get U and shift */
    U = OWPUnifRand64(ectx);

    /*
     * shift until bit 31 is 0 (bits 31-0 are the 32 Low-Order bits
     * representing the "fractional" portion of the number.
     */
    while((U & BIT31) && (j < 32)){
        U <<= 1;
        j++;
    }
    /* remove the '0' itself */
    U <<= 1;

    /* Keep only the fractional part. */
    U = MASK32(U);


    /*
     * S2. Immediate acceptance?
     */
    if (U < LN2){
        return OWPNum64Add(OWPNum64Mult(OWPULongToNum64(j),LN2),U);
    }

    /*
     * S3.
     */
    /* Minimize */
    for(k = 2;k < I2Number(Q); k++){
        if (U < Q[k]){
            break;
        }
    }

    V = OWPUnifRand64(ectx);
    for(i = 2;i <= k; i++){
        tmp = OWPUnifRand64(ectx);
        if (tmp < V){
            V = tmp;
        }
    }

    /*
     * S4.
     */
    /* Return (j+V)*ln2 */
    return OWPNum64Mult(OWPNum64Add(OWPULongToNum64(j),V),
            LN2);
}

/*
 * Function:        CheckSlots
 *
 * Description:        
 *         This function validates the slots parameter of the TestSpec
 *         for the Create/Reset functions of the ScheduleContext. This ensures
 *         that future calls to the GenerateDelta functions will not fail.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
static
int CheckSlots(
        OWPContext  ctx,
        OWPTestSpec *tspec
        )
{
    u_int32_t   i;

    for(i=0;i<tspec->nslots;i++){

        switch(tspec->slots[i].slot_type){
            case OWPSlotRandExpType:
            case OWPSlotLiteralType:
                break;
            default:
                OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "OWPScheduleContextGenerateNextDelta: Invalid slot");
                return 1;
        }
    }

    return 0;
}

/*
 * Function:        OWPScheduleContextFree
 *
 * Description:        
 *         Free a Schedule context.
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
OWPScheduleContextFree(
        OWPScheduleContext  sctx
        )
{
    free(sctx);
}

/*
 * Function:        OWPScheduleContextCreate
 *
 * Description:        
 *        Seed the random number generator using a 16-byte string.
 *        This is used to initialize the random number generator
 *
 *         NOTE: This function does NOT copy the slots parameter of the
 *         TestSpec - instead just referencing the one passed into it.
 *         Therefore, the OWPScheduleContext should be free'd before
 *         free'ing the memory associated with the slots!
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPScheduleContext
OWPScheduleContextCreate(
        OWPContext  ctx,
        OWPSID      sid,
        OWPTestSpec *tspec
        )
{
    OWPScheduleContext  sctx;

    if(!tspec || !tspec->slots || !tspec->nslots || CheckSlots(ctx,tspec)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPScheduleContextCreate: Invalid tspec");
        return NULL;
    }

    sctx = malloc(sizeof(*sctx));
    if (!sctx){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc(): %M");
        return NULL;
    }

    sctx->ctx = ctx;

    /*
     * Initialize Key with sid.
     * (This is only needed for Exponential random numbers, but just
     * do it.)
     */
    bytes2Key(&sctx->exp.key, sid);

    memset(sctx->exp.out,0,16);
    memset(sctx->exp.counter,0,16);

    sctx->i = 0;
    sctx->maxi = tspec->npackets;
    sctx->nslots = MIN(tspec->nslots,tspec->npackets);
    sctx->slots = tspec->slots;

    return(sctx);
}

/*
 * Function:        OWPScheduleContextReset
 *
 * Description:        
 *         This function resets the sctx so the Delta generation can be
 *         restarted. Additionally, if sid and tspec are non-NULL, then
 *         then the sctx is reset to generate delta's for the distribution
 *         defined by those values.
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
OWPScheduleContextReset(
        OWPScheduleContext  sctx,
        OWPSID              sid,
        OWPTestSpec         *tspec
        )
{
    memset(sctx->exp.out,0,16);
    memset(sctx->exp.counter,0,16);
    sctx->i = 0;

    if(sid && tspec){

        if(CheckSlots(sctx->ctx,tspec)){
            return OWPErrFATAL;
        }

        /*
         * Initialize Key with sid.
         * (This is only needed for Exponential random numbers, but just
         * do it.)
         */
        bytes2Key(&sctx->exp.key, sid);

        sctx->maxi = tspec->npackets;
        sctx->nslots = MIN(tspec->nslots,tspec->npackets);
        sctx->slots = tspec->slots;

    }

    return OWPErrOK;
}

/*
 * Function:        OWPScheduleContextGenerateNextDelta
 *
 * Description:        
 *         Fetch the next time offset.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPNum64
OWPScheduleContextGenerateNextDelta(
        OWPScheduleContext  sctx
        )
{
    OWPSlot *slot;

    if(sctx->i >= sctx->maxi){
        OWPError(sctx->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPScheduleContextGenerateNextDelta: Schedule complete");
        return OWPErrFATAL;
    }
    slot = &sctx->slots[sctx->i++ % sctx->nslots];

    switch(slot->slot_type){
        case OWPSlotRandExpType:
            return OWPNum64Mult(OWPExpContextNext(&sctx->exp),
                    slot->rand_exp.mean);
        case OWPSlotLiteralType:
            return slot->literal.offset;
        default:
            /* Create and reset should keep this from happening. */
            OWPError(sctx->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPScheduleContextGenerateNextDelta: Invalid slot");
    }

    /*NOTREACHED*/
    abort();
    return 0;
}

/*
 * Function:        OWPExpContextFree
 *
 * Description:        
 *         Free an Exp context.
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
OWPExpContextFree(
        OWPExpContext   ectx
        )
{
    free(ectx);
}

/*
 * Function:        OWPExpContextCreate
 *
 * Description:        
 *        Seed the random number generator using a 16-byte string.
 *        This is used to initialize the random number generator
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPExpContext
OWPExpContextCreate(
        OWPContext  ctx,
        u_int8_t    seed[16]
        )
{
    OWPExpContext   ectx;

    ectx = malloc(sizeof(*ectx));
    if (!ectx){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"malloc(): %M");
        return NULL;
    }

    /*
     * Initialize Key with seed.
     */
    bytes2Key(&ectx->key, seed);

    memset(ectx->out,0,16);
    memset(ectx->counter,0,16);

    return(ectx);
}
