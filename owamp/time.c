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
 *        File:         time.c
 *
 *        Author:       Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Thu May 30 11:37:48 MDT 2002
 *
 *        Description:        
 *
 *        functions to encode and decode OWPTimeStamp into 8 octet
 *        buffer for transmitting over the network.
 *
 *        The format for a timestamp messages is as follows:
 *
 *           0                   1                   2                   3
 *           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                Integer part of seconds                        |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|              Fractional part of seconds                       |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *        The format for an Error Estimate is:
 *           0                   1           
 *           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|S|Z|   Scale   |   Multiplier  |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
#include <owamp/owampP.h>

#include <string.h>
#include <assert.h>
#include <math.h>
#include <sys/time.h>
#ifdef  HAVE_SYS_TIMEX_H
#include <sys/timex.h>
#endif

static struct timeval  timeoffset;
static int sign_timeoffset = 0;

/*
 * Function:        _OWPInitNTP
 *
 * Description:        
 *         Initialize NTP.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 *
 * If STA_NANO is defined, we insist it is set, this way we can be sure that
 * ntp_gettime is returning a timespec and not a timeval.
 *
 * TODO: The correct way to fix this is:
 * 1. If ntptimeval contains a struct timespec - then use nano's period.
 * 2. else if STA_NANO is set, then use nano's.
 * 3. else ???(mills solution requires root - ugh)
 *    will this work?
 *    (do a timing test:
 *                 gettimeofday(A);
 *                 getntptime(B);
 *                 nanosleep(1000);
 *                 getntptime(C);
 *                 gettimeofday(D);
 *
 *                 1. Interprete B and C as usecs
 *                         if(D-A < C-B)
 *                                 nano's
 *                         else
 *                                 usecs
 */
int
_OWPInitNTP(
        OWPContext  ctx
        )
{
    char    *toffstr=NULL;

    /*
     * If the system has NTP system calls use them. Otherwise
     * timestamps will be marked UNSYNC.
     */
#ifdef  HAVE_SYS_TIMEX_H
    {
        struct timex        ntp_conf;

	memset(&ntp_conf,0,sizeof(ntp_conf));
        if(ntp_adjtime(&ntp_conf) < 0){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"ntp_adjtime(): %M");
            return 1;
        }

        if(ntp_conf.status & STA_UNSYNC){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "NTP: Status UNSYNC (clock offset issues likely)");
        }

#ifdef        STA_NANO
        if( !(ntp_conf.status & STA_NANO)){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "_OWPInitNTP: STA_NANO must be set! - try \"ntptime -N\"");
            return 1;
        }
#endif
    }
#else
    OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
            "NTP syscalls unavail: Status UNSYNC (clock offset issues likely)");
#endif  /* HAVE_SYS_TIMEX_H */

    if( !(toffstr = getenv("OWAMP_DEBUG_TIMEOFFSET"))){
        timeoffset.tv_sec = 0;
        timeoffset.tv_usec = 0;
    }
    else{
        double  td;
        char    *estr=NULL;

        td = strtod(toffstr,&estr);
        if((toffstr == estr) || (errno == ERANGE)){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Invalid OWAMP_DEBUG_TIMEOFFSET env var: %s",toffstr);
            return 1;
        }

        if(td == 0.0){
            sign_timeoffset = 0;
        }
        else{
            if(td > 0.0){
                sign_timeoffset = 1;
            }
            else{
                sign_timeoffset = -1;
                td = -td;
            }

            timeoffset.tv_sec = trunc(td);
            td -= timeoffset.tv_sec;
            td *= 1000000;
            timeoffset.tv_usec = trunc(td);

            OWPError(ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                    "OWAMP_DEBUG_TIMEOFFSET: sec=%c%lu, usec=%lu",
                    (sign_timeoffset > 0)?'+':'-',
                    timeoffset.tv_sec,timeoffset.tv_usec);
        }
    }

    return 0;
}

struct timespec *
_OWPGetTimespec(
        OWPContext      ctx         __attribute__((unused)),
        struct timespec *ts,
        uint32_t       *esterr,
        uint8_t        *sync
        )
{
    struct timeval  tod;
    uint32_t        timeerr;

    /*
     * By default, assume the clock is unsynchronized.
     */
    *sync = 0;
    timeerr = (uint32_t)0;

    if(gettimeofday(&tod,NULL) != 0){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"gettimeofday(): %M");
        return NULL;
    }

    if(sign_timeoffset > 0){
        tvaladd(&tod,&timeoffset);
    }
    else if(sign_timeoffset < 0){
        tvalsub(&tod,&timeoffset);
    }

    /* assign localtime */
    ts->tv_sec = tod.tv_sec;
    ts->tv_nsec = tod.tv_usec * 1000;        /* convert to nsecs */

    /*
     * If ntp system calls are available use them to determine
     * time error.
     */
#ifdef HAVE_SYS_TIMEX_H
    {
        struct timex        ntp_conf;

        memset(&ntp_conf,0,sizeof(ntp_conf));
        if(ntp_adjtime(&ntp_conf) < 0){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"ntp_adjtime(): %M");
            return NULL;
        }

        /*
         * Check sync flag
         */
        if(!(ntp_conf.status & STA_UNSYNC)){
            long    sec;

            *sync = 1;
            /*
             * Apply ntp "offset"
             */
#ifdef        STA_NANO
            sec = 1000000000;
#else
            sec = 1000000;
#endif
            /*
             * Convert negative offsets to positive ones by decreasing
             * the ts->tv_sec.
             */
            while(ntp_conf.offset < 0){
                ts->tv_sec--;
                ntp_conf.offset += sec;
            }

            /*
             * Make sure the "offset" is less than 1 second
             */
            while(ntp_conf.offset >= sec){
                ts->tv_sec++;
                ntp_conf.offset -= sec;
            }

#ifndef        STA_NANO
            ntp_conf.offset *= 1000;
#endif
            ts->tv_nsec += ntp_conf.offset;
            if(ts->tv_nsec >= 1000000000){
                ts->tv_sec++;
                ts->tv_nsec -= 1000000000;
            }

            timeerr = (uint32_t)ntp_conf.esterror;
        }

    }
#endif

    /*
     * Set estimated error
     */
    *esterr = timeerr;

    /*
     * Make sure a non-zero error is always returned - perfection
     * is not allowed if SYNC is true. ;)
     */
    if(*sync && !*esterr){
        *esterr = 1;
    }

    return ts;
}

/*
 * Function:        OWPGetTimeOfDay
 *
 * Description:        
 *         mimic's unix gettimeofday but takes OWPTimestamp's instead
 *         of struct timeval's.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPTimeStamp *
OWPGetTimeOfDay(
        OWPContext      ctx,
        OWPTimeStamp    *tstamp
        )
{
    struct timespec ts;
    uint32_t       esterr;

    if(!tstamp)
        return NULL;

    if(!(_OWPGetTimespec(ctx,&ts,&esterr,&tstamp->sync)))
        return NULL;

    return OWPTimespecToTimestamp(tstamp,&ts,&esterr,NULL);
}

/*
 * Function:        _OWPEncodeTimeStamp
 *
 * Description:        
 *                 Takes an OWPTimeStamp structure and encodes the time
 *                 value from that structure to the byte array in network
 *                 byte order appropriate for sending the value over the wire.
 *                 (See above format diagram.)
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
_OWPEncodeTimeStamp(
        uint8_t         buf[8],
        OWPTimeStamp    *tstamp
        )
{
    uint32_t   t32;

    assert(tstamp);
    assert(buf);

    /*
     * seconds - Most Significant 32 bits hold the seconds in
     * host byte order. Set t32 to this value in network byte order,
     * then copy them to bytes 0-4 in buf.
     */
    t32 = htonl((tstamp->owptime >> 32) & 0xFFFFFFFF);
    memcpy(&buf[0],&t32,4);

    /*
     * frac seconds - Least significant 32 bits hold the fractional
     * seconds in host byte order. Set t32 to this value in network
     * byte order, then copy them to bytes 5-8 in buf.
     */
    t32 = htonl(tstamp->owptime & 0xFFFFFFFF);
    memcpy(&buf[4],&t32,4);

    return;
}

/*
 * Function:        _OWPEncodeTimeStampErrEstimate
 *
 * Description:        
 *                 Takes an OWPTimeStamp structure and encodes the time
 *                 error estimate value from that structure to the byte array
 *                 in network order as appropriate for sending the value over
 *                 the wire. (See above format diagram.)
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
_OWPEncodeTimeStampErrEstimate(
        uint8_t         buf[2],
        OWPTimeStamp    *tstamp
        )
{
    assert(tstamp);
    assert(buf);

    /*
     * If multiplier is 0, this is an invalid error estimate.
     */
    if(!tstamp->multiplier){
        return False;
    }

    /*
     * Scale is 6 bit quantity, and first 2 bits MUST be zero here.
     */
    buf[0] = tstamp->scale & 0x3F;

    /*
     * Set the first bit for sync.
     */
    if(tstamp->sync){
        buf[0] |= 0x80;
    }

    buf[1] = tstamp->multiplier;

    return True;
}

/*
 * Function:        _OWPDecodeTimeStamp
 *
 * Description:        
 *                 Takes a buffer of 8 bytes of owamp protocol timestamp
 *                 information and saves it in the OWPTimeStamp structure
 *                 in the owptime OWPNum64 field. (See above format diagram
 *                 for owamp protocol timestamp format, and owamp.h header
 *                 file for a description of the OWPNum64 type.)
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
_OWPDecodeTimeStamp(
        OWPTimeStamp    *tstamp,
        uint8_t         buf[8]
        )
{
    uint32_t   t32;

    assert(tstamp);
    assert(buf);

    /*
     * First clear owptime.
     */
    memset(&tstamp->owptime,0,8);

    /*
     * seconds is first 4 bytes in network byte order.
     * copy to a 32 bit int, correct the byte order, then assign
     * to the most significant 32 bits of owptime.
     */
    memcpy(&t32,&buf[0],4);
    tstamp->owptime = (OWPNum64)(ntohl(t32)) << 32;

    /*
     * fractional seconds are the next 4 bytes in network byte order.
     * copy to a 32 bit int, correct the byte order, then assign to
     * the least significant 32 bits of owptime.
     */
    memcpy(&t32,&buf[4],4);
    tstamp->owptime |= (ntohl(t32) & 0xFFFFFFFF);

    return;
}

/*
 * Function:        _OWPDecodeTimeStampErrEstimate
 *
 * Description:        
 *                 Takes a buffer of 2 bytes of owamp protocol timestamp
 *                 error estimate information and saves it in the OWPTimeStamp
 *                 structure. (See above format diagram for owamp protocol
 *                 timestamp error estimate format, and owamp.h header
 *                 file for a description of the OWPNum64 type.)
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 *                 True if the ErrEstimate is valid, False if it is not.
 * Side Effect:        
 */
OWPBoolean
_OWPDecodeTimeStampErrEstimate(
        OWPTimeStamp    *tstamp,
        uint8_t         buf[2]
        )
{
    assert(tstamp);
    assert(buf);

    /*
     * If multiplier is 0, this is an invalid timestamp. From here, just
     * set sync and scale to 0 as well.
     */
    if(!buf[1]){
        buf[0] = 0;
    }

    tstamp->sync = (buf[0] & 0x80)?1:0;
    tstamp->scale = buf[0] & 0x3F;
    tstamp->multiplier = buf[1];

    return (tstamp->multiplier != 0);
}

/*
 * Function:        OWPTimevalToTimestamp
 *
 * Description:        
 *         This function takes a struct timeval and converts the time value
 *         to an OWPTimeStamp. This function assumes the struct timeval is
 *         an absolute time offset from unix epoch (0h Jan 1, 1970), and
 *         converts the time to an OWPTimeStamp which uses time similar to
 *         the description in RFC 1305 (NTP). i.e. epoch is 0h Jan 1, 1900.
 *
 *         The Error Estimate of the OWPTimeStamp structure is invalidated
 *         in this function. (A struct timeval gives no indication of the
 *         error.)
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPTimeStamp *
OWPTimevalToTimestamp(
        OWPTimeStamp    *tstamp,
        struct timeval  *tval
        )
{
    /*
     * Ensure valid tstamp, tval - and ensure scale of tv_nsec is valid
     */
    if(!tstamp || !tval)
        return NULL;

    /*
     * Now convert representation.
     */
    OWPTimevalToNum64(&tstamp->owptime,tval);

    /*
     * Convert "epoch"'s - must do after conversion or there is the risk
     * of overflow since time_t is a 32bit signed quantity instead of
     * unsigned.
     */
    tstamp->owptime = OWPNum64Add(tstamp->owptime,
            OWPULongToNum64(OWPJAN_1970));

    return tstamp;
}

/*
 * Function:        OWPTimestampToTimeval
 *
 * Description:        
 *         This function takes an OWPTimeStamp structure and returns a
 *         valid struct timeval based on the time value encoded in it.
 *         This function assumees the OWPTimeStamp is holding an absolute
 *         time value, and is not holding a relative time. i.e. It assumes
 *         the time value is relative to NTP epoch.
 *
 *         The Error Estimate of the OWPTimeStamp structure is ignored by
 *         this function. (A struct timeval gives no indication of the error.)
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
struct timeval *
OWPTimestampToTimeval(
        struct timeval  *tval,
        OWPTimeStamp    *tstamp
        )
{
    OWPNum64    tnum;

    if(!tval || !tstamp)
        return NULL;

    /*
     * Convert "epoch"'s - must do before conversion or there is the risk
     * of overflow since time_t is a 32bit signed quantity instead of
     * unsigned.
     */
    tnum = OWPNum64Sub(tstamp->owptime, OWPULongToNum64(OWPJAN_1970));
    OWPNum64ToTimeval(tval,tnum);

    return tval;
}

/*
 * Function:        OWPTimespecToTimestamp
 *
 * Description:        
 *         This function takes a struct timespec and converts it to an
 *         OWPTimeStamp. The timespec is assumed to be an absolute time
 *         relative to unix epoch. The OWPTimeStamp will be an absolute
 *         time relative to 0h Jan 1, 1900.
 *
 *         If errest is not set, then parts of the OWPTimeStamp that deal
 *         with the error estimate. (scale, multiplier, sync) will be
 *         set to 0.
 *
 *         If errest is set, sync will be unmodified. (An errest of 0 is
 *         NOT valid, and will be treated as if errest was not set.)
 *
 *         Scale and Multiplier will be set from the value of errest.
 *
 *         If last_errest is set, then Scale and Multiplier will be left
 *         unmodified if (*errest == *last_errest).
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPTimeStamp *
OWPTimespecToTimestamp(
        OWPTimeStamp    *tstamp,
        struct timespec *tval,
        uint32_t       *errest,        /* usec's */
        uint32_t       *last_errest
        )
{
    /*
     * Ensure valid tstamp, tval - and ensure scale of tv_nsec is valid
     */
    if(!tstamp || !tval)
        return NULL;

    /*
     * Now convert representation.
     */
    OWPTimespecToNum64(&tstamp->owptime,tval);

    /*
     * Convert "epoch"'s - must do after conversion or there is the risk
     * of overflow since time_t is a 32bit signed quantity instead of
     * unsigned.
     */
    tstamp->owptime = OWPNum64Add(tstamp->owptime,
            OWPULongToNum64(OWPJAN_1970));

    /*
     * If errest is set, and is non-zero.
     */
    if(errest && *errest){
        /*
         * If last_errest is set, and the error hasn't changed,
         * then we don't touch the prec portion assuming it is
         * already correct.
         */
        if(!last_errest || (*errest != *last_errest)){
            OWPNum64        err;

            /*
             * First normalize errest to 32bit fractional seconds.
             */
            err = OWPUsecToNum64(*errest);

            /*
             * Just in the unlikely event that err is represented
             * by a type larger than 64 bits...
             * (This ensures that scale will not overflow the
             * 6 bits available to it.)
             */
            err &= (uint64_t)0xFFFFFFFFFFFFFFFFULL;

            /*
             * Now shift err until it will fit in an 8 bit
             * multiplier (after adding one for rounding err: this
             * is the reason a value of 0xFF is shifted one last
             * time), counting the shifts to set the scale.
             */
            tstamp->scale = 0;
            while(err >= 0xFF){
                err >>= 1;
                tstamp->scale++;
            }
            err++;        /* rounding error:represents shifted off bits */
            tstamp->multiplier = 0xFF & err;
        }
    }
    else{
        tstamp->sync = 0;
        tstamp->scale = 64;
        tstamp->multiplier = 1;
    }

    return tstamp;
}

/*
 * Function:        OWPTimestampToTimespec
 *
 * Description:        
 *         This function takes an OWPTimeStamp structure and returns a
 *         valid struct timespec based on the time value encoded in it.
 *         This function assumees the OWPTimeStamp is holding an absolute
 *         time value, and is not holding a relative time. i.e. It assumes
 *         the time value is relative to NTP epoch.
 *
 *         The Error Estimate of the OWPTimeStamp structure is ignored by
 *         this function. (A struct timespec gives no indication of the error.)
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
struct timespec *
OWPTimestampToTimespec(
        struct timespec *tval,
        OWPTimeStamp    *tstamp
        )
{
    OWPNum64    tnum;

    if(!tval || !tstamp)
        return NULL;

    /*
     * Convert "epoch"'s - must do before conversion or there is the risk
     * of overflow since time_t is a 32bit signed quantity instead of
     * unsigned.
     */
    tnum = OWPNum64Sub(tstamp->owptime, OWPULongToNum64(OWPJAN_1970));
    OWPNum64ToTimespec(tval,tnum);

    return tval;
}

/*
 * Function:        OWPGetTimeStampError
 *
 * Description:        
 *         Retrieve the timestamp error estimate as a double in seconds.
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
OWPGetTimeStampError(
        OWPTimeStamp    *tstamp
        )
{
    OWPNum64    err;
    uint8_t    scale;

    if(!tstamp)
        return 0.0;

    /*
     * Place multiplier in 64bit int large enough to hold full value.
     * (Due to the interpretation of OWPNum64 being 32 bits of seconds,
     * and 32 bits of "fraction", this effectively divides by 2^32.)
     */
    err = tstamp->multiplier & 0xFF;

    /*
     * Now shift it based on the "scale".
     * (This affects the 2^scale multiplication.)
     */
    scale = tstamp->scale & 0x3F;
    while(scale>0){
        err <<= 1;
        scale--;
    }

    /*
     * Return the OWPNum64 value as a double.
     */
    return OWPNum64ToDouble(err);
}
