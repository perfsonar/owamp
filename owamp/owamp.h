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
 **        File:        owamp.h
 **
 **        Author:      Jeff W. Boote
 **                     Anatoly Karp
 **
 **        Date:        Wed Mar 20 11:10:33  2002
 **
 **        Description:        
 **        This header file describes the owamp API. The owamp API is intended
 **        to provide a portable layer for implementing the owamp protocol.
 */
#ifndef        OWAMP_H
#define        OWAMP_H

/*
 * Portablility sanity checkes.
 */
#if        HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PATCH_LEVEL

#include <owamp/config.h>
#endif        /* HAVE_CONFIG_H */

#if        !HAVE_ERRNO_H || !HAVE_NETDB_H || !HAVE_STDLIB_H || !HAVE_SYS_PARAM_H
#error        Missing Header!
#endif

#if        !HAVE_GETADDRINFO || !HAVE_SOCKET
#error        Missing needed networking capabilities! (getaddrinfo and socket)
#endif


#if        !HAVE_MALLOC || !HAVE_MEMSET
#error        Missing needed memory functions!
#endif

#ifndef        HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif

#if        defined HAVE_DECL_FSEEKO && !HAVE_DECL_FSEEKO
#define fseeko(a,b,c) fseek(a,b,c)
#endif

#include <limits.h>
#include <sys/types.h>
#ifdef  HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
/* sys/param.h defines MIN/MAX on some systems... */
#ifdef MIN
#undef MIN
#endif
#ifdef MAX
#undef MAX
#endif
#include <sys/param.h>
#include <netdb.h>
#include <time.h>

/* Deal with needed inttypes.h - hopefully these were already defined... */
#ifndef PRIuPTR
#if SIZEOF_VOID_P == SIZEOF_UNSIGNED_LONG
#define	PRIuPTR "lu"
#elif SIZEOF_VOID_P == SIZEOF_UNSIGNED_LONG_LONG
#define PRIuPTR "llu"
#else
#error "Need real PRIuPTR defined by inttypes.h on this system"
#endif
#endif  /* PRIuPTR */

#ifndef PRIu64
#if SIZEOF_UINT64_T == SIZEOF_UNSIGNED_LONG
#define	PRIu64 "lu"
#elif SIZEOF_UINT64_T == SIZEOF_UNSIGNED_LONG_LONG
#define PRIu64 "llu"
#else
#error "Need real PRIu64 defined by inttypes.h on this system"
#endif
#endif  /* PRIu64 */

#ifndef        False
#define        False        (0)
#endif
#ifndef        True
#define        True        (!False)
#endif

#ifndef MIN
#define MIN(a,b) ((a<b)?a:b)
#endif
#ifndef MAX
#define MAX(a,b) ((a>b)?a:b)
#endif

#include <I2util/util.h>

/*
 * Filename/path component macros used by various parts of owamp.
 */
#ifndef OWP_PATH_SEPARATOR
#define OWP_PATH_SEPARATOR        "/"
#endif
#ifndef OWP_PATH_SEPARATOR_LEN
#define OWP_PATH_SEPARATOR_LEN        1
#endif
#ifndef OWP_FILE_EXT
#define OWP_FILE_EXT        ".owp"
#endif

/*
 * The ascii decimal encoding of the 64 bit timestamps takes this many
 * chars. Log(2^64)
 *
 * fmt indicates 0 padding, 20 significant digits.
 */
#ifndef OWP_TSTAMPFMT 
#define OWP_TSTAMPFMT  "%020" PRIu64
#endif

#ifndef OWP_TSTAMPCHARS
#define OWP_TSTAMPCHARS  20
#endif

/*
 * Char used between start_end.owp files.
 */
#ifndef OWP_NAME_SEP
#define OWP_NAME_SEP    "_"
#endif


#include <owamp/rijndael-api-fst.h>

/* Default mode offered by the server */
#define OWP_DEFAULT_OFFERED_MODE         (OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

/*
 * IANA 'blessed' port numbers for OWAMP & TWAMP
 */
#define OWP_CONTROL_SERVICE_NAME        "861"
#define TWP_CONTROL_SERVICE_NAME        "862"

/*
 * Default value to use for the listen backlog. We pick something large
 * and let the OS truncate it if it isn't willing to do that much.
 */
#define OWP_LISTEN_BACKLOG        (64)

/*
 * OWPNum64 is interpreted as 32bits of "seconds" and 32bits of
 * "fractional seconds".
 * The byte ordering is defined by the hardware for this value. 4 MSBytes are
 * seconds, 4 LSBytes are fractional. Each set of 4 Bytes is pulled out
 * via shifts/masks as a 32bit unsigned int when needed independently.
 *
 * sync/multiplier/scale are defined as in Section 5.1 of
 * draft-ietf-ippm-owdp-05.txt:
 * If sync is non-zero, then the party generating the timestamp claims to
 * have an external source of synchronization to UTC.
 * multiplier and scale are used to indicate the estimated error of
 * owptime.
 * They are interpreted as follows:
 * multiplier*(2^(-32))*(2^Scale)
 *
 * (implementor note)
 * Effectively, this breaks down such that if Scale is 0, then the multiplier
 * is the error in the same scale as the fractional seconds of owptime.
 * Therefore, for "real" errors greater than an 8 bit number at that scale
 * the value can just be right shifted until it fits into an 8 bit integer,
 * and the number of shifts would indicate the "Scale" value.
 */
typedef uint64_t OWPNum64;

/*
 * Arithmetic/Conversion functions on OWPNum64 numbers.
 */

/*
 * These macros should be used instead of directly using
 * arithmetic on these types in the event that the underlying
 * type is changed from an uint64_t to some kind of structure.
 *
 */
#define OWPNum64Add(x,y)    (x+y)
#define OWPNum64Sub(x,y)    (x-y)
#define OWPNum64Cmp(x,y)    ((x<y)?\
        (-1):\
        ((x>y)?1:0))
#define OWPNum64Diff(x,y)   ((x>y)?\
        (x-y):\
        (y-x))
#define OWPNum64Min(x,y)    MIN(x,y)
#define OWPNum64Max(x,y)    MAX(x,y)

extern OWPNum64
OWPNum64Mult(
        OWPNum64    x,
        OWPNum64    y
        );

extern OWPNum64
OWPULongToNum64(
        uint32_t   from
        );


extern void
OWPNum64ToTimeval(
        struct timeval  *to,
        OWPNum64        from
        );

extern void
OWPTimevalToNum64(
        OWPNum64        *to,
        struct timeval  *from
        );

extern void
OWPNum64ToTimespec(
        struct timespec *to,
        OWPNum64        from
        );

extern void
OWPTimespecToNum64(
        OWPNum64        *to,
        struct timespec *from
        );

extern double
OWPNum64ToDouble(
        OWPNum64    from
        );

extern OWPNum64
OWPDoubleToNum64(
        double      from
        );

extern OWPNum64
OWPUsecToNum64(
        uint32_t   usec
        );

/*
 * These structures are opaque to the API user.
 * They are used to maintain state internal to the library.
 */
typedef struct OWPContextRec    *OWPContext;
typedef struct OWPControlRec    *OWPControl;

/*
 * Timestamp related types and structures needed throughout.
 */

typedef struct OWPTimeStampRec{
    OWPNum64    owptime;
    uint8_t    sync;
    uint8_t    multiplier;
    uint8_t    scale;
} OWPTimeStamp;


/* Codes for returning error severity and type. */
/* values are mapped to syslog "priorities" we want to use. */
typedef enum {
    OWPErrFATAL=3,
    OWPErrWARNING=4,
    OWPErrINFO=6,
    OWPErrDEBUG=7,
    OWPErrOK=8
} OWPErrSeverity;

typedef enum {
    OWPErrUNKNOWN=0,
    OWPErrPOLICY,
    OWPErrINVALID,
    OWPErrUNSUPPORTED
} OWPErrType;


/*
 * Valid values for "accept" - this will be added to for the purpose of
 * enumerating the reasons for rejecting a session, or early termination
 * of a test session.
 */
typedef enum{
    OWP_CNTRL_INVALID=-1,           /* No value yet                     */
    OWP_CNTRL_ACCEPT=0,             /* ok                               */
    OWP_CNTRL_REJECT=1,             /* reject for any reason            */
    OWP_CNTRL_FAILURE=2,            /* internal failure                 */
    OWP_CNTRL_UNSUPPORTED=3,        /* request functionality unsupported */
    OWP_CNTRL_UNAVAILABLE_PERM=4,   /* Permanent resource limitation    */
    OWP_CNTRL_UNAVAILABLE_TEMP=5    /* Temporary resource limitation    */
} OWPAcceptType;

typedef intptr_t    OWPBoolean;
typedef uint8_t     OWPSID[16];
typedef uint8_t     OWPSequence[4];

/*
 * technically the username in the client greeting message can have uint8_t
 * but this implementation limits it to a valid "char" type.
 */
#define OWP_USERID_LEN        80
typedef char        OWPUserID[OWP_USERID_LEN+1];        /* add 1 for '\0' */


#define OWP_MODE_UNDEFINED      (0)
#define OWP_MODE_OPEN           (01)
#define OWP_MODE_AUTHENTICATED  (02)
#define OWP_MODE_ENCRYPTED      (04)
#define OWP_MODE_DOCIPHER       (OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

typedef uint32_t        OWPSessionMode;

typedef enum {
    OWPSlotUnspecifiedType = -1,        /* invalid value        */
    OWPSlotRandExpType = 0,
    OWPSlotLiteralType = 1
} OWPSlotType;

typedef struct{
    OWPSlotType slot_type;
    OWPNum64    mean;
} OWPSlotRandExp;

typedef struct{
    OWPSlotType slot_type;
    OWPNum64    offset;
} OWPSlotLiteral;

/*
 * For now - all current slot types are of the exact same format, and
 * the "time" element can be interpreted as the mean_delay between packets
 * for the purposes of bandwidth calculations. If that is ever not true,
 * this type should be removed, and any code that uses it will need to
 * have a switch statement to do whatever is appropriate for each individual
 * slot type.
 */
typedef struct{
    OWPSlotType slot_type;
    OWPNum64    mean_delay;
} OWPSlotAny;

typedef union OWPSlotUnion{
    OWPSlotType     slot_type;
    OWPSlotRandExp  rand_exp;
    OWPSlotLiteral  literal;
    OWPSlotAny      any;
} OWPSlot;

typedef struct{
    OWPNum64    start_time;
    OWPNum64    loss_timeout;
    uint32_t    typeP;
    uint32_t    packet_size_padding;
    uint32_t    npackets;
    uint32_t    nslots;
    OWPSlot     *slots;
} OWPTestSpec;

typedef uint32_t OWPPacketSizeT;

/*
 * an OWPScheduleContextRec is used to maintain state for the schedule
 * generator. Multiple contexts can be allocated to maintain multiple
 * "streams" of schedules.
 */
typedef struct OWPScheduleContextRec        *OWPScheduleContext;

OWPScheduleContext
OWPScheduleContextCreate(
        OWPContext      ctx,
        OWPSID          sid,
        OWPTestSpec     *tspec
        );

void
OWPScheduleContextFree(
        OWPScheduleContext  sctx
        );

OWPErrSeverity
OWPScheduleContextReset(
        OWPScheduleContext  sctx,
        OWPSID              sid,
        OWPTestSpec         *tspec
        );

OWPNum64
OWPScheduleContextGenerateNextDelta(
        OWPScheduleContext  sctx
        );
void
OWPScheduleContextFree(
        OWPScheduleContext  sctx
        );

/*
 * These functions expose the exponential deviates for the exponential
 * distribution used to generate send schedules.
 */
typedef struct OWPExpContextRec *OWPExpContext;

OWPExpContext
OWPExpContextCreate(
        OWPContext      ctx,
        uint8_t        seed[16]
        );
OWPNum64
OWPExpContextNext(
        OWPExpContext   exp
        );

void
OWPExpContextFree(
        OWPExpContext   exp
        );


/*
 * Error Reporting:
 *
 * Notice that this macro expands to multiple statements so it is
 * imperative that you enclose it's use in {} in single statement
 * context's such as:
 *         if(test)
 *                 OWPError(...);        NO,NO,NO,NO!
 * Instead:
 *         if(test){
 *                 OWPError(...);
 *         }
 *
 *
 * (Sure would be nice if it were possible to to vararg macros...)
 */
#define OWPError        I2ErrLocation_(__FILE__,__DATE__,__LINE__);        \
    OWPError_

/*
 * Don't call this directly - use the OWPError macro.
 *         Let me repeat.
 * Don't call this directly - use the OWPError macro.
 */
extern void
OWPError_(
        OWPContext      ctx,
        OWPErrSeverity  severity,
        OWPErrType      etype,
        const char      *fmt,
        ...
        );
        
/*
 * The "context"  is used to basically initialize the library. There is no
 * "global" state - so you can create more than one "context" if you like.
 * (Well... SIGPIPE is disabled... I suppose that is global.)
 *
 * There are specific defaults that can be modified within the context by
 * calling the OWPContextConfigSet{F,V} function with the following keys and
 * types. (The key is a string - the type indicates what type of data
 * will be stored/retrieved using that key.
 * The 'F' version is for setting/getting functions and the 'V' version
 * is for values. (The C standard does not allow us to treat them
 * generically - I suppose I could have exposed a union, but this
 * seems easier.)
 */

/*
 * This typedef is used for the "generic" type of all function pointer
 * types. (void *) is used for the 'value' equivalent.
 */

typedef void (*OWPFunc)(void);

/*
 * This type is used to hold a pointer to an integer pointer. That pointer
 * points at a value that determines if the low/level i/o functions should
 * return on interrupt. If it is non-zero an interrupt will cause the i/o
 * routine to fail and return. If it is zero, the low level i/o routine will
 * ignore the interrupt and restart the i/o.
 * (this can be used to ignore some signals and return on others.)
 */
#define OWPInterruptIO                "OWPInterruptIO"

/*
 * This type is used to hold a pointer to a port-range record. This
 * record is used to indicate what port ranges should be used for
 * opening test connections.
 */
#define        OWPTestPortRange        "OWPTestPortRange"
typedef        struct OWPPortRangeRec{
    uint16_t       low;
    uint16_t       high;
} OWPPortRangeRec, *OWPPortRange;

/*
 * This type is used to define the function that retrieves the shared
 * secret from whatever key-store is in use.
 * It should return True if it is able to returnfill in the key_ret variable that
 * is passed in from the caller. False if not. If the function returns false,
 * the caller should check the err_ret value. If OK, then the userid simply
 * didn't exist - otherwise it indicates an error in the key store mechanism.
 *
 * If an application doesn't set this, Encrypted and Authenticated
 * mode will be disabled.
 *
 * The 'pf_free' pointer will be set to the memory block allocated for pf
 * if the caller needs to free the memory after calling this function.
 * (Different pass-phrase stores use different memory models. The returned
 * pf value should NOT be freed directly!)
 */        
#define        OWPGetPF                "OWPGetPF"
typedef OWPBoolean      (*OWPGetPFFunc)(
        OWPContext      ctx,
        const OWPUserID userid,
        uint8_t         **pf,
        size_t          *pf_len,
        void            **pf_free,  /* If implementation uses dynamic memory */
        OWPErrSeverity  *err_ret
        );

/*
 * This function will be called from OWPControlOpen and OWPServerAccept
 * to determine if the control connection should be accepted.
 * It is called after connecting, and after determining the userid.
 * On failure, value of *err_ret can be inspected: if > OWPErrWARNING,
 * this means rejection based on policy, otherwise there was an error
 * in the function itself.
 *
 * If an application doesn't set this, all connections will be allowed.
 */
#define OWPCheckControlPolicy        "OWPCheckControlPolicy"
typedef OWPBoolean (*OWPCheckControlPolicyFunc)(
        OWPControl      cntrl,
        OWPSessionMode  mode_req,
        const OWPUserID userid,
        struct sockaddr *local_sa_addr,
        struct sockaddr *remote_sa_addr,
        OWPErrSeverity  *err_ret
        );

/*
 * This function will be called by OWPRequestTestSession if
 * one of the endpoints of the test is on the localhost.
 * If err_ret returns OWPErrFATAL, OWPRequestTestSession/OWPProcessTestSession
 * will not continue, and return OWPErrFATAL as well.
 *
 * Only the IP address values will be set in the sockaddr structures -
 * i.e. port numbers will not be valid.
 *
 * If an application doesn't set this, all tests will be allowed.
 *
 * The application can use the "closure" pointer to store data that will
 * be passed onto the Open/Close and TestComplete functions. The intended
 * purpose of this pointer is to keep track of resources that are "reserved"
 * from this function - allowing the other functions to "free" or modify
 * those resource reservations.
 */
#define OWPCheckTestPolicy        "OWPCheckTestPolicy"
typedef OWPBoolean (*OWPCheckTestPolicyFunc)(
        OWPControl      cntrl,
        OWPBoolean      local_sender,
        struct sockaddr *local_sa_addr,
        struct sockaddr *remote_sa_addr,
        socklen_t       sa_len,
        OWPTestSpec     *test_spec,
        void            **closure,
        OWPErrSeverity  *err_ret
        );

/*
 * This function will be called by OWPProcessFetchSession to implement
 * the 'policy' decision if the fetch request should be allowed.
 * If err_ret returns OWPErrFATAL, OWPProcessFetchSession
 * will not continue, and return OWPErrFATAL as well.
 *
 * Only the IP address values will be set in the sockaddr structures -
 * i.e. port numbers will not be valid.
 *
 * If an application doesn't set this, all data that is buffered
 * that can be found, will be returned.
 *
 * The application can use the "closure" pointer to store data that will
 * be passed onto the Open/Close and TestComplete functions. The intended
 * purpose of this pointer is to keep track of resources that are "reserved"
 * from this function - allowing the other functions to "free" or modify
 * those resource reservations.
 *
 */
#define OWPCheckFetchPolicy        "OWPCheckFetchPolicy"
typedef OWPBoolean (*OWPCheckFetchPolicyFunc)(
        OWPControl      cntrl,
        struct sockaddr *local_sa_addr,
        struct sockaddr *remote_sa_addr,
        socklen_t       sa_len,
        uint32_t        begin,
        uint32_t        end,
        OWPSID          sid,
        void            **closure,
        OWPErrSeverity  *err_ret
        );

/*
 * This function will be called when a test is "complete". It is used
 * to free resources that were allocated on behalf of the test including
 * memory associated with the "closure" pointer itself if necessary.
 */
#define OWPTestComplete                "OWPTestComplete"
typedef void (*OWPTestCompleteFunc)(
        OWPControl      cntrl,
        void            *closure,
        OWPAcceptType   aval
        );

/*
 * This function will be called by the test endpoint initialization
 * code to open a file for writing. It will also be called by the
 * fetch-session code to open an existing file to return the data
 * to an application. (fname_ret is PATH_MAX+1 to include a nul byte.)
 * (if 
 */
#define OWPOpenFile                "OWPOpenFile"
typedef FILE* (*OWPOpenFileFunc)(
        OWPControl  cntrl,
        void        *closure,
        OWPSID      sid,
        char        fname_ret[PATH_MAX+1]
        );

/*
 * This function will be called by the test endpoint "cleanup" code
 * to indicate that the given fp (from OWPOpenFile) is no longer needed.
 * This allows the implementation to do it's own cleanup based on policy.
 * For example, a delete-on-fetch functionality could be implemented here
 * to delete the given file now that is it no longer needed.
 */
#define OWPCloseFile                "OWPCloseFile"
typedef void (*OWPCloseFileFunc)(
        OWPControl      cntrl,
        void            *closure,
        FILE            *fp,
        OWPAcceptType   aval
        );

#ifndef NDEBUG
/*
 * This integer type is used to aid in child-debugging. If OWPChildWait is
 * set and non-zero forked off endpoints will go into a busy-wait loop to
 * allow a debugger to attach to the process. (i.e. they will be hung until
 * attached and the loop variable modified with the debugger. This should
 * not strictly be needed, but the gdb on many of the test plateforms I
 * used did not implement the follow-fork-mode option.) This was a quick
 * fix. (This will not be used if owamp is compiled with -DNDEBUG.)
 */
#define OWPChildWait        "OWPChildWait"
#endif

/*
 * If this variable is set in the context, send/recv children processes
 * are directed to detach from the process group. (This is useful to
 * catch ^C from a shell in the parent process without having the
 * SIGINT being sent to the children processes. By doing this, it is
 * possible to gracefully shutdown an owamp test session in response
 * to SIGINT.)
 */
#define OWPDetachProcesses  "OWPDetachProcesses"

/*
 * Set the 'count' value for the pbkdf2 function.
 */
#define OWPKeyDerivationCount "OWPKeyDerivationCount"

/*
 * Set the 'enddelay' (time for a sender to wait after session completion
 * to actually send the stop session message).
 * (double ptr)
 */
#define OWPEndDelay "OWPEndDelay"

/*
 * Use IPv4 addresses only.
 */
#define OWPIPv4Only "OWPIPv4Only"

/*
 * Use IPv6 addresses only.
 */
#define OWPIPv6Only "OWPIPv6Only"

extern int
OWPReportLevelByName(
        const char      *name
        );
        
extern OWPContext
OWPContextCreate(
        I2ErrHandle eh
        );

extern void
OWPContextFree(
        OWPContext  ctx
        );

extern I2ErrHandle
OWPContextErrHandle(
        OWPContext  ctx
        );

extern OWPBoolean
OWPContextConfigSetF(
        OWPContext  ctx,
        const char  *key,
        OWPFunc     func
        );

extern OWPBoolean
OWPContextConfigSetV(
        OWPContext  ctx,
        const char  *key,
        void        *value
        );

extern OWPBoolean
OWPContextConfigSetU32(
        OWPContext  ctx,
        const char  *key,
        uint32_t    value
        );

extern OWPFunc
OWPContextConfigGetF(
        OWPContext  ctx,
        const char  *key
        );

extern void*
OWPContextConfigGetV(
        OWPContext  ctx,
        const char  *key
        );

extern OWPBoolean
OWPContextConfigGetU32(
        OWPContext  ctx,
        const char  *key,
        uint32_t    *val
        );

extern OWPBoolean
OWPContextConfigDelete(
        OWPContext  ctx,
        const char  *key
        );

/*
 * The following functions are completely analogous to the Context versions
 * but are used to maintain state information about a particular control
 * connection.
 */
extern OWPBoolean
OWPControlConfigSetF(
        OWPControl  cntrl,
        const char  *key,
        OWPFunc     func
        );

extern OWPBoolean
OWPControlConfigSetV(
        OWPControl  cntrl,
        const char  *key,
        void        *value
        );

extern OWPFunc
OWPControlConfigGetF(
        OWPControl  cntrl,
        const char  *key
        );

extern void*
OWPControlConfigGetV(
        OWPControl  cntrl,
        const char  *key
        );

extern OWPBoolean
OWPControlConfigDelete(
        OWPControl  cntrl,
        const char  *key
        );

/*
 * OWPControlOpen allocates an OWPclient structure, opens a connection to
 * the OWP server and goes through the initialization phase of the
 * connection. This includes AES/CBC negotiation. It returns after receiving
 * the ServerStart message.
 *
 * This is typically only used by an OWP client application (or a server
 * when acting as a client of another OWP server).
 *
 * err_ret values:
 *         OWPErrOK        completely successful - highest level mode ok'd
 *         OWPErrINFO        session connected with less than highest level mode
 *         OWPErrWARNING        session connected but future problems possible
 *         OWPErrFATAL        function will return NULL - connection is closed.
 *                 (Errors will have been reported through the OWPErrFunc
 *                 in all cases.)
 * function return values:
 *         If successful - even marginally - a valid OWPclient handle
 *         is returned. If unsuccessful, NULL is returned.
 *
 * Once an I2Addr record is passed into this function - it is
 * automatically free'd and should not be referenced again in any way.
 *
 * Client
 */
extern OWPControl
OWPControlOpen(
        OWPContext      ctx,
        const char      *local_addr,    /* src addr or NULL             */
        I2Addr          server_addr,    /* server addr or NULL          */
        uint32_t       mode_mask,      /* OR of OWPSessionMode vals    */
        OWPUserID       userid,         /* null if unwanted             */
        OWPNum64        *uptime_ret,    /* server uptime - ret or NULL  */
        OWPErrSeverity  *err_ret
        );

/*
 * TWPControlOpen is similar to OWPControlOpen, except that it
 * connects to a TWP server
 */
extern OWPControl
TWPControlOpen(
        OWPContext      ctx,
        const char      *local_addr,    /* src addr or NULL             */
        I2Addr          server_addr,    /* server addr or NULL          */
        uint32_t       mode_mask,      /* OR of OWPSessionMode vals    */
        OWPUserID       userid,         /* null if unwanted             */
        OWPNum64        *uptime_ret,    /* server uptime - ret or NULL  */
        OWPErrSeverity  *err_ret
        );

/*
 * Client and Server
 */
extern OWPErrSeverity
OWPControlClose(
        OWPControl  cntrl
        );

/*
 * Request a test session - if the function returns True, then the function
 * returns a valid SID for the session.
 *
 * If the function returns False - check err_ret. If err_ret is ErrOK, the
 * session was denied by the server, and the control connection is still
 * valid.
 *
 * TODO:Add OWPControlStatus(cntrl) function to determine cntrl status...
 *
 * Reasons this function will return False:
 * 1. Server denied test: err_ret==ErrOK
 * 2. Control connection failure: err_ret == ErrFATAL
 * 3. Local resource problem (malloc/fork/fdopen): err_ret == ErrFATAL
 * 4. Bad addresses: err_ret == ErrWARNING
 *
 * Once an I2Addr record has been passed into this function, it
 * is automatically free'd. It should not be referenced again in any way.
 *
 * Conversely, the test_spec is completely copied, and the caller continues
 * to "own" all memory associated with it after this call. (Including
 * the "slots" array that is part of the test_spec.)
 *
 * Client
 */
extern OWPBoolean
OWPSessionRequest(
        OWPControl      control_handle,
        I2Addr          sender,
        OWPBoolean      server_conf_sender,
        I2Addr          receiver,
        OWPBoolean      server_conf_receiver,
        OWPTestSpec     *test_spec,
        FILE            *fp,
        OWPSID          sid_ret,
        OWPErrSeverity  *err_ret
        );

/*
 * Start all test sessions - if successful, returns OWPErrOK.
 *
 * Client and Server
 */
extern OWPErrSeverity
OWPStartSessions(
        OWPControl  control_handle
        );

/*
 * Wait for test sessions to complete. This function will return the
 * following integer values:
 *         <0        ErrorCondition
 *         0        StopSessions received, acted upon, and sent back.
 *         1        wake_time reached
 *
 *        2        system event (signal)
 *
 * To effect a poll - specify a waketime in the past. 1 will be returned
 * if there is nothing to read.
 *
 * To use a signal interaction instead of the waketime interface, set the
 * retn_on_intr pointer. Install a signal handler that sets the value
 * to non-zero, and this function will return 2. (If wake_time is non-null,
 * retn_on_intr is not used.) This interface can be used without signal
 * handlers as well be simply passing in a pointer to a non-zero value.
 * This function will return for any interrupt. (The signal interface
 * allows you to set the value to non-zero only for signals you are
 * actually interested in.)
 *
 * To block indefinately, specify NULL for wake_time and NULL for
 * retn_on_intr. (StopSessionsWait will poll the status of current tests
 * automatically whenever a system event takes place in this case, so
 * StopSessionsWait will never return 1 or 2 in this case.)
 *
 * If wake_time or retn_on_intr is set, and this function returns 1 or 2, then
 * it is required to poll the status of each local endpoint using
 * OWPTestSessionStatus until all sessions complete.  (OWPSessionsActive is
 * a simple way to poll all of them - you know you are done when it returns 0.)
 * You can of course recall StopSessionsWait in this case.
 *
 * If acceptval returns anything other than OWP_CNTRL_ACCEPT, the
 * data files associated with the recieve sessions SHOULD be deleted.
 *
 * Client and Server
 */
extern int
OWPStopSessionsWait(
        OWPControl      control_handle,
        OWPNum64        *wake_time,                /* abs time */
        int             *retn_on_intr,
        OWPAcceptType   *acceptval,                /* out */
        OWPErrSeverity  *err_ret
        );

/*
 * Used to poll the status of a test endpoint.
 *
 * returns:
 *                 True if it could get the status,
 *                 False if it could not. (session with given sid wasn't found,
 *                 or "send" indicated a remote endpoint.)
 *
 *                 aval returns the following for status:
 *         <0        Test is not yet complete.
 *         >=0        Accept value of completed test. 0 indicates success
 *                 other values indicate type of error test encountered.
 */
extern OWPBoolean
OWPSessionStatus(
        OWPControl      cntrl,
        OWPSID          sid,        /* SID of test to poll        */
        OWPAcceptType   *aval        /* out - return accept value        */
        );

/*
 * Used to determine how many local endpoints are still active.
 * (effectively calls the OWPTestSessionStatus function on all endpoints
 * and determines if they are complete yet.)
 *
 * If acceptval is non-null it is set to the MAX acceptval of any
 * complete session.
 *
 * returns:
 *         number of active endpoints.
 */
extern int
OWPSessionsActive(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval        /* rtn */
        );

/*
 * Send the StopSession message, and wait for the response.
 *
 * Client and Server.
 */
extern OWPErrSeverity
OWPStopSessions(
        OWPControl      control_handle,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval        /* in/out */
        );


/*
 * Return the file descriptor being used for the control connection. An
 * application can use this to call select or otherwise poll to determine
 * if anything is ready to be read but they should not read or write to
 * the descriptor.
 * This can be used in conjunction with the OWPStopSessionsWait
 * function so that the application can recieve user input, and only call
 * the OWPStopSessionsWait function when there is something to read
 * from the connection. (A nul timestamp would be used in this case
 * so that OWPStopSessionsWait does not block.)
 *
 * This is also useful in a policy context - getpeername can be called
 * on this descriptor.
 *
 * If the control_handle is no longer connected - the function will return
 * a negative value.
 *
 * Client and Server.
 */
extern int
OWPControlFD(
        OWPControl  control_handle
        );

extern int
OWPErrorFD(
        OWPContext  ctx
        );

extern
I2Addr
OWPServerSockCreate(
        OWPContext      ctx,
        I2Addr          addr,
        OWPErrSeverity  *err_ret
        );

extern I2Addr
TWPServerSockCreate(
        OWPContext      ctx,
        I2Addr          addr,
        OWPErrSeverity  *err_ret
        );

/*!
 * Function:        OWPControlAccept
 *
 * Description:        
 *                 This function is used to initialiize the communication
 *                 to the peer.
 *           
 * In Args:        
 *                 connfd,connsaddr, and connsaddrlen are all returned
 *                 from "accept".
 *
 * Returns:        Valid OWPControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *
 *              If *rtn_on_intr and an inturrupt happens during write/read
 *              err_ret will be set to OWPErrWARNING.
 *
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
extern OWPControl
OWPControlAccept(
        OWPContext      ctx,            /* library context              */
        int             connfd,         /* conencted socket             */
        struct sockaddr *connsaddr,     /* connected socket addr        */
        socklen_t       connsaddrlen,   /* connected socket addr len    */
        uint32_t       mode_offered,   /* advertised server mode       */
        OWPNum64        uptime,         /* uptime report                */
        int             *retn_on_intr,  /* return on i/o interrupt      */
        OWPErrSeverity  *err_ret        /* err - return                 */
        );

extern OWPControl
TWPControlAccept(
        OWPContext      ctx,            /* library context              */
        int             connfd,         /* conencted socket             */
        struct sockaddr *connsaddr,     /* connected socket addr        */
        socklen_t       connsaddrlen,   /* connected socket addr len    */
        uint32_t       mode_offered,   /* advertised server mode       */
        OWPNum64        uptime,         /* uptime report                */
        int             *retn_on_intr,  /* return on i/o interrupt      */
        OWPErrSeverity  *err_ret        /* err - return                 */
        );

typedef enum OWPRequestType{
    OWPReqInvalid=-1,
    OWPReqSockClose=10,
    OWPReqSockIntr=11,
    OWPReqTest=1,
    OWPReqStartSessions=2,
    OWPReqStopSessions=3,
    OWPReqFetchSession=4,
    OWPReqTestTW=5,
} OWPRequestType;

extern OWPRequestType
OWPReadRequestType(
        OWPControl  cntrl,
        int         *retn_on_intr
        );

extern OWPErrSeverity
OWPProcessTestRequest(
        OWPControl  cntrl,
        int         *retn_on_intr
        );

extern OWPErrSeverity
OWPProcessTestRequestTW(
        OWPControl  cntrl,
        int         *retn_on_intr
        );

extern OWPErrSeverity
OWPProcessStartSessions(
        OWPControl  cntrl,
        int         *retn_on_intr
        );

extern OWPErrSeverity
OWPProcessStopSessions(
        OWPControl  cntrl
        );

extern OWPErrSeverity
OWPProcessFetchSession(
        OWPControl  cntrl,
        int         *retn_on_intr
        );

extern OWPContext
OWPGetContext(
        OWPControl  cntrl
        );

extern OWPSessionMode
OWPGetMode(
        OWPControl  cntrl
        );


/*
 ** Given the protocol family, OWAMP mode and packet padding,
 ** compute the size of resulting full IP test packet.
 */

/*
 * Payload size is used to determine how large the buffers need to be
 * to read a packet.
 */
extern OWPPacketSizeT
OWPTestPayloadSize(
        OWPSessionMode  mode,
        uint32_t       padding
        );
extern OWPPacketSizeT
OWPTestTWPayloadSize(
        OWPSessionMode  mode,
        uint32_t       padding
    );
/*
 * PacketSize is used to compute the full packet size - this is used to
 * determine bandwidth requirements for policy purposes.
 */
extern OWPPacketSizeT
OWPTestPacketSize(
        int             af,
        OWPSessionMode  mode,
        uint32_t       padding
        );
extern OWPPacketSizeT
OWPTestTWPacketSize(
        int             af,    /* AF_INET, AF_INET6 */
        OWPSessionMode  mode,
        uint32_t       padding
    );

/*
 * Returns # packets/second: 0.0 on error.
 */
extern double
OWPTestPacketRate(
        OWPContext      ctx,
        OWPTestSpec     *tspec
        );

/*
 * Returns bits/second: 0.0 on error.
 */
extern double
OWPTestPacketBandwidth(
        OWPContext      ctx,
        int             af,
        OWPSessionMode  mode,
        OWPTestSpec     *tspec
        );

extern uint32_t
OWPFetchSession(
        OWPControl      cntrl,
        FILE            *fp,
        uint32_t       begin,
        uint32_t       end,
        OWPSID          sid,
        OWPErrSeverity  *err_ret
        );

/*
 ** Processing Session data to/from local disk.
 */
typedef enum{
    OWP_SESSION_FINISHED_ERROR=0,       /* Invalid session datafile     */
    OWP_SESSION_FINISHED_NORMAL=1,      /* Complete datafile            */
    OWP_SESSION_FINISHED_INCOMPLETE=2   /* StopSessions did not happen  */
} OWPSessionFinishedType;

/*
 * This data structure is used to read/write a session header. When
 * reading a header, if the "header" element returns false, the file
 * did not contain any header information, and the remaining fields
 * are not valid.
 */
typedef struct OWPSessionHeaderRec{
    OWPBoolean              header;         /* RO: TestSession header?  */
    uint32_t                version;        /* RO: File version         */
    uint32_t                rec_size;       /* RO: data record size     */
    OWPSessionFinishedType  finished;       /* RW: is session finished?
                                               0:no,1:yes,2:unknown     */

    uint32_t                next_seqno;     /* RW: next seq for sender  */
    uint32_t                num_skiprecs;   /* RW: nskips               */
    uint32_t                num_datarecs;   /* RW: nrecs                */

    off_t                   oset_skiprecs;  /* RO: file offset to skips */
    off_t                   oset_datarecs;  /* RO: file offset to data  */
    struct stat             sbuf;           /* RO: sbuf of file         */

    uint8_t                 ipvn;           /* RO: ipvn of addrs        */
    socklen_t               addr_len;       /* RO: saddr_len of saddrs  */
    struct sockaddr_storage addr_sender;    /* RW                       */
    struct sockaddr_storage addr_receiver;  /* RW                       */
    OWPBoolean              conf_sender;    /* RW                       */
    OWPBoolean              conf_receiver;  /* RW                       */
    OWPSID                  sid;            /* RW                       */
    OWPTestSpec             test_spec;      /* RW                       */
} OWPSessionHeaderRec, *OWPSessionHeader;

/*
 * Write data header to the file.
 * Returns:
 */
extern OWPBoolean
OWPWriteDataHeader(
        OWPContext          ctx,
        FILE                *fp,
        OWPSessionHeader    hdr
        );

/*
 *  OWPWriteDataHeaderNumSkipRecs
 * Sets num_skips filed and the oset_skips field. oset_datarecs and
 * num_datarecs MUST be set in the file before this call. (Either by
 * calling OWPWriteDataHeader with num_datarecs or by calling
 * OWPWriteDataHeaderNumDataRecs.)
 *
 * This funciton should only be called if skip records are being placed
 * in the file after datarecs, and then only after the number of datarecs
 * has been fixed.
 */
extern OWPBoolean
OWPWriteDataHeaderNumSkipRecs(
        OWPContext  ctx,
        FILE        *fp,
        uint32_t   num_skiprecs
        );

/*
 *  OWPWriteDataHeaderNumDataRecs
 * Sets the num_datarecs field in the file. If oset_skiprecs is nil, this
 * function sets that to just beyond the data records.
 */
extern OWPBoolean
OWPWriteDataHeaderNumDataRecs(
        OWPContext  ctx,
        FILE        *fp,
        uint32_t   num_datarecs
        );

/*
 * Returns:
 * number of records in the file. 0 on error. (errno will be set.)
 * fp is moved to beginning of data records.
 */
extern uint32_t
OWPReadDataHeader(
        OWPContext          ctx,
        FILE                *fp,
        OWPSessionHeader    hdr_ret
        );

/*
 * OWPReadDataHeaderSlots
 *  This function is used to read the "slots" out of the file. It is only
 *  valid for data files of version 2 or above so it is important to check
 *  the file version using OWPReadDataHeader before calling this function.
 *  OWPReadDataHeader only reads the fixed portion of the TestReq out
 *  of the file. OWPReadDataHeader can be used to determine how many slots
 *  are in the file, and the caller of this function is required to pass
 *  in the memory for "slots".
 *
 * Returns:
 * OWPBoolean - T if successful, F if not.
 */
extern OWPBoolean
OWPReadDataHeaderSlots(
        OWPContext  ctx,
        FILE        *fp,
        uint32_t   nslots,
        OWPSlot     *slots
        );

/*
 * Applications use this type to manipulate individual timestamp data records.
 */
typedef struct OWPDataRec {
    uint32_t       seq_no;
    OWPTimeStamp    send;
    OWPTimeStamp    recv;
    uint8_t        ttl;
} OWPDataRec;

/*
 * Write data record to a file.
 * Returns:
 * 0        Success
 */
extern OWPBoolean
OWPWriteDataRecord(
        OWPContext  ctx,
        FILE        *fp,
        OWPDataRec  *rec
        );

/*
 * This (type of) function is used by Fetch-Client to process
 * data records.
 *
 * The function should return < 0 to indicate an error condition in which
 * case OWPParseRecords will return OWPErrFATAL.
 * It should return 0 to continue parsing.
 * It should return 1 to terminate parsing in which case OWPParseRecords will
 * return OWPErrOK.
 *
 * num_rec can be any number less than or equal to the number of valid
 * records in the file reported by OWPReadDataHeader. This function assumes
 * the fp is currently pointing at the beginning of a data record.
 * (This can be done simply by calling OWPReadDataHeader or fseek'ing to
 * the offset reported by OWPReadDataHeader.) Or advancing by some multiple
 * of hdr.rec_size.
 *
 * If OWPParseRecords completes parsing "num_rec" records with out error,
 * it will return OWPErrOK.
 * If OWPParseRecords is unable to complete parsing because of file i/o problems
 * it will return OWPErrFATAL.
 */
typedef int (*OWPDoDataRecord)(
        OWPDataRec  *rec,
        void        *udata
        );

extern OWPErrSeverity
OWPParseRecords(
        OWPContext      ctx,
        FILE            *fp,
        uint32_t       num_rec, 
        uint32_t       file_version,   /* from OWPReadDataHeader   */
        OWPDoDataRecord proc_rec,
        void            *udata          /* passed into proc_rec     */
        );

/*
 * OWPReadDataSkipRecs
 *  This function is used to read the "skips" out of the file. It is only
 *  valid for data files of version 2 or above so it is important to check
 *  the file version.
 *  OWPReadDataHeader can be used to determine how many skips
 *  are in the file, and the caller of this function is required to pass
 *  in the memory for "skips".
 *
 *  (For very large session files it may become necessary to create a
 *  Parse interface so the entire array does not have to be in memory
 *  at one time - but for now I will be wasteful.)
 *
 * Returns:
 * OWPBoolean - T if successful, F if not.
 */
typedef struct OWPSkipRec OWPSkipRec, *OWPSkip;
struct OWPSkipRec{
    uint32_t   begin;
    uint32_t   end;
};

extern OWPBoolean
OWPReadDataSkips(
        OWPContext          ctx,
        FILE                *fp,
        uint32_t           nskips,
        OWPSkip             skips
        );


extern double
OWPDelay(
        OWPTimeStamp    *send_time,
        OWPTimeStamp    *recv_time
        );

extern OWPBoolean
OWPIsLostRecord(
        OWPDataRec      *rec
        );

extern I2Boolean
OWPParsePortRange (
        char    *pspec,
        OWPPortRangeRec   *portspec
        );
/*
 * TODO: This needs lots of clean-up to be a good public interface.
 * Most of these fields do not really need to be exposed.
 *
 * This structure is used to pass into a OWPDoDataRecord function
 * that will parse an owd file and generate some statistics.
 */
typedef struct OWPPacketRec OWPPacketRec, *OWPPacket;
struct OWPPacketRec{
    OWPPacket   next;
    uint32_t    seq;        /* packet seq no */
    OWPNum64    schedtime;  /* scheduled send time */
    uint32_t    seen;       /* how many times seen? */
    OWPBoolean  lost;
};

typedef struct OWPBucketRec OWPBucketRec, *OWPBucket;
struct OWPBucketRec{
    OWPBucket   next;
    int         b;      /* bucket index */
    uint32_t    n;      /* samples in this bucket */
};

typedef struct OWPStatsRec{

    /*
     * Error reporting context
     */
    OWPContext          ctx;

    /*
     * Output values
     */
    FILE                *output;    /* If set, verbose description of rec's */

    char                fromhost[NI_MAXHOST];
    char                fromaddr[NI_MAXHOST];
    char                fromserv[NI_MAXSERV];

    char                tohost[NI_MAXHOST];
    char                toaddr[NI_MAXHOST];
    char                toserv[NI_MAXSERV];
    
    float               scale_factor;
    char                scale_abrv[3];

    unsigned long       rec_limit; /* limits the number of records to print */
    OWPBoolean          display_unix_ts; /* If set, prints timestamps in unix format */

    /*
     * data file information
     */
    FILE                *fp;
    OWPSessionHeaderRec hdr_rec;
    OWPSessionHeader    hdr;    /* file header                          */
    OWPSkip             skips;
    long int            iskip;

    /*
     * TestSession information
     */
    OWPScheduleContext  sctx;
    uint32_t            isctx;      /* index for next seq_no */
    OWPNum64            endnum;     /* current sched time for (isctx-1) */

    OWPNum64            start_time; /* send time for first scheduled packet */
    OWPNum64            end_time;   /* send time for last scheduled packet */

    /*
     * Parsing information
     */
    uint32_t            i;      /* keeps track of current record index  */

    uint32_t            first;  /* first seqno of interest (inclusive)  */
    uint32_t            last;   /* last seqno of interest (non-inclusive)   */

    off_t               begin_oset; /* starting file offset                 */
    off_t               next_oset;  /* upon completing, this will have either
                                     * null, or the offset of the first seqno
                                     * greater than or equal to "last".
                                     */
    uint32_t            sent;   /* actual number sent */

    /*
     * Packet records (used to count dups/lost)
     */
    I2Table         ptable;
    long int        plistlen;
    OWPPacket       pallocated;
    OWPPacket       pfreelist;
    OWPPacket       pbegin;
    OWPPacket       pend;

    /*
     * Delay histogram
     */
    double          bucketwidth;
    I2Table         btable;
    long int        blistlen;
    OWPBucket       ballocated;
    OWPBucket       bfreelist;
    OWPBucket       *bsort;
    uint32_t        bsorti;         /* current index */
    uint32_t        bsortsize;      /* number used in sort array */
    uint32_t        bsortlen;       /* number allocated */

    /*
     * TTL info - histogram of received TTL values.
     */
    uint8_t        ttl_count[256];

    /*
     * Reordering buffers
     */
    long int        rlistlen;
    long int        rindex;
    long int        rnumseqno;
    uint32_t       *rseqno;    /* buffer of seqno's seen */
    uint32_t       *rn;        /* number of j-reordered packets */

    /*
     * Summary Stats
     */
    double          inf_delay;
    double          min_delay;
    double          max_delay;
    OWPBoolean      sync;
    double          maxerr;

    uint32_t       dups;
    uint32_t       lost;

} OWPStatsRec, *OWPStats;

/*
 * Stats utility functions:
 *
 * The Stats functions are used to create/free context for statistics
 * functions as well as providing those functions.
 */

extern void
OWPStatsFree(
        OWPStats    stats
        );

extern OWPStats
OWPStatsCreate(
        OWPContext          ctx,
        FILE                *fp,
        OWPSessionHeader    hdr,
        char                *fromhost,  /* from hostname */
        char                *tohost,    /* to hostname */
        char                scale,
        double              bucketWidth
        );

extern OWPBoolean
OWPStatsParse(
        OWPStats    stats,          /* Stats record */
        FILE        *output,        /* Print packet records here */
        off_t       begin_oset,     /* Hint:start offset - multistage parsing */
        uint32_t   first,           /* first seq num inclusive */
        uint32_t   last             /* last seq num non-inclusive */
        );

extern OWPBoolean
OWPStatsPrintSummary(
        OWPStats    stats,
        FILE        *output,
        float       *percentiles,
        uint32_t   npercentiles
        );

extern OWPBoolean
OWPStatsPrintMachine(
        OWPStats    stats,
        FILE        *output
        );

extern float
OWPStatsScaleFactor(
        char        scale,
        char        *abrv,
        size_t      *abrv_len
        );

/*
 * How much disk space will a given test require?
 * (This is only an estimate - duplicates/loss will change this.)
 */
extern uint64_t
OWPTestDiskspace(
        OWPTestSpec     *tspec
        );

/*
 * time.c conversion functions.
 */

#define OWPJAN_1970 (unsigned long)0x83aa7e80        /* diffs in epoch*/

#ifndef tvalclear
#define tvalclear(a)        (a)->tv_sec = (a)->tv_usec = 0
#endif

#ifndef tvaladd
#define tvaladd(a,b)                        \
    do{                                     \
        (a)->tv_sec += (b)->tv_sec;         \
        (a)->tv_usec += (b)->tv_usec;       \
        if((a)->tv_usec >= 1000000){        \
            (a)->tv_sec++;                  \
            (a)->tv_usec -= 1000000;        \
        }                                   \
    } while (0)
#endif

#ifndef tvalsub
#define tvalsub(a,b)                        \
    do{                                     \
        (a)->tv_sec -= (b)->tv_sec;         \
        (a)->tv_usec -= (b)->tv_usec;       \
        if((a)->tv_usec < 0){               \
            (a)->tv_sec--;                  \
            (a)->tv_usec += 1000000;        \
        }                                   \
    } while (0)
#endif

#ifndef tvalcmp
#define tvalcmp(tvp,uvp,cmp)                \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?     \
     ((tvp)->tv_usec cmp (uvp)->tv_usec) :  \
     ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

/* Operations on timespecs */
#ifndef timespecclear
#define timespecclear(tvp)      ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#endif

#ifndef timespecisset
#define timespecisset(tvp)      ((tvp)->tv_sec || (tvp)->tv_nsec)
#endif

#ifndef timespeccmp
#define timespeccmp(tvp, uvp, cmp)          \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?     \
     ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :  \
     ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef        timespecadd
#define timespecadd(vvp, uvp)               \
    do {                                    \
        (vvp)->tv_sec += (uvp)->tv_sec;     \
        (vvp)->tv_nsec += (uvp)->tv_nsec;   \
        if ((vvp)->tv_nsec >= 1000000000){  \
            (vvp)->tv_sec++;                \
            (vvp)->tv_nsec -= 1000000000;   \
        }                                   \
    } while (0)
#endif

#ifndef timespecsub
#define timespecsub(vvp, uvp)               \
    do {                                    \
        (vvp)->tv_sec -= (uvp)->tv_sec;     \
        (vvp)->tv_nsec -= (uvp)->tv_nsec;   \
        if ((vvp)->tv_nsec < 0) {           \
            (vvp)->tv_sec--;                \
            (vvp)->tv_nsec += 1000000000;   \
        }                                   \
    } while (0)
#endif

#ifndef        timespecdiff
#define        timespecdiff(vvp,uvp)        \
    do {                                    \
        struct timespec        ts1_,ts2_;   \
        if(timespeccmp(vvp,uvp,>)){         \
            ts1_ = *vvp;                    \
            ts2_ = *uvp;                    \
        }else{                              \
            ts1_ = *uvp;                    \
            ts2_ = *vvp;                    \
        }                                   \
        timespecsub(&ts1_,&ts2_);           \
        *vvp = ts1_;                        \
    } while(0)
#endif

extern OWPNum64
OWPGetRTTBound(
        OWPControl  cntrl
        );

extern double
OWPGetTimeStampError(
        OWPTimeStamp    *tstamp
        );

extern OWPTimeStamp *
OWPGetTimeOfDay(
        OWPContext      ctx,
        OWPTimeStamp    *tstamp
        );

extern OWPTimeStamp *
OWPTimevalToTimestamp(
        OWPTimeStamp    *tstamp,
        struct timeval  *tval
        );

extern struct timeval *
OWPTimestampToTimeval(
        struct timeval  *tval,
        OWPTimeStamp    *tstamp
        );

extern OWPTimeStamp *
OWPTimespecToTimestamp(
        OWPTimeStamp    *tstamp,
        struct timespec *tval,
        uint32_t       *errest,        /* usec's */
        uint32_t       *last_errest    /* usec's */
        );

extern struct timespec *
OWPTimestampToTimespec(
        struct timespec *tval,
        OWPTimeStamp    *tstamp
        );

extern OWPErrSeverity
OWPUnexpectedRequestType(
    OWPControl cntrl
    );

extern OWPBoolean
OWPControlIsTwoWay(
    OWPControl cntrl
    );

#endif        /* OWAMP_H */
