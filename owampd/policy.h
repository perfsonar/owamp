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
 *        File:         policy.h
 *
 *        Author:       Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Sat Jan 11 00:15:45 MST 2003
 *
 *        Description:        
 *                      This file declares the types needed by applications
 *                      to use the "default" 
 *
 */
#ifndef _OWP_DEFAULTS_H
#define _OWP_DEFAULTS_H

#include <I2util/util.h>
#include <owamp/owamp.h>

#define OWP_PFS_FILE_SUFFIX    ".pfs"
#define OWP_LIMITS_FILE_SUFFIX ".limits"

/*
 * Defines for path elements of the server datastore:
 *         datadir/
 *                 catalog/
 *                         (symlinks named by SID pointing to real files
 *                         in datadir/nodes.)
 *                 nodes/
 *                         (dir hier based on user classification hier.)
 *                         This allows filesystem based limits to be used
 *                         by mounting a particular filesystem into this
 *                         hierarchy.
 */
#ifndef OWP_CATALOG_DIR
#define OWP_CATALOG_DIR "catalog"
#endif
#ifndef OWP_HIER_DIR
#define OWP_HIER_DIR    "hierarchy"
#endif

/*
 * Holds the policy record that was parsed and contains all the "limits"
 * and identity information.
 *
 * type: (owp_policy_data*) - defined in access.h
 * location: Context Config
 */
#define OWPDPOLICY      "OWPDPOLICY"

/*
 * Holds the identifying "node" from the policy tree that contains the
 * class and limits information for the given control connection.
 *
 * type: (owp_tree_node_ptr) - defined in access.h
 * location: Control Config
 */
#define OWPDPOLICY_NODE "OWPDPOLICY_NODE"

/*
 * Types used by policy functions
 */
#define OWPDMAXCLASSLEN (80)

typedef struct OWPDPolicyRec OWPDPolicyRec, *OWPDPolicy;
typedef struct OWPDPolicyNodeRec OWPDPolicyNodeRec, *OWPDPolicyNode;
typedef struct OWPDPolicyKeyRec OWPDPolicyKeyRec, *OWPDPolicyKey;

struct OWPDPolicyRec{
    OWPContext      ctx;

    double          diskfudge;

    int             fd;        /* socket to parent. */
    char            *datadir;

    OWPDPolicyNode  root;

    /* limits:
     *         key = char* (classname from "limit" lines)
     *         val = OWPDPolicyNode
     */
    I2Table         limits;

    /* idents:
     *         key = OWPDPid
     *         val = OWPDPolicyNode
     */
    I2Table         idents;

    /* pfs:
     *         key = OWPUserID (uint8_t[80])    (username from owamp protocol)
     *         val = uint8_t *
     */
    I2Table         pfs;

};

typedef I2numT      OWPDLimitT;                /* values */
typedef uint32_t    OWPDMesgT;

typedef struct OWPDLimRec{
    OWPDMesgT   limit;
    OWPDLimitT  value;
} OWPDLimRec;

/* parent           cname           */
/* bandwidth        uint (bits/sec) */
/* disk             uint (bytes)    */
/* delete_on_fetch  on/(off)        */
/* allow_open_mode  (on)/off        */
/* test_sessions    uint            */

#define OWPDLimParent           0
#define OWPDLimBandwidth        1
#define OWPDLimDisk             3
#define OWPDLimDeleteOnFetch    4
#define OWPDLimAllowOpenMode    5
#define OWPDLimTestSessions     6

struct OWPDPolicyNodeRec{
    OWPDPolicy      policy;
    char            *nodename;
    OWPDPolicyNode  parent;
    size_t          ilim;
    OWPDLimRec      *limits;
    OWPDLimRec      *used;
    off_t           initdisk;
};

typedef enum{
    OWPDPidInvalid=0,
    OWPDPidDefaultType,
    OWPDPidNetmaskType,
    OWPDPidUserType
} OWPDPidType;

typedef struct{
    OWPDPidType id_type;
    uint8_t     mask_len;
    size_t      addrsize;
    uint8_t     addrval[16];
} OWPDPidNetmask;

typedef struct{
    OWPDPidType id_type;
    OWPUserID   userid;
} OWPDPidUser;

typedef union OWPDPidUnion{
    OWPDPidType     id_type;
    OWPDPidNetmask  net;
    OWPDPidUser     user;
} OWPDPidRec, *OWPDPid;

/*
 * The following section defines the message tags used to communicate
 * from the children processes to the parent to request/release
 * resources on a global basis.
 *
 * All message "type" defines will be of type OWPDMesgT.
 */
#define OWPDMESGMARK        0xfefefefe
#define OWPDMESGCLASS       0xcdef
#define OWPDMESGRESOURCE    0xbeef
#define OWPDMESGREQUEST     0xfeed
#define OWPDMESGRELEASE     0xdead
#define OWPDMESGCLAIM       0x1feed1

/*
 * "parent" response messages will be one of:
 */
#define OWPDMESGINVALID 0x0
#define OWPDMESGOK      0x1
#define OWPDMESGDENIED  0x2

/*
 * After forking, the new "server" process (called "child" in the following)
 * should determine the "usage class" the given connection should belong to.
 * The first message to the "parent" master process should communicate this
 * information so that all further resource requests/releases are relative
 * to that "usage class". The format of this message should be as follows:
 *
 * (All integers are in host order since this is expected to be ipc
 * communication on a single host. It could be a future enhancement to
 * allow a "single" distributed owampd OWAMP-Control server to manage
 * multiple test  endpoints at which time it might be worth the overhead
 * to deal with byte ordering issues.)
 *
 * Initial child->parent message:
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                      OWPDMESGMARK                             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                      OWPDMESGCLASS                            |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                    [nul terminated ascii string of classname]
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                      OWPDMESGMARK                             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * There is one other child message format. This message is used to either
 * request or release resources. (The parent should release all "temporary"
 * resources (i.e. bandwidth) on exit of the child if the child does not
 * explicitly release the resource. More "permenent" resources should only
 * be released explicitly (i.e. disk-space).
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                      OWPDMESGMARK                             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                     OWPDMESGRESOURCE                          |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                OWPDMESGWANT|OWPDMESGRELEASE                   |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        12|                      OWPDMesgT(limit name)                    |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        16|                        OWPDLimitT                             |
 *        20|                                                               |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        24|                      OWPDMESGMARK                             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Parent responses are all of the format:
 *
 *            0                   1                   2                   3
 *            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        00|                      OWPDMESGMARK                             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        04|                OWPDMESGOK|OWPDMESGDENIED                      |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        08|                      OWPDMESGMARK                             |
 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/*
 * The following api convienence functions are defined to make the child/parent
 * communication easier. (These are the functions needed by the parent in
 * the master owampd "resource broker" process.)
 */

extern OWPDPolicyNode
OWPDReadClass(
        OWPDPolicy  policy,
        int         fd,
        int         *err
        );

/*
 * returns True on success - query/lim_ret will contain request
 * err will be non-zero on error. 0 on empty read.
 */
extern OWPBoolean
OWPDReadQuery(
        int         fd,
        OWPDMesgT   *query,
        OWPDLimRec  *lim_ret,
        int         *err
        );

extern int
OWPDSendResponse(
        int         fd,
        OWPDMesgT   mesg
        );

/*
 * This function is used to add/subtract resource allocations from the
 * current tree of resource usage. It is only used in the resource
 * broker process.
 */
extern OWPBoolean
OWPDResourceDemand(
        OWPDPolicyNode  node,
        OWPDMesgT       query,
        OWPDLimRec      lim
        );
/*
 * Functions called directly from owampd regarding "policy" decisions
 * (If false, check err_ret to determine if it is an "error" condition,
 * or if open_mode is simply denied.)
 */
extern OWPBoolean
OWPDAllowOpenMode(
        OWPDPolicy      policy,
        struct sockaddr *peer_addr,
        OWPErrSeverity  *err_ret
        );

/*
 * Functions actually used to install policy hooks into libowamp.
 */
extern OWPBoolean
OWPDGetPF(
        OWPContext      ctx,
        const OWPUserID userid,
        uint8_t         **pf,
        size_t          *pf_len,
        void            **pf_free,
        OWPErrSeverity  *err_ret
        );

extern OWPBoolean
OWPDCheckControlPolicy(
        OWPControl      cntrl,
        OWPSessionMode  mode,
        const OWPUserID userid,
        struct sockaddr *local_saddr,
        struct sockaddr *remote_saddr,
        OWPErrSeverity  *err_ret
        );

extern OWPBoolean
OWPDCheckTestPolicy(
        OWPControl      cntrl,
        OWPBoolean      local_sender,
        struct sockaddr *local_saddr,
        struct sockaddr *remote_saddr,
        socklen_t       sa_len,
        OWPTestSpec     *test_spec,
        void            **closure,
        OWPErrSeverity  *err_ret
        );

extern OWPBoolean
OWPDCheckFetchPolicy(
        OWPControl      cntrl,
        struct sockaddr *local_saddr,
        struct sockaddr *remote_saddr,
        socklen_t       sa_len,
        uint32_t        begin,
        uint32_t        end,
        OWPSID          sid,
        void            **closure,
        OWPErrSeverity  *err_ret
        );

extern void
OWPDTestComplete(
        OWPControl      cntrl,
        void            *closure,
        OWPAcceptType   aval
        );

extern FILE*
OWPDOpenFile(
        OWPControl      cntrl,
        void            *closure,
        OWPSID          sid,
        char            fname_ret[PATH_MAX+1]
        );

extern void
OWPDCloseFile(
        OWPControl      cntrl,
        void            *closure,
        FILE            *fp,
        OWPAcceptType   aval
        );

extern OWPDPolicy
OWPDPolicyInstall(
        OWPContext      ctx,
        char            *datadir,   /* root dir for datafiles   */
        char            *confdir,   /* conf dir for policy      */
        double          diskfudge,
        const char      *fileprefix, /* prefix to use for pfs and lim files */
        char            **lbuf,
        size_t          *lbuf_max
        );

extern OWPBoolean
OWPDPolicyPostInstall(
        OWPDPolicy  policy
        );

#endif        /*        _OWP_DEFAULTS_H        */
