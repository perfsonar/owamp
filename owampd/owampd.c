/*! \file owampd.c */
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
 *        File:         owampd.c
 *
 *        Author:       Anatoly Karp
 *                      Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Mon Jun 03 10:57:07 MDT 2002
 *
 *        Description:        
 */
#include <owamp/owamp.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <poll.h>

#include "owampdP.h"
#include "policy.h"

#ifdef TWAMP
#define NWAMPD_FILE_PREFIX "twampd-server"
#define NWPServerSockCreate TWPServerSockCreate
#define NWPControlAccept TWPControlAccept
#define OWP_DFLT_CONTROL_TIMEOUT 900
#else
#define NWAMPD_FILE_PREFIX "owampd-server"
#define NWPServerSockCreate OWPServerSockCreate
#define NWPControlAccept OWPControlAccept
#define OWP_DFLT_CONTROL_TIMEOUT 1800
#endif

#define OWAMPD_PID_FILE  NWAMPD_FILE_PREFIX".pid"
#define OWAMPD_INFO_FILE NWAMPD_FILE_PREFIX".info"

/* Global variable - the total number of allowed Control connections. */
static pid_t                mypid;
static int                  owpd_chld = 0;
static int                  owpd_int = 0;
static int                  owpd_exit = 0;
static int                  owpd_alrm = 0;
static int                  owpd_intr = 0;
static owampd_opts          opts;
static OWPPortRangeRec      portrec;
static I2ErrLogSyslogAttr   syslogattr;
static I2ErrHandle          errhand=NULL;
static I2Table              fdtable=NULL;
static I2Table              pidtable=NULL;
static OWPNum64             uptime;
static uint32_t             control_sessions = 0;

#if defined HAVE_DECL_OPTRESET && !HAVE_DECL_OPTRESET
int optreset;
#endif

static void
usage(
        const char *progname,
        const char *msg        __attribute__((unused))
     )
{
    fprintf(stderr, "Usage: %s [options]\n", progname);
    fprintf(stderr, "\nWhere \"options\" are:\n\n");

    fprintf(stderr,
            "   -a authmode       Default supported authmodes:[E]ncrypted,[A]uthenticated,[O]pen\n"
            "   -c confdir        Configuration directory\n"
            "   -d datadir        Data directory\n"
            "   -e facility       Syslog \"facility\" to log errors\n"
            "   -f                Allow %s to run as root\n"
            "   -G group          Run as group \"group\" :-gid also valid\n"
            "   -h                Print this message and exit\n",
            progname
           );
    fprintf(stderr,
            "   -P portrange      port range for recivers to use\n"
            "   -R vardir         directory for " OWAMPD_PID_FILE " file\n"
            "   -S nodename:port  Srcaddr to bind to\n"
            "   -U user           Run as user \"user\" :-uid also valid\n"
            "   -v                verbose output\n"
#ifndef        NDEBUG
            "   -w                Debugging: busy-wait children after fork to allow attachment\n"
            "   -Z                Debugging: Run in foreground\n"
#endif
            "\n"
           );
    if (PATCH_LEVEL) {
        fprintf(stderr, "\nVersion: %s-%d\n\n", PACKAGE_VERSION, PATCH_LEVEL);
    }
    else {
        fprintf(stderr, "\nVersion: %s\n\n", PACKAGE_VERSION);
    }
    return;
}

/*
 ** Handler function for SIG_CHLD. It updates the number
 ** of available Control connections.
 */
static void
signal_catch(
        int        signo
        )
{
    switch(signo){
        case SIGINT:
            owpd_int = 1;
            /* fallthru*/
        case SIGTERM:
        case SIGHUP:
        case SIGUSR1:
        case SIGUSR2:
            if(!owpd_exit){
                owpd_exit = 1;
            }
            break;
        case SIGCHLD:
            owpd_chld = 1;
            break;
        case SIGALRM:
            owpd_alrm = 1;
            break;
        default:
            I2ErrLog(errhand,"signal_catch(): Invalid signal(%d)",
                    signo);
            _exit(OWP_CNTRL_FAILURE);
    }

    owpd_intr = 1;

    return;
}

struct ChldStateRec{
    OWPDPolicy      policy;
    pid_t           pid;
    int             fd;
    OWPDPolicyNode  node;
    OWPDLimRec      used[2];    /* disk/bandwidth */
};

typedef struct ChldStateRec ChldStateRec, *ChldState;

static ChldState
AllocChldState(
        OWPDPolicy  policy,
        pid_t       pid,
        int         fd
        )
{
    ChldState   cstate = calloc(1,sizeof(*cstate));
    I2Datum     k,v;

    if(!cstate){
        OWPError(policy->ctx,OWPErrFATAL,ENOMEM,"malloc(): %M");
        return NULL;
    }

    cstate->policy = policy;
    cstate->pid = pid;
    cstate->fd = fd;

    /*
     * Add cstate into the hash's.
     */
    v.dptr = (void*)cstate;
    v.dsize = sizeof(*cstate);

    /*
     * add cstate to the pidtable hash
     */
    k.dptr = NULL;
    k.dsize = pid;
    if(I2HashStore(pidtable,k,v) != 0){
        free(cstate);
        return NULL;
    }

    /*
     * add cstate to the fdtable hash
     */
    k.dsize = fd;
    if(I2HashStore(fdtable,k,v) != 0){
        k.dsize = pid;
        I2HashDelete(pidtable,k);
        free(cstate);
        return NULL;
    }

    control_sessions++;

    return cstate;
}

static void
FreeChldState(
        ChldState   cstate,
        struct pollfd **fds,
        nfds_t      *nfds
        )
{
    I2Datum k;
    nfds_t i;
    struct pollfd *newfds;

    k.dptr = NULL;

    if(cstate->fd >= 0){

        while((close(cstate->fd) < 0) && (errno == EINTR));

        /*
         * Find index of pollfd element
         */
        for (i = 0; i < *nfds; i++) {
            if (cstate->fd == (*fds)[i].fd) {
                break;
            }
        }
        if (i == *nfds) {
            OWPError(cstate->policy->ctx,OWPErrWARNING,
                    OWPErrUNKNOWN,
                    "fd(%d) not in poll fds!?!",cstate->fd);
            return;
        }
        /*
         * Remove the element from the array
         */
        if (i < *nfds - 1) {
            memmove(&(*fds)[i], &(*fds)[i + 1], (*nfds - 1 - i) * sizeof(**fds));
        }

        if (*nfds - 1 == 0) {
            free(*fds);
            newfds = NULL;
        } else {
            /*
             * Ensure that we don't leak memory by overwriting *fds on
             * failure
             */
            newfds = realloc(*fds, (*nfds - 1) * sizeof(**fds));
            if (!newfds) {
                OWPError(cstate->policy->ctx,OWPErrWARNING,
                         OWPErrUNKNOWN,
                         "unable to realloc poll fds: %M");
                return;
            }
        }
        *fds = newfds;
        (*nfds)--;

        k.dsize = cstate->fd;
        if(I2HashDelete(fdtable,k) != 0){
            OWPError(cstate->policy->ctx,OWPErrWARNING,
                    OWPErrUNKNOWN,
                    "fd(%d) not in fdtable!?!",cstate->fd);
        }
    }

    k.dsize = cstate->pid;
    if(I2HashDelete(pidtable,k) != 0){
        OWPError(cstate->policy->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "pid(%d) not in pidtable!?!",cstate->pid);
    }

    /*
     * TODO: Release bandwidth resources here if there are any left.
     */
    control_sessions--;

    /*
     * TODO: If exit was not normal... Should we be looking at
     * disk usage for this class and adjusting for the fact that
     * the file was not completely saved?
     */
    free(cstate);

    return;
}

static void
ReapChildren(
        struct pollfd **fds,
        nfds_t      *nfds
        )
{
    int         status;
    pid_t       child;
    I2Datum     key;
    I2Datum     val;
    ChldState   cstate;

    if(!owpd_chld)
        return;

    key.dptr = NULL;
    while ( (child = waitpid(-1, &status, WNOHANG)) > 0){
        key.dsize = child;
        if(!I2HashFetch(pidtable,key,&val)){
            OWPError(cstate->policy->ctx,OWPErrWARNING,
                    OWPErrUNKNOWN,
                    "pid(%d) not in pidtable!?!",child);
        }
        cstate = val.dptr;

        FreeChldState(cstate,fds,nfds);
    }


    owpd_chld = 0;
}

struct CleanPipeArgRec{
    struct pollfd *fds;
    nfds_t        nfds;
    int           nready;
};

static I2Boolean
CheckFD(
        I2Datum fdkey       __attribute__((unused)),
        I2Datum fdval,
        void    *app_data
       )
{
    struct CleanPipeArgRec  *arg = (struct CleanPipeArgRec *)app_data;
    ChldState               cstate = fdval.dptr;
    int                     err=1;
    nfds_t                  i;

    /*
     * If this fd is not ready, return.
     */
    for (i = 0; i < arg->nfds; i++) {
        if (arg->fds[i].fd == cstate->fd) {
            break;
        }
    }
    if (i == arg->nfds || !(arg->fds[i].revents & POLLIN))
        return True;

    arg->fds[i].revents = 0;

    /*
     * This fd needs processing - reduce the "ready" count.
     */
    arg->nready--;

    /*
     * child initialization - first message.
     * Get classname and find policy node for that class.
     */
    if(!cstate->node){
        cstate->node = OWPDReadClass(cstate->policy,cstate->fd,&err);
    }
    else{
        OWPDMesgT        query;
        OWPDMesgT        resp;
        OWPDLimRec        lim;

        /* read child request for resources */
        if(!OWPDReadQuery(cstate->fd,&query,&lim,&err)){
            goto done;
        }

        /*
         * parse tree for resource request/release
         */
        resp = OWPDResourceDemand(cstate->node,query,lim) ?
            OWPDMESGOK : OWPDMESGDENIED;

        /*
         * Send response
         */
        err = OWPDSendResponse(cstate->fd,resp);
    }

done:
    if(err){
        OWPError(cstate->policy->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "Invalid message from child pid=%d",cstate->pid);
        (void)kill(cstate->pid,SIGTERM);
    }

    /*
     * Return true if there are more fd's to process.
     */
    return (arg->nready > 0);
}

/*
 * avail contains the fd_set of fd's that are currently readable, readfds is
 * the set of all fd's that the server needs to pay attention to.
 */
static void
CleanPipes(
        struct pollfd *fds,
        nfds_t      nfds,
        int     nready
        )
{
    struct CleanPipeArgRec  cpargs;

    cpargs.fds = fds;
    cpargs.nfds = nfds;
    cpargs.nready = nready;

    I2HashIterate(fdtable,CheckFD,&cpargs);

    return;
}

static I2Boolean
ClosePipes(
        I2Datum key,
        I2Datum value,
        void    *app_data
        )
{
    ChldState   cstate = value.dptr;
    int         sd = 0;

    if(app_data){
        sd = *(int *)app_data;
    }

    /*
     * shutdown the socket if terminating so child processes will
     * not wait for responses when releasing resources.
     */
    if(sd){
        if( (shutdown(cstate->fd,SHUT_RDWR) != 0)){
            OWPError(cstate->policy->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                    "shutdown(%d,SHUT_RDWR): %M", cstate->fd);
        }
    }

    while((close(cstate->fd) < 0) && (errno == EINTR));
    if(I2HashDelete(fdtable,key) != 0){
        OWPError(cstate->policy->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "fd(%d) not in fdtable!?!",cstate->fd);
    }
    cstate->fd = -1;

    return True;
}


/*
 * This function needs to create a new child process with a pipe to
 * communicate with it. It needs to add the new pipefd into the readfds,
 * and update maxfd if the new pipefd is greater than the current max.
 */
static void
NewConnection(
        OWPDPolicy  policy,
        I2Addr      listenaddr,
        struct pollfd **fds,
        nfds_t      *nfds
        )
{
    int                     connfd;
    struct sockaddr_storage sbuff;
    socklen_t               sbufflen;
    int                     new_pipe[2];
    pid_t                   pid;
    OWPSessionMode          mode = opts.auth_mode;
    int                     listenfd = I2AddrFD(listenaddr);
    OWPControl              cntrl=NULL;
    OWPErrSeverity          out;
    struct itimerval        itval;
    OWPRequestType          msgtype=OWPReqInvalid;
    struct pollfd           *newfds;

ACCEPT:
    sbufflen = sizeof(sbuff);
    connfd = accept(listenfd, (struct sockaddr *)&sbuff, &sbufflen);
    if (connfd < 0){
        switch(errno){
            case EINTR:
                /*
                 * Exit signal received, no reason to do more.
                 */
                if(owpd_exit){
                    return;
                }

                /*
                 * Go ahead and reap before re-entering
                 * accept since it could make more free
                 * connections.
                 */
                ReapChildren(fds,nfds);
                goto ACCEPT;
                break;
            case ECONNABORTED:
                return;
                break;
            default:
                OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "accept(): %M");
                return;
                break;
        }
    }

    if (opts.maxcontrolsessions &&
        (control_sessions + 1 > opts.maxcontrolsessions)) {
        /*
         * Go ahead and reap before declaring this to have exceeded
         * the max control sessions since it could make more free
         * connections.
         */
        ReapChildren(fds,nfds);
        if (control_sessions + 1 > opts.maxcontrolsessions) {
            OWPError(policy->ctx,OWPErrWARNING,OWPErrPOLICY,
                     "Resource usage exceeds limits %s "
                     "(used = %" PRIu32 ", limit = %" PRIu32 ")",
                     "maxcontrolsessions",
                     control_sessions,opts.maxcontrolsessions);
            OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,"socketpair(): %M");
            (void)close(connfd);
            return;
        }
    }

    if (socketpair(AF_UNIX,SOCK_STREAM,0,new_pipe) < 0){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,"socketpair(): %M");
        (void)close(connfd);
        return;
    }

    pid = fork();

    /* fork error */
    if (pid < 0){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,"fork(): %M");
        (void)close(new_pipe[0]);
        (void)close(new_pipe[1]);
        (void)close(connfd);
        return;
    }

    /* Parent */
    if (pid > 0){
        ChldState   chld;


        /*
         * If close is interupted, continue to try and close,
         * otherwise, ignore the error.
         */
        while((close(new_pipe[1]) < 0) && (errno == EINTR));
        while((close(connfd) < 0) && (errno == EINTR));

        if(!(chld = AllocChldState(policy,pid,new_pipe[0]))){
            (void)close(new_pipe[0]);
            (void)kill(pid,SIGKILL);
            return;
        }

        /*
         * Ensure that we don't leak memory by overwriting *fds on
         * failure
         */
        newfds = realloc(*fds, (*nfds + 1) * sizeof(**fds));
        if (!newfds) {
            OWPError(policy->ctx,OWPErrWARNING,
                    OWPErrUNKNOWN,
                    "unable to realloc poll fds: %M");
            return;
        }
        /*
         * Add new element to end of newly (re-)allocated array
         */
        newfds[*nfds].fd = chld->fd;
        newfds[*nfds].events = POLLIN;
        newfds[*nfds].revents = 0;
        *fds = newfds;
        (*nfds)++;

        return;
    }

    /* Rest of function is child */

#ifndef        NDEBUG
    {
        void *childwait;

        if((childwait = opts.childwait)){
            OWPError(policy->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                    "Busy-loop...");
            /* busy loop to wait for debug-attach */
            while(childwait);
            /*
             * set OWPChildWait if you want to attach
             * to them... (by resetting childwait back to non-zero)
             */
            if(childwait && !OWPContextConfigSetV(policy->ctx,OWPChildWait,
                        childwait)){
                OWPError(policy->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                        "OWPContextConfigSetV(): Unable to set OWPChildWait?!");
            }
        }
    }
#endif

    /*
     * Close unneeded fd's (these are used by the parent)
     */
    I2HashIterate(fdtable,ClosePipes,NULL);

    /*
     * reset error logging
     */
    I2ErrReset(errhand);

    /*
     * check/set signal vars.
     */
    if(owpd_exit){
        exit(0);
    }
    owpd_intr = 0;

    /*
     * Initialize itimer struct. The it_value.tv_sec will be
     * set to interrupt socket i/o if the message is not received
     * within the timeout as described by owdp draft section 4
     * (OWAMP-Control).
     */
    memset(&itval,0,sizeof(itval));

    /*
     * save the pipe fd in the policy record for the hooks to
     * pick it up.
     */
    policy->fd = new_pipe[1];

    /*
     * If the daemon is configured to do open_mode, check if
     * there is an open_mode limit defined for the given
     * address.
     */
    if((mode & OWP_MODE_OPEN) && !OWPDAllowOpenMode(policy,
                (struct sockaddr *)&sbuff,&out)){
        if(out != OWPErrOK){
            exit(out);
        }
        mode &= ~OWP_MODE_OPEN;
    }

    owpd_intr = 0;
    itval.it_value.tv_sec = opts.controltimeout;
    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
        I2ErrLog(errhand,"setitimer(): %M");
        exit(OWPErrFATAL);
    }
    cntrl = NWPControlAccept(
        policy->ctx,connfd,
        (struct sockaddr *)&sbuff,sbufflen,
        mode,uptime,&owpd_intr,&out);

    /*
     * session not accepted.
     */
    if(!cntrl){
        exit(out);        
    }

    /*
     * Process all requests - return when complete.
     */
    while(1){
        OWPErrSeverity  rc;

        rc = OWPErrOK;
        /*
         * reset signal vars
         */
        owpd_intr = owpd_alrm = owpd_chld = 0;
        itval.it_value.tv_sec = opts.controltimeout;
        if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
            I2ErrLog(errhand,"setitimer(): %M");
            goto done;
        }

        msgtype = OWPReadRequestType(cntrl,&owpd_intr);

        switch (msgtype){

#ifdef TWAMP
            case OWPReqTestTW:
                rc = OWPProcessTestRequestTW(cntrl,&owpd_intr);
                break;
#else
            case OWPReqTest:
                rc = OWPProcessTestRequest(cntrl,&owpd_intr);
                break;
#endif

            case OWPReqStartSessions:
                rc = OWPProcessStartSessions(cntrl,&owpd_intr);
                if(rc < OWPErrOK){
                    break;
                }
                /*
                 * Test session started - unset timer - wait
                 * until all sessions are complete, then
                 * reset the timer and wait for stopsessions
                 * to complete.
                 */
                owpd_intr = 0;
                itval.it_value.tv_sec = 0;
                if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                    I2ErrLog(errhand,"setitimer(): %M");
                    goto done;
                }
                while(True){
                    int        wstate;

                    rc = OWPErrOK;
                    owpd_intr = 0;
                    wstate = OWPStopSessionsWait(cntrl,NULL,
                            &owpd_intr,NULL,&rc);
                    if(owpd_int){
                        goto done;
                    }
                    else if(owpd_exit){
                        /*
                         * wstate == 2 indicates gracefull shutdown...
                         * Continue on and let StopSessions happen.
                         */
                        if(wstate != 2){
                            goto done;
                        }
                        break;
                    }
                    if(wstate <= 0){
                        goto nextreq;
                    }
                }

#ifndef TWAMP
                /*
                 * Sessions are complete, but StopSessions
                 * message has not been exchanged - set the
                 * timer and trade StopSessions messages
                 */
                owpd_intr = 0;
                itval.it_value.tv_sec = opts.controltimeout;
                if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                    I2ErrLog(errhand,"setitimer(): %M");
                    goto done;
                }
                rc = OWPStopSessions(cntrl,&owpd_intr,NULL);
#endif

                break;

#ifndef TWAMP
            case OWPReqFetchSession:
                /*
                 * TODO: Should the timeout be suspended
                 * for fetchsession?
                 * (If session files take longer than
                 * the timeout - this will fail... The
                 * default is 30 min. Leave for now.
                 * (The fix would be to leave the timeout in
                 * place for completing the fetchsession
                 * read, and then process the write
                 * of the session separately.)
                 */
                rc = OWPProcessFetchSession(cntrl,&owpd_intr);
                break;
#endif

            case OWPReqSockIntr:
                break;

            case OWPReqSockClose:
                rc = OWPErrFATAL;
                break;

            default:
                /*
                 * Don't log an error message if already classified as
                 * invalid request, since OWPReadRequestType will have
                 * already logged one.
                 */
                if (msgtype != OWPReqInvalid) {
                    I2ErrLog(errhand,"Unexpected message type %d", msgtype);
                }
                rc = OWPUnexpectedRequestType(cntrl);
                break;
        }
nextreq:
        if(rc < OWPErrWARNING){
            break;
        }
        if(owpd_exit || owpd_alrm){
            break;
        }
    }

done:
    OWPControlClose(cntrl);

    if(owpd_exit){
        exit(0);
    }

    /*
     * Normal socket close
     */
    if(msgtype == OWPReqSockClose){
        exit(0);
    }

    I2ErrLog(errhand,"Control session terminated abnormally...");

    exit(1);
}

/*
 * hash functions...
 * I cheat - I use the "dsize" part of the datum for the key data since
 * pid and fd are both integers.
 */
static int
intcmp(
        const I2Datum   x,
        const I2Datum   y
      )
{
    return(x.dsize != y.dsize);
}

static uint32_t
inthash(
        I2Datum key
       )
{
    return (uint32_t)key.dsize;
}

static I2Boolean
parse_ports(
        char    *pspec
        )
{
    char    *tstr,*endptr;
    long    tint;

    if(!pspec) return False;

    tstr = pspec;
    endptr = NULL;

    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    portrec.low = (uint16_t)tint;

    while(isspace((int)*endptr)) endptr++;

    switch(*endptr){
        case '\0':
            ///* only allow a single value if it is 0 */
            //if(portrec.low){
            //    goto failed;
            //}
            portrec.high = portrec.low;
            goto done;
            break;
        case '-':
            endptr++;
            break;
        default:
            goto failed;
    }

    tstr = endptr;
    endptr = NULL;
    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    portrec.high = (uint16_t)tint;

    if(portrec.high < portrec.low){
        goto failed;
    }

done:
    /*
     * If ephemeral is specified, shortcut by not setting.
     */
    if(!portrec.high && !portrec.low)
        return True;

    /*
     * Set.
     */
    opts.portspec = &portrec;
    return True;

failed:
    if(errhand){
        I2ErrLogP(errhand,EINVAL,"Invalid port-range: \"%s\"",pspec);
    }
    else{
        fprintf(stderr,"Invalid port-range: \"%s\"",pspec);
    }

    return False;
}

static void
LoadConfig(
        char    **lbuf,
        size_t  *lbuf_max
        )
{
    FILE    *conf;
    char    conf_file[MAXPATHLEN+1];
    char    keybuf[MAXPATHLEN],valbuf[MAXPATHLEN];
    char    *key = keybuf;
    char    *val = valbuf;
    int     rc=0;

    conf_file[0] = '\0';

    rc = strlen(OWAMPD_CONF_FILE);
    if(rc > MAXPATHLEN){
        fprintf(stderr,"strlen(OWAMPD_CONF_FILE) > MAXPATHLEN\n");
        exit(1);
    }
    if(opts.confdir){
        rc += strlen(opts.confdir) + strlen(OWP_PATH_SEPARATOR);
        if(rc > MAXPATHLEN){
            fprintf(stderr,"Path to %s > MAXPATHLEN\n",
                    OWAMPD_CONF_FILE);
            exit(1);
        }
        strcpy(conf_file, opts.confdir);
        strcat(conf_file, OWP_PATH_SEPARATOR);
    }
    strcat(conf_file, OWAMPD_CONF_FILE);

    if(!(conf = fopen(conf_file, "r"))){
        if(opts.confdir){
            fprintf(stderr,"Unable to open %s: %s\n",conf_file,
                    strerror(errno));
            exit(1);
        }
        return;
    }

    while((rc = I2ReadConfVar(conf,rc,key,val,MAXPATHLEN,lbuf,lbuf_max))
            > 0){

        /* syslog facility */
        if(!strncasecmp(key,"facility",9)){
            int fac = I2ErrLogSyslogFacility(val);
            if(fac == -1){
                fprintf(stderr,
                        "Invalid -e: Syslog facility \"%s\" unknown\n",
                        val);
                rc = -rc;
                break;
            }
            syslogattr.facility = fac;
        }
        else if(!strncasecmp(key,"loglevel",9)){
            int report_level = OWPReportLevelByName(val);
            if(report_level == -1){
                     fprintf(stderr,
                            "Log level \"%s\" invalid\n",
                            val);
                    rc = -rc;
                    break;
            }
            syslogattr.report_level = report_level;
        }
        else if(!strncasecmp(key,"loglocation",12)){
            syslogattr.line_info |= I2FILE|I2LINE;
        }
        else if(!strncasecmp(key,"rootfolly",10)){
            opts.allowroot = True;
        }
        else if(!strncasecmp(key,"datadir",8)){
            if(!(opts.datadir = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"user",5)){
            if(!(opts.user = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"group",6)){
            if(!(opts.group = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"verbose",8)){
            opts.verbose = True;
        }
        else if(!strncasecmp(key,"authmode",9)){
            if(!(opts.authmode = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"srcnode",8)){
            if(!(opts.srcnode = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"testports",10)){
            if(!parse_ports(val)){
                fprintf(stderr,
                        "Invalid test port range specified.");
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"vardir",7)){
            if(!(opts.vardir = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
#ifndef TWAMP
        else if(!strncasecmp(key,"diskfudge",10)){
            char        *end=NULL;
            double        tdbl;

            errno = 0;
            tdbl = strtod(val,&end);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtod(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            if((tdbl >= 1.0) && (tdbl <= 10.0)){
                opts.diskfudge = tdbl;
            }
            else{
                fprintf(stderr,"Invalid diskfudge \"%f\":"
                        "valid values 1.0<=diskfudge<=10.0",
                        tdbl);
                rc=-rc;
                break;
            }
        }
#endif
        else if(!strncasecmp(key,"dieby",6)){
            char                *end=NULL;
            uint32_t        tlng;

            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.dieby = tlng;
        }
        else if(!strncasecmp(key,"controltimeout",15)){
            char                *end=NULL;
            uint32_t        tlng;

            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.controltimeout = tlng;
        }
        else if(!strncasecmp(key,"pbkdf2_count",13)){
            char        *end=NULL;
            uint32_t    tlng;

            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.pbkdf2_count = tlng;
        }
        else if(!strncasecmp(key,"enddelay",9)){
            char        *end=NULL;
            double        tdbl;

            errno = 0;
            tdbl = strtod(val,&end);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtod(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            if(tdbl >= 0.0){
                opts.setEndDelay = True;
                opts.endDelay = tdbl;
            }
            else{
                fprintf(stderr,"Invalid enddelay \"%f\":"
                        "positive value expected",
                        tdbl);
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"maxcontrolsessions",
                             strlen("maxcontrolsessions"))){
            char            *end=NULL;
            uint32_t        tlng;

            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.maxcontrolsessions = tlng;
        }
#ifdef TWAMP
        else if(!strncasecmp(key,"testtimeout",
                             strlen("testtimeout"))){
            char        *end=NULL;
            uint32_t    tlng;

            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.testtimeout = tlng;
        }
#endif
        else{
            fprintf(stderr,"Unknown key=%s\n",key);
            rc = -rc;
            break;
        }
    }

    if(rc < 0){
        fprintf(stderr,"%s:%d Problem parsing conffile\n",
                conf_file,-rc);
        exit(1);
    }

    return;
}

int main(
        int     argc,
        char    *argv[]
        )
{
    char                *progname=NULL;
    OWPErrSeverity      out = OWPErrFATAL;
    char                pid_file[MAXPATHLEN],
                        info_file[MAXPATHLEN];

    struct pollfd       *fds;
    nfds_t              nfds;
    OWPContext          ctx;
    OWPDPolicy          policy;
    I2Addr              listenaddr = NULL;
    int                 listenfd;
    int                 rc;
    I2Datum             data;
    struct flock        flk;
    int                 pid_fd;
    FILE                *pid_fp, *info_fp;
    OWPTimeStamp        currtime;        
    int                 ch;
    uid_t               setuser=0;
    gid_t               setgroup=0;
    char                *lbuf=NULL;
    size_t              lbuf_max=0;

    struct sigaction    ignact,setact;
    sigset_t            sigs;

#ifndef NDEBUG
    char                *optstring = "a:c:d:e:fG:hP:R:S:U:vwZ";
#else        
    char                *optstring = "a:c:d:e:fG:hP:R:S:U:vZ";
#endif

    /*
     * remove any path component from argv[0] for progname.
     */
    progname = (progname = strrchr(argv[0],'/')) ? progname+1 : *argv;

    /*
     * Start an error loggin session for reporting errors to the
     * standard error
     */
    syslogattr.ident = progname;
    syslogattr.logopt = LOG_PID;
    syslogattr.facility = LOG_DAEMON;
    syslogattr.priority = LOG_ERR;
    syslogattr.line_info = I2MSG;
    syslogattr.report_level = OWPErrINFO;
    
    /* Set up options defaults */
    opts.verbose = False;
    opts.passwd = "passwd.conf";
    opts.vardir = opts.confdir = opts.datadir = NULL;
    opts.authmode = NULL; 
    opts.srcnode = NULL;
    opts.daemon = 1;
    opts.user = opts.group = NULL;
    opts.diskfudge = 1.0;
    opts.dieby = 5;
    opts.controltimeout = OWP_DFLT_CONTROL_TIMEOUT;
    opts.portspec = NULL;
    opts.maxcontrolsessions = 0;

    if(!getcwd(opts.cwd,sizeof(opts.cwd))){
        perror("getcwd()");
        exit(1);
    }

    /*
     * Fetch config file option if present
     */
    opterr = 0;
    while((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch){
            case 'c':        /* -c "Config directory" */
                if (!(opts.confdir = strdup(optarg))) {
                    /* eh isn't setup yet...*/
                    perror("strdup()");
                    exit(1);
                }
                break;
            default:
                break;
        }
    }
    opterr = optreset = optind = 1;

    /*
     * Load Config file.
     * lbuf/lbuf_max keep track of a dynamically grown "line" buffer.
     * (It is grown using realloc.)
     * This will be used throughout all the config file reading and
     * should be free'd once all config files have been read.
     */
    LoadConfig(&lbuf,&lbuf_max);

    /*
     * Read cmdline options that effect syslog so the rest of cmdline
     * processing can be reported via syslog.
     */
    opterr = 0;
    while((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch){
            int fac;
            case 'e':        /* -e "syslog err facility" */
            fac = I2ErrLogSyslogFacility(optarg);
            if(fac == -1){
                fprintf(stderr,
                        "Invalid -e: Syslog facility \"%s\" unknown\n",
                        optarg);
                exit(1);
            }
            syslogattr.facility = fac;
            break;
            case 'Z':
            opts.daemon = 0;
            break;
            default:
            break;
        }
    }
    opterr = optreset = optind = 1;

    /*
     * Always use LOG_PERROR - if daemonizing, stderr will be closed,
     * and this hurts nothing. And... commandline reporting is good
     * until after the fork.
     */
    syslogattr.logopt |= LOG_PERROR;
    errhand = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);
    if(! errhand) {
        fprintf(stderr, "%s : Couldn't init error module\n", progname);
        exit(1);
    }
    I2ErrSetResetFunc(errhand,I2ErrLogSyslogReset);

    /*
     * Initialize the context. (Set the error handler to the app defined
     * one.)
     */
    if( !(ctx = OWPContextCreate(errhand))){
        fprintf(stderr, "%s: Unable to initialize application\n",progname);
        exit(1);
    }

    /*
     * Now deal with "all" cmdline options.
     */
    while ((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch) {
            case 'a':        /* -a "authmode" */
                if (!(opts.authmode = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'd':        /* -d "data directory" */
                if (!(opts.datadir = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'f':       /* -f */
                opts.allowroot = True;
                break;
            case 'v':        /* -v "verbose" */
                opts.verbose = True;
                break;
            case 'S':  /* -S "src addr" */
                if (!(opts.srcnode = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'U':
                if(!(opts.user = strdup(optarg))){
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'G':
                if(!(opts.group = strdup(optarg))){
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'P':
                if(!parse_ports(optarg)){
                    I2ErrLog(errhand,
                            "Invalid test port range specified.");
                    exit(1);
                }
                break;
            case 'R':        /* -R "var/run directory" */
                if (!(opts.vardir = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'c':
            case 'e':
            case 'Z':
                break;
#ifndef NDEBUG
            case 'w':
                opts.childwait = (void*)True;
                break;
#endif
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

    if (argc) {
        usage(progname, "");
        exit(1);
    }

    /*
     * Setup portrange
     */
    if(opts.portspec && !OWPContextConfigSetV(ctx,OWPTestPortRange,
                (void*)opts.portspec)){
        I2ErrLog(errhand,
                "OWPContextConfigSetV(): Unable to set OWPTestPortRange?!");
        exit(1);
    }

    /*
     * Setup count
     */
    if(opts.pbkdf2_count && !OWPContextConfigSetU32(ctx,OWPKeyDerivationCount,
                opts.pbkdf2_count)){
        I2ErrLog(errhand,
                "OWPContextConfigSetU32(): Can't set OWPKeyDerivationCount?!");
        exit(1);
    }

    /*
     * Setup testtimeout
     */
#ifdef TWAMP
    if(opts.testtimeout && !OWPContextConfigSetU32(ctx,TWPTestTimeout,
                opts.testtimeout)){
        I2ErrLog(errhand,
                "OWPContextConfigSetU32(): Can't set TWPTestTimeout?!");
        exit(1);
    }
#endif

    /*
     * Setup enddelay
     */
    if(opts.setEndDelay && !OWPContextConfigSetV(ctx,OWPEndDelay,
                &opts.endDelay)){
        I2ErrLog(errhand,
                "OWPContextConfigSetV(): Can't set OWPEndDelay?!");
        exit(1);
    }

    if(!opts.vardir)
        opts.vardir = opts.cwd;
    if(!opts.confdir)
        opts.confdir = opts.cwd;
    if(!opts.datadir)
        opts.datadir = opts.cwd;

    /*  Get exclusive lock for pid file. */
    strcpy(pid_file, opts.vardir);
    strcat(pid_file, OWP_PATH_SEPARATOR);
    strcat(pid_file, OWAMPD_PID_FILE);
    if ((pid_fd = open(pid_file, O_RDWR|O_CREAT,
                    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
        I2ErrLog(errhand, "open(%s): %M", pid_file);
        exit(1);
    }

    memset(&flk,0,sizeof(flk));
    flk.l_start = 0;
    flk.l_len = 0;
    flk.l_type = F_WRLCK;
    flk.l_whence = SEEK_SET; 
    while((rc=fcntl(pid_fd, F_SETLK, &flk)) < 0 && errno == EINTR);
    if(rc < 0){
        I2ErrLog(errhand,"Unable to lock file %s: %M", pid_file);
        exit(1);
    }
    if ((pid_fp = fdopen(pid_fd, "wr")) == NULL) {
        I2ErrLog(errhand, "fdopen(): %M");
        exit(1);
    }

    /*
     * Install policy for "ctx" - and return policy record.
     */
    if(!(policy = OWPDPolicyInstall(ctx,opts.datadir,opts.confdir,
                    opts.diskfudge,NWAMPD_FILE_PREFIX,&lbuf,&lbuf_max))){
        I2ErrLog(errhand, "PolicyInit failed. Exiting...");
        exit(1);
    };

    /*
     * Done with the line buffer. (reset to 0 for consistancy.)
     */
    if(lbuf){
        free(lbuf);
    }
    lbuf = NULL;
    lbuf_max = 0;

    if (opts.maxcontrolsessions) {
        struct rlimit rlim;
        rc = getrlimit(RLIMIT_NOFILE, &rlim);
        if (rc < 0) {
            I2ErrLog(errhand,"getrlimit(): %M");
        } else {
            /*
             * We don't know how many files the libraries that we link
             * to will use, so use double the max sessions as a crude
             * estimate.
             */
            if (rlim.rlim_cur < (opts.maxcontrolsessions*2) &&
                rlim.rlim_cur != rlim.rlim_max) {
                rlim.rlim_cur = (opts.maxcontrolsessions*2);
                rc = setrlimit(RLIMIT_NOFILE, &rlim);
                if (rc < 0) {
                    I2ErrLog(errhand,"setrlimit(): %M");
                }
            }
        }

    }
    /*
     * If running as root warn if the -U/-G flags not set.
     */
    if(!geteuid()){
        struct passwd        *pw;
        struct group        *gr;

        /*
         * Validate user option.
         */
        if(opts.user){
            if((pw = getpwnam(opts.user))){
                setuser = pw->pw_uid;
            }
            else if(opts.user[0] == '-'){
                setuser = strtoul(&opts.user[1],NULL,10);
                if(errno || !getpwuid(setuser)){
                    I2ErrLog(errhand,"Invalid user/-U option: %s",opts.user);
                    exit(1);
                }
            }
            else{
                I2ErrLog(errhand,"Invalid user/-U option: %s",opts.user);
                exit(1);
            }
        }

        if(!setuser && !opts.allowroot){
            I2ErrLog(errhand,"Running %s as root is folly!", progname);
            I2ErrLog(errhand,
                    "Use the -U option! (or allow root with the -f option)");
            exit(1);
        }

        /*
         * Validate group option.
         */
        if(opts.group){
            if((gr = getgrnam(opts.group))){
                setgroup = gr->gr_gid;
            }
            else if(opts.group[0] == '-'){
                setgroup = strtoul(&opts.group[1],NULL,10);
                if(errno || !getgrgid(setgroup))
                    setgroup = 0;
            }

            if(!setgroup){
                I2ErrLog(errhand,"Invalid user/-G option: %s",
                        opts.group);
                exit(1);
            }
        }

        /*
         * Only setting effective id for now. This will catch
         * errors, and will still allow the rename of the
         * pid/info file later.
         */
        if(setgroup && (setegid(setgroup) != 0)){
            I2ErrLog(errhand,"Unable to setgid to \"%s\": %M",
                    opts.group);
            exit(1);
        }
        if(seteuid(setuser) != 0){
            I2ErrLog(errhand,"Unable to setuid to \"%s\": %M",
                    opts.user);
            exit(1);
        }
    }

    /*
     * Finish policy - this part needs to be done after loosing
     * "root" permissions.
     */
    if( !OWPDPolicyPostInstall(policy)){
        I2ErrLog(errhand, "PolicyInit failed. Exiting...");
        exit(1);
    };

    /*
     * Setup the "default_mode".
     */
    if(opts.authmode){
        char        *s = opts.authmode;
        opts.auth_mode = 0;
        while(*s != '\0'){
            switch(toupper(*s)){
                case 'O':
                    opts.auth_mode |= OWP_MODE_OPEN;
                    break;
                case 'A':
                    opts.auth_mode |= OWP_MODE_AUTHENTICATED;
                    break;
                case 'E':
                    opts.auth_mode |= OWP_MODE_ENCRYPTED;
                    break;
                default:
                    I2ErrLogP(errhand,EINVAL,
                            "Invalid -authmode %c",*s);
                    usage(progname,NULL);
                    exit(1);
            }
            s++;
        }
    }
    else{
        /*
         * Default to all modes.
         */
        opts.auth_mode = OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|
            OWP_MODE_ENCRYPTED;
    }

    /*
     * TODO: a config test for this would probably be cleaner...
     */
    {        /* ensure intcmp will work */
        size_t        psize = sizeof(pid_t);
        assert(psize<=sizeof(data.dsize));
    }

    pidtable = I2HashInit(errhand,0,intcmp,inthash);
    fdtable = I2HashInit(errhand,0,intcmp,inthash);
    if(!pidtable || !fdtable){
        I2ErrLogP(errhand,0,"Unable to setup hash tables...");
        exit(1);
    }

    /*
     * Get start-time for server greeting report.
     */
    if(!OWPGetTimeOfDay(ctx,&currtime)){
        I2ErrLogP(errhand, errno, "OWPGetTimeOfDay: %M");
        kill(mypid,SIGTERM);
        exit(1);
    }
    uptime = currtime.owptime;

    /*
     * daemonize here
     */
    mypid = 0;
    if(opts.daemon){

        /*
         * chdir to '/' so filesystems can be unmounted.
         */
        if(chdir("/") < 0){
            I2ErrLog(errhand,"Unable to chdir to /: %M");
            exit(1);
        }

        /*
         * reopen stdin/stdout/stderr fd's
         */
        for(rc=0;rc<3;rc++){
            if(close(rc) == -1 || open("/dev/null",O_RDWR) != rc){
                I2ErrLog(errhand,"Unable to reopen fd(%d): %M",
                        rc);
                exit(1);
            }
        }

        /*
         * respawn self to detach from terminal.
         */
        mypid = fork();
        if(mypid < 0){
            I2ErrLog(errhand,"Unable to fork: %M");
            exit(1);
        }
        if((mypid == 0) && (setsid() == -1)){
            I2ErrLog(errhand,"setsid(): %M");
            exit(1);
        }
    }
    else{
        /*
         * Depending upon the shell that starts this -Z "foreground"
         * daemon, this process may or may not be the Process Group
         * leader... This will make sure. (Needed so HUP/TERM
         * catching can kill the whole process group with one
         * kill call.) setsid handles this when daemonizing.
         */
        mypid = getpid();
        if(setpgid(0,mypid) != 0){
            I2ErrLog(errhand,"setpgid(): %M");
            exit(1);
        }
    }

    /*
     * Temporarily take root permissions back.
     * (If this is parent of daemonizing - exit immediately after
     * updating pid/info files. If not daemonizing, setuid/setgid
     * is called after the mypid if to return to lesser
     * permissions.)
     */
    if((setuser) && (seteuid(getuid()) != 0)){
        I2ErrLog(errhand,"seteuid(): %M");
        kill(mypid,SIGTERM);
        exit(1);
    }
    if((setgroup) && (setegid(getgid()) != 0)){
        I2ErrLog(errhand,"setegid(): %M");
        kill(mypid,SIGTERM);
        exit(1);
    }

    /*
     * If this is the parent process (or not daemonizing) - write the pid
     * and info files.
     */
    if(mypid > 0){

        /* Record pid.  */
        ftruncate(pid_fd, 0);
        fprintf(pid_fp, "%lld\n", (long long)mypid);
        if (fflush(pid_fp) < 0) {
            I2ErrLogP(errhand, errno, "fflush: %M");
            kill(mypid,SIGTERM);
            exit(1);
        }

        /* Record the start timestamp in the info file. */
        strcpy(info_file, opts.vardir);
        strcat(info_file, OWP_PATH_SEPARATOR);
        strcat(info_file, OWAMPD_INFO_FILE);
        if ((info_fp = fopen(info_file, "w")) == NULL) {
            I2ErrLog(errhand, "fopen(%s): %M", info_file);
            kill(mypid,SIGTERM);
            exit(1);
        }

        fprintf(info_fp, "START="OWP_TSTAMPFMT"\n", uptime);
        fprintf(info_fp, "PID=%lld\n", (long long)mypid);
        while ((rc = fclose(info_fp)) < 0 && errno == EINTR);
        if(rc < 0){
            I2ErrLog(errhand,"fclose(): %M");
            kill(mypid,SIGTERM);
            exit(1);
        }

        /*
         * If daemonizing - this is parent - exit.
         */
        if(opts.daemon) exit(0);
    }

    /*
     * If the local interface was specified, use it - otherwise use NULL
     * for wildcard.
     */
    if(opts.srcnode && !(listenaddr = I2AddrByNode(ctx,opts.srcnode))){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Invalid source address specified: %s",opts.srcnode);
        exit(1);
    }
    listenaddr = NWPServerSockCreate(ctx,listenaddr,&out);
    if(!listenaddr){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to create server socket. Exiting...");
        exit(1);
    }

    /*
     * set real uid/gid, not just effective.
     */
    if((setgroup) && (setgid(setgroup) != 0)){
        I2ErrLog(errhand,"setegid(): %M");
        exit(1);
    }
    if((setuser) && (setuid(setuser) != 0)){
        I2ErrLog(errhand,"setuid(): %M");
        exit(1);
    }

    /*
     * Set up signal handling.
     */
    memset(&ignact,0,sizeof(ignact));
    memset(&setact,0,sizeof(setact));

    ignact.sa_handler = SIG_IGN;
    setact.sa_handler = signal_catch;
    sigemptyset(&ignact.sa_mask);
    sigemptyset(&setact.sa_mask);
    ignact.sa_flags = setact.sa_flags = 0;

    if(     (sigaction(SIGPIPE,&ignact,NULL) != 0)  ||
            (sigaction(SIGTERM,&setact,NULL) != 0)  ||
            (sigaction(SIGUSR1,&setact,NULL) != 0)  ||
            (sigaction(SIGUSR2,&setact,NULL) != 0)  ||
            (sigaction(SIGINT,&setact,NULL) != 0)   ||
            (sigaction(SIGHUP,&setact,NULL) != 0)   ||
            (sigaction(SIGCHLD,&setact,NULL) != 0)  ||
            (sigaction(SIGALRM,&setact,NULL) != 0)  ){
        I2ErrLog(errhand,"sigaction(): %M");
        exit(1);
    }

    listenfd = I2AddrFD(listenaddr);
    nfds = 1;
    fds = malloc(sizeof(*fds));
    if (!fds) {
        I2ErrLog(errhand,"unable to allocate memory: %M");
        exit(1);
    }
    fds[0].fd = listenfd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    while (1) {
        int     nfound;

        if(owpd_exit){
            break;
        }

        nfound = poll(fds,nfds,-1);

        /*
         * Handle select interupts/errors.
         */
        if(nfound < 0){
            if(errno == EINTR){
                if(owpd_exit){
                    break;
                }
                ReapChildren(&fds,&nfds);
                continue;
            }
            OWPError(ctx,OWPErrFATAL,errno,"select(): %M");
            exit(1);
        }

        /*
         * shouldn't happen, but for completeness...
         */
        if(nfound == 0)
            continue;

        if(fds[0].revents & POLLIN){ /* new connection */
            NewConnection(policy,listenaddr,&fds,&nfds);
            fds[0].revents = 0;
        }
        else{
            CleanPipes(fds,nfds,nfound);
        }

        if(owpd_exit){
            break;
        }

        ReapChildren(&fds,&nfds);
    }

    I2ErrLog(errhand,"%s: exiting...",progname);
    /*
     * Close the server socket. set poll slot fd to -1 so that it
     * won't confuse later ReapChildren calls.
     */
    I2AddrFree(listenaddr);
    fds[0].fd = -1;

    /*
     * Signal the process group to exit.
     */
    kill(-mypid,SIGTERM);

    /*
     * Set an alarm to exit by even if graceful shutdown doesn't occur.
     */
    owpd_alrm = 0;
    alarm(opts.dieby);

    /*
     * Close all the pipes so pipe i/o can stay simple. (Don't have
     * to deal with interrupts for this.)
     */
    rc=1;
    I2HashIterate(fdtable,ClosePipes,&rc);

    /*
     * Loop until all children have been waited for, or until
     * alarm goes off.
     */
    sigemptyset(&sigs);
    while(!owpd_alrm && (I2HashNumEntries(pidtable) > 0)){
        if(!owpd_chld){
            (void)sigsuspend(&sigs);
        }
        ReapChildren(&fds,&nfds);
    }

    /*
     * If children didn't die, report the error - send SIGKILL and exit.
     */
    if(I2HashNumEntries(pidtable) > 0){
        I2ErrLog(errhand,
                "Children still alive... Time for brute force.");
        kill(-mypid,SIGKILL);
    }

    I2ErrLog(errhand,"%s: exited.",progname);

    exit(0);
}
