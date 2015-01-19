/*
 **      $Id$
 */
/************************************************************************
 *                                                                      *
 *                             Copyright (C)  2003                      *
 *                                Internet2                             *
 *                             All Rights Reserved                      *
 *                                                                      *
 ************************************************************************/
/*
 **        File:            policy.c
 **
 **        Author:          Jeff W. Boote
 **
 **        Date:            Mon Jan 20 10:42:57 MST 2003
 **
 **        Description:        
 **      Default policy  functions used by OWAMP applications.
 */
#include <owamp/owamp.h>

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>
#include <assert.h>

#include "policy.h"
#include "fts.h"

/*
 * Function:        parsepfs
 *
 * Description:        
 *                 Read all pass-phrases from the pfsfile and populate the pfs
 *                 hash with that data.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
static int
parsepfs(
        OWPDPolicy  policy,
        FILE        *fp,
        char        **lbuf,
        size_t      *lbuf_max
        )
{
    int         rc=0;
    char        *username;
    char        *passphrase;
    size_t      pf_len;
    I2Datum     key,val;
    I2ErrHandle eh = OWPContextErrHandle(policy->ctx);

    if(!fp){
        return 0;
    }

    while((rc = I2ParsePFFile(eh,fp,NULL,rc,
                    NULL,
                    &username,
                    &passphrase,
                    &pf_len,
                    lbuf,lbuf_max)) > 0){

        /*
         * Make sure the username is not already in the hash.
         */
        key.dptr = username;
        key.dsize = strlen(username);
        if(I2HashFetch(policy->pfs,key,&val)){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                    "username \"%s\" duplicated",username);
            return -rc;
        }

        /*
         * alloc memory for the username key.
         */
        if(!(key.dptr = strdup(username))){
            OWPError(policy->ctx,OWPErrFATAL,errno,
                    "strdup(username): %M");
            return -rc;
        }

        /*
         * alloc memory for pass-phrase value.
         */
        if(!(val.dptr = malloc(pf_len))){
            free(key.dptr);
            OWPError(policy->ctx,OWPErrFATAL,errno,
                    "malloc(len(pass-phrase)): %M");
            return -rc;
        }
        memcpy(val.dptr,passphrase,pf_len);
        val.dsize = pf_len;

        if(I2HashStore(policy->pfs,key,val) != 0){
            free(key.dptr);
            free(val.dptr);
            OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to store pass-phrase for %s",
                    username);
            return -rc;
        }
    }

    return rc;
}

enum limtype{LIMINTVAL,LIMBOOLVAL,LIMNOT};
struct limdesc{
    OWPDMesgT       limit;
    char            *lname;
    enum limtype    ltype;
    OWPBoolean      release_on_exit;
    OWPDLimitT      def_value;
};

static struct limdesc        limkeys[] = {
{OWPDLimParent,         "parent",           LIMNOT,     0,  0},
{OWPDLimBandwidth,      "bandwidth",        LIMINTVAL,  1,  0},
{OWPDLimDisk,           "disk",             LIMINTVAL,  0,  0},
{OWPDLimDeleteOnFetch,  "delete_on_fetch",  LIMBOOLVAL, 0,  0},
{OWPDLimAllowOpenMode,  "allow_open_mode",  LIMBOOLVAL, 0,  1},
{OWPDLimTestSessions,   "test_sessions",    LIMINTVAL,  0,  0},
};

static OWPDLimitT
GetDefLimit(
        OWPDMesgT   lim
        )
{
    size_t  i;

    for(i=0;i<I2Number(limkeys);i++){
        if(lim == limkeys[i].limit){
            return limkeys[i].def_value;
        }
    }

    return 0;
}

static char *
GetLimName(
        OWPDMesgT   lim
        )
{
    size_t        i;

    for(i=0;i<I2Number(limkeys);i++){
        if(lim == limkeys[i].limit){
            return limkeys[i].lname;
        }
    }

    return "unknown";
}

static int
parselimitline(
        OWPDPolicy  policy,
        char        *line,
        size_t      maxlim
        )
{
    size_t              i,j;
    char                *cname;
    OWPDLimRec          limtemp[I2Number(limkeys)];
    OWPDPolicyNodeRec   tnode;
    OWPDPolicyNode      node;
    I2Datum             key,val;

    /*
     * Grab new classname
     */
    if(!(line = strtok(line,I2WSPACESET))){
        return 1;
    }
    cname = line;

    /*
     * verify classname has not been defined before.
     */
    key.dptr = cname;
    key.dsize = strlen(cname);
    if(key.dsize > OWPDMAXCLASSLEN){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "classname \"%s\" too long - max length = %u",cname,
                OWPDMAXCLASSLEN);
        return 1;
    }
    if(I2HashFetch(policy->limits,key,&val)){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "classname \"%s\" duplicated",cname);
        return 1;
    }

    /*
     * parse "with"
     */
    if(!(line = strtok(NULL,I2WSPACESET))){
        return 1;
    }
    /* compare strings INCLUDING the '\0' */
    if(strncasecmp(line,"with",5)){
        return 1;
    }

    memset(&tnode,0,sizeof(tnode));
    memset(limtemp,0,sizeof(limtemp));

    tnode.policy = policy;

    /*
     * Process key/value pairs delimited by ','
     */
    while((line = strtok(NULL,","))){
        char                *limname,*limval;
        OWPBoolean        found;

        if(tnode.ilim >= maxlim){
            OWPError(policy->ctx,OWPErrFATAL,
                    OWPErrINVALID,
                    "Too many limit declarations");
            return 1;
        }

        /*
         * Grab the keyname off the front.
         */
        while(isspace((int)*line)){line++;}
        limname = line;
        while(!isspace((int)*line) && (*line != '=')){
            line++;
        }
        *line++ = '\0';

        /*
         * Grab the valname
         */
        while(isspace((int)*line) || (*line == '=')){
            line++;
        }
        limval = line;
        while(!isspace((int)*line) && (*line != '\0')){
            line++;
        }
        *line = '\0';

        if(!strncasecmp(limname,"parent",7)){
            if(!policy->root){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                        "\"parent\" specified for root node.");
                return 1;
            }
            if(tnode.parent){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                        "multiple parents specified.");
                return 1;
            }

            /* validate and fetch parent */
            key.dptr = limval;
            key.dsize = strlen(limval);
            if(!I2HashFetch(policy->limits,key,&val)){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                        "parent \"%s\" undefined",limval);
                return 1;
            }
            tnode.parent = val.dptr;
            continue;
        }

        found = False;
        for(i=0;i < I2Number(limkeys);i++){
            /* skip "special" limit types */
            if(limkeys[i].ltype == LIMNOT){
                continue;
            }

            /* skip non-matching limit names */
            if(strncasecmp(limname,limkeys[i].lname,
                        strlen(limkeys[i].lname)+1)){
                continue;
            }

            /* i now points at correct record in limkeys */
            found=True;
            break;
        }

        if(!found){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Unknown limit name \"%s\".",limname);
            return 1;
        }

        /* check for a multiple definition */
        for(j=0;j<tnode.ilim;j++){
            if(limtemp[j].limit == limkeys[i].limit){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                        "multiple %s values specified.",
                        limname);
                return 1;
            }
        }

        /*
         * Set the next record in limtemp with this limname/limvalue.
         */
        limtemp[tnode.ilim].limit = limkeys[i].limit;
        switch(limkeys[i].ltype){

            case LIMINTVAL:
                if(I2StrToNum(&limtemp[tnode.ilim].value,limval)){
                    OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                            "Invalid value specified for \"%s\".",
                            limname);
                    return 1;
                }
                break;
            case LIMBOOLVAL:
                if(!strncasecmp(limval,"on",3)){
                    limtemp[tnode.ilim].value = 1;
                }else if(strncasecmp(limval,"off",4)){
                    OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                            "Invalid value specified for \"%s\".",
                            limname);
                    return 1;
                }
                break;
            default:
                /* NOTREACHED */
                OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "limkeys array is invalid!");
        }

        tnode.ilim++;
    }

    /*
     * Now copy the parent parameters that were not overridden.
     */
    if(tnode.parent){
        for(i=0;i<tnode.parent->ilim;i++){
            for(j=0;j<tnode.ilim;j++){
                if(tnode.parent->limits[i].limit ==
                        limtemp[j].limit){
                    goto override;
                }
            }
            limtemp[tnode.ilim++] = tnode.parent->limits[i];
override:
            ;
        }
    }
    /*
     * No parent - if root has been set, this is invalid.
     */
    else if(policy->root){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "\"parent\" must be specified for non-root node");
        return 1;
    }

    /*
     * Now alloc memory and insert this node into the hash.
     */
    if(!(node = malloc(sizeof(*node))) ||
            !(tnode.nodename = strdup(cname)) ||
            !(tnode.limits = calloc(maxlim,sizeof(OWPDLimRec))) ||
            !(tnode.used = calloc(maxlim,sizeof(OWPDLimRec)))){
        OWPError(policy->ctx,OWPErrFATAL,errno,"alloc(): %M");
        return 1;
    }
    memcpy(node,&tnode,sizeof(*node));
    if(tnode.ilim){
        memcpy(node->limits,limtemp,sizeof(OWPDLimRec)*tnode.ilim);
        memcpy(node->used,limtemp,sizeof(OWPDLimRec)*tnode.ilim);
        for(i=0;i<tnode.ilim;i++){
            node->used[i].value = 0;
        }
    }

    key.dptr = node->nodename;
    key.dsize = strlen(node->nodename);
    val.dptr = node;
    val.dsize = sizeof(*node);
    if(I2HashStore(policy->limits,key,val) != 0){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to store limit description!");
        return 1;
    }

    if(!policy->root){
        policy->root = node;
    }

    return 0;
}

static int
parseassignline(
        OWPDPolicy  policy,
        char        *line
        )
{
    OWPDPidRec  tpid;
    OWPDPid     pid;
    I2Datum     key,val;

    memset(&tpid,0,sizeof(tpid));

    /*
     * Grab assign "type"
     */
    if(!(line = strtok(line,I2WSPACESET))){
        return 1;
    }

    if(!strncasecmp(line,"default",8)){
        tpid.id_type = OWPDPidDefaultType;
        key.dptr = &tpid;
        key.dsize = sizeof(tpid);
        if(I2HashFetch(policy->idents,key,&val)){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid multiple \"assign default\" lines.");
            return 1;
        }
    }
    else if(!strncasecmp(line,"net",4)){
        int                tint;
        char                *mask, *end;
        struct addrinfo        hints, *res;
        uint8_t        nbytes,nbits,*ptr;

        tpid.id_type = OWPDPidNetmaskType;
        /*
         * Grab addr/mask
         */
        if(!(line = strtok(NULL,I2WSPACESET))){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid \"assign net\" argument.");
            return 1;
        }

        if((mask = strchr(line,'/'))){
            *mask++ = '\0';
            if(*mask == '\0'){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                        "Invalid address mask.");
                return 1;
            }
        }

        memset(&hints,0,sizeof(hints));
        hints.ai_flags = AI_NUMERICHOST;
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype= SOCK_STREAM;
        res = NULL;

        if((tint = getaddrinfo(line,NULL,&hints,&res)) < 0){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid address \"%s\": %s",line,
                    gai_strerror(tint));
            return 1;
        }
        else if(!res){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid address \"%s\".",line);
            return 1;
        }

        switch(res->ai_family){
            struct sockaddr_in        *saddr4;
#ifdef        AF_INET6
            struct sockaddr_in6        *saddr6;

            case AF_INET6:
            saddr6 = (struct sockaddr_in6*)res->ai_addr;
            tpid.net.addrsize = 16;
            memcpy(tpid.net.addrval,saddr6->sin6_addr.s6_addr,16);
            break;
#endif
            case AF_INET:
            saddr4 = (struct sockaddr_in*)res->ai_addr;
            tpid.net.addrsize = 4;
            memcpy(tpid.net.addrval,&saddr4->sin_addr.s_addr,4);
            break;

            default:
            freeaddrinfo(res);
            OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unknown address protocol family.");
            return 1;
            break;
        }
        freeaddrinfo(res);
        res = NULL;

        if(mask){
            unsigned long tlng;

            tlng = (int)strtoul(mask,&end,10);
            if((*end != '\0') || (tlng < 1) ||
                    (tlng > (tpid.net.addrsize*8))){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                        "Invalid address mask \"%s\".",mask);
                return 1;
            }
            tpid.net.mask_len = tlng;
        }
        else{
            tpid.net.mask_len = tpid.net.addrsize*8;
        }

        /*
         * ensure addr part of addr/mask doesn't set any bits.
         */

        nbytes = tpid.net.mask_len/8;
        nbits = tpid.net.mask_len%8;
        ptr = &tpid.net.addrval[nbytes];

        /*
         * Check bits in byte following last complete one.
         */
        if(nbytes < tpid.net.addrsize){
            if(*ptr & ~(0xFF << (8-nbits))){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                        "Invalid address/mask combination.");
                return 1;
            }
        }

        /*
         * Check remaining bytes following the partial one.
         */
        nbytes++;
        ptr++;
        while(nbytes < tpid.net.addrsize){
            if(*ptr){
                OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                        "Invalid address/mask combination.");
                return 1;
            }
            nbytes++;
            ptr++;
        }
    }
    else if(!strncasecmp(line,"user",5)){
        /*
         * Grab username
         */
        if(!(line = strtok(NULL,I2WSPACESET))){
            return 1;
        }
        key.dptr = line;
        key.dsize = strlen(line);

        if((key.dsize >= sizeof(tpid.user.userid)) ||
                !I2HashFetch(policy->pfs,key,&val)){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                    "Invalid user \"%s\".",line);
            return 1;
        }

        tpid.id_type = OWPDPidUserType;
        strcpy(tpid.user.userid,line);
    }
    else{
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "Unknown \"assign\" specification.");
        return 1;
    }

    /*
     * The Pid is valid - now parse and check for limits for
     * the "classname".
     */
    if(!(line = strtok(NULL,I2WSPACESET))){
        return 1;
    }

    key.dptr = line;
    key.dsize = strlen(line);
    if(!I2HashFetch(policy->limits,key,&val)){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "Unknown limitclass name \"%s\".",line);
        return 1;
    }

    if(!(pid = malloc(sizeof(*pid)))){
        OWPError(policy->ctx,OWPErrFATAL,errno,
                "malloc(OWPDPidRec): %M");
        return 1;
    }
    memcpy(pid,&tpid,sizeof(*pid));
    key.dptr = pid;
    key.dsize = sizeof(*pid);
    if(I2HashStore(policy->idents,key,val) != 0){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to store assign description!");
        return 1;
    }

    return 0;
}

static int
parselimits(
        OWPDPolicy  policy,
        FILE        *fp,
        char        **lbuf,
        size_t      *lbuf_max
        )
{
    int         rc = 0;
    size_t      i;
    size_t      maxlim = 0;
    char        *line;
    I2ErrHandle eh = OWPContextErrHandle(policy->ctx);

    /*
     * Count number of possible limit parameters
     */
    for(i=0;i < I2Number(limkeys);i++){
        if(limkeys[i].ltype != LIMNOT){
            maxlim++;
        }
    }

    /*
     * parse the file, one line at a time.
     */
    while(fp && ((rc = I2GetConfLine(eh,fp,rc,lbuf,lbuf_max)) > 0)){
        line = *lbuf;

        /*
         * parse limit lines. (These create the "user classes" and
         * specify the "authorization" level of that authenticated
         * "user class".
         */
        if(!strncasecmp(line,"limit",5)){
            line += 5;
            while(isspace((int)*line)){
                line++;
            }

            if(parselimitline(policy,line,maxlim) != 0){
                return -rc;
            }
        }
        /*
         * parse "assign" lines. These are used to determine the
         * identity of a connection. i.e. authenticate a particular
         * connection as a particular identity/user class.
         */
        else if(!strncasecmp(line,"assign",6)){
            line += 6;
            while(isspace((int)*line)){
                line++;
            }

            if(parseassignline(policy,line) != 0){
                return -rc;
            }
        }
        else{
            rc = -rc;
            break;
        }
    }

    /*
     * Add a "default" class if none was specified.
     */
    if((rc == 0) && !policy->root){
        char        defline[] = "default with";

        OWPError(policy->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "WARNING: No limits specified.");

        line = *lbuf;
        if(sizeof(defline) > *lbuf_max){
            *lbuf_max += I2LINEBUFINC;
            *lbuf = realloc(line,sizeof(char) * *lbuf_max);
            if(!*lbuf){
                if(line){
                    free(line);
                }
                OWPError(policy->ctx,OWPErrFATAL,errno,
                        "realloc(%u): %M",*lbuf_max);
                return -1;
            }
            line = *lbuf;
        }
        strcpy(line,defline);
        if(parselimitline(policy,line,maxlim) != 0){
            OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Unable to install default (open) limits");
            return -1;
        }
    }


    return rc;
}

/*
 * Function:        node_dir
 *
 * Description:        
 *         This function creates a directory hierarchy based at datadir
 *         equivalent to the "class" hierarchy reference by node.
 *         i.e. It traverses up the "node" to determine all the parent nodes
 *         that should be above it and uses the node names to create directory
 *         names.
 *
 *         The "memory" record is PATH_MAX+1 bytes long - add_chars is used
 *         to keep track of the number of bytes that are needed "after" this
 *         node in the recursion to allow for graceful failure.
 *
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
static char *
node_dir(
        OWPContext      ctx,
        OWPBoolean      make,
        char            *datadir,
        OWPDPolicyNode  node,
        unsigned int    add_chars,
        char            *memory
        )
{
    char    *path;
    int     len;

    if(node){
        path = node_dir(ctx,make,datadir,node->parent,
                strlen(node->nodename) +
                OWP_PATH_SEPARATOR_LEN + add_chars, memory);
        if(!path)
            return NULL;
        strcat(path,OWP_PATH_SEPARATOR);
        strcat(path,node->nodename);
    } 
    else {
        len = strlen(datadir) + OWP_PATH_SEPARATOR_LEN
            + strlen(OWP_HIER_DIR) + add_chars;
        if(len > PATH_MAX){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "Data file path length too long.");
            return NULL;
        }
        path = memory;

        strcpy(path,datadir);
        strcat(path,OWP_PATH_SEPARATOR);
        strcat(path, OWP_HIER_DIR);
    }

    if(make && (mkdir(path,0755) != 0) && (errno != EEXIST)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to mkdir(%s): %M",path);
        return NULL;
    }

    return path;
}

static OWPBoolean
clean_catalog(
        OWPContext  ctx,
        char        *path
        )
{
    char        *ftsargv[2];
    FTS         *fts;
    FTSENT      *p;
    OWPBoolean  ret=False;

    ftsargv[0] = path;
    ftsargv[1] = NULL;

    /*
     * Make sure catalog dir exists.
     */
    if((mkdir(path,0755) != 0) && (errno != EEXIST)){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to mkdir(%s): %M",path);
        return False;
    }

    if(!(fts = fts_open(ftsargv, FTS_PHYSICAL,NULL))){
        OWPError(ctx,OWPErrFATAL,errno,"fts_open(%s): %M",path);
        return False;
    }

    while((p = fts_read(fts)) != NULL){
        switch(p->fts_info){
            case FTS_D:        /* ignore */
            case FTS_DC:
                break;
            case FTS_ERR:
                if(p->fts_errno != ENOENT){
                    OWPError(ctx,OWPErrFATAL,p->fts_errno,"%s: %M",
                            p->fts_path);
                    goto err;
                }
                break;
            case FTS_DNR:
            case FTS_DP:
                /*
                 * Keep the catalog dir itself.
                 */
                if(p->fts_level < 1){
                    break;
                }
                /*
                 * Shouldn't really be any directories in here...
                 * But delete any that show up.
                 */
                if(rmdir(p->fts_accpath) && (errno != ENOENT)){
                    OWPError(ctx,OWPErrFATAL,errno,"rmdir(%s): %M",
                            p->fts_path);
                    goto err;
                }
                break;
            default:
                if(unlink(p->fts_accpath) && (errno != ENOENT)){
                    OWPError(ctx,OWPErrFATAL,errno,"unlink(%s): %M",
                            p->fts_path);
                    goto err;
                }
                break;
        }
    }

    ret = True;
err:
    fts_close(fts);

    return ret;
}

static void
OWPDResourceUsage(
        OWPDPolicyNode  node,
        OWPDLimRec      lim
        );

static OWPBoolean
verify_datadir(
        OWPDPolicy  policy,
        char        *cpath, /* catalog  */
        char        *npath  /* nodes    */
        )
{
    char            *ftsargv[2];
    FTS             *fts;
    FTSENT          *p;
    OWPBoolean      ret=False;
    I2Datum         key,val;
    OWPDPolicyNode  node;
    char            pathname[PATH_MAX+1];
    OWPDLimRec      lim;
    OWPSID          tsid;
    size_t          len;

    ftsargv[0] = npath;
    ftsargv[1] = NULL;

    lim.limit = OWPDLimDisk;

    /*
     * Need FTS_NOCHDIR because symlink could be created from
     * a relative path. (i.e. if datadir is not set, it is relative
     * to the current directory of the owampd process.)
     */
    if(!(fts = fts_open(ftsargv, FTS_NOCHDIR|FTS_PHYSICAL,NULL))){
        if(errno == ENOENT){
            return True;
        }
        OWPError(policy->ctx,OWPErrFATAL,errno,"fts_open(%s): %M",
                npath);
        return False;
    }

    while((p = fts_read(fts)) != NULL){
        switch(p->fts_info){
            case FTS_D:
                /*
                 * pre-order directory. Find "node" and verify
                 * parent.
                 */

                /*
                 * ignore "nodes" directory and fts "root".
                 */
                if(p->fts_level <= 0){
                    break;
                }

                key.dptr = p->fts_name;
                key.dsize = p->fts_namelen;
                if(!I2HashFetch(policy->limits,key,&val)){
                    OWPError(policy->ctx,OWPErrWARNING,OWPErrPOLICY,
                            "verify_datadir: Ignoring \"%s\": "
                            "No associated user class",p->fts_path);
                    fts_set(fts,p,FTS_SKIP);
                    break;
                }
                node = val.dptr;

                /*
                 * verify node is in the correct hierarchy.
                 * (It is either the root at level 0 - or the parent
                 * found via fts must equal the node->parent.)
                 */
                if(((p->fts_level == 1) && (policy->root == node)) ||
                        ((p->fts_level > 1) &&
                         (p->fts_parent->fts_pointer ==
                          node->parent))){
                    p->fts_pointer = node;
                    break;
                }

                OWPError(policy->ctx,OWPErrFATAL,OWPErrPOLICY,
                        "verify_datadir: Directory \"%s\" "
                        "expect at \"%s\"",
                        p->fts_path,
                        (node_dir(policy->ctx,False,
                                  policy->datadir,node,0,
                                  pathname))?pathname:"unknown");
                goto err;
                break;

            case FTS_DC:        /* ignore */
                break;
            case FTS_DNR:
            case FTS_ERR:
                if(p->fts_errno != ENOENT){
                    OWPError(policy->ctx,OWPErrFATAL,p->fts_errno,
                            "%s: %M",p->fts_path);
                    goto err;
                }
                break;
            case FTS_DP:
                /*
                 * We should have skipped any directory entries
                 * that don't coorespond to nodes - but check just
                 * in case.
                 */
                if(!p->fts_pointer){
                    break;
                }
                node = p->fts_pointer;

                /*
                 * Now - place the "usage" for this level in the
                 * node's disk usage pointer.
                 * convert from st_blocks to bytes
                 */
                lim.value = node->initdisk;
                OWPDResourceUsage((OWPDPolicyNode)p->fts_pointer,lim);

                /*
                 * Add disk space from this level to parent.
                 */
                if(node->parent){
                    node->parent->initdisk += node->initdisk;
                }

                break;

            default:
                /*
                 * First - make sure this file is in a node managed
                 * directory.
                 */
                if(!p->fts_parent->fts_pointer){
                    break;
                }
                node = p->fts_parent->fts_pointer;

                /*
                 * Now make sure this file is a "session" file.
                 * (Is the length correct, does the suffix match,
                 * and are the first 32 charactors 16 hex encoded
                 * bytes?)
                 */
                len = strlen(OWP_FILE_EXT);
                if(((len + (sizeof(OWPSID)*2)) != p->fts_namelen) ||
                        strncmp(&p->fts_name[sizeof(OWPSID)*2],
                            OWP_FILE_EXT,len+1) ||
                        !I2HexDecode(p->fts_name,tsid,
                            sizeof(tsid))){
                    break;
                }

                /*
                 * build symlink in catalog to this file.
                 */
                strcpy(pathname,cpath);
                strcat(pathname,OWP_PATH_SEPARATOR);
                strcat(pathname,p->fts_name);
                if(symlink(p->fts_path,pathname) != 0){
                    OWPError(policy->ctx,OWPErrFATAL,errno,
                            "symlink(%s,%s): %M",
                            p->fts_path,pathname);
                    goto err;
                }

                /*
                 * Add size of this file to node.
                 */
                node->initdisk += p->fts_statp->st_size;

                break;
        }
    }

    ret = True;
err:
    fts_close(fts);

    return ret;
}

static OWPBoolean
InitializeDiskUsage(
        OWPDPolicy  policy
        )
{
    char    cpath[PATH_MAX+1];
    char    npath[PATH_MAX+1];
    size_t  len1,len2;

    /*
     * Verify length of "catalog" symlink pathnames.
     * {datadir}/{OWP_CATALOG_DIR}/{SIDHEXNAME}{OWP_FILE_EXT}
     *
     * Verify length of the root of the "nodes" directory.
     * {datadir}/{OWP_HIER_DIR} - individual node paths will be
     * verified as the node hierarchy is validated and the catalog
     * is rebuilt.
     */
    len1 = strlen(policy->datadir) + OWP_PATH_SEPARATOR_LEN*2 +
        strlen(OWP_CATALOG_DIR) + sizeof(OWPSID)*2 +
        strlen(OWP_FILE_EXT);
    len2 = strlen(policy->datadir) + OWP_PATH_SEPARATOR_LEN +
        strlen(OWP_HIER_DIR);
    if(MAX(len1,len2) > PATH_MAX){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "InitializeDiskUsage: datadir too long (%s)",
                policy->datadir);
        return False;
    }

    /*
     * verify datadir exists!
     */
    if((strlen(policy->datadir) > 0) &&
            (mkdir(policy->datadir,0755) != 0) &&
            (errno != EEXIST)){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to mkdir(%s): %M",policy->datadir);
        return False;
    }

    /*
     * Clean the catalog out. It is recreated each time owampd is
     * re-initialized.
     */
    strcpy(cpath,policy->datadir);
    strcat(cpath,OWP_PATH_SEPARATOR);
    strcat(cpath,OWP_CATALOG_DIR);

    if(!clean_catalog(policy->ctx,cpath)){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "InitializeDiskUsage: Invalid catalog directory: %s",
                cpath);
        return False;
    }

    /*
     * Verify the datadir hierarchy - this determines the current disk
     * usage of each user-class and rebuilds the catalog.
     */
    strcpy(npath,policy->datadir);
    strcat(npath,OWP_PATH_SEPARATOR);
    strcat(npath,OWP_HIER_DIR);

    if(!verify_datadir(policy,cpath,npath)){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "InitializeDiskUsage: Invalid datadir directory: %s",
                policy->datadir);
        return False;
    }

    return True;
}

/*
 * Function:        OWPDPolicyInstall
 *
 * Description:        
 *         This function installs the functions defined in this file as
 *         the "policy" hooks within the owamp application.
 *
 *         The main reason for defining the policy in the owamp library
 *         like this was that it made it possible to share the policy
 *         code between client/server applications such as owping and
 *         owampd. Also, it is a good example of how this can be done for
 *         custom appliations (such as powstream).
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 *         None.
 */
OWPDPolicy
OWPDPolicyInstall(
        OWPContext  ctx,
        char        *datadir,
        char        *confdir,
        double      diskfudge,
        const char  *fileprefix,
        char        **lbuf,
        size_t      *lbuf_max
        )
{
    OWPDPolicy  policy;
    I2ErrHandle eh;
    char        pfname[MAXPATHLEN+1];
    char        lfname[MAXPATHLEN+1];
    int         len;
    FILE        *kfp = NULL,*lfp = NULL;
    int         rc;        /* row count */

    /*
     * use variables for the func pointers so the compiler can give
     * type-mismatch warnings.
     */
    OWPGetPFFunc                getpf = OWPDGetPF;
    OWPCheckControlPolicyFunc   checkcontrolfunc = OWPDCheckControlPolicy;
    OWPCheckTestPolicyFunc      checktestfunc = OWPDCheckTestPolicy;
    OWPCheckFetchPolicyFunc     checkfetchfunc = OWPDCheckFetchPolicy;
    OWPTestCompleteFunc         testcompletefunc = OWPDTestComplete;
    OWPOpenFileFunc             openfilefunc = OWPDOpenFile;
    OWPCloseFileFunc            closefilefunc = OWPDCloseFile;


    eh = OWPContextErrHandle(ctx);

    /*
     * Alloc main policy record
     */
    if(!(policy = calloc(1,sizeof(*policy)))){
        OWPError(ctx,OWPErrFATAL,errno,"calloc(policy rec): %M");
        return NULL;
    }

    policy->ctx = ctx;
    policy->diskfudge = diskfudge;

    /*
     * copy datadir
     */
    if(!datadir){
        datadir = ".";
    }
    if(!(policy->datadir = strdup(datadir))){
        OWPError(ctx,OWPErrFATAL,errno,"strdup(datadir): %M");
        goto error;
    }

    /*
     * Alloc hashes.
     */
    if(!(policy->limits = I2HashInit(eh,0,NULL,NULL)) ||
            !(policy->idents =
                I2HashInit(eh,0,NULL,NULL)) ||
            !(policy->pfs = I2HashInit(eh,0,NULL,NULL))){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPDPolicyInstall: Unable to allocate hashes");
        goto error;
    }

    /*
     * Open the pass-phrase file.
     */
    pfname[0] = '\0';
    len = strlen(fileprefix) + strlen(OWP_PFS_FILE_SUFFIX);
    if(len > MAXPATHLEN){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "strlen(OWP_PFS_FILE > MAXPATHLEN)");
        goto error;
    }

    len += strlen(confdir) + strlen(OWP_PATH_SEPARATOR);
    if(len > MAXPATHLEN){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                 "Path to %s%s > MAXPATHLEN",fileprefix,OWP_PFS_FILE_SUFFIX);
        goto error;
    }
    strcpy(pfname,confdir);
    strcat(pfname,OWP_PATH_SEPARATOR);
    strcat(pfname,fileprefix);
    strcat(pfname,OWP_PFS_FILE_SUFFIX);
    if(!(kfp = fopen(pfname,"r")) && (errno != ENOENT)){
        OWPError(ctx,OWPErrFATAL,errno,"Unable to open %s: %M",pfname);
        goto error;
    }

    /*
     * Open the limits file.
     */
    lfname[0] = '\0';
    len = strlen(fileprefix) + strlen(OWP_LIMITS_FILE_SUFFIX);
    if(len > MAXPATHLEN){
        OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "strlen(OWP_LIMITS_FILE > MAXPATHLEN)");
        goto error;
    }

    len += strlen(confdir) + strlen(OWP_PATH_SEPARATOR);
    if(len > MAXPATHLEN){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                 "Path to %s%s > MAXPATHLEN",fileprefix,OWP_LIMITS_FILE_SUFFIX);
        goto error;
    }
    strcpy(lfname,confdir);
    strcat(lfname,OWP_PATH_SEPARATOR);
    strcat(lfname,fileprefix);
    strcat(lfname,OWP_LIMITS_FILE_SUFFIX);

    if(!(lfp = fopen(lfname,"r"))){
        if(errno != ENOENT){
            OWPError(ctx,OWPErrFATAL,errno,"Unable to open %s: %M",
                    lfname);
            goto error;
        }
    }

    /*
     * lbuf is a char buffer that grows as needed in I2GetConfLine
     * lbuf will be realloc'd repeatedly as needed. Once conf file
     * parsing is complete - it is free'd from this function.
     */
    if((rc = parsepfs(policy,kfp,lbuf,lbuf_max)) < 0){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "%s:%d Invalid file syntax",pfname,-rc);
        goto error;
    }

    if((rc = parselimits(policy,lfp,lbuf,lbuf_max)) < 0){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "%s:%d Invalid file syntax",lfname,-rc);
        goto error;
    }

    if(kfp && (fclose(kfp) != 0)){
        OWPError(ctx,OWPErrFATAL,errno,"fclose(%s): %M",pfname);
        goto error;
    }
    kfp = NULL;

    if(lfp && (fclose(lfp) != 0)){
        OWPError(ctx,OWPErrFATAL,errno,"fclose(%s): %M",lfname);
        goto error;
    }
    lfp = NULL;

    /*
     * Policy files were parsed and loaded ok. Now, install policy
     * hook functions that will use it.
     *
     * Use func pointers to ensure we have functions of the correct
     * type.
     */

    if(!OWPContextConfigSetV(ctx,OWPDPOLICY,policy)){
        goto error;
    }
    if(!OWPContextConfigSetF(ctx,OWPGetPF,(OWPFunc)getpf)){
        goto error;
    }
    if(!OWPContextConfigSetF(ctx,OWPCheckControlPolicy,
                (OWPFunc)checkcontrolfunc)){
        goto error;
    }
    if(!OWPContextConfigSetF(ctx,OWPCheckTestPolicy,
                (OWPFunc)checktestfunc)){
        goto error;
    }
    if(!OWPContextConfigSetF(ctx,OWPCheckFetchPolicy,
                (OWPFunc)checkfetchfunc)){
        goto error;
    }
    if(!OWPContextConfigSetF(ctx,OWPTestComplete,
                (OWPFunc)testcompletefunc)){
        goto error;
    }
    if(!OWPContextConfigSetF(ctx,OWPOpenFile,(OWPFunc)openfilefunc)){
        goto error;
    }
    if(!OWPContextConfigSetF(ctx,OWPCloseFile,(OWPFunc)closefilefunc)){
        goto error;
    }

    return policy;

error:
    if (lfp) {
        fclose(lfp);
    }
    if (kfp) {
        fclose(kfp);
    }
    if (policy) {
        if (policy->pfs) {
            I2HashClose(policy->pfs);
        }
        if (policy->idents) {
            I2HashClose(policy->idents);
        }
        if (policy->limits) {
            I2HashClose(policy->limits);
        }
        free(policy->datadir);
    }
    free(policy);
    return NULL;
}

OWPBoolean
OWPDPolicyPostInstall(
    OWPDPolicy  policy
        )
{
    /*
     * Now that the "user class" hierarchy is loaded - take a look
     * at datadir and initialize disk usage.
     */
    if(!InitializeDiskUsage(policy)){
        return False;
    }

    return True;
}

/*
 * Function:        OWPDGetPF
 *
 * Description:        
 *         Fetch the 128 bit AES key for a given userid and return it.
 *
 *         Returns True if successful.
 *         If False is returned err_ret can be checked to determine if
 *         the key store had a problem(ErrFATAL) or if the userid is
 *         invalid(ErrOK).
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        T/F
 * Side Effect:        
 */
extern OWPBoolean
OWPDGetPF(
        OWPContext      ctx,
        const OWPUserID userid,
        uint8_t         **pf,
        size_t          *pf_len,
        void            **pf_free,
        OWPErrSeverity  *err_ret
        )
{
    OWPDPolicy  policy;
    I2Datum     key,val;

    *err_ret = OWPErrOK;

    if(!(policy = (OWPDPolicy)OWPContextConfigGetV(ctx,OWPDPOLICY))){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDGetPF: OWPDPOLICY not set");
        *err_ret = OWPErrFATAL;
        return False;
    }

    key.dptr = (void*)userid;
    key.dsize = strlen(userid);
    if(!I2HashFetch(policy->pfs,key,&val)){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrPOLICY,
                "userid \"%s\" unknown",userid);
        return False;
    }

    /* just point directly at memory in store */
    *pf = val.dptr;
    *pf_len = val.dsize;
    *pf_free = NULL;

    return True;
}

static OWPDPolicyNode
GetNodeDefault(
        OWPDPolicy  policy
        )
{
    OWPDPidRec  tpid;
    I2Datum     key,val;

    memset(&tpid,0,sizeof(tpid));

    tpid.id_type = OWPDPidDefaultType;
    key.dptr = &tpid;
    key.dsize = sizeof(tpid);
    if(I2HashFetch(policy->idents,key,&val)){
        return (OWPDPolicyNode)val.dptr;
    }

    return policy->root;
}

static OWPDPolicyNode
GetNodeFromUserID(
        OWPDPolicy      policy,
        const OWPUserID userid  /* MUST BE VALID MEMORY */
        )
{
    OWPDPidRec  pid;
    I2Datum     key,val;

    memset(&pid,0,sizeof(pid));

    pid.id_type = OWPDPidUserType;
    key.dptr = &pid;
    key.dsize = sizeof(pid);

    memcpy(pid.user.userid,userid,sizeof(pid.user.userid));

    if(I2HashFetch(policy->idents,key,&val)){
        return (OWPDPolicyNode)val.dptr;
    }

    return NULL;
}

static OWPDPolicyNode
GetNodeFromAddr(
        OWPDPolicy      policy,
        struct sockaddr *remote_sa_addr
        )
{
    OWPDPidRec  pid;
    uint8_t    nbytes,nbits,*ptr;
    I2Datum     key,val;

    memset(&pid,0,sizeof(pid));

    pid.id_type = OWPDPidNetmaskType;
    key.dptr = &pid;
    key.dsize = sizeof(pid);

    switch(remote_sa_addr->sa_family){
        struct sockaddr_in        *saddr4;
#ifdef        AF_INET6
        struct sockaddr_in6        *saddr6;

        case AF_INET6:
        saddr6 = (struct sockaddr_in6*)remote_sa_addr;
        /*
         * If this is a v4 mapped address - match it as a v4 address.
         */
        if(IN6_IS_ADDR_V4MAPPED(&saddr6->sin6_addr)){
            memcpy(pid.net.addrval,
                    &saddr6->sin6_addr.s6_addr[12],4);
            pid.net.addrsize = 4;
        }
        else{
            memcpy(pid.net.addrval,saddr6->sin6_addr.s6_addr,16);
            pid.net.addrsize = 16;
        }
        break;
#endif
        case AF_INET:
        saddr4 = (struct sockaddr_in*)remote_sa_addr;
        memcpy(pid.net.addrval,&saddr4->sin_addr.s_addr,4);
        pid.net.addrsize = 4;
        break;

        default:
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unknown address protocol family.");
        return NULL;
        break;
    }

    /*
     * Start with the max mask size (full address) and keep decreasing
     * the mask size until all possible address masks have been checked
     * for the given address.
     */
    for(pid.net.mask_len=pid.net.addrsize*8;
            pid.net.mask_len > 0; pid.net.mask_len--){
        /*
         * nbytes is number of complete bytes in "mask".
         * nbits is number of bits in the following byte that
         * are part of the "mask".
         */
        nbytes = pid.net.mask_len/8;
        nbits = pid.net.mask_len%8;
        ptr = &pid.net.addrval[nbytes];

        /*
         * Zero out one more bit each time through the loop.
         * (The "if" skips the "max" case.)
         */
        if(nbytes < pid.net.addrsize){
            *ptr &= (0xFF << (8-nbits));
        }

        if(I2HashFetch(policy->idents,key,&val)){
            return (OWPDPolicyNode)val.dptr;
        }
    }

    return GetNodeDefault(policy);
}

static OWPDLimitT
GetLimit(
        OWPDPolicyNode  node,
        OWPDMesgT       lim
        )
{
    size_t  i;

    for(i=0;i<node->ilim;i++){
        if(lim == node->limits[i].limit){
            return node->limits[i].value;
        }
    }

    return GetDefLimit(lim);
}

static OWPDLimitT
GetUsed(
        OWPDPolicyNode  node,
        OWPDMesgT       lim
       )
{
    size_t  i;

    for(i=0;i<node->ilim;i++){
        if(lim == node->limits[i].limit){
            return node->used[i].value;
        }
    }

    return 0;
}

/*
 * Returns True if the usage is less than the limit - false if it is greater.
 * It sets the usage to the value passed in either way. (well - only if the
 * resource is being tracked.)
 */
static void
IntegerResourceUsage(
        OWPDPolicyNode  node,
        OWPDLimRec      lim
        )
{
    size_t  i;

    for(i=0;i<node->ilim;i++){
        if(node->limits[i].limit == lim.limit){
            goto found;
        }
    }

    /*
     * If there is not limit record, then the default must be 0 or the
     * logic breaks.
     */
    assert(!GetDefLimit(lim.limit));

    /*
     * No reason to keep track if this resource is unlimited all the
     * way up the tree - so just return true.
     */
    return;

found:
    /*
     * Ok - found the resource limits
     */

    /*
     * If no limit at this level, just return true
     */
    if(!node->limits[i].value){
        return;
    }

    node->used[i].value = lim.value;

    if(node->used[i].value > node->limits[i].value){
        OWPError(node->policy->ctx,OWPErrWARNING,OWPErrPOLICY,
                "Resource usage exceeds limits %s:%s "
                "(used = %" PRIu64 ", limit = %" PRIu64 ")",node->nodename,
                GetLimName(lim.limit),node->used[i].value,
                node->limits[i].value);
    }

    return;
}

static void
OWPDResourceUsage(
        OWPDPolicyNode  node,
        OWPDLimRec      lim
        )
{
    size_t          maxdef = I2Number(limkeys);
    size_t          i;
    enum limtype    limkind = LIMNOT;

    for(i=0;i<maxdef;i++){
        if(lim.limit == limkeys[i].limit){
            limkind = limkeys[i].ltype;
            break;
        }
    }

    if(limkind != LIMINTVAL){
        return;
    }

    OWPError(node->policy->ctx,OWPErrDEBUG,OWPErrPOLICY,
            "ResInit %s:%s = %" PRIu64,node->nodename,
            GetLimName(lim.limit),lim.value);
    IntegerResourceUsage(node,lim);

    return;
}

static OWPBoolean
IntegerResourceDemand(
        OWPDPolicyNode  node,
        OWPDMesgT       query,
        OWPDLimRec      lim
        )
{
    size_t  i;
    double  fudge = 1.0;

    /*
     * terminate recursion
     */
    if(!node){
        return True;
    }

    for(i=0;i<node->ilim;i++){
        if(node->limits[i].limit == lim.limit){
            goto found;
        }
    }

    /*
     * If there is not limit record, then the default must be 0 or the
     * logic breaks.
     */
    assert(!GetDefLimit(lim.limit));

    /*
     * No reason to keep track if this resource is unlimited all the
     * way up the tree - so just return true.
     */
    return True;

found:
    /*
     * Ok - found the resource limits
     */

    /*
     * If no limit at this level, go on to next.
     */
    if(!node->limits[i].value){
        return IntegerResourceDemand(node->parent,query,lim);
    }

    /*
     * Deal with resource releases.
     */
    else if(query == OWPDMESGRELEASE){
        if(lim.value > node->used[i].value){
            OWPError(node->policy->ctx,OWPErrFATAL,OWPErrPOLICY,
                    "Request to release unallocated resouces: "
                    "%s:%s (currently allocated = %u, "
                    "release amount = %u)",node->nodename,
                    GetLimName(lim.limit),node->used[i].value,
                    lim.value);
            return False;
        }

        if(!IntegerResourceDemand(node->parent,query,lim)){
            return False;
        }

        node->used[i].value -= lim.value;

        return True;
    }

    /*
     * The rest deals with resource requests.
     */

    /*
     * If this is a OWPDMESGCLAIM request - apply the fudge.
     */
    if(query == OWPDMESGCLAIM){
        switch(lim.limit){
            case OWPDLimDisk:
                fudge = node->policy->diskfudge;
                break;

            default:
                OWPError(node->policy->ctx,OWPErrFATAL,OWPErrPOLICY,
                        "Invalid \"CLAIM\" request");
                return False;
        }
    }
    else if(query != OWPDMESGREQUEST){
        OWPError(node->policy->ctx,OWPErrFATAL,OWPErrPOLICY,
                "Unknown resource request type: %u",query);
        return False;
    }

    /*
     * If this level doesn't have the resources available - return false.
     */
    if((lim.value+node->used[i].value) > (node->limits[i].value * fudge)){
        return False;
    }

    /*
     * Are the resource available the next level up?
     */
    if(!IntegerResourceDemand(node->parent,query,lim)){
        return False;
    }

    node->used[i].value += lim.value;

    return True;
}

OWPBoolean
OWPDResourceDemand(
        OWPDPolicyNode  node,
        OWPDMesgT       query,
        OWPDLimRec      lim
        )
{
    size_t          maxdef = I2Number(limkeys);
    size_t          i;
    enum limtype    limkind = LIMNOT;
    OWPDLimitT      val;
    OWPBoolean      ret;

    for(i=0;i<maxdef;i++){
        if(lim.limit == limkeys[i].limit){
            limkind = limkeys[i].ltype;
            break;
        }
    }

    if(limkind == LIMNOT){
        return False;
    }

    if(limkind == LIMBOOLVAL){
        if(query == OWPDMESGRELEASE){
            return True;
        }
        val = GetLimit(node,lim.limit);
        return (val == lim.value);
    }

    ret = IntegerResourceDemand(node,query,lim);

    /*
     * These messages are printed to DEBUG if allowed and FATAL if denied
     */
    OWPError(node->policy->ctx,(ret)?OWPErrDEBUG:OWPErrFATAL,OWPErrPOLICY,
            "ResReq %s: %s:%s:%s = %" PRIu64 " (result = %" PRIu64
            ", limit = %" PRIu64 ")",
            (ret)?"ALLOWED":"DENIED",
            node->nodename,
            (query == OWPDMESGRELEASE)?"release":"request",
            GetLimName(lim.limit),
            lim.value,
            GetUsed(node,lim.limit),
            GetLimit(node,lim.limit));
    for(node = node->parent;!ret && node;node = node->parent){
        OWPError(node->policy->ctx,(ret)?OWPErrDEBUG:OWPErrFATAL,OWPErrPOLICY,
                "ResReq %s: %s:%s:%s = %" PRIu64
                " (result = %" PRIu64 ", limit = %" PRIu64")",
                (ret)?"ALLOWED":"DENIED",
                node->nodename,
                (query == OWPDMESGRELEASE)?"release":"request",
                GetLimName(lim.limit),
                lim.value,
                GetUsed(node,lim.limit),
                GetLimit(node,lim.limit));
    }

    return ret;
}

/*
 * Function:        OWPDSendResponse
 *
 * Description:        
 *         This function is called from the parent perspective.
 *
 *         It is used to respond to a child request/release of resources.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
int
OWPDSendResponse(
        int         fd,
        OWPDMesgT   mesg
        )
{
    OWPDMesgT   buf[3];
    int         fail_on_intr=1;

    buf[0] = buf[2] = OWPDMESGMARK;
    buf[1] = mesg;

    if(I2Writeni(fd,&buf[0],12,&fail_on_intr) != 12){
        return 1;
    }

    return 0;
}

/*
 * Function:        OWPDReadResponse
 *
 * Description:        
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
static OWPDMesgT
OWPDReadResponse(
        int fd
        )
{
    OWPDMesgT   buf[3];
    int         fail_on_intr=1;

    if(I2Readni(fd,&buf[0],12,&fail_on_intr) != 12){
        return OWPDMESGINVALID;
    }

    if((buf[0] != OWPDMESGMARK) || (buf[2] != OWPDMESGMARK)){
        return OWPDMESGINVALID;
    }

    return buf[1];
}

/*
 * Function:        OWPDReadClass
 *
 * Description:        
 *         This function is called from the parent perspective.
 *
 *         It is used to read the initial message from a child to determine
 *         the "user class" of the given connection.
 *
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
OWPDPolicyNode
OWPDReadClass(
        OWPDPolicy  policy,
        int         fd,
        int         *err
        )
{
    ssize_t         i;
    const OWPDMesgT mark=OWPDMESGMARK;
    const OWPDMesgT mclass=OWPDMESGCLASS;
    uint8_t        buf[OWPDMAXCLASSLEN+1 + sizeof(OWPDMesgT)*3];
    I2Datum         key,val;
    int             fail_on_intr=1;

    *err = 1;

    /*
     * Read message header
     */
    if((i = I2Readni(fd,&buf[0],8,&fail_on_intr)) != 8){
        if(i == 0){
            *err = 0;
        }
        return NULL;
    }

    if(memcmp(&buf[0],&mark,sizeof(OWPDMesgT)) ||
            memcmp(&buf[4],&mclass,sizeof(OWPDMesgT))){
        return NULL;
    }

    /*
     * read classname
     */
    for(i=0;i<= OWPDMAXCLASSLEN;i++){
        if(I2Readni(fd,&buf[i],1,&fail_on_intr) != 1){
            return NULL;
        }

        if(buf[i] == '\0'){
            break;
        }
    }

    if(i > OWPDMAXCLASSLEN){
        return NULL;
    }

    key.dptr = &buf[0];
    key.dsize = i;

    /*
     * read message trailer.
     */
    i++;
    if((I2Readni(fd,&buf[i],4,&fail_on_intr) != 4) ||
            memcmp(&buf[i],&mark,sizeof(OWPDMesgT))){
        return NULL;
    }

    if(I2HashFetch(policy->limits,key,&val)){
        if(OWPDSendResponse(fd,OWPDMESGOK) != 0){
            return NULL;
        }
        *err = 0;
        return val.dptr;
    }

    (void)OWPDSendResponse(fd,OWPDMESGDENIED);
    return NULL;
}

static OWPDMesgT
OWPDSendClass(
        OWPDPolicy      policy,
        OWPDPolicyNode  node
        )
{
    uint8_t    buf[OWPDMAXCLASSLEN+1 + sizeof(OWPDMesgT)*3];
    OWPDMesgT   mesg;
    ssize_t     len;
    int         fail_on_intr=1;

    mesg = OWPDMESGMARK;
    memcpy(&buf[0],&mesg,4);
    mesg = OWPDMESGCLASS;
    memcpy(&buf[4],&mesg,4);
    len = strlen(node->nodename);
    len++;
    strncpy((char*)&buf[8],node->nodename,len);
    len += 8;
    mesg = OWPDMESGMARK;
    memcpy(&buf[len],&mesg,4);
    len += 4;

    if(I2Writeni(policy->fd,buf,len,&fail_on_intr) != len){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPDCheckControlPolicy: Unable to contact parent");
        return OWPDMESGINVALID;
    }

    return OWPDReadResponse(policy->fd);
}

/*
 * True if there is a request
 */
OWPBoolean
OWPDReadQuery(
        int         fd,
        OWPDMesgT   *query,
        OWPDLimRec  *lim_ret,
        int         *err
        )
{
    ssize_t     i;
    OWPDMesgT   buf[7];
    int         fail_on_intr=1;

    *err = 1;

    /*
     * Read message header
     */
    if((i = I2Readni(fd,&buf[0],28,&fail_on_intr)) != 28){
        if(i == 0){
            *err = 0;
        }
        return False;
    }

    if((buf[0] != OWPDMESGMARK) || (buf[6] != OWPDMESGMARK) ||
            (buf[1] != OWPDMESGRESOURCE)){
        return False;
    }

    switch(buf[2]){
        case OWPDMESGREQUEST:
        case OWPDMESGRELEASE:
        case OWPDMESGCLAIM:
            *query = buf[2];
            break;
        default:
            return False;
    }

    lim_ret->limit = buf[3];
    memcpy(&lim_ret->value,&buf[4],8);

    *err = 0;

    return True;
}

static OWPDMesgT
OWPDQuery(
        OWPDPolicy  policy,
        OWPDMesgT   mesg,   /* OWPDMESGREQUEST or OWPDMESGRELEASE   */
        OWPDLimRec  lim
        )
{
    OWPDMesgT   buf[7];
    int         fail_on_intr=1;

    buf[0] = buf[6] = OWPDMESGMARK;
    buf[1] = OWPDMESGRESOURCE;
    buf[2] = mesg;
    buf[3] = lim.limit;
    memcpy(&buf[4],&lim.value,8);

    if(I2Writeni(policy->fd,buf,28,&fail_on_intr) != 28){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPDQuery: Unable to contact parent");
        return OWPDMESGINVALID;
    }

    return OWPDReadResponse(policy->fd);
}

/*
 * Function:        OWPDAllowOpenMode
 *
 * Description:        
 *        check if the given address is allowed to have open_mode communication.
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
OWPDAllowOpenMode(
        OWPDPolicy      policy,
        struct sockaddr *remote_sa_addr,
        OWPErrSeverity  *err_ret            /* error - return   */
        )
{
    OWPDPolicyNode  node;

    *err_ret = OWPErrOK;

    if(!(node = GetNodeFromAddr(policy,remote_sa_addr))){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDAllowOpenMode: Invalid policy");
        *err_ret = OWPErrFATAL;
        return False;
    }

    return GetLimit(node,OWPDLimAllowOpenMode);
}

/*
 * Function:        OWPDCheckControlPolicy
 *
 * Description:        
 *         Determines the "user class" of the given connection and
 *         sends that information to the "parent" so the parent can
 *         approve future resource requests.
 *
 *         Returns False and sets err_ret if the "user class" cannot be
 *         determined or if there is an error communicating with the parent.
 *         (The parent communication is necessary to keep track of resource
 *         allocations on a "global" basis instead of per-connection.)
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
OWPDCheckControlPolicy(
        OWPControl      cntrl,
        OWPSessionMode  mode,               /* requested mode       */
        const OWPUserID userid,             /* identity             */
        struct sockaddr *local_sa_addr      __attribute__((unused)),
                                            /* local addr or NULL   */
        struct sockaddr *remote_sa_addr,    /* remote addr          */
        OWPErrSeverity  *err_ret            /* error - return       */
        )
{
    OWPContext      ctx;
    OWPDPolicy      policy;
    OWPDPolicyNode  node=NULL;
    I2Datum         key,val;
    OWPDMesgT       ret;

    *err_ret = OWPErrOK;

    ctx = OWPGetContext(cntrl);

    if(!(policy = (OWPDPolicy)OWPContextConfigGetV(ctx,OWPDPOLICY))){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDCheckControlPolicy: OWPDPOLICY not set");
        *err_ret = OWPErrFATAL;
        return False;
    }

    /*
     * Determine userclass and send that to the parent.
     * (First try based on userid.)
     */
    if(((mode & OWP_MODE_DOCIPHER) && userid) &&
            !(node = GetNodeFromUserID(policy,userid))){
        OWPError(policy->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                "OWPDCheckControlPolicy: No policy match for userid(%s) - using netmask match",userid);
    }

    if((mode & OWP_MODE_DOCIPHER) && userid){
        key.dptr = (void*)userid;
        key.dsize = strlen(userid);

        if(I2HashFetch(policy->limits,key,&val)){
            node = val.dptr;
        }
    }

    /*
     * If we don't have a userclass from the userid, then get one
     * based on the address. (This returns the default if no
     * address matched.)
     */
    if(!node && !(node = GetNodeFromAddr(policy,remote_sa_addr))){
        OWPError(policy->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDCheckControlPolicy: Invalid policy");
        *err_ret = OWPErrFATAL;
        return False;
    }

    /*
     * Initialize the communication with the parent resource broker
     * process.
     */
    if((ret = OWPDSendClass(policy,node)) == OWPDMESGOK){
        /*
         * Success - now save the node in the control config
         * for later hook functions to access.
         */
        if(!OWPControlConfigSetV(cntrl,OWPDPOLICY_NODE,node)){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "OWPDCheckControlPolicy: Unable to save \"class\" for connection");
            *err_ret = OWPErrFATAL;
            return False;
        }

        return True;
    }

    /*
     * If ret wasn't OWPDMESGDENIED - there was some kind of error.
     */
    if(ret != OWPDMESGDENIED){
        *err_ret = OWPErrFATAL;
    }

    return False;
}

/*
 * This structure is used to keep track of the path information used by
 * a fp allocated by the OWPDOpenFile function.
 * This macro is the prefix for a given finfo in the cntrl Config table. The
 * fd number is concatenated to this string (in ascii) to get a key for
 * adding and removing a finfo record to the Config table.
 */
#define OWPDPOLICY_KEYLEN   64
#define OWPDPOLICY_FILEINFO "OWPDPOLICY_FILEINFO"
typedef struct OWPDFileInformationRec{
    OWPDPolicyNode  node;   /* node specific to file, not connection */
    FILE            *fp;
    char            filepath[PATH_MAX+1];
    char            linkpath[PATH_MAX+1];
} OWPDFileInformationRec, *OWPDFileInformation;

/*
 * Enum used to keep track of the 'type' of the structure union
 */
typedef enum {OWPDINFO_INVALID=0,OWPDINFO_FETCH,OWPDINFO_TEST} OWPDInfoType;

/*
 * This structure is returned in the "closure" pointer of the CheckTestPolicy
 * pointer - and provided to the Open/Close file functions as well as the
 * TestComplete function.
 */
typedef struct OWPDInfoTestRec{
    OWPDInfoType        itype;
    OWPDPolicyNode      node;
    OWPDFileInformation finfo;
    OWPDLimRec          res[2];        /* 0=bandwidth,1=disk */
} OWPDInfoTestRec, *OWPDInfoTest;

typedef struct OWPDInfoFetchRec{
    OWPDInfoType        itype;
    OWPDPolicyNode      node;
    OWPDFileInformation finfo;
    uint32_t            begin;
    uint32_t            end;
} OWPDInfoFetchRec, *OWPDInfoFetch;

union OWPDInfoRequestUnion{
    OWPDInfoType        itype;
    OWPDInfoTestRec     test;
    OWPDInfoFetchRec    fetch;
};

typedef union OWPDInfoRequestUnion OWPDInfoRequestRec, *OWPDInfoRequest;

OWPBoolean
OWPDCheckTestPolicy(
        OWPControl      cntrl,
        OWPBoolean      local_sender,
        struct sockaddr *local_sa_addr      __attribute__((unused)),
        struct sockaddr *remote_sa_addr,
        socklen_t       sa_len              __attribute__((unused)),
        OWPTestSpec     *test_spec,
        void            **closure,
        OWPErrSeverity  *err_ret
        )
{
    OWPContext      ctx = OWPGetContext(cntrl);
    OWPDPolicyNode  node;
    OWPDInfoTest    tinfo;
    OWPDMesgT       ret;
    static const OWPDLimRec one_session = {OWPDLimTestSessions,1};

    *err_ret = OWPErrOK;

    /*
     * Fetch the "user class" for this connection.
     */
    if(!(node = (OWPDPolicyNode)OWPControlConfigGetV(cntrl,
                    OWPDPOLICY_NODE))){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDCheckTestPolicy: OWPDPOLICY_NODE not set");
        *err_ret = OWPErrFATAL;
        return False;
    }


    if(!(tinfo = calloc(1,sizeof(OWPDInfoTestRec)))){
        OWPError(ctx,OWPErrFATAL,errno,"calloc(1,OWPDInfoTestRec): %M");
        *err_ret = OWPErrFATAL;
        return False;
    }

    tinfo->itype = OWPDINFO_TEST;
    tinfo->node = node;

    /*
     * Stored in control session process, so query locally.
     */
    if(!OWPDResourceDemand(node,OWPDMESGREQUEST,one_session)) {
        goto done;
    }

    /*
     * Check bandwidth for one-way sessions.
     *
     * This doesn't apply to two-way sessions since we don't know in
     * advance the sender's send schedule, unlike for one-way
     * sessions.
     */
    if (!OWPControlIsTwoWay(cntrl)) {
        tinfo->res[0].limit = OWPDLimBandwidth;
        tinfo->res[0].value = OWPTestPacketBandwidth(ctx,
                remote_sa_addr->sa_family,OWPGetMode(cntrl),test_spec);
        if((ret = OWPDQuery(node->policy,OWPDMESGREQUEST,tinfo->res[0]))
           == OWPDMESGDENIED){
            OWPDResourceDemand(node,OWPDMESGRELEASE,one_session);
            goto done;
        }
        if(ret == OWPDMESGINVALID){
            *err_ret = OWPErrFATAL;
            goto done;
        }
    }


    /*
     * If we are receiver - check disk-space.
     */
    if(!local_sender){
        /*
         * Request 10% more than our estimate to cover duplicates.
         * reality will be adjusted in CloseFile.
         */
        tinfo->res[1].limit = OWPDLimDisk;
        tinfo->res[1].value = OWPTestDiskspace(test_spec);

        if((ret = OWPDQuery(node->policy,OWPDMESGREQUEST,tinfo->res[1]))
                == OWPDMESGDENIED){
            OWPDResourceDemand(node,OWPDMESGRELEASE,one_session);
            OWPDQuery(node->policy,OWPDMESGRELEASE,tinfo->res[0]);
            goto done;
        }
        if(ret == OWPDMESGINVALID){
            *err_ret = OWPErrFATAL;
            goto done;
        }
    }

    *closure = tinfo;
    return True;
done:
    free(tinfo);
    return False;
}

OWPBoolean
OWPDCheckFetchPolicy(
        OWPControl      cntrl,
        struct sockaddr *local_sa_addr      __attribute__((unused)),
        struct sockaddr *remote_sa_addr     __attribute__((unused)),
        socklen_t       sa_len              __attribute__((unused)),
        uint32_t        begin,
        uint32_t        end,
        OWPSID          sid                 __attribute__((unused)),
        void            **closure,
        OWPErrSeverity  *err_ret
        )
{
    OWPContext      ctx = OWPGetContext(cntrl);
    OWPDPolicyNode  node;
    OWPDInfoFetch   fetch;

    *err_ret = OWPErrOK;

    /*
     * Fetch the "user class" for this connection.
     */
    if(!(node = (OWPDPolicyNode)OWPControlConfigGetV(cntrl,
                    OWPDPOLICY_NODE))){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDCheckTestPolicy: OWPDPOLICY_NODE not set");
        *err_ret = OWPErrFATAL;
        return False;
    }

    /*
     * Could implement something here that only allowed the user-class
     * that created the data to fetch it, but for now this function
     * is only used to keep track of what was actually requested so
     * the CloseFile function can properly implement delete_on_fetch
     * functionality. (Only delete the file if the entire file is
     * requested.)
     */
    if(!(fetch = calloc(1,sizeof(OWPDInfoFetchRec)))){
        OWPError(ctx,OWPErrFATAL,errno,"calloc(1,OWPDInfoFetchRec): %M");
        *err_ret = OWPErrFATAL;
        return False;
    }

    fetch->itype = OWPDINFO_FETCH;
    fetch->node = node;
    fetch->begin = begin;
    fetch->end = end;

    *closure = fetch;
    return True;
}

extern void
OWPDTestComplete(
        OWPControl      cntrl       __attribute__((unused)),
        void            *closure,   /* closure from CheckTestPolicy        */
        OWPAcceptType   aval        __attribute__((unused))
        )
{
    OWPDInfoRequest rinfo = (OWPDInfoRequest)closure;
    OWPDInfoTest    tinfo = NULL;
    int             i;

    if(!rinfo || (rinfo->itype != OWPDINFO_TEST)){
        OWPError(OWPGetContext(cntrl),OWPErrFATAL,OWPErrINVALID,
                "OWPDTestComplete: Invalid closure");
        return;
    }

    tinfo = &rinfo->test;

    for(i=0;i<2;i++){
        if(!tinfo->res[i].limit){
            continue;
        }
        (void)OWPDQuery(tinfo->node->policy,OWPDMESGRELEASE,
                        tinfo->res[i]);
    }

    if(tinfo->finfo){
        OWPError(OWPGetContext(cntrl),OWPErrWARNING,OWPErrUNKNOWN,
                "OWPDTestComplete: finfo not closed?");
    }

    free(tinfo);

    return;
}

/*
 * Function:        OWPDOpenFile
 *
 * Description:        
 *         This function opens a file and saves state about it in the
 *         cntrl State hash. This is used to implement policy.
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
FILE*
OWPDOpenFile(
        OWPControl  cntrl,
        void        *closure,
        OWPSID      sid,
        char        fname_ret[PATH_MAX+1]
        )
{
    OWPContext          ctx = OWPGetContext(cntrl);
    OWPDInfoRequest     rinfo = (OWPDInfoRequest)closure;
    OWPDInfoTest        tinfo = NULL;
    OWPDInfoFetch       xinfo;
    OWPDFileInformation finfo;
    OWPDPolicyNode      node;
    char                sid_name[sizeof(OWPSID)*2+1];

    if(!rinfo || (rinfo->itype == OWPDINFO_INVALID)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDOpenFile: closure not set");
        return NULL;
    }

    /*
     * Hex Encode the sid.
     */
    I2HexEncode(sid_name,sid,sizeof(OWPSID));

    if(!(finfo = (calloc(1,sizeof(*finfo))))){
        OWPError(ctx,OWPErrFATAL,errno,"calloc(OWPDFileInformation): %M");
        return NULL;
    }

    if(rinfo->itype == OWPDINFO_TEST){
        tinfo = &rinfo->test;

        node = tinfo->node;

        /*
         * Now place pathname to catalog dir in finfo->linkpath.
         */
        strcpy(finfo->linkpath,node->policy->datadir);
        strcat(finfo->linkpath,OWP_PATH_SEPARATOR);
        strcat(finfo->linkpath,OWP_CATALOG_DIR);

        finfo->node = tinfo->node;

        /*
         * Make sure the node directory exists first.
         * (setting add_chars to the length of the filename part
         * that needs to be concatenated on after the directory.
         * This does not include the nul byte.)
         */
        if(!node_dir(ctx,True,node->policy->datadir,node,
                    OWP_PATH_SEPARATOR_LEN + (sizeof(OWPSID)*2) +
                    strlen(OWP_FILE_EXT),finfo->filepath)){
            return NULL;
        }

        strcat(finfo->filepath,OWP_PATH_SEPARATOR);
        strcat(finfo->filepath,sid_name);
        strcat(finfo->filepath,OWP_FILE_EXT);

        /*
         * we know top-level datadir exists from last call to
         * node_dir, now make sure "catalog" directory exists.
         */
        if((mkdir(finfo->linkpath,0755) != 0) && (errno != EEXIST)){
            OWPError(ctx,OWPErrFATAL,OWPErrUNKNOWN,"Unable to mkdir(%s): %M",
                    finfo->linkpath);
            return NULL;
        }

        strcat(finfo->linkpath,OWP_PATH_SEPARATOR);
        strcat(finfo->linkpath,sid_name);
        strcat(finfo->linkpath,OWP_FILE_EXT);

        /*
         * Now open the file.
         */
        if(!(finfo->fp = fopen(finfo->filepath,"w+b"))){
            OWPError(ctx,OWPErrFATAL,errno,"fopen(%s,\"wb\"): %M",
                    finfo->filepath);
            goto error;
        }

        /*
         * Create the symlink first.
         * This is how fetchsession will find the file.
         */
        if(symlink(finfo->filepath,finfo->linkpath) != 0){
            OWPError(ctx,OWPErrFATAL,errno,"symlink(%s,%s): %M",
                    finfo->filepath,finfo->linkpath);
            goto error;
        }

        if(fname_ret){
            strcpy(fname_ret,finfo->filepath);
        }

        /*
         * finfo is retrieved via closure for receive sessions.
         */
        tinfo->finfo = finfo;
    }
    else if(rinfo->itype == OWPDINFO_FETCH){
        int     len1,len2;
        char    tc;
        char    *dname;
        I2Datum key,val;

        xinfo = &rinfo->fetch;

        node = xinfo->node;

        /*
         * Now place pathname to catalog dir in finfo->linkpath.
         */
        strcpy(finfo->linkpath,node->policy->datadir);
        strcat(finfo->linkpath,OWP_PATH_SEPARATOR);
        strcat(finfo->linkpath,OWP_CATALOG_DIR);
        strcat(finfo->linkpath,OWP_PATH_SEPARATOR);
        strcat(finfo->linkpath,sid_name);
        strcat(finfo->linkpath,OWP_FILE_EXT);
        finfo->filepath[0] = '\0';

        /*
         * Determine the "real" filename so it
         * can be used to find the "policy" node for this file.
         * Policy for this file (delete_on_fetch) is determined by
         * the "user class" that created the file, not the
         * "user class" of the current fetch session.
         */

        /*
         * set len1 to length of path "after" last node.
         */
        len1 = OWP_PATH_SEPARATOR_LEN + sizeof(OWPSID)*2 +
            strlen(OWP_FILE_EXT);

        /*
         * len2 becomes length of the full filepath
         */
        if((len2 = readlink(finfo->linkpath,finfo->filepath,
                        PATH_MAX)) < 1){
            OWPError(ctx,OWPErrFATAL,errno,
                    "readlink(%s): %M",finfo->linkpath);
            goto error;
        }
        /*
         * If the filepath is longer than PATH_MAX or shorter than
         * len1 - it can't be valid.
         */
        if(((size_t)len2 >= sizeof(finfo->filepath)) || (len2 < len1)){
            OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                    "readlink(%s): Invalid link",
                    finfo->linkpath);
            goto error;
        }

        /*
         * terminate full filepath
         */
        finfo->filepath[len2] = '\0';

        /*
         * temporarily terminate filepath just after last nodename
         * to fetch dirname component. (Not using libgen "dirname"
         * because libgen doesn't look to exist everywhere...)
         *
         * strrchr/rindex would probably be nicer than what I'm doing
         * here...
         */
        tc = finfo->filepath[len2-len1];
        finfo->filepath[len2-len1] = '\0';
        dname = &finfo->filepath[len2-len1] - 1;
        while(dname > finfo->filepath){
            if(!strncmp(dname,OWP_PATH_SEPARATOR,
                        OWP_PATH_SEPARATOR_LEN)){
                dname += OWP_PATH_SEPARATOR_LEN;
                break;
            }
            dname--;
        }
        if(dname <= finfo->filepath){
            OWPError(node->policy->ctx,OWPErrFATAL,OWPErrPOLICY,
                    "Unable to determine policy for %s",
                    finfo->linkpath);
            goto error;
        }

        /*
         * Now that we have a dirname - try fetching the policy
         * node for it.
         */
        key.dptr = dname;
        key.dsize = &finfo->filepath[len2-len1] - dname;
        if(!I2HashFetch(node->policy->limits,key,&val)){
            OWPError(node->policy->ctx,OWPErrFATAL,OWPErrPOLICY,
                    "Unable to determine policy for %s: class %s",
                    finfo->linkpath,dname);
        }

        /*
         * assign the node.
         */
        finfo->node = val.dptr;

        /*
         * reset the char pulled from the filepath to terminate
         * the nodename.
         */
        finfo->filepath[len2-len1] = tc;

        /*
         * Now open the file.
         */
        if(!(finfo->fp = fopen(finfo->linkpath,"rb"))){
            OWPError(ctx,OWPErrFATAL,errno,"fopen(%s,\"rb\"): %M",
                    finfo->linkpath);
            goto error;
        }
        if(fname_ret){
            strcpy(fname_ret,finfo->linkpath);
        }

        xinfo->finfo = finfo;
    }
    else{
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDOpenFile: invalid closure");
        goto error;
    }

    return finfo->fp;

error:
    if(tinfo){
        (void)unlink(finfo->linkpath);
        (void)unlink(finfo->filepath);
    }

    if(finfo->fp){
        fclose(finfo->fp);
    }

    free(finfo);

    return NULL;
}

/*
 * Function:        OWPDCloseFile
 *
 * Description:        
 *         This function closes a file and looks at the cntrl state hash to
 *         determine if additional action should be performed to adhere to
 *         policy. i.e. should the file be unlinked now that it has been
 *         read? (del_on_fetch)
 *
 * In Args:        
 *
 * Out Args:        
 *
 * Scope:        
 * Returns:        
 * Side Effect:        
 */
extern void
OWPDCloseFile(
        OWPControl      cntrl,
        void            *closure,
        FILE            *fp,
        OWPAcceptType   aval
        )
{
    OWPDInfoRequest     rinfo = (OWPDInfoRequest)closure;
    OWPDInfoTest        tinfo = NULL;
    OWPDInfoFetch       xinfo = NULL;
    OWPDFileInformation finfo = NULL;
    OWPContext          ctx = OWPGetContext(cntrl);
    struct stat         sbuf;
    OWPDMesgT           mesg,ret;
    OWPDLimRec          lim;

    if(!rinfo || (rinfo->itype == OWPDINFO_INVALID)){
        OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPDCloseFile: closure not set");
        return;
    }

    /*
     * File was from a TestRequest
     */
    if(rinfo->itype == OWPDINFO_TEST){
        /*
         * This was a receive endpoint. revise resource
         * request to reality.
         */
        tinfo = &rinfo->test;
        finfo = tinfo->finfo;
        tinfo->finfo = NULL;


        /*
         * stat the file to determine how much disk was actually
         * used.
         */
        if(fstat(fileno(fp),&sbuf) != 0){
            OWPError(ctx,OWPErrFATAL,errno,
                    "OWPDCloseFile: fstat(): %M: Unable to determine filesize...");
            goto end;
        }

        assert(tinfo->res[1].limit == OWPDLimDisk);
        lim.limit = OWPDLimDisk;

        if(aval != OWP_CNTRL_ACCEPT){
            /*
             * The test session was invalid, delete the file,
             * and release the resources.
             */

            /*
             * Unlink the files
             */
            (void)unlink(finfo->linkpath);
            (void)unlink(finfo->filepath);

            assert(tinfo->res[1].limit == OWPDLimDisk);
            mesg = OWPDMESGRELEASE;
            lim = tinfo->res[1];
        }
        /*
         * Can we release some diskspace from the resource broker?
         */
        else if(sbuf.st_size < (off_t)tinfo->res[1].value){
            mesg = OWPDMESGRELEASE;
            lim.value = tinfo->res[1].value - sbuf.st_size;
        }
        /*
         * Ugh. Need to request more... Use "CLAIM" so the
         * "diskfudge" factor will be used.
         */
        else if(sbuf.st_size > (off_t)tinfo->res[1].value){
            mesg = OWPDMESGCLAIM;
            lim.value = sbuf.st_size - tinfo->res[1].value;
        }
        /*
         * resource is exactly correct - skip resource broker.
         */
        else{
            goto end;
        }

        ret = OWPDQuery(finfo->node->policy,mesg,lim);

        /*
         * If we were requesting more space, and it was denied,
         * unlink the files.
         */
        if((mesg == OWPDMESGCLAIM) && (ret == OWPDMESGDENIED)){
            OWPError(ctx,OWPErrWARNING,OWPErrPOLICY,
                    "%s Too large! Deleting... (See diskfudge)",
                    finfo->filepath);
            (void)unlink(finfo->linkpath);
            (void)unlink(finfo->filepath);
            /*
             * Completely free the resource then.
             */
            (void)OWPDQuery(finfo->node->policy,OWPDMESGRELEASE,tinfo->res[1]);
        }
    }
    /*
     * otherwise - this is a fetch-session target file.
     */
    else if(rinfo->itype == OWPDINFO_FETCH){
        xinfo = &rinfo->fetch;
        finfo = xinfo->finfo;
        xinfo->finfo = NULL;

        /*
         * Check for the delete_on_fetch option...
         *
         * Only delete if this fetch was successful for the complete session,
         * and the delete_on_fetch option is specified for the
         * files limit_class definition.
         *
         */
        if((xinfo->begin == 0) && (xinfo->end == 0xFFFFFFFF) &&
                (aval == OWP_CNTRL_ACCEPT) &&
                GetLimit(finfo->node,OWPDLimDeleteOnFetch)){
            /*
             * stat the file to determine the size so the resources
             * associated with this file can be released.
             */
            if(fstat(fileno(fp),&sbuf) != 0){
                OWPError(ctx,OWPErrFATAL,errno,
                        "OWPDCloseFile: fstat(): %M: Unable to determine filesize...");
                sbuf.st_size = 0;
            }

            /*
             * Unlink the files
             */
            (void)unlink(finfo->linkpath);
            (void)unlink(finfo->filepath);

            /*
             * If we were able to stat - then free the resources.
             */
            if(sbuf.st_size > 0){
                lim.limit = OWPDLimDisk;
                lim.value = sbuf.st_size;
                (void)OWPDQuery(finfo->node->policy,
                                OWPDMESGRELEASE,lim);
            }
        }
    }
end:
    if(tinfo){
        tinfo->res[1].limit = 0;
        tinfo->res[1].value = 0;
    }
    if(finfo){
        free(finfo);
    }
    if(xinfo){
        free(xinfo);
    }
    if(fclose(fp) != 0){
        OWPError(ctx,OWPErrFATAL,errno,"fclose(): %M");
    }

    return;
}
