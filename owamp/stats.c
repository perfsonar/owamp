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
 *        File:         stats.c
 *
 *        Author:       Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Fri Nov  4 14:42:29 MST 2005
 *
 *        Description:        
 *
 * This file contains the  convinience functions used to compute statistics
 * in many of the owamp tools.
 *
 * A fair amount of effort has been made to pre-allocate the memory needed
 * to support these summary statistics.  This is being done because powstream
 * in particular will be using the statistics functions to generate summary
 * information on the fly during tests, therefore it is important to minimize
 * the number of system calls.
 *
 */
#include <owamp/owamp.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <math.h>
#include <ctype.h>

/*
 * PacketBuffer utility functions:
 *
 * The packet buffer is basically a buffer that holds a record of every
 * packet of interest that can still effect summary statistics.
 *
 * It is a linked list with hash accesses to individual nodes. It is primarily
 * used to track loss and dups. The buffer needs to be large enough to hold
 * as many packets as can be seen within the loss-threshold (timeout) period.
 *
 */


/*
 * Function:    PacketFree
 *
 * Description:    
 *              Used to take a PacketRecord and put it back in the freelist.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static void
PacketFree(
        OWPStats    stats,
        OWPPacket   node
        )
{
    I2Datum k;

    k.dptr = &node->seq;
    k.dsize = sizeof(node->seq);

    if(I2HashDelete(stats->ptable[node->type],k) != 0){
        OWPError(stats->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "PacketFree: Unable to remove seq #%lu from OWPPacket table %u",
                node->seq,node->type);
    }

    node->seq = 0;
    node->seen = 0;
    node->next = stats->pfreelist[node->type];
    stats->pfreelist[node->type] = node;

    return;
}

/*
 * Function:    PacketBufferClean
 *
 * Description:    
 *              Used to completly clear out the ring-buffer. This is used
 *              just before generating new statistics using the same
 *              stats object.
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
static I2Boolean
PacketBufferClean(
        I2Datum k   __attribute__((unused)),
        I2Datum v,
        void    *app_data
        )
{
    OWPStats   stats = app_data;
    OWPPacket  node = v.dptr;

    PacketFree(stats,node);

    return True;
}

/*
 * Function:    PacketAlloc
 *
 * Description:    
 *              Used to take a packet record off the freelist and add it
 *              into the current buffer.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static OWPPacket
PacketAlloc(
    OWPStats        stats,
    uint32_t        seq,
    OWPPacketType   type
    )
{
    OWPPacket   node;
    I2Datum     k,v;

    if((type != TWP_BCK_PKTS && seq > stats->last) ||
       (stats->pend[type] && (seq <= stats->pend[type]->seq))){
        OWPError(stats->ctx,OWPErrFATAL,OWPErrINVALID,
                "PacketAlloc: Invalid seq number for OWPPacket buffer %u",type);
        return NULL;
    }

    if(!stats->pfreelist[type]){
        long int    i;

        /*
         * print out info message to inform that the "size" calculation was not
         * good enough. (dynamic memory allocations during parsing is to be
         * avoided if possible).
         *
         * Note that with two-way pings, we don't know the client's
         * send schedule so this is expected and we don't want to
         * print a message in that case.
         */
        if (!stats->hdr->twoway) {
            OWPError(stats->ctx,OWPErrINFO,OWPErrUNKNOWN,
                     "PacketAlloc: Allocating OWPPacket!: plistlen=%u, timeout=%g",
                     stats->plistlen,
                     OWPNum64ToDouble(stats->hdr->test_spec.loss_timeout));
        }

        if(!(node = calloc(sizeof(OWPPacketRec),stats->plistlen))){
            OWPError(stats->ctx,OWPErrFATAL,errno,"calloc(): %M");
            return NULL;
        }

        node[0].next = stats->pallocated[type];
        stats->pallocated[type] = node;
        for(i=1;i<stats->plistlen;i++){
            node[i].next = stats->pfreelist[type];
            stats->pfreelist[type] = &node[i];
        }
    }

    node = stats->pfreelist[type];
    stats->pfreelist[type] = stats->pfreelist[type]->next;

    node->next = NULL;
    node->seq = seq;
    node->seen = 0;
    node->lost = False;
    node->type = type;

    k.dptr = &node->seq;
    k.dsize = sizeof(node->seq);
    v.dptr = node;
    v.dsize = sizeof(*node);

    if(I2HashStore(stats->ptable[type],k,v) != 0){
        return NULL;
    }

    return node;
}

/*
 * Function:    PacketGet
 *
 * Description:    
 *              This function retrieves the packet record for a given
 *              sequence number. If necessary, it will call PacketAlloc
 *              to allocate the record if it does not exist yet. (Which
 *              will create records for all sequence numbers between
 *              the current end-of-list and this new sequence number
 *              in the process.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static OWPPacket
PacketGet(
        OWPStats        stats,
        uint32_t        seq,
        OWPPacketType   type
        )
{
    OWPPacket   node;
    I2Datum     k,v;

    /*
     * optimize for most frequent case.
     */
    if(seq == stats->pend[type]->seq){
        return stats->pend[type];
    }

    /*
     * Ignore invalid seq num.
     */
    if((seq < stats->first) || (type != TWP_BCK_PKTS && (seq > stats->last))){
        OWPError(stats->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid type %u seq number request (out of range)",type);
        return NULL;
    }

    /*
     * Need to build the list from current "end" to this seq num.
     */
    if(seq > stats->pend[type]->seq){
        node = stats->pend[type];

        while(node->seq < seq){
            /* bug if context is not alligned with node allocation */
            assert(node->seq+1 == stats->isctx[type]);

            if(type != TWP_BCK_PKTS){
                /* update current schedule value */
                stats->endnum = OWPNum64Add(stats->endnum,
                        OWPScheduleContextGenerateNextDelta(stats->sctx));

            }
            stats->isctx[type]++;

            /* allocate and initialize next packet record */
            node->next = PacketAlloc(stats,node->seq+1,type);
            node->next->schedtime = stats->endnum;

            node = node->next;
        }

        stats->pend[type] = node;

        return node;
    }

    /*
     * Shouldn't be requesting this seq num... It should already
     * be loss_timeout in the past.
     */
    if(seq < stats->pbegin[type]->seq){
        OWPError(stats->ctx,OWPErrFATAL,OWPErrINVALID,
                "Invalid type %u seq number request",type);
        return NULL;
    }

    /*
     * seq requested in within the begin<->end range, just fetch from
     * hash.
     */
    k.dptr = &seq;
    k.dsize = sizeof(seq);

    if(!I2HashFetch(stats->ptable[type],k,&v)){
        OWPError(stats->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "Unable to fetch seq (%lu) from packet hash %u",seq,type);
        return NULL;
    }

    return (OWPPacket)v.dptr;
}

/*
 * BucketBuffer utility functions:
 *
 * The BucketBuffer is basically just a hash of bucketed delay's that are
 * used to generate a histogram of the latency values for the given
 * summary session. (Basically used to quantile.)
 */

/*
 * Function:    BucketBufferClean
 *
 * Description:    
 *              Used to clean out the current hash of all existing values.
 *              Useful for re-using a stats object for a new summary
 *              period.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static I2Boolean
BucketBufferClean(
        I2Datum k,
        I2Datum v,
        void    *app_data
        )
{
    OWPStats    stats = app_data;
    OWPBucket   node = v.dptr;

    if(I2HashDelete(stats->btable,k) != 0){
        OWPError(stats->ctx,OWPErrWARNING,OWPErrUNKNOWN,
                "BucketBufferClean: Unable to remove bucket #%d",node->b);
    }

    node->b = 0;
    node->delay_samples[OWP_DELAY] = 0;
    node->delay_samples[TWP_FWD_DELAY] = 0;
    node->delay_samples[TWP_BCK_DELAY] = 0;
    node->next = stats->bfreelist;
    stats->bfreelist = node;

    return True;
}

/*
 * Function:    BucketBufferPrint
 *
 * Description:    
 *              Used to print out the current hash of all existing values.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static I2Boolean
BucketBufferPrint(
        I2Datum k __attribute__((unused)),
        I2Datum v,
        void    *app_data
        )
{
    OWPBucket   node = v.dptr;
    FILE        *fp = app_data;

    fprintf(fp,"\t%d\t%u\n",node->b,node->delay_samples[OWP_DELAY]);

    return True;
}

static I2Boolean
BucketBufferPrintJSON(
        I2Datum k __attribute__((unused)),
        I2Datum v,
        void    *app_data
        )
{
    OWPBucket   node = v.dptr;
    OWPStats    stats = app_data;
    cJSON * bucket = cJSON_CreateObject();
    if (!stats->owp_histogram_latency_json)
    {
        stats->owp_histogram_latency_json = cJSON_CreateArray();
    }
    // TODO random number
    char name[15];
    snprintf(name,sizeof(name),"%d", node->b);
    cJSON_AddNumberToObject(bucket, name, node->delay_samples[OWP_DELAY]);
    cJSON_AddItemToArray(stats->owp_histogram_latency_json, bucket);

    //fprintf(fp,"\t%d\t%u\n",node->b,node->delay_samples[OWP_DELAY]);

    return True;
}

/*
 * Function:    BucketBufferPrintTW
 *
 * Description:
 *              Used to print out the current hash of all existing values
 *              for two-way sessions.
 *
 * In Args:
 *
 * Out Args:
 *
 * Scope:
 * Returns:
 * Side Effect:
 */
static I2Boolean
BucketBufferPrintTW(
        I2Datum k __attribute__((unused)),
        I2Datum v,
        void    *app_data
        )
{
    OWPBucket   node = v.dptr;
    FILE        *fp = app_data;

    fprintf(fp,"\t%d\t%u\t%u\t%u\n",node->b,
            node->delay_samples[OWP_DELAY],
            node->delay_samples[TWP_FWD_DELAY],
            node->delay_samples[TWP_BCK_DELAY]);

    return True;
}

static I2Boolean
BucketBufferPrintTWJSON(
        I2Datum k __attribute__((unused)),
        I2Datum v,
        void    *app_data
        )
{
    OWPBucket   node = v.dptr;
    OWPStats    stats = app_data;
    if (!stats->owp_histogram_latency_json)
    {
        stats->owp_histogram_latency_json = cJSON_CreateArray();
    }
    // TODO random number
    //char name[15];
    //snprintf(name,sizeof(name),"%d", node->b);
    cJSON * bucket = cJSON_CreateObject();
    cJSON_AddNumberToObject(bucket, "node", node->b);
    cJSON_AddNumberToObject(bucket, "owp_delay", node->delay_samples[OWP_DELAY]);
    cJSON_AddNumberToObject(bucket, "twp_fwd_delay", node->delay_samples[TWP_FWD_DELAY]);
    cJSON_AddNumberToObject(bucket, "twp_bck_delay", node->delay_samples[TWP_BCK_DELAY]);

    cJSON_AddItemToArray(stats->owp_histogram_latency_json, bucket);
    char * str = cJSON_Print(stats->owp_histogram_latency_json);
    printf("histogram_latency: %s", str);

    //fprintf(fp,"\t%d\t%u\t%u\t%u\n",node->b,
    //        node->delay_samples[OWP_DELAY],
    //        node->delay_samples[TWP_FWD_DELAY],
    //        node->delay_samples[TWP_BCK_DELAY]);

    return True;
}

/*
 * Function:    BucketBufferSortFill
 *
 * Description:    
 *              Used to copy bucket ref's into an array for sorting.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static I2Boolean
BucketBufferSortFill(
        I2Datum k   __attribute__((unused)),
        I2Datum v,
        void    *app_data
        )
{
    OWPStats    stats = app_data;
    OWPBucket   node = v.dptr;

    stats->bsort[stats->bsorti++] = node;

    return True;
}

/*
 * Function:    BucketIncrementDelay
 *
 * Description:    
 *              Used to record that fact that a given packet was recieved
 *              in a given delay time. Adds a new record into the hash
 *              if necessary.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static OWPBoolean
BucketIncrementDelay(
    OWPStats        stats,
    double          d,       /* delay */
    OWPDelayType    type
    )
{
    int         b;
    OWPBucket   node;
    I2Datum     k,v;

    /* Not supported for the processing delay */
    assert(type < OWP_DELAY_TYPE_NUM);

    /*
     * XXX: May eventually need to round these off to some significant number
     * of digits instead of using floor/ceil. (Currently, the algorithm is
     * biased away from 0.)
     */
    d /= stats->bucketwidth;
    b = (d<0)?floor(d):ceil(d);

    k.dsize = sizeof(b);
    k.dptr = &b;

    if(I2HashFetch(stats->btable,k,&v)){
        node = (OWPBucket)v.dptr;
    }
    else{
        long int    i;

        if(!stats->bfreelist){
            /*
             * print out info message to inform that the "size" calculation
             * was not good enough. (dynamic memory allocations during parsing
             * should be avoided if possible)
             */
            OWPError(stats->ctx,OWPErrINFO,OWPErrUNKNOWN,
                    "BucketIncrementDelay: Allocating additional memory for OWPBucket buffer!");

            if(!(node = calloc(sizeof(OWPBucketRec),stats->blistlen))){
                OWPError(stats->ctx,OWPErrFATAL,errno,"calloc(): %M");
                return False;
            }

            node[0].next = stats->ballocated;
            stats->ballocated = node;
            for(i=1;i<stats->blistlen;i++){
                node[i].next = stats->bfreelist;
                stats->bfreelist = &node[i];
            }
        }

        node = stats->bfreelist;
        stats->bfreelist = stats->bfreelist->next;

        node->next = NULL;
        node->b = b;
        for(i=0;i<OWP_DELAY_TYPE_NUM;i++){
            node->delay_samples[i] = 0;
        }

        k.dptr = &node->b;
        k.dsize = sizeof(node->b);
        v.dptr = node;
        v.dsize = sizeof(*node);

        if(I2HashStore(stats->btable,k,v) != 0){
            return False;
        }
    }

    /*
     * Increment number of samples.
     */
    node->delay_samples[type]++;

    return True;
}

/*
 * Stats utility functions:
 *
 * The Stats functions are used to create/free context for statistics
 * functions as well as providing those functions.
 */

/*
 * Function:    OWPStatsFree
 *
 * Description:    
 *              Used to free a Stats object.
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
OWPStatsFree(
        OWPStats    stats
        )
{
    uint8_t type;

    if(!stats)
        return;

    if(stats->rn){
        free(stats->rn);
        stats->rn = NULL;
    }
    if(stats->rseqno){
        free(stats->rseqno);
        stats->rseqno = NULL;
    }

    if(stats->bsort){
        free(stats->bsort);
        stats->bsort = NULL;
        stats->bsortlen = 0;
    }
    if(stats->btable){
        I2HashClose(stats->btable);
    }
    while(stats->ballocated){
        OWPBucket   t;

        t = stats->ballocated->next;
        free(stats->ballocated);
        stats->ballocated = t;
    }

    for(type=0;type<OWP_PKT_TYPE_NUM;type++){
        if(stats->ptable[type]){
            I2HashClose(stats->ptable[type]);
        }
        while(stats->pallocated[type]){
            OWPPacket   t;

            t = stats->pallocated[type]->next;
            free(stats->pallocated[type]);
            stats->pallocated[type] = t;
        }
    }

    if(stats->sctx){
        OWPScheduleContextFree(stats->sctx);
        stats->sctx = NULL;
    }
    if(stats->skips){
        free(stats->skips);
        stats->skips = NULL;
    }
    if(stats->hdr && stats->hdr->test_spec.slots){
        free(stats->hdr->test_spec.slots);
        stats->hdr->test_spec.slots = NULL;
    }

    free(stats);

    return;
}

/*
 * Function:    OWPStatsCreate
 *
 * Description:    
 *              used to create a stats object that is used to manage
 *              statistics parsing for a given owp file.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 *
 *
 * TODO: Create a more extensible interface for create. I'm in a hurry, so
 * for now I will just create an arg for every config option, but to
 * allow for other as yet unforseen stats it would be better to provide
 * a structure with some kind of bitmask to indicate which parts of the
 * structure are valid.
 */
OWPStats
OWPStatsCreate(
        OWPContext          ctx,
        FILE                *fp,
        OWPSessionHeader    hdr,
        char                *fromhost,
        char                *tohost,
        char                scale,
        double              bucketwidth
        )
{
    char        *func = "OWPStatsCreate";
    OWPStats    stats=NULL;
    double      d;
    uint8_t     type;
    long int    i;
    size_t      s;

    /*
     * Verify args
     */
    if(!hdr->header || (hdr->version < 2)){
        uint32_t   version = 0;
        if(hdr->header){
            version = hdr->version;
        }
        OWPError(ctx,OWPErrFATAL,EINVAL,
                "%s: owp files must be version 2 or greater. (version = %lu)",
                func,version);
        return NULL;
    }

    /*
     * alloc base memory
     */
    if(! (stats = calloc(1,sizeof(OWPStatsRec)))){
        OWPError(ctx,OWPErrFATAL,errno,"%s: calloc(OWPStats): %M",func);
        return NULL;
    }

    stats->ctx = ctx;
    stats->fp = fp;

    /*
     * Pretty hostname/servname buffers
     */
    if( (getnameinfo((struct sockaddr*)&hdr->addr_sender,
                hdr->addr_len,
                stats->fromaddr,NI_MAXHOST,
                stats->fromserv,NI_MAXSERV,
                NI_NUMERICSERV | NI_NUMERICHOST) != 0)){
        strcpy(stats->fromaddr,"***");
        stats->fromserv[0] = '\0';
    }

    if(fromhost){
        strncpy(stats->fromhost,fromhost,NI_MAXHOST-1);
    }
    else if( (getnameinfo((struct sockaddr*)&hdr->addr_sender,
                hdr->addr_len,stats->fromhost,NI_MAXHOST,
                NULL,0,0) != 0)){
        strcpy(stats->fromhost,"***");
    }

    if( (getnameinfo((struct sockaddr*)&hdr->addr_receiver,
                hdr->addr_len,
                stats->toaddr,NI_MAXHOST,
                stats->toserv,NI_MAXSERV,
                NI_NUMERICSERV | NI_NUMERICHOST) != 0)){
        strcpy(stats->toaddr,"***");
        stats->toserv[0] = '\0';
    }

    if(tohost){
        strncpy(stats->tohost,tohost,NI_MAXHOST-1);
    }
    else if( (getnameinfo((struct sockaddr*)&hdr->addr_receiver,
                hdr->addr_len,stats->tohost,NI_MAXHOST,
                NULL,0,0) != 0)){
        strcpy(stats->tohost,"***");
    }

    /*
     * Scale for reports
     */
    s = sizeof(stats->scale_abrv);
    stats->scale_factor = OWPStatsScaleFactor(scale,stats->scale_abrv,&s);
    if(stats->scale_factor == 0.0){
        OWPError(ctx,OWPErrFATAL,EINVAL,"%s: Invalid scale \'%c\'",scale);
        goto error;
    }

    /*
     * Copy hdr record
     */
    memcpy(&stats->hdr_rec,hdr,sizeof(stats->hdr_rec));
    stats->hdr = &stats->hdr_rec;

    /*
     * Read slots from the file to be sure they are good.
     */
    stats->hdr->test_spec.slots = NULL;
    if(stats->hdr->test_spec.nslots){
        if( !(stats->hdr->test_spec.slots =
                    calloc(stats->hdr->test_spec.nslots,sizeof(OWPSlot)))){
            OWPError(stats->ctx,OWPErrFATAL,errno,"%s: calloc(%lu,OWPSlot): %M",
                    func,stats->hdr->test_spec.nslots);
            goto error;
        }

        if( !OWPReadDataHeaderSlots(stats->ctx,stats->fp,
                    stats->hdr->test_spec.nslots,stats->hdr->test_spec.slots)){
            OWPError(stats->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "%s: Unable to read scheduling slots from file",func);
            goto error;
        }
    }

    /*
     * Copy skiprecs
     */
    if(stats->hdr->num_skiprecs){
        if( !(stats->skips = calloc(stats->hdr->num_skiprecs,
                        sizeof(OWPSkipRec)))){
            OWPError(stats->ctx,OWPErrFATAL,errno,
                    "%s: calloc(%lu,OWPSkipRec): %M",
                    func,stats->hdr->num_skiprecs);
            goto error;
        }
        if( !OWPReadDataSkips(stats->ctx,stats->fp,stats->hdr->num_skiprecs,
                    stats->skips)){
            OWPError(stats->ctx,OWPErrFATAL,errno,
                    "%s: Unable to read skip records from file",func);
            goto error;
        }
    }

    /*
     * Test schedule information
     */
    if( !(stats->sctx = OWPScheduleContextCreate(stats->ctx,stats->hdr->sid,
                    &stats->hdr->test_spec))){
        OWPError(stats->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "OWPStatsCreate: Unable to create schedule context");
        goto error;
    }
    for(type=0;type<OWP_PKT_TYPE_NUM;type++){
        stats->isctx[type] = 0;
    }
    stats->endnum = stats->hdr->test_spec.start_time;

    /*
     * pre-allocate packet records. Generally, the packet rate and the
     * loss-timeout can be used to determine how many packet records
     * are need. Because the exp distribution could actually produce
     * more packets than the rate allows for in a specific time period
     * a factor is needed to allocate something greater than this amount.
     * If this factor is too small, there will be entries in syslog and
     * it can be increased. (A dynmic allocation will happen in this event.)
     */
    if (hdr->twoway) {
        d = 0.0;
    } else {
#define PACKETBUFFERALLOCFACTOR   3.5
        d = OWPTestPacketRate(stats->ctx,&stats->hdr->test_spec) *
            OWPNum64ToDouble(stats->hdr->test_spec.loss_timeout) *
            PACKETBUFFERALLOCFACTOR;
    }
    if(d > 0x7fffffffL){
        OWPError(stats->ctx,OWPErrDEBUG,OWPErrUNKNOWN,
                "%s: Extreme packet rate (%g) requires excess memory usage",d);
        stats->plistlen = 0x7fffffffL;
    }
    else{
        stats->plistlen = d;
    }
    stats->plistlen = MAX(stats->plistlen,10); /* never alloc less than 10 */

    for(type=0;type<OWP_PKT_TYPE_NUM;type++){
        if( !(stats->pallocated[type] = calloc(stats->plistlen,sizeof(OWPPacketRec)))){
                OWPError(stats->ctx,OWPErrFATAL,errno,
                        "%s: calloc(%lu,OWPPacketRec): %M",func,stats->plistlen);
                goto error;
        }

        /*
         * Packet buffer hash table
         */
        if( !(stats->ptable[type] = I2HashInit(OWPContextErrHandle(stats->ctx),
                        stats->plistlen,NULL,NULL))){
            OWPError(stats->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                    "%s: Unable to allocate PacketRec hash");
            goto error;
        }

        /*
         * [0] is used to track the list of allocated arrays so they can
         * be freed. (So, only index 1 and above from each array are actually
         * used.)
         * This loop takes each one of those nodes and puts them in the freelist.
         */
        for(i=1; i<stats->plistlen; i++){
            stats->pallocated[type][i].next = stats->pfreelist[type];
            stats->pfreelist[type] = &stats->pallocated[type][i];
        }
    }

    /*
     * pre-allocate bucket records. Generally, the bucket width can
     * be used to estimate a reasonable number of buckets.
     *
     * The number of buckets needed is bounded by the loss timeout.
     *
     * XXX: It is further bounded by MIN_BUCKETS and MAX_BUCKETS. These
     * constants can be adjusted or even removed...)
     *
     */
#define MIN_BUCKETS 10
#define MAX_BUCKETS 2048
    assert(bucketwidth > 0.0);
    stats->bucketwidth = bucketwidth;
    d = stats->hdr->test_spec.loss_timeout / stats->bucketwidth;
    if(d > 0x7fffffffL){
        stats->blistlen = 0x7fffffffL;
    }
    else{
        stats->blistlen = d;
    }
    stats->blistlen = MAX(stats->blistlen,MIN_BUCKETS); /* never less than */
    stats->blistlen = MIN(stats->blistlen,MAX_BUCKETS); /* never more than */
    if( !(stats->ballocated = calloc(stats->blistlen,sizeof(OWPBucketRec)))){
            OWPError(stats->ctx,OWPErrFATAL,errno,
                    "%s: calloc(%lu,OWPBucketRec): %M",func,stats->blistlen);
            goto error;
    }

    /*
     * Bucket hash table
     */
    if( !(stats->btable = I2HashInit(OWPContextErrHandle(stats->ctx),
                    stats->blistlen,NULL,NULL))){
        OWPError(stats->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                "%s: Unable to allocate BucketRec hash");
        goto error;
    }

    /*
     * [0] is used to track the list of allocated arrays so they can
     * be freed. (So, only index 1 and above from each array are actually
     * used.)
     * This loop takes each one of those nodes and puts them in the freelist.
     */
    for(i=1; i<stats->blistlen; i++){
        stats->ballocated[i].next = stats->bfreelist;
        stats->bfreelist = &stats->ballocated[i];
    }

    /*
     * reordering buffers
     * (Not supported for TWAMP)
     */
    if(!stats->hdr->twoway){
        stats->rlistlen = stats->plistlen;
        if( !(stats->rseqno = calloc(stats->rlistlen,sizeof(uint32_t)))){
                OWPError(stats->ctx,OWPErrFATAL,errno,
                        "%s: calloc(%lu,uint32_t): %M",func,stats->rlistlen);
                goto error;
        }
        if( !(stats->rn = calloc(stats->rlistlen,sizeof(uint32_t)))){
                OWPError(stats->ctx,OWPErrFATAL,errno,
                        "%s: calloc(%lu,uint32_t): %M",func,stats->rlistlen);
                goto error;
        }
    }

    return stats;

error:
    OWPStatsFree(stats);

    return NULL;
}

static OWPBoolean
PacketBeginFlush(
        OWPStats        stats,
        OWPPacketType   type
        )
{
    OWPPacket   node = stats->pbegin[type];
    OWPBoolean  keep_parsing = True;

    if(!node){
        OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                "PacketBeginFlush: type %u begin node empty?",type);
        return False;
    }

    /*
     * Move begin skip to next skip if needed (based on node->seq).
     */
    while(stats->skips && (stats->iskip < (long int)stats->hdr->num_skiprecs) &&
            (node->seq > stats->skips[stats->iskip].end)){
        stats->iskip++;
    }

    /*
     * Check if in "skip" range. If so, then skip aggregation information
     * and flush the packet. (iskip has been forwarded to guarentee the
     * first skip range is the only possible match.)
     */
    if(stats->skips && (stats->iskip < (long int)stats->hdr->num_skiprecs) &&
            (node->seq >= stats->skips[stats->iskip].begin)){
        goto flush;
    }

    /*
     * Loss and Dup Stats Happen Here
     */
    if(node->lost){
        /* count lost packets */
        stats->lost++;
        assert(type != TWP_BCK_PKTS);
    }
    else if(node->seen){
        /* count dups */
        stats->dups[type] += (node->seen - 1);
    }

flush:

    /* Retain the last scheduled timestamp */
    stats->end_time = node->schedtime;

    if(node->next){
        stats->pbegin[type] = node->next;
    }
    else if((node->seq+1) < stats->last){
        stats->pbegin[type] = PacketGet(stats,node->seq+1,type);
    }
    else{
        keep_parsing = False;
    }

    PacketFree(stats,node);

    return keep_parsing;
}

static int
IterateSummarizeSession(
        OWPDataRec  *rec,
        void        *cdata
        )
{
    OWPStats    stats = cdata;
    OWPPacket   node;
    double      d;
    double      derr;
    long int    i;

    /*
     * Mark the first offset that has a seq greater than currently
     * interested in. This allows the caller to know what offset to
     * use for the "beginning" of the next summary.
     */
    if(!stats->next_oset && (rec->seq_no >= stats->last)){
        stats->next_oset = stats->begin_oset + stats->i * stats->hdr->rec_size;
    }

    /* increase file index */
    stats->i++;

    /*
     * return (cont processing) if this record is not part of this sum-session
     *
     * XXX: This may not be completely correct with respect to reordering...
     * If the first packet of the "next" session takes place before the
     * last packet of the "previous" session - should reordering be counted?
     *
     */ 
    if((rec->seq_no < stats->first) || (rec->seq_no >= stats->last)){
        return 0;
    }

    /*
     * Flush OWPPacket buffer before dealing with this packet so the buffer
     * only holds as many records as is needed.
     *
     */
    if(OWPIsLostRecord(rec)){
        /*
         * if current rec is lost, then all seq nums less than this one
         * can be flushed.
         */
        while(stats->pbegin[OWP_PKTS]->seq < rec->seq_no){
            if(!PacketBeginFlush(stats,OWP_PKTS)){
                OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                         "IterateSummarizeSession: Unable to flush lost packets");
                return -1;
            }
        }
    }else{
        /*
         * If this packet is not lost, then compute recv-lossThresh
         * and flush all packets with "sent" before this time.
         */
        OWPNum64    thresh = OWPNum64Sub(rec->recv.owptime,
                stats->hdr->test_spec.loss_timeout);

        while(OWPNum64Cmp(stats->pbegin[OWP_PKTS]->schedtime,thresh) < 0){
            if(!PacketBeginFlush(stats,OWP_PKTS)){
                OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                         "IterateSummarizeSession: Unable to flush packets");
                return -1;
            }
        }
    }

    /*
     * Fetch current packet record
     */
    if( !(node = PacketGet(stats,rec->seq_no,OWP_PKTS))){
        OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                "IterateSummarizeSession: Unable to fetch packet #%lu",
                rec->seq_no);
        return -1;
    }

    // TODO - probably shouldn't be here?
    if (stats->is_json_format)
    {
        cJSON * report = cJSON_CreateObject();
        // TODO
        cJSON_AddNumberToObject(report, "ip-ttl", rec->ttl);
        cJSON_AddNumberToObject(report, "seq-num", rec->seq_no);

        cJSON_AddNumberToObject(report, "dst-clock-err-multiplier", rec->send.multiplier);
        cJSON_AddNumberToObject(report, "dst-clock-err-scale", rec->send.scale);
        cJSON_AddBoolToObject(report, "dst-clock-sync", rec->send.sync);
        cJSON_AddNumberToObject(report, "dst-clock-err", OWPGetTimeStampError(&rec->send));
        cJSON_AddNumberToObject(report, "dst-ts", rec->send.owptime);

        cJSON_AddNumberToObject(report, "src-clock-err-multiplier", rec->recv.multiplier);
        cJSON_AddNumberToObject(report, "src-clock-err-scale", rec->recv.scale);
        cJSON_AddNumberToObject(report, "src-clock-err", OWPGetTimeStampError(&rec->recv));
        cJSON_AddBoolToObject(report, "src-clock-sync", rec->recv.sync);
        cJSON_AddNumberToObject(report, "src-clock-ts", rec->recv.owptime);

        if (!stats->owp_raw_packets)
        {
            stats->owp_raw_packets = cJSON_CreateArray();
        }
        if (!stats->owp_histogram_ttl_json)
        {
            stats->owp_histogram_ttl_json = cJSON_CreateArray();
        }
        if (!stats->owp_histogram_latency_json)
        {
            stats->owp_histogram_latency_json = cJSON_CreateArray();
        }
        if (!stats->results)
        {
            stats->results = cJSON_CreateArray();
        }
        cJSON_AddItemToArray(stats->owp_raw_packets, report);

        //char * str = cJSON_Print(stats->owp_raw_packets);
        //printf("report: %s", str);
    }

    /*
     * Check if in "skip" range. If so, then skip aggregation information
     * for this record.
     */
    i = stats->iskip;
    while(stats->skips && (i < (long int)stats->hdr->num_skiprecs)){
        if((node->seq >= stats->skips[i].begin) &&
                (node->seq <= stats->skips[i].end)){
            return 0;
        }
        i++;
    }

    if( OWPIsLostRecord(rec)){
        /*
         * If this has been seen before, then we have a problem.
         */
        if(node->seen){
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                    "IterateSummarizeSession: Unexpected lost packet record");
            return -1;
        }
        node->lost = True;
        stats->sent++;

        /* sync */
        if(!rec->recv.sync){
            stats->sync = 0;
        }

        /*
         * Time error
         */
        derr = OWPGetTimeStampError(&rec->recv);
        stats->maxerr[OWP_DELAY] = MAX(stats->maxerr[OWP_DELAY],derr);

        if(stats->output){
            fprintf(stats->output,"seq_no=%-10u *LOST*\n", rec->seq_no);
        }

        return 0;
    }
    else{
        /*
         * If this has already been declared lost, we have a problem.
         */
        if(node->lost){
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                    "IterateSummarizeSession: Unexpected duplicate packet record (for lost one)");
            return -1;
        }

        if(!node->seen){
            stats->sent++;
        }
        node->seen++;
    }

    /*
     * j-reordering. See:
     * http://www.internet2.edu/~shalunov/ippm/\
     *                          draft-shalunov-reordering-definition-02.txt
     */
#define rseqindex(x)    ((x) >= 0? x: x + stats->rlistlen)
    for(i=0;i < MIN(stats->rnumseqno,stats->rlistlen) &&
            rec->seq_no < stats->rseqno[rseqindex(stats->rindex-i-1)];i++){
        stats->rn[i]++;
    }
    stats->rseqno[stats->rindex] = rec->seq_no;
    stats->rnumseqno++;
    stats->rindex++;
    stats->rindex %= stats->rlistlen;
#undef rseqindex

    /* sync */
    if(!rec->send.sync || !rec->recv.sync){
        stats->sync = 0;
    }

    /*
     * compute delay for this packet
     */
    d = OWPDelay(&rec->send, &rec->recv);

    /*
     * compute total error from send/recv
     */
    derr = OWPGetTimeStampError(&rec->send) + OWPGetTimeStampError(&rec->recv);
    stats->maxerr[OWP_DELAY] = MAX(stats->maxerr[OWP_DELAY],derr);

    /*
     * Print individual packet record
     */
    if(stats->output){
        if(rec->send.sync && rec->recv.sync){
	  if (stats->display_unix_ts == True) {
	    /* print using unix timestamp */
	    double epochdiff = (OWPULongToNum64(OWPJAN_1970))>>32;
	    fprintf(stats->output,
		    "seq_no=%d delay=%e %s (sync, err=%.3g %s) sent=%f recv=%f\n",
		    rec->seq_no, d*stats->scale_factor, stats->scale_abrv,
		    derr*stats->scale_factor, stats->scale_abrv,
		    OWPNum64ToDouble(rec->send.owptime) - epochdiff,
		    OWPNum64ToDouble(rec->recv.owptime) - epochdiff
		    );
	  } 
	  else {
	    /* print the default */
	    fprintf(stats->output,
		    "seq_no=%-10u delay=%.3g %s\t(sync, err=%.3g %s)\n",
		    rec->seq_no, d*stats->scale_factor, stats->scale_abrv,
		    derr*stats->scale_factor,stats->scale_abrv);
	  }
        }
        else{
            fprintf(stats->output,
                    "seq_no=%-10u delay=%.3g %s\t(unsync)\n",
                    rec->seq_no, d*stats->scale_factor,stats->scale_abrv);
        }
    }

    /*
     * Save max/min delays
     */
    stats->min_delay[OWP_DELAY] = MIN(stats->min_delay[OWP_DELAY],d);
    stats->max_delay[OWP_DELAY] = MAX(stats->max_delay[OWP_DELAY],d);

    /*
     * Delay and TTL stats not computed on duplicates
     */
    if(node->seen > 1){
        return 0;
    }

    /*
     * Increment histogram for this delay
     */
    if( !BucketIncrementDelay(stats,d,OWP_DELAY)){
        /* error return */
        OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                "IterateSummarizeSession: Unable to increment delay bucket");
        return -1;
    }

    /*
     * TTL info
     */
    stats->ttl_count[OWP_TTL][rec->ttl]++;

    return 0;
}


static int
IterateSummarizeTWSession(
        OWPTWDataRec *rec,
        void        *cdata
        )
{
    OWPStats    stats = cdata;
    OWPPacket   node[OWP_PKT_TYPE_NUM];
    double      delay[OWP_DELAY_TYPE_NUM_INC_PROC];
    double      delay_err[OWP_DELAY_TYPE_NUM];
    double      derr;
    long int    i;

    /*
     * Mark the first offset that has a seq greater than currently
     * interested in. This allows the caller to know what offset to
     * use for the "beginning" of the next summary.
     */
    if(!stats->next_oset && (rec->sent.seq_no >= stats->last)){
        stats->next_oset = stats->begin_oset + stats->i * stats->hdr->rec_size;
    }

    /* increase file index */
    stats->i++;

    /*
     * return (cont processing) if this record is not part of this sum-session
     *
     * XXX: This may not be completely correct with respect to reordering...
     * If the first packet of the "next" session takes place before the
     * last packet of the "previous" session - should reordering be counted?
     *
     */
    if((rec->sent.seq_no < stats->first) || (rec->sent.seq_no >= stats->last)){
        return 0;
    }

    /*
     * Flush OWPPacket buffer before dealing with this packet so the buffer
     * only holds as many records as is needed.
     *
     */
    if(OWPIsLostRecord(&rec->sent)){
        /*
         * if current rec is lost, then all seq nums less than this one
         * can be flushed.
         */
        while(stats->pbegin[TWP_FWD_PKTS]->seq < rec->sent.seq_no){
            if(!PacketBeginFlush(stats,TWP_FWD_PKTS)){
                OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                         "IterateTWSummarizeSession: Unable to flush lost send packets");
                return -1;
            }
        }
    }else{
        /*
         * If this packet is not lost, then compute recv-lossThresh
         * and flush all packets with "sent" before this time.
         */
        OWPNum64    thresh = OWPNum64Sub(rec->sent.send.owptime,
                stats->hdr->test_spec.loss_timeout);

        while(OWPNum64Cmp(stats->pbegin[TWP_FWD_PKTS]->schedtime,thresh) < 0){
            if(!PacketBeginFlush(stats,TWP_FWD_PKTS)){
                OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                         "IterateTWSummarizeSession: Unable to flush send packets");
                return -1;
            }
        }
    }

    /*
     * Flush all reflect packets where the associated send packet has
     * already been flushed. This ensures that the reflect packet buffer
     * stays in sync with the send packet buffer.
     */
    while(stats->pbegin[TWP_FWD_PKTS]->associated_seq > stats->pbegin[TWP_BCK_PKTS]->seq){
        if(!PacketBeginFlush(stats,TWP_BCK_PKTS)){
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                     "IterateTWSummarizeSession: Unable to flush reflect packets");
            return -1;
        }
    }

    /*
     * Fetch current send packet record
     */
    if( !(node[TWP_FWD_PKTS] = PacketGet(stats,rec->sent.seq_no,TWP_FWD_PKTS))){
        OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                "IterateSummarizeTWSession: Unable to fetch send packet #%lu",
                rec->sent.seq_no);
        return -1;
    }

    if( OWPIsLostRecord(&rec->sent)){
        /*
         * If this has been seen before, then we have a problem.
         */
        if(node[TWP_FWD_PKTS]->seen){
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                    "IterateSummarizeTWSession: Unexpected lost packet record");
            return -1;
        }

        /*
         * Only mark one node as lost otherwise the lost count is
         * double what is expected.
         *
         * Also, the sequence number for a lost reflect record is 0
         * which will conflict with the actual record with sequence
         * number 0.
         */
        node[TWP_FWD_PKTS]->lost = True;
        stats->sent++;

        /* sync */
        if(!rec->sent.recv.sync){
            stats->sync = 0;
        }

        /*
         * Time error
         */
        derr = OWPGetTimeStampError(&rec->sent.recv);
        for(i=0;i<OWP_DELAY_TYPE_NUM;i++){
            stats->maxerr[i] = MAX(stats->maxerr[i],derr);
        }

        if(stats->output){
            fprintf(stats->output,"seq_no=%-10u *LOST*\n", rec->sent.seq_no);
        }

        return 0;
    }
    else{
        /*
         * If this has already been declared lost, we have a problem.
         */
        if(node[TWP_FWD_PKTS]->lost){
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                    "IterateSummarizeTWSession: Unexpected duplicate packet record (for lost one)");
            return -1;
        }

        /* Get current reflect packet record */
        if( !(node[TWP_BCK_PKTS] = PacketGet(stats,rec->reflected.seq_no,TWP_BCK_PKTS))){
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                    "IterateSummarizeTWSession: Unable to fetch reflect packet #%lu",
                    rec->reflected.seq_no);
            return -1;
        }

        /*
         * Store the send sequence number the first time we encounter
         * this reflect sequence number so that we can ensure that the
         * reflect sequence number is only ever associated with one
         * send sequence number
         */
        if(!node[TWP_BCK_PKTS]->seen){
            node[TWP_BCK_PKTS]->associated_seq = rec->sent.seq_no;
        }
        /*
         * If this reflect sequence number has been seen before
         * but associated with different send sequence numbers then
         * there is a problem
         */
        else if(node[TWP_BCK_PKTS]->associated_seq != rec->sent.seq_no){
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                    "IterateSummarizeTWSession: Reflect sequence number associated with multiple send sequence numbers");
            return -1;
        }
        node[TWP_BCK_PKTS]->seen++;

        /*
         * Record a sent packet for each unseen forward packet.
         * Store the reflect sequence number so that send duplicates
         * can be differentiated from reflect duplicates
         */
        if(!node[TWP_FWD_PKTS]->seen){
            stats->sent++;
            node[TWP_FWD_PKTS]->seen++;
            node[TWP_FWD_PKTS]->associated_seq = rec->reflected.seq_no;
        }
        /*
         * The reflect sequence number of a send duplicate is different
         * since it is reflected multiple times.
         *
         * If the reflect sequence number is different to that of the
         * first record for this send sequence number and if this is
         * the first time we have seen this reflect sequence number
         * then this record represents a send duplicate
         */
        else if(node[TWP_FWD_PKTS]->associated_seq != rec->reflected.seq_no &&
           node[TWP_BCK_PKTS]->seen == 1){
            node[TWP_FWD_PKTS]->seen++;
        }
    }

    /*
     * compute processing delay on far end
     */
    delay[TWP_PROC_DELAY] = OWPDelay(&rec->sent.recv, &rec->reflected.send);
    /*
     * compute best possible estimate for network round-trip time for this packet
     */
    delay[OWP_DELAY] = OWPDelay(&rec->sent.send, &rec->reflected.recv) - delay[TWP_PROC_DELAY];

    /*
     * compute the sending delay for this packet
     */
    delay[TWP_FWD_DELAY] = OWPDelay(&rec->sent.send, &rec->sent.recv);

    /*
     * compute the reflection delay for this packet
     */
    delay[TWP_BCK_DELAY] = OWPDelay(&rec->reflected.send, &rec->reflected.recv);

    /*
     * compute total error from send/recv.
     */
    delay_err[OWP_DELAY] = OWPGetTimeStampError(&rec->sent.send) +
        OWPGetTimeStampError(&rec->reflected.recv) +
        OWPGetTimeStampError(&rec->reflected.send) +
        OWPGetTimeStampError(&rec->sent.recv);

    /*
     * compute the send delay error
     */
    delay_err[TWP_FWD_DELAY] = OWPGetTimeStampError(&rec->sent.send) +
        OWPGetTimeStampError(&rec->sent.recv);

    /*
     * compute the reflection delay error
     */
    delay_err[TWP_BCK_DELAY] = OWPGetTimeStampError(&rec->reflected.send) +
        OWPGetTimeStampError(&rec->reflected.recv);

    /*
     * Local and remote clocks are out of sync if the delays are negative
     */
    if(delay[TWP_FWD_DELAY] < 0 || delay[TWP_BCK_DELAY] < 0){
        stats->clocks_offset = True;
    }

    /*
     * Print individual packet record
     */
    if(stats->output){
        if (stats->display_unix_ts == True) {
            /* print using unix timestamp */
            double epochdiff = (OWPULongToNum64(OWPJAN_1970))>>32;
            fprintf(stats->output,
                    "seq_no=%d fwd_delay=%e %s bck_delay=%e %s delay=%e %s proc_delay=%e %s (err=%.3g %s) sent=%f recv=%f reflected=%f recv=%f\n",
                    rec->sent.seq_no,
                    delay[TWP_FWD_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay[TWP_BCK_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay[OWP_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay[TWP_PROC_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay_err[OWP_DELAY]*stats->scale_factor, stats->scale_abrv,
                    OWPNum64ToDouble(rec->sent.send.owptime) - epochdiff,
                    OWPNum64ToDouble(rec->sent.recv.owptime) - epochdiff,
                    OWPNum64ToDouble(rec->reflected.send.owptime) - epochdiff,
                    OWPNum64ToDouble(rec->reflected.recv.owptime) - epochdiff
                );
        }
        else {
            /* print the default */
            fprintf(stats->output,
                    "seq_no=%-10u fwd_delay=%.3g %s bck_delay=%.3g %s delay=%.3g %s proc_delay=%.3g %s\t(err=%.3g %s)\n",
                    rec->sent.seq_no,
                    delay[TWP_FWD_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay[TWP_BCK_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay[OWP_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay[TWP_PROC_DELAY]*stats->scale_factor, stats->scale_abrv,
                    delay_err[OWP_DELAY]*stats->scale_factor, stats->scale_abrv);
        }
    }

    /*
     * Save max/min delays
     */
    for(i=0;i<OWP_DELAY_TYPE_NUM_INC_PROC;i++){
        stats->min_delay[i] = MIN(stats->min_delay[i],delay[i]);
        stats->max_delay[i] = MAX(stats->max_delay[i],delay[i]);
    }

    for(i=0;i<OWP_DELAY_TYPE_NUM;i++){
        stats->maxerr[i] = MAX(stats->maxerr[i],delay_err[i]);
    }

    /*
     * Delay and TTL stats not computed on duplicates
     */
    if(node[TWP_FWD_PKTS]->seen > 1 || node[TWP_BCK_PKTS]->seen > 1){
        return 0;
    }

    /*
     * Increment histogram for this delay
     */
    for(i=0;i<OWP_DELAY_TYPE_NUM;i++){
        if( !BucketIncrementDelay(stats,delay[i],i)){
            /* error return */
            OWPError(stats->ctx,OWPErrFATAL,EINVAL,
                    "IterateSummarizeTWSession: Unable to increment delay type %l bucket",i);
            return -1;
        }
    }

    /*
     * TTL info
     */
    stats->ttl_count[TWP_FWD_TTL][rec->sent.ttl]++;
    stats->ttl_count[TWP_BCK_TTL][rec->reflected.ttl]++;

    return 0;
}

static void
PrintStatsHeader(
        OWPStats    stats,
        FILE        *output
        )
{
    char        sid_name[sizeof(OWPSID)*2+1];

    if(!output)
        return;

    fprintf(output,"\n--- %s statistics from [%s]:%s to [%s]:%s ---\n",
            stats->hdr->twoway ? "twping" : "owping",
            stats->fromhost,stats->fromserv,stats->tohost,stats->toserv);
    I2HexEncode(sid_name,stats->hdr->sid,sizeof(OWPSID));
    fprintf(output,"SID:\t%s\n",sid_name);

    return;
}

static int
BucketBufferSortCmp(
        const void *bp1,
        const void *bp2)
{
    OWPBucket   b1 = *(OWPBucket *)bp1;
    OWPBucket   b2 = *(OWPBucket *)bp2;

    return (b1->b - b2->b);
}

static OWPBoolean
BucketBufferSortPercentile(
        OWPStats        stats,
        double          alpha,
        double          *delay_ret,
        OWPDelayType    type
        )
{
    uint32_t    i;
    double      sum=0;

    assert((0.0 <= alpha) && (alpha <= 1.0));

    /* Not supported for the processing delay */
    assert(type < OWP_DELAY_TYPE_NUM);

    for(i=0;
            (i < stats->bsortsize) &&
            ((stats->bsort[i]->delay_samples[type] + sum) < (alpha * stats->sent));
            i++){
        sum += stats->bsort[i]->delay_samples[type];
    }

    if(i >= stats->bsortsize){
        return False;
    }

    *delay_ret = stats->bsort[i]->b * stats->bucketwidth;
    return True;
}

OWPBoolean
OWPStatsParse(
        OWPStats    stats,
        FILE        *output,
        off_t       begin_oset,
        uint32_t    first,
        uint32_t    last
        )
{
    off_t       fileend;
    uint32_t    nrecs;
    long int    i;
    uint8_t     type;

    if(last == (uint32_t)~0){
        last = stats->hdr->test_spec.npackets;
    }
    if((first > last) || (last > stats->hdr->test_spec.npackets)){
        OWPError(stats->ctx,OWPErrFATAL,OWPErrINVALID,
                "OWPStatsParse: Invalid sample range [%lu,%lu]",first,last);
        return False;
    }

    stats->begin_oset = begin_oset;
    stats->next_oset = 0;
    stats->first = first;
    stats->last = last;
    stats->iskip = 0;
    stats->sent = 0;

    /*
     * Initialize file record information: oset's/ record index/ nrecs
     */

    stats->i = 0;

    /*
     * determine end of packet records in file.
     */
    if(stats->hdr->oset_skiprecs > stats->hdr->oset_datarecs){
        fileend = stats->hdr->oset_skiprecs;
    }
    else{
        if(fseeko(stats->fp,0,SEEK_END) != 0){
            OWPError(stats->ctx,OWPErrFATAL,errno,
                    "OWPStatsParse: fseeko(): %M");
            return False;
        }
        if((fileend = ftello(stats->fp)) < 0){
            OWPError(stats->ctx,OWPErrFATAL,errno,
                    "OWPStatsParse: ftello(): %M");
            return False;
        }
    }

    /* determine position of first record */
    if(stats->begin_oset < stats->hdr->oset_datarecs){
        stats->begin_oset = stats->hdr->oset_datarecs;
    }

    /* position fp to start */
    if(fseeko(stats->fp,stats->begin_oset,SEEK_SET) != 0){
        OWPError(stats->ctx,OWPErrFATAL,errno,
                "OWPStatsParse: fseeko(): %M");
        return False;
    }

    /* determine how many records to look through */
    nrecs = (fileend - stats->begin_oset) / stats->hdr->rec_size;

    if ((stats->rec_limit > 0) && (stats->rec_limit < nrecs))
      nrecs = stats->rec_limit;

    /*
     * Initialize statistics variables
     */

    /* Schedule information: advance sctx to appropriate value */
    if( !first || (first < stats->isctx[OWP_PKTS])){
        OWPScheduleContextReset(stats->sctx,NULL,NULL);
        stats->isctx[OWP_PKTS] = 0;
        stats->endnum = stats->hdr->test_spec.start_time;
    }
    while(stats->isctx[OWP_PKTS] <= first){
        stats->endnum = OWPNum64Add(stats->endnum,
                OWPScheduleContextGenerateNextDelta(stats->sctx));
        stats->isctx[OWP_PKTS]++;
    }
    stats->isctx[TWP_BCK_PKTS] = stats->isctx[OWP_PKTS];
    stats->start_time = stats->endnum;

    /*
     * PacketBuffer stuff (used for dups,lost)
     * First clear out any existing data from the packet buffer, then
     * initialize with first record needed.
     */

    for(type=0;type<OWP_PKT_TYPE_NUM;type++){
        /* clean up */
        I2HashIterate(stats->ptable[type],PacketBufferClean,stats);

        /* alloc first node */
        stats->pbegin[type] = stats->pend[type] = PacketAlloc(stats,first,type);

        /*
         * update sctx/isctx to approprate place
         */

        /* initialize first node with appropriate sched time */
        stats->pbegin[type]->schedtime = stats->endnum;

        /* dups per packet type */
        stats->dups[type] = 0;
    }

    /*
     *
     * Clear btable
     *  iterate with BucketBufferClean
     *
     * init stats (min/max/ttl stuff)
     */

    /* clean up */
    I2HashIterate(stats->btable,BucketBufferClean,stats);

    /* ttl */
    for(type=0;type<OWP_TTL_TYPE_NUM;type++){
        for(i=0;i<256;i++)
            stats->ttl_count[type][i] = 0;
    }

    /* re-order buffers
     * (Not supported for TWAMP)
     */
    if(!stats->hdr->twoway){
        for(i=0;i<stats->rlistlen;i++){
            stats->rseqno[i]=0;
            stats->rn[i]=0;
        }
    }

    /* init min_delay to +inf, max_delay to -inf */
    stats->inf_delay = OWPNum64ToDouble(stats->hdr->test_spec.loss_timeout + 1);
    for(i=0;i<OWP_DELAY_TYPE_NUM_INC_PROC;i++){
        stats->min_delay[i] = stats->inf_delay;
        stats->max_delay[i] = -stats->inf_delay;
    }
    stats->clocks_offset = False;

    /* timestamp quality */
    stats->sync = 1;
    for(i=0;i<OWP_DELAY_TYPE_NUM;i++){
        stats->maxerr[i] = 0.0;
    }

    /* lost */
    stats->lost = 0;

    /*
     * Iterate function to read all data
     */
    PrintStatsHeader(stats,output);
    stats->output = output;
    if (stats->hdr->twoway) {
        if(OWPParseTWRecords(stats->ctx,stats->fp,nrecs,stats->hdr->version,
                             IterateSummarizeTWSession,(void*)stats) != OWPErrOK){
            OWPError(stats->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                     "OWPStatsParse: iteration of twoway data records failed");
            stats->output = NULL;
            return False;
        }
    } else {
        if(OWPParseRecords(stats->ctx,stats->fp,nrecs,stats->hdr->version,
                           IterateSummarizeSession,(void*)stats) != OWPErrOK){
            OWPError(stats->ctx,OWPErrFATAL,OWPErrUNKNOWN,
                     "OWPStatsParse: iteration of data records failed");
            stats->output = NULL;
            return False;
        }
    }
    stats->output = NULL;

    /*
     * Process remaining buffered packet records
     */
    for(type=0;type<OWP_PKT_TYPE_NUM;type++){
        while(stats->pbegin[type] && PacketBeginFlush(stats,type));
    }

    /*
     * Sort Delay histogram
     */

    /* alloc sort array */
    stats->bsortsize = I2HashNumEntries(stats->btable);
    if(stats->bsortlen < stats->bsortsize){
        OWPBucket   *tbp;
        if( (tbp = realloc(stats->bsort,sizeof(OWPBucket)*stats->bsortsize))){
            stats->bsortlen = stats->bsortsize;
            stats->bsort = tbp;
        }
        else{
            OWPError(stats->ctx,OWPErrFATAL,errno,
                    "OWPStatsParse: allocating memory for sort array: %M");
            return False;
        }
    }

    /* fill sort array with entries */
    stats->bsorti = 0;
    I2HashIterate(stats->btable,BucketBufferSortFill,stats);
    assert(stats->bsorti == stats->bsortsize);

    /* sort */
    qsort(stats->bsort,stats->bsortsize,sizeof(OWPBucket),BucketBufferSortCmp);

    /*
     * Stats structure now holds complete statistics information
     */

    return True;
}

/*
 * Return the correct scale factor to use for the given scale indication.
 * The abbreviation used for this scale is returned, if abrv is non-null
 * and *abrv_len is long enough.
 *
 * Returns 0.0 on error.
 */
float
OWPStatsScaleFactor(
        char    scale,
        char    *abrv,
        size_t  *abrv_len)
{
    double  factor = 1.0;

    /* 3 (2 char abrv and nul byte) */
    if(abrv && abrv_len && (*abrv_len >= 3)){
        *abrv_len = 2;
    }
    else{
        abrv = NULL;
    }

    switch(tolower(scale)){
        case 'n':
            factor *= 1000000000; /* 1e-9 */
            if(abrv) strcpy(abrv,"ns");
            break;
        case 'u':
            factor *= 1000000; /* 1e-6 */
            if(abrv) strcpy(abrv,"us");
            break;
        case 'm':
            factor *= 1000; /* 1e-3 */
            if(abrv) strcpy(abrv,"ms");
        case 's':
            break;
        default:
            if(abrv_len){
                *abrv_len = 0;
            }
            return 0.0;
    }

    return factor;
}

static void
PrintDelayStats(
        OWPStats        stats,
        FILE            *output,
        OWPDelayType    type
        )
{
    char            minval[80];
    char            maxval[80];
    char            n1val[80];
    char            *delaydesc;
    double          d1;

    /*
     * Min, Max, Median
     */

    /*
     * parse min/max - Sure would be easier if C99 soft-float were portable...
     * XXX: Just use NAN as the float value once that works everywhere!
     *      (BucketBufferSortPercentile would be WAY easier!!!)
     */
    if(stats->min_delay[type] >= stats->inf_delay){
        strncpy(minval,"nan",sizeof(minval));
    }
    else if( (snprintf(minval,sizeof(minval),"%.3g",
                    stats->min_delay[type] * stats->scale_factor) < 0)){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: snprintf(): %M");
        strncpy(minval,"XXX",sizeof(minval));
    }
    if(stats->max_delay[type] <= -stats->inf_delay){
        strncpy(maxval,"nan",sizeof(maxval));
    }
    else if( (snprintf(maxval,sizeof(maxval),"%.3g",
                    stats->max_delay[type] * stats->scale_factor) < 0)){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: snprintf(): %M");
        strncpy(maxval,"XXX",sizeof(maxval));
    }

    /* Delay type description */
    switch(type){
        case OWP_DELAY:
            delaydesc = stats->hdr->twoway ? "round-trip time" : "one-way delay";
            break;
        case TWP_FWD_DELAY:
            delaydesc = "send time";
            break;
        case TWP_BCK_DELAY:
            delaydesc = "reflect time";
            break;
        case TWP_PROC_DELAY:
            delaydesc = "reflector processing time";
            break;
        default:
            return;
    }

    /* Print delay statistics */
    switch(type){
        case OWP_DELAY:
        case TWP_FWD_DELAY:
        case TWP_BCK_DELAY:
            /* Calculate the median delay for these types */
            if( !BucketBufferSortPercentile(stats,0.5,&d1,type)){
                strncpy(n1val,"nan",sizeof(n1val));
            }
            else if(snprintf(n1val,sizeof(n1val),"%.3g",
                              (d1 * stats->scale_factor)) < 0){
                OWPError(stats->ctx,OWPErrWARNING,errno,
                            "OWPStatsPrintSummary: snprintf(): %M");
                strncpy(n1val,"XXX",sizeof(n1val));
            }

            fprintf(output,"%s min/median/max = %s/%s/%s %s, ",
                    delaydesc,minval,n1val,maxval,stats->scale_abrv);

            if(stats->sync){
                fprintf(output,"(err=%.3g %s)\n",
                        stats->maxerr[type] * stats->scale_factor,
                        stats->scale_abrv);
            }
            else{
                fprintf(output,"(unsync)\n");
            }
            break;
        case TWP_PROC_DELAY:
            fprintf(output,"%s min/max = %s/%s %s\n",
                    delaydesc,minval,maxval,stats->scale_abrv);
            break;
    }
}

static OWPBoolean
CalculateJitter(
        OWPStats        stats,
        OWPDelayType    type,
        double          *jitter_ret
        )
{
    double pc95,pc50;

    if( !BucketBufferSortPercentile(stats,0.95,&pc95,type) ||
        !BucketBufferSortPercentile(stats,0.5,&pc50,type)){
        return False;
    }

    *jitter_ret = pc95-pc50;
    return True;
}

static void
PrintJitterStats(
        OWPStats        stats,
        FILE            *output,
        OWPDelayType    type
        )
{
    char            n1val[80];
    char            *jitterdesc;
    double          jitter;

    if( !CalculateJitter(stats,type,&jitter)){
        strncpy(n1val,"nan",sizeof(n1val));
    }
    else if(snprintf(n1val,sizeof(n1val),"%.3g",
                      jitter * stats->scale_factor) < 0){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: snprintf(): %M");
        strncpy(n1val,"XXX",sizeof(n1val));
    }

    switch(type){
        case OWP_DELAY:
            jitterdesc = stats->hdr->twoway ? "two-way" : "one-way";
            break;
        case TWP_FWD_DELAY:
            jitterdesc = "send";
            break;
        case TWP_BCK_DELAY:
            jitterdesc = "reflect";
            break;
        default:
            return;
    }
    fprintf(output,"%s jitter = %s %s (P95-P50)\n",
            jitterdesc,n1val,stats->scale_abrv);
}

static int
CalculateTtlStats(
        OWPStats    stats,
        OWPTtlType  type,
        uint8_t     *min_ttl,
        uint8_t     *max_ttl
        )
{
    uint8_t ttl_num=0;
    uint16_t i;

    *min_ttl=255;
    *max_ttl=0;

    for(i=0;i<256;i++){
        if(!stats->ttl_count[type][i])
            continue;
        ttl_num++;
        if(i < *min_ttl)
            *min_ttl = i;
        if(i > *max_ttl)
            *max_ttl = i;
    }

    return ttl_num;
}

static void
PrintTtlStats(
        OWPStats    stats,
        FILE        *output,
        OWPTtlType  type
        )
{
    uint8_t ttl_num;
    uint8_t min_ttl;
    uint8_t max_ttl;
    char    *ttl_desc;

    ttl_num = CalculateTtlStats(stats, type, &min_ttl, &max_ttl);

    switch(type){
        case OWP_TTL:
            ttl_desc = stats->hdr->twoway ? "send " : "";
            break;
        case TWP_BCK_TTL:
            ttl_desc = "reflect ";
            break;
    }

    if(ttl_num < 1){
        fprintf(output,"%sTTL not reported\n", ttl_desc);
    }
    else if(ttl_num == 1){
        fprintf(output,"%shops = %d (consistently)\n",ttl_desc,255-min_ttl);
    }
    else{
        fprintf(output,"%shops takes %d values; min hops = %d, max hops = %d\n",
                ttl_desc,ttl_num,255-max_ttl,255-min_ttl);
    }
}

/*
 * Human-readable statistics summary
 */
OWPBoolean
OWPStatsPrintSummary(
        OWPStats    stats,
        FILE        *output,
        float       *percentiles,
        uint32_t   npercentiles
        )
{
    long int        i;
    uint32_t        ui;
    char            n1val[80];
    double          d1;
    struct timespec sspec;
    struct timespec espec;
    struct timespec *sspecp,*especp;
    struct tm       stm,etm;
    struct tm       *stmp,*etmp;
    char            stval[50],etval[50];
    OWPTimeStamp    ttstamp;

    /*
     * If local and remote clocks are offset from each other
     * then the directional delay stats are not meaningful
     */
    if(stats->clocks_offset){
        fprintf(output,"\nDirectional delays may be inaccurate due to out of sync clocks!\n");
    }

    PrintStatsHeader(stats,output);

    /*
     * Print out timerange
     */
    memset(&stm,0,sizeof(stm));
    memset(&etm,0,sizeof(etm));
    memset(&sspec,0,sizeof(sspec));
    memset(&espec,0,sizeof(espec));

    /* set start-time string */
    ttstamp.owptime = stats->start_time;
    if( !(sspecp = OWPTimestampToTimespec(&sspec,&ttstamp))){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: OWPTimestampToTimespec(): Unable to convert time value");
        strncpy(stval,"XXX",sizeof(stval));
    }
    else if( !(stmp = localtime_r(&sspecp->tv_sec,&stm))){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: localtime_r(): Unable to convert time value");
        strncpy(stval,"XXX",sizeof(stval));
    }
    else if( !strftime(stval,sizeof(stval),"%FT%T",stmp)){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: strftime(): Unable to convert time value");
        strncpy(stval,"XXX",sizeof(stval));
    }

    /* set end-time string */
    ttstamp.owptime = stats->end_time;
    if( !(especp = OWPTimestampToTimespec(&espec,&ttstamp))){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: OWPTimestampToTimespec(): Unable to convert time value");
        strncpy(etval,"XXX",sizeof(etval));
    }
    else if( !(etmp = localtime_r(&especp->tv_sec,&etm))){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: localtime_r(): Unable to convert time value");
        strncpy(etval,"XXX",sizeof(etval));
    }
    else if( !strftime(etval,sizeof(etval),"%FT%T",etmp)){
        OWPError(stats->ctx,OWPErrWARNING,errno,
                    "OWPStatsPrintSummary: strftime(): Unable to convert time value");
        strncpy(etval,"XXX",sizeof(etval));
    }

    /*
     * Divide the integer nanoseconds by 1 million to get 3 significant
     * digits of the fractional seconds to the left of the decimal point.
     */
#define MILLION (1000000)
    fprintf(output,"first:\t%s.%03.0f\nlast:\t%s.%03.0f\n",
            stval,((float)sspec.tv_nsec)/MILLION,
            etval,((float)espec.tv_nsec)/MILLION);

    /*
     * lost % is 0 if sent == 0.
     */
    if(stats->sent > 0){
        d1 = (double)stats->lost/stats->sent;
    }
    else{
        d1 = 0.0;
    }
    fprintf(output,"%u sent, %u lost (%.3f%%), ",
                    stats->sent,stats->lost,100.0*d1);
    if(stats->hdr->twoway){
        fprintf(output,"%u send duplicates, %u reflect duplicates\n",
                stats->dups[TWP_FWD_PKTS],stats->dups[TWP_BCK_PKTS]);
    }
    else{
        fprintf(output,"%u duplicates\n",stats->dups[OWP_PKTS]);
    }

    PrintDelayStats(stats,output,OWP_DELAY);
    if(stats->hdr->twoway){
        PrintDelayStats(stats,output,TWP_FWD_DELAY);
        PrintDelayStats(stats,output,TWP_BCK_DELAY);
        PrintDelayStats(stats,output,TWP_PROC_DELAY);
    }

    /*
     * "jitter"
     */
    PrintJitterStats(stats,output,OWP_DELAY);
    if(stats->hdr->twoway){
        PrintJitterStats(stats,output,TWP_FWD_DELAY);
        PrintJitterStats(stats,output,TWP_BCK_DELAY);
    }

    /*
     * Print out random percentiles
     */
    if(npercentiles){
        fprintf(output,"Percentiles:\n");
        for(ui=0;ui<npercentiles;ui++){
            if( !BucketBufferSortPercentile(stats,percentiles[ui]/100.0,&d1,OWP_DELAY)){
                strncpy(n1val,"nan",sizeof(n1val));
            }
            else if(snprintf(n1val,sizeof(n1val),"%.3g",
                        d1 * stats->scale_factor) < 0){
                OWPError(stats->ctx,OWPErrWARNING,errno,
                        "OWPStatsPrintSummary: snprintf(): %M");
                strncpy(n1val,"XXX",sizeof(n1val));
            }
            fprintf(output,"\t%.1f: %s %s\n",
                    percentiles[ui],n1val,stats->scale_abrv);
        }
    }

    /*
     * Report ttl's
     */
    PrintTtlStats(stats,output,OWP_TTL);
    if(stats->hdr->twoway)
        PrintTtlStats(stats,output,TWP_BCK_TTL);

    /*
     * Report j-reordering
     *
     * (Not needed for TWAMP as twping won't allow packets to be
     * re-ordered)
     */
    if(!stats->hdr->twoway){
        for(i=0;((i<stats->rlistlen) && (stats->rn[i]));i++){
            fprintf(output,"%ld-reordering = %f%%\n",i+1,
                    100.0*stats->rn[i]/(stats->rnumseqno));
        }
        if(i==0){
            fprintf(output,"no reordering\n");
        }
        else if(i < stats->rlistlen){
            fprintf(output,"no %ld-reordering\n", i+1);
        }
        else{
            fprintf(output,"%ld-reordering not handled\n",stats->rlistlen+1);
        }
    }

    fprintf(output,"\n");

    return True;
}

static char
*MachineDelayTypeDesc(
        OWPDelayType    type
        )
{
    switch(type){
        case OWP_DELAY:
            return "";
        case TWP_FWD_DELAY:
            return "_FWD";
        case TWP_BCK_DELAY:
            return "_BCK";
        case TWP_PROC_DELAY:
            return "_PROC";
        default:
            return "_UNKNOWN";
    }
}

static inline void
PrintMinDelayMachine(
        OWPStats        stats,
        OWPDelayType    type,
        FILE            *output
        )
{
    if(stats->min_delay[type] < stats->inf_delay){
        fprintf(output,"MIN%s\t%g\n",MachineDelayTypeDesc(type),
                stats->min_delay[type]);
    }
}

static inline void
PrintMinDelayMachineJSON(
        OWPStats        stats,
        OWPDelayType    type,
        FILE            *output
        )
{
    if (!stats->sum_json)
    {
        stats->sum_json = cJSON_CreateObject();
    }
    if(stats->min_delay[type] < stats->inf_delay){
        char name[15];
	snprintf(name, sizeof(name), "MIN%s", MachineDelayTypeDesc(type));
        cJSON_AddNumberToObject(stats->sum_json, name, stats->min_delay[type]);
        //fprintf(output,"MIN%s\t%g\n",MachineDelayTypeDesc(type),
        //        stats->min_delay[type]);
    }
}

static inline void
PrintMaxDelayMachine(
        OWPStats        stats,
        OWPDelayType    type,
        FILE            *output
        )
{
    if(stats->max_delay[type] > -stats->inf_delay){
        fprintf(output,"MAX%s\t%g\n",MachineDelayTypeDesc(type),
                stats->max_delay[type]);
    }
}

static inline void
PrintMaxDelayMachineJSON(
        OWPStats        stats,
        OWPDelayType    type,
        FILE            *output
        )
{
    if (!stats->sum_json)
    {
        stats->sum_json = cJSON_CreateObject();
    }
    if(stats->max_delay[type] > -stats->inf_delay){
        char name[15];
	snprintf(name, sizeof(name), "MAX%s", MachineDelayTypeDesc(type));
        cJSON_AddNumberToObject(stats->sum_json, name, stats->max_delay[type]);
        //fprintf(output,"MAX%s\t%g\n",MachineDelayTypeDesc(type),
        //        stats->max_delay[type]);
    }
}

static inline uint8_t
PrintMinMaxTtlMachine(
        OWPStats    stats,
        FILE        *output,
        OWPTtlType  type
        )
{
    uint8_t     ttl_num;
    uint8_t     min_ttl;
    uint8_t     max_ttl;
    char        *type_desc;

    ttl_num = CalculateTtlStats(stats,type,&min_ttl,&max_ttl);

    switch(type){
        case OWP_TTL:
            type_desc = stats->hdr->twoway ? "_FWD" : "";
            break;
        case TWP_BCK_TTL:
            type_desc = "_BCK";
            break;
    }

    fprintf(output,"MINTTL%s\t%u\n",type_desc,min_ttl);
    fprintf(output,"MAXTTL%s\t%u\n",type_desc,max_ttl);

    return ttl_num;
}

static inline uint8_t
PrintMinMaxTtlMachineJSON(
        OWPStats    stats,
        FILE        *output,
        OWPTtlType  type
        )
{
    uint8_t     ttl_num;
    uint8_t     min_ttl;
    uint8_t     max_ttl;
    char        *type_desc;

    if (!stats->owp_histogram_ttl_json)
    {
        stats->owp_histogram_ttl_json = cJSON_CreateObject();
    }
    if (!stats->results)
    {
        stats->results = cJSON_CreateObject();
    }

    ttl_num = CalculateTtlStats(stats,type,&min_ttl,&max_ttl);

    switch(type){
        case OWP_TTL:
            type_desc = stats->hdr->twoway ? "_FWD" : "";
            break;
        case TWP_BCK_TTL:
            type_desc = "_BCK";
            break;
    }
    // TODO fix this?

    //fprintf(output,"MINTTL%s\t%u\n",type_desc,min_ttl);
    //fprintf(output,"MAXTTL%s\t%u\n",type_desc,max_ttl);
    cJSON * minttl = cJSON_CreateObject();
    cJSON * maxttl = cJSON_CreateObject();
    char min_name[15];
    char max_name[15];
    snprintf(min_name, sizeof(min_name), "MINTTL%s", type_desc);
    snprintf(max_name, sizeof(max_name), "MAXTTL%s", type_desc);
    //cJSON_AddNumberToObject(minttl, min_name, min_ttl);
    //cJSON_AddNumberToObject(maxttl, max_name, max_ttl);
    cJSON_AddItemToObject(stats->results, min_name, minttl);
    cJSON_AddItemToObject(stats->results, max_name, maxttl);
    //cJSON_AddItemToArray(stats->owp_histogram_ttl_json, minttl);
    //cJSON_AddItemToArray(stats->owp_histogram_ttl_json, maxttl);
    char * str =cJSON_Print(stats->owp_histogram_ttl_json);
        //char * str = cJSON_Print(stats->owp_raw_packets);
    //printf("owp_histogram_ttl_json: %s\n", str);

    return ttl_num;
}

/* Print TTL count for one-way sessions */
static void
PrintTtlBucket(
        OWPStats    stats,
        FILE        *output,
        uint16_t    bucket
        )
{
    if(stats->ttl_count[OWP_TTL][bucket])
        fprintf(output,"\t%u\t%lu\n",bucket,stats->ttl_count[OWP_TTL][bucket]);
}

static void
PrintTtlBucketJSON(
        OWPStats    stats,
        FILE        *output,
        uint16_t    bucket
        )
{
    if (!stats->owp_histogram_ttl_json)
    {
        stats->owp_histogram_ttl_json = cJSON_CreateArray();
    }

    if(stats->ttl_count[OWP_TTL][bucket])
    {
        //fprintf(output,"\t%u\t%lu\n",bucket,stats->ttl_count[OWP_TTL][bucket]);
	cJSON * bucket_json = cJSON_CreateObject();
	// TODO magic number
	char bucket_name [15];
	snprintf(bucket_name, sizeof(bucket_name), "%u", bucket);
	cJSON_AddNumberToObject(bucket_json, bucket_name, stats->ttl_count[OWP_TTL][bucket]);
	cJSON_AddItemToArray(stats->owp_histogram_ttl_json, bucket_json);
        //fprintf(output,"\t%u\t%lu\n",bucket,stats->ttl_count[OWP_TTL][bucket]);
    }
}

/* Print TTL counts for two-way sessions */
static void
PrintTtlBucketTW(
        OWPStats    stats,
        FILE        *output,
        uint16_t    bucket
        )
{
    if(stats->ttl_count[TWP_FWD_TTL][bucket] ||
       stats->ttl_count[TWP_BCK_TTL][bucket])
        fprintf(output,"\t%u\t%lu\t%lu\n",bucket,
                stats->ttl_count[TWP_FWD_TTL][bucket],
                stats->ttl_count[TWP_BCK_TTL][bucket]);
}

static void
PrintTtlBucketTWJSON(
        OWPStats    stats,
        FILE        *output,
        uint16_t    bucket
        )
{
    if (!stats->owp_histogram_ttl_json)
    {
        stats->owp_histogram_ttl_json = cJSON_CreateArray();
    }
    // TODO Finish

    if(stats->ttl_count[TWP_FWD_TTL][bucket] ||
       stats->ttl_count[TWP_BCK_TTL][bucket])
    {
	cJSON * bucket_json = cJSON_CreateObject();
	//char bucket_name[15];
	//snprintf(bucket_name, sizeof(bucket_name), "%u", bucket);
	cJSON_AddNumberToObject(bucket_json, "bucket", bucket);
	cJSON_AddNumberToObject(bucket_json, "TWP_FWD_TTL", stats->ttl_count[TWP_FWD_TTL][bucket]);
	cJSON_AddNumberToObject(bucket_json, "TWP_BCK_TTL", stats->ttl_count[TWP_BCK_TTL][bucket]);
	//cJSON_AddNumberToObject(bucket_json, bucket_name, stats->ttl_count[TWP_FWD_TTL][bucket]);
	//cJSON_AddNumberToObject(bucket_json, bucket_name, stats->ttl_count[TWP_BCK_TTL][bucket]);
	cJSON_AddItemToArray(stats->owp_histogram_ttl_json, bucket_json);
        //fprintf(output,"\t%u\t%lu\t%lu\n",bucket,
        //        stats->ttl_count[TWP_FWD_TTL][bucket],
        //        stats->ttl_count[TWP_BCK_TTL][bucket]);
        char * sum_json_str = cJSON_Print(stats->owp_histogram_ttl_json);
        printf("%s", sum_json_str);
    }
}

static void
PrintTtlStatsMachine(
        OWPStats    stats,
        FILE        *output
        )
{
    uint16_t ttl_num;
    uint16_t i;

    ttl_num = PrintMinMaxTtlMachine(stats,output,OWP_TTL);
    if(stats->hdr->twoway)
        ttl_num += PrintMinMaxTtlMachine(stats,output,TWP_BCK_TTL);

    if(ttl_num > 0){
        fprintf(output,"<TTLBUCKETS>\n");
        for(i=0;i<256;i++){
            if(stats->hdr->twoway)
                PrintTtlBucketTW(stats,output,i);
            else
                PrintTtlBucket(stats,output,i);
        }
        fprintf(output,"</TTLBUCKETS>\n");
    }
}

static void
PrintTtlStatsMachineJSON(
        OWPStats    stats,
        FILE        *output
        )
{
    uint16_t ttl_num;
    uint16_t i;
    if (!stats->owp_histogram_ttl_json)
    {
        stats->owp_histogram_ttl_json = cJSON_CreateObject();
    }

    ttl_num = PrintMinMaxTtlMachineJSON(stats,output,OWP_TTL);
    if(stats->hdr->twoway)
        ttl_num += PrintMinMaxTtlMachineJSON(stats,output,TWP_BCK_TTL);

    if(ttl_num > 0){
        //fprintf(output,"<TTLBUCKETS>\n");
        for(i=0;i<256;i++){
            if(stats->hdr->twoway)
                PrintTtlBucketTWJSON(stats,output,i);
            else
                PrintTtlBucketJSON(stats,output,i);
        }
        //fprintf(output,"</TTLBUCKETS>\n");
    }
}


OWPBoolean
OWPStatsPrintMachineJSON(
        OWPStats stats,
        FILE     *output
)
{
    /* Version 3.0 of stats output */
    float       version=3.0;
    char        sid_name[sizeof(OWPSID)*2+1];
    long int    j;
    double      d1;

    if (!stats->results)
    {
        stats->results = cJSON_CreateObject();
    }

    I2HexEncode(sid_name,stats->hdr->sid,sizeof(OWPSID));

    /*
     * Basic session information
     */
    if (!stats->sum_json)
    {
        stats->sum_json = cJSON_CreateObject();
    }

    //fprintf(output,"SUMMARY\t%.2f\n",version);
    cJSON_AddNumberToObject(stats->sum_json, "SUMMARY", version);
    //fprintf(output,"SID\t%s\n",sid_name);
    cJSON_AddStringToObject(stats->sum_json, "SID", sid_name);
    //fprintf(output,"FROM_HOST\t%s\n",stats->fromhost);
    cJSON_AddStringToObject(stats->sum_json, "FROM_HOST", stats->fromhost);
    //fprintf(output,"FROM_ADDR\t%s\n",stats->fromaddr);
    cJSON_AddStringToObject(stats->sum_json, "FROM_ADDR", stats->fromaddr);
    //fprintf(output,"FROM_PORT\t%s\n",stats->fromserv);
    cJSON_AddStringToObject(stats->sum_json, "FROM_PORT", stats->fromserv);
    //fprintf(output,"TO_HOST\t%s\n",stats->tohost);
    cJSON_AddStringToObject(stats->sum_json, "TO_HOST", stats->tohost);
    //fprintf(output,"TO_ADDR\t%s\n",stats->toaddr);
    cJSON_AddStringToObject(stats->sum_json, "TO_ADDR", stats->toaddr);
    //fprintf(output,"TO_PORT\t%s\n",stats->toserv);
    cJSON_AddStringToObject(stats->sum_json, "TO_PORT", stats->toserv);

    //fprintf(output,"START_TIME\t" OWP_TSTAMPFMT "\n",stats->start_time);
    cJSON_AddNumberToObject(stats->sum_json, "START_TIME", stats->start_time);
    //fprintf(output,"END_TIME\t" OWP_TSTAMPFMT "\n",stats->end_time);
    cJSON_AddNumberToObject(stats->sum_json, "END_TIME", stats->end_time);

    /* print unix versions of timestamp */
    if (stats->display_unix_ts == True) {
        double epochdiff = (OWPULongToNum64(OWPJAN_1970))>>32;
        //fprintf(output,"UNIX_START_TIME\t%f\n", OWPNum64ToDouble(stats->start_time) - epochdiff);
        cJSON_AddNumberToObject(stats->sum_json, "UNIX_START_TIME", OWPNum64ToDouble(stats->start_time) - epochdiff);
        //fprintf(output,"UNIX_END_TIME\t%f\n", OWPNum64ToDouble(stats->end_time) - epochdiff);
        cJSON_AddNumberToObject(stats->sum_json, "UNIX_END_TIME", OWPNum64ToDouble(stats->end_time) - epochdiff);
    }

    /*
     * If typeP is specified as a DSCP code-byte, then output it too.
     * (If any bits are set outside of the low-order 6 bits of the
     * high-order byte, then it is not a DSCP.)
     */
    if( !(stats->hdr->test_spec.typeP & ~0x3F000000)){
        uint8_t dscp = stats->hdr->test_spec.typeP >> 24;
        //fprintf(output,"DSCP\t0x%2.2x\n",dscp);
        cJSON_AddNumberToObject(stats->sum_json, "DSCP", dscp);
    }
    //fprintf(output,"LOSS_TIMEOUT\t%"PRIu64"\n", stats->hdr->test_spec.loss_timeout);
    cJSON_AddNumberToObject(stats->sum_json, "LOSS_TIMEOUT", stats->hdr->test_spec.loss_timeout);
    //fprintf(output,"PACKET_PADDING\t%u\n",
    //        stats->hdr->test_spec.packet_size_padding);
    cJSON_AddNumberToObject(stats->sum_json, "PACKET_PADDING",
            stats->hdr->test_spec.packet_size_padding);
    //fprintf(output,"SESSION_PACKET_COUNT\t%u\n",
    cJSON_AddNumberToObject(stats->sum_json, "SESSION_PACKET_COUNT", stats->hdr->test_spec.npackets);
    //fprintf(output,"SAMPLE_PACKET_COUNT\t%u\n",
    cJSON_AddNumberToObject(stats->sum_json, "SAMPLE_PACKET_COUNT", stats->last - stats->first);
    //fprintf(output,"BUCKET_WIDTH\t%g\n",
    cJSON_AddNumberToObject(stats->sum_json, "BUCKET_WIDTH", stats->bucketwidth);
    //fprintf(output,"SESSION_FINISHED\t%d\n",
    cJSON_AddNumberToObject(stats->sum_json, "SESSION_FINISHED",
            (stats->hdr->finished == OWP_SESSION_FINISHED_NORMAL)?1:0);

    /*
     * Summary results
     */
    //fprintf(output,"SENT\t%u\n",stats->sent);
    cJSON_AddNumberToObject(stats->sum_json, "SENT", stats->sent);
    //fprintf(output,"SYNC\t%" PRIuPTR "\n",stats->sync);
    cJSON_AddNumberToObject(stats->sum_json, "SYNC", stats->sync);
    //fprintf(output,"MAXERR\t%g\n",stats->maxerr[OWP_DELAY]);
    cJSON_AddNumberToObject(stats->sum_json, "MAXERR", stats->maxerr[OWP_DELAY]);
    if(stats->hdr->twoway){
        cJSON_AddNumberToObject(stats->sum_json, "MAXERR_FWD", stats->maxerr[TWP_FWD_DELAY]);
        //fprintf(output,"MAXERR_FWD\t%g\n",stats->maxerr[TWP_FWD_DELAY]);
        cJSON_AddNumberToObject(stats->sum_json, "MAXERR_BCK", stats->maxerr[TWP_BCK_DELAY]);
        //fprintf(output,"MAXERR_BCK\t%g\n",stats->maxerr[TWP_BCK_DELAY]);

        cJSON_AddNumberToObject(stats->sum_json, "DUPS_FWD", stats->dups[TWP_FWD_PKTS]);
        //fprintf(output,"DUPS_FWD\t%u\n",stats->dups[TWP_FWD_PKTS]);
        cJSON_AddNumberToObject(stats->sum_json, "DUPS_BCK", stats->dups[TWP_BCK_PKTS]);
        //fprintf(output,"DUPS_BCK\t%u\n",stats->dups[TWP_BCK_PKTS]);
    }
    else{
        cJSON_AddNumberToObject(stats->sum_json, "DUPS", stats->dups[OWP_PKTS]);
        //fprintf(output,"DUPS\t%u\n",
    }
    //fprintf(output,"LOST\t%u\n",stats->lost);
    cJSON_AddNumberToObject(stats->sum_json, "LOST", stats->lost);

    /* Min delay */
    PrintMinDelayMachineJSON(stats,OWP_DELAY,output);
    if(stats->hdr->twoway){
        PrintMinDelayMachineJSON(stats,TWP_FWD_DELAY,output);
        PrintMinDelayMachineJSON(stats,TWP_BCK_DELAY,output);
        PrintMinDelayMachineJSON(stats,TWP_PROC_DELAY,output);
    }

    /* Median delay */
    if(BucketBufferSortPercentile(stats,0.5,&d1,OWP_DELAY)){
        //fprintf(output,"MEDIAN\t%g\n",d1);
        cJSON_AddNumberToObject(stats->sum_json, "MEDIAN", d1);
    }
    if(stats->hdr->twoway){
        if(BucketBufferSortPercentile(stats,0.5,&d1,TWP_FWD_DELAY)){
            cJSON_AddNumberToObject(stats->sum_json, "MEDIAN_FWD", d1);
            //fprintf(output,"MEDIAN_FWD\t%g\n",d1);
        }
        if(BucketBufferSortPercentile(stats,0.5,&d1,TWP_BCK_DELAY)){
            cJSON_AddNumberToObject(stats->sum_json, "MEDIAN_BCK", d1);
            //fprintf(output,"MEDIAN_BCK\t%g\n",d1);
        }
    }

    /* Max delay */
    PrintMaxDelayMachineJSON(stats,OWP_DELAY,output);
    if(stats->hdr->twoway){
        PrintMaxDelayMachineJSON(stats,TWP_FWD_DELAY,output);
        PrintMaxDelayMachineJSON(stats,TWP_BCK_DELAY,output);
        PrintMaxDelayMachineJSON(stats,TWP_PROC_DELAY,output);
        //PrintMaxDelayMachine(stats,TWP_FWD_DELAY,output);
        //PrintMaxDelayMachine(stats,TWP_BCK_DELAY,output);
        //PrintMaxDelayMachine(stats,TWP_PROC_DELAY,output);
    }

    /*
     * PDV
     */
    if(CalculateJitter(stats,OWP_DELAY,&d1)){
        //fprintf(output,"PDV\t%g\n",d1);
	cJSON_AddNumberToObject(stats->sum_json, "PDV", d1);
    }
    if(stats->hdr->twoway){
        if(CalculateJitter(stats,TWP_FWD_DELAY,&d1)){
            //fprintf(output,"PDV_FWD\t%g\n",d1);
	    cJSON_AddNumberToObject(stats->sum_json, "PDV_FWD", d1);
        }
        if(CalculateJitter(stats,TWP_BCK_DELAY,&d1)){
            //fprintf(output,"PDV_BCK\t%g\n",d1);
	    cJSON_AddNumberToObject(stats->sum_json, "PDV_BCK", d1);
        }
    }

    /*
     * Delay histogram
     */
    //cJSON * delay_histogram = cJSON_CreateArray();
    if (!stats->owp_histogram_latency_json)
    {
        stats->owp_histogram_latency_json = cJSON_CreateArray();
    }
    if(stats->sent > stats->lost){
        //fprintf(output,"<BUCKETS>\n");
        if(stats->hdr->twoway)
        {
            I2HashIterate(stats->btable,BucketBufferPrintTWJSON,stats);
            //I2HashIterate(stats->btable,BucketBufferPrintTW,output);
        }
        else
        {
            I2HashIterate(stats->btable,BucketBufferPrintJSON,stats);
            //I2HashIterate(stats->btable,BucketBufferPrint,output);
        }
        //fprintf(output,"</BUCKETS>\n");
    }
    cJSON_AddItemToObject(stats->results, "BUCKETS", stats->owp_histogram_latency_json);
    // Add
    // stats->maxerr[OWP_DELAY_TYPE_NUM] [total fwd back]
    cJSON_AddNumberToObject(stats->results, "max-clock-err", stats->maxerr[OWP_DELAY]);
    //stats->maxerr[type] * stats->scale_factor,
    //    stats->maxerr[OWP_DELAY] = MAX(stats->maxerr[OWP_DELAY],derr);
    cJSON_AddNumberToObject(stats->results, "max-clock-err", 0);
    //cJSON_AddNumberToObject(stats->results, "packets-duplicated", stats->dups[]);
    cJSON_AddNumberToObject(stats->results, "packets-duplicated", stats->dups[OWP_PKTS]);
    cJSON_AddNumberToObject(stats->results, "packets-lost", stats->lost);
    //cJSON_AddNumberToObject(stats->results, "packets-received", 0);
    //// TODO or last - first?
    cJSON_AddNumberToObject(stats->results, "packets-received", stats->plistlen);
    //cJSON_AddNumberToObject(stats->results, "packets-reordered", 0);
    cJSON_AddNumberToObject(stats->results, "packets-reordered", stats->rlistlen);
    cJSON_AddNumberToObject(stats->results, "packets-sent", stats->sent);

    /*
     * TTL histogram
     */
    //cJSON * ttl_histogram = cJSON_CreateArray();
    if (!stats->owp_histogram_ttl_json)
    {
        stats->owp_histogram_ttl_json = cJSON_CreateArray();
    }
    PrintTtlStatsMachineJSON(stats,output);
    cJSON_AddItemToObject(stats->results, "ttl", stats->owp_histogram_ttl_json);

    //fprintf(output,"\n");

    /*
     * Reordering histogram
     *
     * (Not needed for TWAMP as twping won't allow packets to be
     * re-ordered)
     */
    cJSON * nreordering = cJSON_CreateArray();
    if (!stats->sum_json)
    {
        stats->sum_json = cJSON_CreateObject();
    }

    if(!stats->hdr->twoway){
        cJSON * record = cJSON_CreateObject();

        //fprintf(output,"<NREORDERING>\n");
        for(j=0;((j<stats->rlistlen) && (stats->rn[j]));j++){
            //fprintf(output,"\t%u\t%u\n",(uint32_t)j+1,
            //        stats->rn[j]);
            char name [15];
            snprintf(name, sizeof(name), "%u", (uint32_t)j+1);
            cJSON_AddNumberToObject(record, name, stats->rn[j]);
            cJSON_AddItemToArray(nreordering, record);
        }
        if((j==0) || (j >= stats->rlistlen)){
            //fprintf(output,"\t%u\t%u\n",(uint32_t)j+1,0);
            char name [15];
            snprintf(name, sizeof(name), "%u", (uint32_t)j+1);
            cJSON_AddNumberToObject(record, name, 0);
            cJSON_AddItemToArray(nreordering, record);
        }
        //fprintf(output,"</NREORDERING>\n");
    }
    cJSON_AddItemToObject(stats->sum_json, "NREORDERING", nreordering);

    // TODO switch back to other version
    //char * sum_json_str = cJSON_Print(stats->sum_json);
    //fprintf(output, "%s", sum_json_str);

    return True;
}

/*
 * Program-readable statistics summary
 */
OWPBoolean
OWPStatsPrintMachine(
        OWPStats    stats,
        FILE        *output
        )
{
    /* Version 3.0 of stats output */
    float       version=3.0;
    char        sid_name[sizeof(OWPSID)*2+1];
    long int    j;
    double      d1;

    I2HexEncode(sid_name,stats->hdr->sid,sizeof(OWPSID));

    /*
     * Basic session information
     */
    fprintf(output,"SUMMARY\t%.2f\n",version);
    fprintf(output,"SID\t%s\n",sid_name);
    fprintf(output,"FROM_HOST\t%s\n",stats->fromhost);
    fprintf(output,"FROM_ADDR\t%s\n",stats->fromaddr);
    fprintf(output,"FROM_PORT\t%s\n",stats->fromserv);
    fprintf(output,"TO_HOST\t%s\n",stats->tohost);
    fprintf(output,"TO_ADDR\t%s\n",stats->toaddr);
    fprintf(output,"TO_PORT\t%s\n",stats->toserv);

    fprintf(output,"START_TIME\t" OWP_TSTAMPFMT "\n",stats->start_time);
    fprintf(output,"END_TIME\t" OWP_TSTAMPFMT "\n",stats->end_time);
    
    /* print unix versions of timestamp */
    if (stats->display_unix_ts == True) {
        double epochdiff = (OWPULongToNum64(OWPJAN_1970))>>32;
        fprintf(output,"UNIX_START_TIME\t%f\n", OWPNum64ToDouble(stats->start_time) - epochdiff);
        fprintf(output,"UNIX_END_TIME\t%f\n", OWPNum64ToDouble(stats->end_time) - epochdiff);
    }

    /*
     * If typeP is specified as a DSCP code-byte, then output it too.
     * (If any bits are set outside of the low-order 6 bits of the
     * high-order byte, then it is not a DSCP.)
     */
    if( !(stats->hdr->test_spec.typeP & ~0x3F000000)){
        uint8_t dscp = stats->hdr->test_spec.typeP >> 24;
        fprintf(output,"DSCP\t0x%2.2x\n",dscp);
    }
    fprintf(output,"LOSS_TIMEOUT\t%"PRIu64"\n",stats->hdr->test_spec.loss_timeout);
    fprintf(output,"PACKET_PADDING\t%u\n",
            stats->hdr->test_spec.packet_size_padding);
    fprintf(output,"SESSION_PACKET_COUNT\t%u\n",stats->hdr->test_spec.npackets);
    fprintf(output,"SAMPLE_PACKET_COUNT\t%u\n", stats->last - stats->first);
    fprintf(output,"BUCKET_WIDTH\t%g\n",stats->bucketwidth);
    fprintf(output,"SESSION_FINISHED\t%d\n",
            (stats->hdr->finished == OWP_SESSION_FINISHED_NORMAL)?1:0);

    /*
     * Summary results
     */
    fprintf(output,"SENT\t%u\n",stats->sent);
    fprintf(output,"SYNC\t%" PRIuPTR "\n",stats->sync);
    fprintf(output,"MAXERR\t%g\n",stats->maxerr[OWP_DELAY]);
    if(stats->hdr->twoway){
        fprintf(output,"MAXERR_FWD\t%g\n",stats->maxerr[TWP_FWD_DELAY]);
        fprintf(output,"MAXERR_BCK\t%g\n",stats->maxerr[TWP_BCK_DELAY]);

        fprintf(output,"DUPS_FWD\t%u\n",stats->dups[TWP_FWD_PKTS]);
        fprintf(output,"DUPS_BCK\t%u\n",stats->dups[TWP_BCK_PKTS]);
    }
    else{
        fprintf(output,"DUPS\t%u\n",stats->dups[OWP_PKTS]);
    }
    fprintf(output,"LOST\t%u\n",stats->lost);

    /* Min delay */
    PrintMinDelayMachine(stats,OWP_DELAY,output);
    if(stats->hdr->twoway){
        PrintMinDelayMachine(stats,TWP_FWD_DELAY,output);
        PrintMinDelayMachine(stats,TWP_BCK_DELAY,output);
        PrintMinDelayMachine(stats,TWP_PROC_DELAY,output);
    }

    /* Median delay */
    if(BucketBufferSortPercentile(stats,0.5,&d1,OWP_DELAY)){
        fprintf(output,"MEDIAN\t%g\n",d1);
    }
    if(stats->hdr->twoway){
        if(BucketBufferSortPercentile(stats,0.5,&d1,TWP_FWD_DELAY)){
            fprintf(output,"MEDIAN_FWD\t%g\n",d1);
        }
        if(BucketBufferSortPercentile(stats,0.5,&d1,TWP_BCK_DELAY)){
            fprintf(output,"MEDIAN_BCK\t%g\n",d1);
        }
    }

    /* Max delay */
    PrintMaxDelayMachine(stats,OWP_DELAY,output);
    if(stats->hdr->twoway){
        PrintMaxDelayMachine(stats,TWP_FWD_DELAY,output);
        PrintMaxDelayMachine(stats,TWP_BCK_DELAY,output);
        PrintMaxDelayMachine(stats,TWP_PROC_DELAY,output);
    }

    /*
     * PDV
     */
    if(CalculateJitter(stats,OWP_DELAY,&d1)){
        fprintf(output,"PDV\t%g\n",d1);
    }
    if(stats->hdr->twoway){
        if(CalculateJitter(stats,TWP_FWD_DELAY,&d1)){
            fprintf(output,"PDV_FWD\t%g\n",d1);
        }
        if(CalculateJitter(stats,TWP_BCK_DELAY,&d1)){
            fprintf(output,"PDV_BCK\t%g\n",d1);
        }
    }

    /*
     * Delay histogram
     */
    if(stats->sent > stats->lost){
        fprintf(output,"<BUCKETS>\n");
        if(stats->hdr->twoway)
            I2HashIterate(stats->btable,BucketBufferPrintTW,output);
        else
            I2HashIterate(stats->btable,BucketBufferPrint,output);
        fprintf(output,"</BUCKETS>\n");
    }

    /*
     * TTL histogram
     */
    PrintTtlStatsMachine(stats,output);

    fprintf(output,"\n");

    /*
     * Reordering histogram
     *
     * (Not needed for TWAMP as twping won't allow packets to be
     * re-ordered)
     */
    if(!stats->hdr->twoway){
        fprintf(output,"<NREORDERING>\n");
        for(j=0;((j<stats->rlistlen) && (stats->rn[j]));j++){
            fprintf(output,"\t%u\t%u\n",(uint32_t)j+1,
                    stats->rn[j]);
        }
        if((j==0) || (j >= stats->rlistlen)){
            fprintf(output,"\t%u\t%u\n",(uint32_t)j+1,0);
        }
        fprintf(output,"</NREORDERING>\n");
    }

    return True;
}
