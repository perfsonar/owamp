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
 *        File:         owampdP.h
 *
 *        Author:       Jeff W. Boote
 *                      Internet2
 *
 *        Date:         Mon Jun 03 15:31:22 MDT 2002
 *
 *        Description:        
 */
#ifndef _OWAMPDP_H_
#define _OWAMPDP_H_

#ifndef OWAMPD_CONF_FILE
#ifdef TWAMP
#define OWAMPD_CONF_FILE        "twamp-server.conf"
#else
#define OWAMPD_CONF_FILE        "owamp-server.conf"
#endif
#endif

/*
 * Types
 */
typedef struct {

    I2Boolean       verbose;
    I2Boolean       help;

    char            cwd[MAXPATHLEN];
    char            *confdir;
    char            *vardir;
    char            *passwd;

    char            *datadir;

    char            *authmode;
    uint32_t        auth_mode;        /* cooked version of authmode */
    char            *srcnode;

    OWPPortRange    portspec;

    char            *user;
    char            *group;

    OWPBoolean      allowroot;

    double          diskfudge;
    uint32_t        dieby;
    uint32_t        controltimeout;
#ifdef TWAMP
    uint32_t        testtimeout;
#endif
    uint32_t        pbkdf2_count;
    uint32_t        maxcontrolsessions;
#ifdef DEBUG
    void            *childwait;
#endif
    I2Boolean       daemon;

    I2Boolean       setEndDelay;
    double          endDelay;

    I2Boolean       patt_remote;      /* -x */
    I2Boolean       natt_server;      /* -Y */
    I2Boolean       switchUnspec;     /* -W */
} owampd_opts;

#endif        /*        _OWAMPDP_H_        */
