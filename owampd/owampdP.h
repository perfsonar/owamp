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
#define OWAMPD_CONF_FILE        "twampd-server.conf"
#else
#define OWAMPD_CONF_FILE        "owampd-server.conf"
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
    uint32_t        pbkdf2_count;
    uint32_t        maxcontrolsessions;
#ifndef        NDEBUG
    void            *childwait;
#endif
    I2Boolean       daemon;

    I2Boolean       setEndDelay;
    double          endDelay;
} owampd_opts;

#endif        /*        _OWAMPDP_H_        */
