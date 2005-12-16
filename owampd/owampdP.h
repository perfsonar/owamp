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
#define OWAMPD_CONF_FILE        "owampd.conf"
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
    u_int32_t       auth_mode;        /* cooked version of authmode */
    char            *srcnode;

    OWPPortRange    portspec;

    char            *user;
    char            *group;

    OWPBoolean      allowroot;

    double          diskfudge;
    u_int32_t       dieby;
    u_int32_t       controltimeout;
#ifndef        NDEBUG
    I2Boolean       childwait;
#endif
    I2Boolean       daemon;
} owampd_opts;

#endif        /*        _OWAMPDP_H_        */
