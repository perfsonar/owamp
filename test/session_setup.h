/*
 *        File:         session_setup.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  declarations for use with setup_session.c
 */

extern OWPGetPFFunc default_passphrase_callback;


typedef OWPControl (*XWPControlOpen)(
    OWPContext, const char *, I2Addr, uint32_t, OWPUserID, OWPNum64*, OWPErrSeverity*);

int session_setup_test(
        char **argv,
        uint32_t client_mode_mask,
        uint32_t num_packets,
        uint32_t num_slots,
        struct _server_test_params *test_params,
        XWPControlOpen control_open,
        OWPGetPFFunc passphrase_callback);

