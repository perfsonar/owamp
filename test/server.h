/*
 *        File:         server.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Declaration for owping control server handler
 */

#define SESSION_USERID "bogus userid"
#define SESSION_PASSPHRASE "this is the passphrase"

struct _server_test_params {
    struct {
        uint32_t expected_modes;
        uint32_t expected_num_test_slots;
        uint32_t expected_num_test_packets;    
        OWPSID sid;
    } input;
    struct {
        int sent_greeting;
        int setup_response_ok;
        int sent_server_start;
        int sent_accept_session;
        int test_complete;
    } output;
};

// context should point to a _server_test_params struct
int do_control_setup_server(int s, void *context);
int do_control_setup_server_encrypted(int s, void *context);



