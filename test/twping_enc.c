/*
 *        File:         twping1.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Basic twping client control setup test
 */

#include <owamp/owamp.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "./server.h"
#include "./session_setup.h"

#define NUM_TEST_SLOTS 15
#define NUM_TEST_PACKETS 18
#define SID_VALUE "this is the SID!"


/*
 * Function:        main
 *
 * Description:     launch a simulated twamp server & send commands
 *                  so they can be validated in do_control_setup_server
 *
 * In Args:         argc, argv (unused)
 *
 * Out Args:
 *
 * Scope:           unit test (run using make check)
 * Returns:         non-zero in case of error
 * Side Effect:
 */
int
main(
        int argc __attribute__((unused)),
        char    **argv
    ) {

    struct _server_test_params test_params;

    memset(&test_params, 0, sizeof test_params);
    test_params.input.expected_modes = OWP_MODE_ENCRYPTED;
    test_params.input.expected_num_test_slots = 0;
    test_params.input.expected_num_test_packets = 0; 
    assert(sizeof test_params.input.sid <= sizeof SID_VALUE); // configuration sanity
    memcpy(test_params.input.sid, SID_VALUE, sizeof test_params.input.sid);

    if (session_setup_test(
            argv,
            OWP_MODE_ENCRYPTED,
            NUM_TEST_PACKETS,
            NUM_TEST_SLOTS,
            &test_params,
            TWPControlOpen,
            default_passphrase_callback)) {
        fprintf(stderr, "ping client detected an error\n");
        return 1;
    }

    return !test_params.output.sent_greeting ||
        !test_params.output.setup_response_ok ||
        !test_params.output.sent_server_start ||
        !test_params.output.sent_accept_session ||
        !test_params.output.test_complete;
}
