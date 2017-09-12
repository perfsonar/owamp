/*
 *        File:         session_setup.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Utilities for launching a *wping client
 *                      and setting up a control session
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>


#include <owamp/owamp.h>
#include <owamp/owampP.h>
#include <I2util/util.h>
#include <I2util/addr.h>

#include "./owtest_utils.h"
#include "./server.h"

#define DEFAULT_PPCB_DEFINED
#include "./session_setup.h"


#define TMP_SOCK_FILENAME_TPL "twsock.XXXXXX"


/*
 * Function:        passphrase_callback_impl 
 *
 * Description:     default passphrase callback that returns the same
 *                  passphrase used by the server emulator
 *
 * In Args:         cf. OWPGetPFFunc
 *
 * Out Args:
 *
 * Scope:
 * Returns:         True
 * Side Effect:
 */
static OWPBoolean passphrase_callback_impl(
        OWPContext      ctx __attribute__((unused)),
        const OWPUserID userid    __attribute__((unused)),
        uint8_t         **pf,
        size_t          *pf_len,
        void            **pf_free,
        OWPErrSeverity  *err_ret __attribute__((unused))
        ) {
    static char *passphrase = SESSION_PASSPHRASE;
    *pf = (uint8_t *) passphrase;
    *pf_len = strlen(passphrase);
    *pf_free = NULL;
    return True;
}

OWPGetPFFunc default_passphrase_callback = passphrase_callback_impl;


/*
 * Function:        server_proc 
 *
 * Description:     wrapper for run_server(struct _server_params *) used
 *                  with pthread_create
 *
 * In Args:         ptr to a struct _server_params
 *
 * Out Args:
 *
 * Scope:
 * Returns:         NULL in case of error or server completion
 * Side Effect:
 */
void *server_proc(void *context) {
    return run_server((struct _server_params *) context);
}


/*
 * Function:        session_setup_test
 *
 * Description:     launch a simulated owamp server & send commands
 *                  so they can be validated in do_control_setup_server
 *
 * In Args:         argv
 *
 * Out Args:
 *
 * Scope:           unit test (run using make check)
 * Returns:         non-zero in case of error
 * Side Effect:
*/
int session_setup_test(
        char **argv,
        uint32_t client_mode_mask,
        uint32_t num_test_packets,
        uint32_t num_test_slots,
        struct _server_test_params *test_params,
        XWPControlOpen control_open,
        OWPGetPFFunc passphrase_callback) {

    int client_successful = 0;
    pthread_t server_thread;
    int thread_valid = 0;
    OWPContext ctx = NULL;
    I2Addr serverAddr = NULL;
    OWPControl cntrl = NULL;
    OWPTestSpec tspec;
    int fd = -1;
    struct _server_params server_params;

    server_params.client_proc = do_control_setup_server;
    server_params.test_context = test_params;

    memset(&tspec, 0, sizeof tspec);

    // create a tmp file to use as the unix socket
    server_params.socket_path = (char *) malloc(sizeof TMP_SOCK_FILENAME_TPL + 1);
    strcpy(server_params.socket_path, TMP_SOCK_FILENAME_TPL);
    int tmpfd = mkstemp(server_params.socket_path);
    if(tmpfd < 0) {
        perror("mkstemp error");
        goto cleanup;
    }
    close(tmpfd);
    unlink(server_params.socket_path);

    // start the server thread
    errno = pthread_create(&server_thread, NULL, server_proc, &server_params);
    if (errno) {
        perror("pthread_create error");
        goto cleanup;
    }
    thread_valid = 1;


    // create the client socket & wait until we're able to connect
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("error creating client socket");
        goto cleanup;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, server_params.socket_path, sizeof addr.sun_path - 1);

    int connected = 0;
    for(int i=0; i<10 && !connected; i++) {
        if(connect(fd, (struct sockaddr *) &addr, sizeof addr) == -1) {
            perror("waiting for server");
            sleep(1);
        } else {
            connected = 1;
        }
    }
    if (!connected) {
        printf("giving up connection to test server\n");
        goto cleanup;
    }


    ctx = tmpContext(argv);

    if (passphrase_callback) {
        // install the passphrase callback
        if (!OWPContextConfigSetF(
                    ctx,
                    OWPGetPF,
                    (OWPFunc) passphrase_callback)) {
            printf("OWPContextConfigSetF failed!");
            goto cleanup;
        }
    }

    // open the control connection
    serverAddr = I2AddrBySockFD(ctx->eh, fd, False);
    OWPErrSeverity owp_severity;
    cntrl = control_open(
            ctx,
            NULL,
            serverAddr,
            client_mode_mask,
            SESSION_USERID,
            NULL, &owp_severity);

    if (!cntrl) {
        printf("OWPControlOpen error\n");
        goto cleanup;
    }

    OWPTimeStamp curr_time;
    OWPGetTimeOfDay(ctx, &curr_time);
    tspec.start_time = curr_time.owptime;
    tspec.loss_timeout = OWPDoubleToNum64(0.0);
    tspec.typeP = 0; 
    tspec.packet_size_padding = 0;
    tspec.npackets = num_test_packets;
    tspec.nslots = num_test_slots;
    tspec.slots = (OWPSlot *) calloc(num_test_slots, sizeof(OWPSlot));
    memset(tspec.slots, 0, num_test_slots * sizeof(OWPSlot));
    for(int i=0; i<num_test_slots; i++) {
        tspec.slots[i].slot_type = OWPSlotLiteralType;
        tspec.slots[i].literal.offset = OWPDoubleToNum64((double) i);
    }
    OWPSID sid_ret;
    OWPErrSeverity err_ret;
    if (!OWPSessionRequest(
                cntrl,
                // not a real test, but these params run through the basic setup
                I2AddrByNode(ctx->eh, "127.0.0.1"), True,
                I2AddrByNode(ctx->eh, "127.0.0.1"), True,
                &tspec,
                NULL,
                sid_ret, &err_ret)) {
        printf("OWPSessionRequest returned error\n ");
        goto cleanup;
    }

    if (memcmp(sid_ret, test_params->input.sid, sizeof(OWPSID))) {
        printf("received incorrect SID\n");
        goto cleanup;
    }

    client_successful = 1;

cleanup:

    if (thread_valid) {

        for(int i=0; i<5; i++) {
            sleep(1);
            if (test_params->output.test_complete) {
                break;
            }
        }

        if (test_params->output.test_complete) {
            pthread_join(server_thread, NULL);
        } else {
            printf("warning: server thread didn't exit\n");
            pthread_cancel(server_thread);
        }
    }

    if (server_params.socket_path) {
        unlink(server_params.socket_path);
        free(server_params.socket_path);
    }

    if (cntrl) {
        OWPControlClose(cntrl);
    }
    if (ctx) {
        OWPContextFree(ctx);
    }
    if (fd >= 0) {
        close(fd);
    }

    if (tspec.slots) {
        free(tspec.slots);
    }

    return !client_successful;
}

