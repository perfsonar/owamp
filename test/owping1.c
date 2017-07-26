/*
 *        File:         owping1.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Basic owping client connection setup test
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


#define TMP_SOCK_FILENAME_TPL "owsock.XXXXXX"
#define SERVER_TEST_IV "this is the IV!!"
#define NUM_TEST_SLOTS 10
#define NUM_TEST_PACKETS 19 
#define SESSION_PORT 0xABCD
#define SID_VALUE "this is the SID!"


// cf. rfc 4656, pg 6 
struct _greeting {
    uint8_t Unused[12];
    uint8_t Modes[4];
    uint8_t Challenge[16];
    uint8_t Salt[16];
    uint8_t Count[4];
    uint8_t MBZ[12];
};

// cf. rfc 4656, pg 7 
struct _setup_response {
    uint8_t Mode[4];
    uint8_t KeyID[80];
    uint8_t Token[64];
    uint8_t Client_IV[16];
};

// cf. rfc 4656, pg 9
struct _server_start {
    uint8_t MBZ[15];
    uint8_t Accept;
    uint8_t Server_IV[16];
    uint64_t StartTime;
    uint8_t MBZ2[8];
};

// cf. rfc 4656, pg 13
struct _request_session {
    uint8_t CommandId;
    union {
        uint8_t MBZ: 4;
        uint8_t IPVN: 4;
    } version;
    uint8_t ConfSender;
    uint8_t ConfReceiver;
    uint32_t NumSlots;
    uint32_t NumPackets;
    uint16_t SenderPort;
    uint16_t ReceiverPort;
    uint8_t SenderAddress[4];
    uint8_t SenderAddress1[12];
    uint8_t ReceiverAddress[4];
    uint8_t ReceiverAddress2[12];
    uint8_t SID[16];
    uint32_t PaddingLength;
    uint64_t StartTime;
    uint64_t Timeout;
    uint32_t TypeP;
    uint8_t MBZ2[8];
    uint8_t HMAC[16];
};

// cf. rfc 4656, pg 14
struct _schedule_slot_description {
    uint8_t slot_type;
    uint8_t MBZ[7];
    uint32_t SlotParameter;
};

struct _hmac {
    uint8_t HMAC[16];
};

// cf. rfc 4656, pg 16
struct _accept_session {
    uint8_t Accept;
    uint8_t MBZ;
    uint16_t Port;
    uint8_t SID[16];
    uint8_t MBZ2[12];
    uint8_t HMAC[16];
};


// used with do_server
struct _server_test_results {
    int sent_greeting;
    int setup_response_ok;
    int sent_server_start;
    int sent_accept_session;
    int test_complete;
};


/*
 * Function:        do_server
 *
 * Description:     emulates the server side of a test session
 *
 * In Args:         void pointer to struct _server_test_results
 *
 * Out Args:
 *
 * Scope:
 * Returns:          non-zero if the server should continue
 *                   accepting new clients
 * Side Effect:
 */
int do_server(int s, void *context) {
    struct _server_test_results *test_results
        = (struct _server_test_results *) context;
    memset(test_results, 0, sizeof(struct _server_test_results));

    struct _greeting greeting;
    memset(&greeting, 0, sizeof greeting);
    *((uint32_t *) greeting.Modes) = htonl(7);
    memset(greeting.Challenge, 0x55, sizeof greeting.Challenge);
    memset(greeting.Salt, 0x78, sizeof greeting.Salt);
    *((uint32_t *) greeting.Count) = htonl(1024);
    test_results->sent_greeting 
        = write(s, &greeting, sizeof greeting) == sizeof greeting;


    struct _setup_response setup_response;
//    if(read(s, &setup_response, sizeof setup_response) != sizeof setup_response) {
    if(recv(s, &setup_response, sizeof setup_response, MSG_WAITALL) != sizeof setup_response) {
        perror("error reading setup response");
        return 0;
    }

    uint32_t mode = ntohl(*(uint32_t *) &setup_response.Mode);
    if (mode != OWP_MODE_OPEN) {
        printf("expected setup response mode == OWP_MODE_OPEN, got: 0x%08x", mode);
        return 0;
    }
    // nothing to check in the other fields in unauthenticated mode
    test_results->setup_response_ok = 1;

    struct _server_start server_start;
    memset(&server_start, 0, sizeof server_start);
    server_start.StartTime = htonll(time(NULL));
    memcpy(server_start.Server_IV, SERVER_TEST_IV, sizeof server_start.Server_IV);
    test_results->sent_server_start
        = write(s, &server_start, sizeof server_start) == sizeof server_start;
    if (!test_results->sent_server_start) {
        perror("error sending server start response");
        return 0;
    }

    struct _request_session request_session;
//    if (read(s, &request_session, sizeof request_session) != sizeof request_session) {
    if (recv(s, &request_session, sizeof request_session, MSG_WAITALL) != sizeof request_session) {
        perror("error reading request session message");
        return 0; 
    }

    uint32_t num_slots = ntohl(request_session.NumSlots);
    if (num_slots != NUM_TEST_SLOTS) {
        printf("expected %d test slots, got %d\n", NUM_TEST_SLOTS, num_slots);
        return 0;
    }

    uint32_t num_packets = ntohl(request_session.NumPackets);
    if (num_packets != NUM_TEST_PACKETS) {
        printf("expected %d test packets, got %d\n", NUM_TEST_PACKETS, num_packets);
        return 0;
    }

    struct _schedule_slot_description slots[NUM_TEST_SLOTS];
//    if (read(s, slots, sizeof slots) != sizeof(slots)) {
    if (recv(s, slots, sizeof slots, MSG_WAITALL) != sizeof slots) {
        perror("error reading slot descriptions");
//printf("read slot bytes: %lu bytes\n", ttt);
        return 0;
    }

    struct _hmac hmac;
//    if (read(s, &hmac, sizeof hmac) != sizeof hmac) {
    if (recv(s, &hmac, sizeof hmac, MSG_WAITALL) != sizeof hmac) {
        perror("error reading hmac");
        return 0;
    }

    struct _accept_session accept_session;
    memset(&accept_session, 0, sizeof accept_session);
    memcpy(&accept_session.SID, SID_VALUE, sizeof accept_session.SID);
    accept_session.Port = htons(SESSION_PORT);
    if (write(s, &accept_session, sizeof accept_session) != sizeof accept_session) {
        perror("error sending Accept-Session response");
        return 0;
    }

    test_results->sent_accept_session = 1;

    printf("do_server: finished!\n");
    test_results->test_complete = 1;
    return 0;
}


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
 * Function:        main
 *
 * Description:     launch a simulated owamp server & send commands
 *                  so they can be validated in do_server (above)
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
    
    int client_successful = 0;
    pthread_t server_thread;
    int thread_valid = 0;
    OWPContext ctx = NULL;
    I2Addr serverAddr = NULL;
    OWPControl cntrl = NULL;
    OWPTestSpec tspec;
    int fd = -1;
    struct _server_params server_params;
    struct _server_test_results test_results;

    memset(&tspec, 0, sizeof tspec);
    memset(&test_results, 0, sizeof test_results);
    server_params.client_proc = do_server;
    server_params.test_context = &test_results;

    // create a tmp file to use as the unix socket
    server_params.socket_path = (char *) malloc(sizeof TMP_SOCK_FILENAME_TPL + 1);
    strcpy(server_params.socket_path, TMP_SOCK_FILENAME_TPL);
    if(!mktemp(server_params.socket_path)) {
        perror("mktemp error");
        goto cleanup;
    }

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
        printf("giving up connection to test server");
        goto cleanup;
    }


    // open the control connection
    ctx = tmpContext(argv);
    serverAddr = I2AddrBySockFD(ctx->eh, fd, False);
    OWPErrSeverity owp_severity;
    cntrl = OWPControlOpen(ctx, NULL, serverAddr, OWP_MODE_OPEN, NULL, NULL, &owp_severity);

    if (!cntrl) {
        printf("OWPControlOpen error\n");
        goto cleanup;
    }

    if (memcmp(cntrl->readIV, SERVER_TEST_IV, 16)) {
        printf("incorrect server iv received");
        goto cleanup;
    }


    OWPTimeStamp curr_time;
    OWPGetTimeOfDay(ctx, &curr_time);
    tspec.start_time = curr_time.owptime;
    tspec.loss_timeout = OWPDoubleToNum64(0.0);
    tspec.typeP = 0; 
    tspec.packet_size_padding = 0;
    tspec.npackets = NUM_TEST_PACKETS;
    tspec.nslots = NUM_TEST_SLOTS;
    tspec.slots = (OWPSlot *) calloc(NUM_TEST_SLOTS, sizeof(OWPSlot));
    memset(tspec.slots, 0, NUM_TEST_SLOTS * sizeof(OWPSlot));
    for(int i=0; i<NUM_TEST_SLOTS; i++) {
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
        goto cleanup;
    }

    client_successful = 1;

cleanup:

    if (thread_valid) {
        // possible, but unlikely race condition
        if (test_results.test_complete) {
            pthread_join(server_thread, NULL);
        } else {
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

    int exit_code = !client_successful
        || !test_results.sent_greeting
        || !test_results.setup_response_ok
        || !test_results.sent_server_start
        || !test_results.sent_accept_session
        || !test_results.test_complete;
    exit(exit_code);
}

