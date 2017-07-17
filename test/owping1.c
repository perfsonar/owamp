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

struct _greeting {
    uint8_t Unused[12];
    uint8_t Modes[4];
    uint8_t Challenge[16];
    uint8_t Salt[16];
    uint8_t Count[4];
    uint8_t MBZ[12];
};

struct _setup_response {
    uint8_t Mode[4];
    uint8_t KeyID[80];
    uint8_t Token[64];
    uint8_t Client_IV[16];
};

struct _server_start {
    uint8_t MBZ_Accept[16];
    uint8_t Server_IV[16];
    uint8_t Start_Time[4];
    uint8_t MBZ2[15];
};


struct _server_test_results {
    uint32_t start_time;
    int sent_greeting;
    int setup_response_ok;
    int sent_server_start;
    int test_complete;
};


int do_server(int s, void *context) {

    struct _server_test_results *test_results
        = (struct _server_test_results *) context;
    memset(test_results, 0, sizeof (struct _server_test_results));

    struct _greeting greeting;
    memset(&greeting, 0, sizeof greeting);
    *((uint32_t *) greeting.Modes) = htonl(7);
    memset(greeting.Challenge, 0x55, sizeof greeting.Challenge);
    memset(greeting.Salt, 0x78, sizeof greeting.Salt);
    *((uint32_t *) greeting.Count) = htonl(1024);
    test_results->sent_greeting 
        = write(s, &greeting, sizeof greeting) == sizeof greeting;


    struct _setup_response setup_response;
    if(read(s, &setup_response, sizeof setup_response) != sizeof setup_response) {
        printf("error reading setup response: '%m'\n");
        return 0;
    }

    uint32_t mode = ntohl(*(uint32_t *) &setup_response.Mode);
    if (mode != OWP_MODE_OPEN) {
        printf("expeced setup response mode == OWP_MODE_OPEN, got: 0x%08x", mode);
        return 0;
    }
    // nothing to check in the other fields in unauthenticated mode
    test_results->setup_response_ok = 1;

    struct _server_start server_start;
    memset(&server_start, 0, sizeof server_start);
    *((uint32_t *) server_start.Start_Time) = htonl(test_results->start_time);
    test_results->sent_server_start
        = write(s, &server_start, sizeof server_start) == sizeof server_start;

    printf("do_server: finished!\n");
    test_results->test_complete = 1;
    return 0;
}


int
main(
    int argc __attribute__((unused)),
    char    **argv
) {

    pthread_t server_thread;
    int thread_valid = 0;
    OWPContext ctx = NULL;
    I2Addr serverAddr = NULL;
    OWPControl cntrl = NULL;
    int fd = -1;
    struct _server_params server_params;
    struct _server_test_results test_results;

    memset(&test_results, 0, sizeof test_results);
    test_results.start_time = (uint32_t) time(NULL);
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
            printf("%s:%d waiting for server: '%m'\n", __func__, __LINE__);
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
    }


cleanup:

    if (thread_valid) {
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

    int exit_code = !test_results.sent_greeting
        || !test_results.setup_response_ok
        || !test_results.sent_server_start
        || !test_results.test_complete;
    exit(exit_code);
}

