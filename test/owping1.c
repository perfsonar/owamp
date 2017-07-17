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



int do_server(int s, uint32_t start_time) {

    struct _greeting greeting;
    memset(&greeting, 0, sizeof greeting);
    *((uint32_t *) greeting.Modes) = htonl(7);
    memset(greeting.Challenge, 0x55, sizeof greeting.Challenge);
    memset(greeting.Salt, 0x78, sizeof greeting.Salt);
    *((uint32_t *) greeting.Count) = htonl(1024);
    write(s, &greeting, sizeof greeting);


    struct _setup_response setup_response;
    read(s, &setup_response, sizeof setup_response);
    uint32_t mode = ntohl(*(uint32_t *) &setup_response.Mode);
    if (mode != OWP_MODE_OPEN) {
        printf("expeced setup response mode == OWP_MODE_OPEN, got: 0x%08x", mode);
        return 1;
    }
    // nothing to check in the other fields in unauthenticated mode

   
    struct _server_start server_start;
    memset(&server_start, 0, sizeof server_start);
    *((uint32_t *) server_start.Start_Time) = htonl(start_time);
    write(s, &server_start, sizeof server_start);


    for(int i=0; i<100; i++) {
        char c;
        if(read(s, &c, 1) <= 0) {
            perror("read error");
            exit(1);
        }

        printf("read byte #%d: 0x%02x\n", i, (int) c);

        c = ~c;
        if(write(s, &c, 1) <= 0) {
            perror("write error");
            exit(1);
        }
    }

    printf("do_server: finished!\n");
    return 0;
}

void *server_proc(void *socket_path) {
    int fd;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, (char *) socket_path, sizeof addr.sun_path - 1);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("error creating server socket");
        exit(1);
    }

    if(bind(fd, (struct sockaddr *) &addr, sizeof addr) == -1) {
        perror("bind error");
        exit(1);
    }

   if (listen(fd, 1) == -1) {
        perror("listen error");
        exit(1);
    }

    uint32_t server_start_time = (uint32_t) time(NULL);

    while(1) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd == -1) {
            perror("accept error");
            exit(1);
        }

        if (do_server(cfd, server_start_time)) {
            close(fd);
            exit(1);
        }

        close(cfd);
    }

    close(fd);
    return NULL;
}

int
main(
        int     argc    __attribute__((unused)),
        char    **argv
    ) {

    char *socket_path = (char *) malloc(sizeof TMP_SOCK_FILENAME_TPL + 1);
    strcpy(socket_path, TMP_SOCK_FILENAME_TPL);

    if(!mktemp(socket_path)) {
        perror("mktemp error");
        exit(1);
    }

    pthread_t server_thread;

    errno = pthread_create(&server_thread, NULL, server_proc, socket_path);
    if (errno) {
        perror("pthread_create error");
        exit(1);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("error creating client socket");
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof addr.sun_path - 1);


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
        exit(1);
    }


    OWPContext ctx = tmpContext(argv);
    I2Addr serverAddr = I2AddrBySockFD(ctx->eh, fd, False);
    OWPErrSeverity  owp_severity;
    OWPControl cntrl = OWPControlOpen(
        ctx, NULL, serverAddr,
        OWP_MODE_OPEN, NULL,
        NULL, &owp_severity);

    if (!cntrl) {
        printf("OWPControlOpen error\n");
        exit(1);
    }

    pthread_cancel(server_thread);
    unlink(socket_path);

    OWPControlClose(cntrl);
    OWPContextFree(ctx);
    close(fd);
}

