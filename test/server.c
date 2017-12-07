/*
 *        File:         server.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Basic twping control server emulation
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>

#include <owamp/owamp.h>
#
#include "./server.h"

//#include <I2util/util.h>
#include <I2util/hmac-sha1.h>
#include <I2util/pbkdf2.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>


#define SESSION_PORT 0xABCD // not verified 
#define GREETING_COUNT 1024
#define GREETING_CHALLENGE "just a challenge"
#define GREETING_SALT "some funny saltT"
#define SERVER_TEST_IV "this is the IV!!"



// Greeting message [RFC 4656 pg. 6]
struct _greeting {
    uint8_t Unused[12];
    uint32_t Modes;
    uint8_t Challenge[16];
    uint8_t Salt[16];
    uint32_t Count;
    uint8_t MBZ[12];
};

// Set-Up-Response message [RFC 4656 pg. 7]
struct _setup_response {
    uint32_t Mode;
    char KeyID[80];
    uint8_t Token[64];
    uint8_t Client_IV[16];
};

// Server-Start message [RFC 4656 pg. 9]
struct _server_start {
    uint8_t MBZ[15];
    uint8_t Accept;
    uint8_t Server_IV[16];
    uint64_t StartTime;
    uint8_t MBZ2[8];
};

// Request-Session message [RFC 4656 pg. 13]
#pragma pack(push)
#pragma pack(4) // StartTime & Timeout don't fall on dword boundaries
struct _request_session {
    // 00
    uint8_t CommandId;
    union {
        uint8_t MBZ: 4;
        uint8_t IPVN: 4;
    } version;
    uint8_t ConfSender;
    uint8_t ConfReceiver;

    // 04
    uint32_t NumSlots;

    // 08
    uint32_t NumPackets;

    // 12
    uint16_t SenderPort;
    uint16_t ReceiverPort;

    // 16/20/24/28
    uint8_t SenderAddress[4];
    uint8_t SenderAddress1[12];

    // 32/36/40/44
    uint8_t ReceiverAddress[4];
    uint8_t ReceiverAddress2[12];

    // 48/52/56/60
    uint8_t SID[16];

    // 64
    uint32_t PaddingLength;

    // 68/72
    uint64_t StartTime;

    // 76/80
    uint64_t Timeout;

    // 84
    uint32_t TypeP;

    // 88/92
    uint8_t MBZ2[8];

    // 96/100/104/108
    uint8_t HMAC[16];
};
#pragma pack(pop)


// schedule slot description format [RFC 4656 pg. 14]
// these are sent following the Request-Session message
struct _schedule_slot_description {
    uint8_t slot_type;
    uint8_t MBZ[7];
    uint64_t SlotParameter;
};

// hmac sent following a sequence of schedule
// slot descriptions
struct _hmac {
    uint8_t hmac[16];
};

// Accept-Session message [RFC 4656 pg. 16]
struct _accept_session {
    uint8_t Accept;
    uint8_t MBZ;
    uint16_t Port;
    uint8_t SID[16];
    uint8_t MBZ2[12];
    uint8_t HMAC[16];
};

struct _session_token {
    uint8_t challenge[16];
    uint8_t aes_session_key[16];
    uint8_t hmac_session_key[32];
};


/*
 * Function:        encrypt_outgoing
 *
 * Description:     wrapper used below for aes/cbc encrypting output using a
 *                  fresh temporary context, clear/cipher buffers can overlap
 *
 * In Args:
 *
 * Out Args:
 *
 * Scope:
 * Returns:         iv for the next cbc cipher
 *
 * Side Effect:     asserts if message_size % 16 != 0
 */
static void encrypt_outgoing(
    void *clear,
    void *cipher, /* can overlap with clear */
    size_t message_size,
    uint8_t key_bytes[16],
    uint8_t iv_bytes[16] /* [in|out] */) {

    assert(message_size % 16 == 0); // sanity (not a generic function)
    if (message_size == 0) { return; }

    AES_KEY key;
    AES_set_encrypt_key(key_bytes, 128, &key);

    void *output_tmp = malloc(message_size);
    AES_cbc_encrypt(
        clear,
        output_tmp,
        message_size,
        &key,
        iv_bytes,
        AES_ENCRYPT);

    memcpy(cipher, output_tmp, message_size);
    memcpy(iv_bytes, &((uint8_t *)cipher)[message_size-16], 16);
    free(output_tmp);
}

/*
 * Function:        decrypt_outgoing
 *
 * Description:     wrapper used below for aes/cbc decrypting input using a
 *                  fresh temporary context, clear/cipher buffers can overlap
 *
 * In Args:
 *
 * Out Args:
 *
 * Scope:
 * Returns:         iv for the next cbc cipher
 *
 * Side Effect:     asserts if message_size % 16 != 0
 */
static void decrypt_incoming(
    void *cipher,
    void *clear, /* can overlap with cipher */
    size_t message_size,
    uint8_t key_bytes[16],
    uint8_t iv_bytes[16] /* [in|out] */) {

    assert(message_size % 16 == 0); // sanity (not a generic function)
    if (message_size == 0) { return; }

    uint8_t next_iv[16];
    memcpy(next_iv, &((uint8_t *)cipher)[message_size-16], 16);

    AES_KEY key;
    AES_set_decrypt_key(key_bytes, 128, &key);

    void *output_tmp = malloc(message_size);
    AES_cbc_encrypt(
        cipher,
        output_tmp,
        message_size,
        &key,
        iv_bytes,
        AES_DECRYPT);

    memcpy(clear, output_tmp, message_size);
    memcpy(iv_bytes, next_iv, 16);
    free(output_tmp);
}

/*
 * Function:        do_control_setup_server
 *
 * Description:     emulates the server side of the test control protocol 
 *
 * In Args:         void pointer to struct _server_test_params
 *
 * Out Args:
 *
 * Scope:
 * Returns:         0 (i.e. test is finished - server shouldn't accept new clients)
 *
 * Side Effect:
 */
int do_control_setup_server(int s, void *context) {

    struct _server_test_params *test_context
        = (struct _server_test_params *) context;
    memset(&test_context->output, 0, sizeof test_context->output);

    struct _schedule_slot_description *slots = NULL;

    HMAC_CTX send_hmac_ctx;
    HMAC_CTX receive_hmac_ctx;
    HMAC_CTX_init(&send_hmac_ctx);
    HMAC_CTX_init(&receive_hmac_ctx);

    uint8_t expected_hmac[20];
    unsigned int hmac_len = sizeof expected_hmac;
 
    struct _greeting greeting;
    memset(&greeting, 0, sizeof greeting);
    greeting.Modes = htonl(OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED|OWP_MODE_OPEN);
    memcpy(greeting.Challenge, GREETING_CHALLENGE, sizeof greeting.Challenge);
    memcpy(greeting.Salt, GREETING_SALT, sizeof greeting.Salt);
    greeting.Count = htonl(GREETING_COUNT);
    test_context->output.sent_greeting 
        = write(s, &greeting, sizeof greeting) == sizeof greeting;

    struct _setup_response setup_response;
    if(recv(s, &setup_response, sizeof setup_response, MSG_WAITALL) != sizeof setup_response) {
        perror("error reading setup response");
        goto cleanup;
    }


    uint32_t mode = ntohl(setup_response.Mode);
    if (mode != test_context->input.expected_modes) {
        printf("expected setup response mode == 0x%08x, got: 0x%08x",
            test_context->input.expected_modes, mode);
        goto cleanup;
    }

    if (mode & (OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED)) {
            if (strcmp(setup_response.KeyID, SESSION_USERID)) {
            printf("expected key id '%s', got '%s'\n",
                    SESSION_USERID, setup_response.KeyID);
            goto cleanup;
            }
    }

    uint8_t dk[16];
    assert(strlen(GREETING_SALT) == 16); // _OWP_SALT_SIZE, config sanity
    if( I2pbkdf2(
            I2HMACSha1,
            (uint32_t) I2SHA1_DIGEST_SIZE,
            (uint8_t *) SESSION_PASSPHRASE,
            strlen(SESSION_PASSPHRASE),
            (uint8_t *) GREETING_SALT,
            strlen(GREETING_SALT),
            GREETING_COUNT,
            sizeof(dk), dk) ) {
        printf("error deriving token decryption key\n");
        goto cleanup;
    }

    struct _session_token clear_session_token;
    assert(sizeof clear_session_token == sizeof setup_response.Token); // config sanity
    memset(&clear_session_token, 0, sizeof clear_session_token);

    if (mode & (OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED)) {
        // decrypt the token
        AES_KEY tk;
        AES_set_decrypt_key(dk, 8 * sizeof(dk), &tk);
        uint8_t iv[16];
        memset(iv, 0, sizeof iv);
        AES_cbc_encrypt(
                setup_response.Token,
                (void *) &clear_session_token,
                sizeof setup_response.Token,
                &tk, iv, AES_DECRYPT);

        if (memcmp(clear_session_token.challenge, GREETING_CHALLENGE, sizeof clear_session_token.challenge)) {
            printf("failed to validate challenge in decrypted token\n");
            goto cleanup;
        }
    }


    // nothing to check in the other fields in unauthenticated mode
    test_context->output.setup_response_ok = 1;

    uint8_t enc_session_iv[16];
    uint8_t dec_session_iv[16];
    memcpy(enc_session_iv, SERVER_TEST_IV, sizeof enc_session_iv);
    memcpy(dec_session_iv, setup_response.Client_IV, sizeof dec_session_iv);

    HMAC_Init_ex(&send_hmac_ctx,
            clear_session_token.hmac_session_key, sizeof clear_session_token.hmac_session_key,
            EVP_sha1(), NULL);
    HMAC_Init_ex(&receive_hmac_ctx,
            clear_session_token.hmac_session_key, sizeof clear_session_token.hmac_session_key,
            EVP_sha1(), NULL);


    struct _server_start server_start;
    memset(&server_start, 0, sizeof server_start);
    server_start.StartTime = htonll(time(NULL));
    memcpy(server_start.Server_IV, SERVER_TEST_IV, sizeof server_start.Server_IV);

    HMAC_Update(&send_hmac_ctx, (unsigned char *) &server_start.StartTime, 16);
    if (mode & OWP_MODE_ENCRYPTED) {
        encrypt_outgoing(&server_start.StartTime, &server_start.StartTime, 16,
                clear_session_token.aes_session_key, enc_session_iv);
    }

    test_context->output.sent_server_start
        = write(s, &server_start, sizeof server_start) == sizeof server_start;
    if (!test_context->output.sent_server_start) {
        perror("error sending server start response");
        goto cleanup;
    }

    struct _request_session request_session;
    if (recv(s, &request_session, sizeof request_session, MSG_WAITALL) != sizeof request_session) {
        perror("error reading request session message");
        goto cleanup; 
    }

    if (mode & OWP_MODE_ENCRYPTED) {
        decrypt_incoming(&request_session, &request_session, sizeof request_session,
                clear_session_token.aes_session_key, dec_session_iv);
    }

    HMAC_Update(&receive_hmac_ctx, (unsigned char *) &request_session, (sizeof request_session) - 16);
    hmac_len = sizeof expected_hmac;
    HMAC_Final(&receive_hmac_ctx, expected_hmac, &hmac_len);
    assert(hmac_len == 20);
    HMAC_Init_ex(&receive_hmac_ctx, NULL, 0, NULL, NULL);

    if (mode & (OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED)) {
        if (memcmp(expected_hmac, request_session.HMAC, 16)) {
            printf("hmac verification error in Request-Session\n");
            goto cleanup;
        }
    }

    uint32_t num_slots = ntohl(request_session.NumSlots);
    if (num_slots != test_context->input.expected_num_test_slots) {
        printf("expected %d test slots, got %d\n",
            test_context->input.expected_num_test_slots, num_slots);
        goto cleanup;
    }

    uint32_t num_packets = ntohl(request_session.NumPackets);
    if (num_packets != test_context->input.expected_num_test_packets) {
        printf("expected %d test packets, got %d\n",
            test_context->input.expected_num_test_packets, num_packets);
        goto cleanup;
    }

    if (num_slots) {
        slots = (struct _schedule_slot_description *)
            calloc(num_slots, sizeof(struct _schedule_slot_description));
        size_t slots_num_bytes = num_slots * sizeof(struct _schedule_slot_description);
        if (recv(s, slots, slots_num_bytes, MSG_WAITALL) != slots_num_bytes) {
            perror("error reading slot descriptions");
            goto cleanup;
        }

        if (mode & (OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED)) {
            decrypt_incoming(slots, slots, slots_num_bytes,
                    clear_session_token.aes_session_key, dec_session_iv);
        }

        HMAC_Update(&receive_hmac_ctx, (unsigned char *) slots, slots_num_bytes);
        hmac_len = sizeof expected_hmac;
        HMAC_Final(&receive_hmac_ctx, expected_hmac, &hmac_len);
        assert(hmac_len == 20);
        HMAC_Init_ex(&receive_hmac_ctx, NULL, 0, NULL, NULL);

        struct _hmac hmac;
        if (recv(s, &hmac, sizeof hmac, MSG_WAITALL) != sizeof hmac) {
            perror("error reading hmac");
            goto cleanup;
        }

        if (mode & OWP_MODE_ENCRYPTED) {
            decrypt_incoming(&hmac, &hmac, sizeof hmac,
                    clear_session_token.aes_session_key, dec_session_iv);
        }

        if (mode & (OWP_MODE_ENCRYPTED|OWP_MODE_AUTHENTICATED)) {
            if (memcmp(expected_hmac, hmac.hmac, 16)) {
                printf("hmac verification error for Slot list\n");
                goto cleanup;
            }
        }
    }

    struct _accept_session accept_session;
    memset(&accept_session, 0, sizeof accept_session);
    assert(sizeof accept_session.SID <= sizeof test_context->input.sid); // config sanity
    memcpy(&accept_session.SID, test_context->input.sid, sizeof accept_session.SID);
    accept_session.Port = htons(SESSION_PORT);

    HMAC_Update(&send_hmac_ctx, (unsigned char *) &accept_session, (sizeof accept_session) - 16);
    hmac_len = sizeof expected_hmac;
    HMAC_Final(&send_hmac_ctx, expected_hmac, &hmac_len);
    assert(hmac_len == 20);
    memcpy(accept_session.HMAC, expected_hmac, sizeof accept_session.HMAC);
    HMAC_Init_ex(&send_hmac_ctx, NULL, 0, NULL, NULL); // reset in case we continue
    if (mode & OWP_MODE_ENCRYPTED) {
        encrypt_outgoing(&accept_session, &accept_session, sizeof accept_session,
                clear_session_token.aes_session_key, enc_session_iv);
    }

    if (write(s, &accept_session, sizeof accept_session) != sizeof accept_session) {
        perror("error sending Accept-Session response");
        goto cleanup;
    }

    test_context->output.sent_accept_session = 1;

    printf("do_server: finished!\n");
    test_context->output.test_complete = 1;

cleanup:
    if (slots) {
        free(slots);
    }

    HMAC_CTX_cleanup(&send_hmac_ctx);
    HMAC_CTX_cleanup(&receive_hmac_ctx);

    return 0;
}

