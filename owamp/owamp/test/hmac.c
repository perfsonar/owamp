/*
 *        File:         hmac.c 
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  HMAC-SHA1 verifications based on data from RFC 2202
 */
#include <string.h>
#include <I2util/hmac-sha1.h>
#include <openssl/hmac.h>

struct _test_case {
    int test_case;
    uint8_t *key;
    int key_len;
    uint8_t *data;
    int data_len;
    uint8_t digest[20];
};

/**
 * init _test_case structs containing the data from rfc 2202
 */
struct _test_case **init_test_case_defs() {
    struct _test_case **tcs = (struct _test_case **) calloc(8, sizeof(struct _test_case *));

    tcs[0] = (struct _test_case *) malloc(sizeof(struct _test_case));
    tcs[0]->test_case = 1;
    tcs[0]->key = (uint8_t *) malloc(20);
    memset(tcs[0]->key, 0xb, 20);
    tcs[0]->key_len = 20;
    tcs[0]->data = (uint8_t *) malloc(8);
    memcpy(tcs[0]->data, "Hi There", 8);
    tcs[0]->data_len = 8;
    I2HexDecode("b617318655057264e28bc0b6fb378c8ef146be00", tcs[0]->digest, 20);

    tcs[1] = (struct _test_case *) malloc(sizeof(struct _test_case));
    tcs[1]->test_case = 2;
    tcs[1]->key = (uint8_t *) malloc(4);
    memcpy(tcs[1]->key, "Jefe", 4);
    tcs[1]->key_len = 4;
    tcs[1]->data = (uint8_t *) malloc(28);
    memcpy(tcs[1]->data, "what do ya want for nothing?", 28);
    tcs[1]->data_len = 28;
    I2HexDecode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", tcs[1]->digest, 20);

    tcs[2] = (struct _test_case *) malloc(sizeof(struct _test_case));
    tcs[2]->test_case = 3;
    tcs[2]->key = (uint8_t *) malloc(20);
    memset(tcs[2]->key, 0xaa, 20);
    tcs[2]->key_len = 20;
    tcs[2]->data = (uint8_t *) malloc(50);
    memset(tcs[2]->data, 0xdd, 50);
    tcs[2]->data_len = 50;
    I2HexDecode("125d7342b9ac11cd91a39af48aa17b4f63f175d3", tcs[2]->digest, 20);

    tcs[3] = (struct _test_case *) malloc(sizeof(struct _test_case));
    tcs[3]->test_case = 4;
    tcs[3]->key = (uint8_t *) malloc(25);
    I2HexDecode("0102030405060708090a0b0c0d0e0f10111213141516171819", tcs[3]->key, 25);
    tcs[3]->key_len = 25;
    tcs[3]->data = (uint8_t *) malloc(50);
    memset(tcs[3]->data, 0xcd, 50);
    tcs[3]->data_len = 50;
    I2HexDecode("4c9007f4026250c6bc8414f9bf50c86c2d7235da", tcs[3]->digest, 20);

    tcs[4] = (struct _test_case *) malloc(sizeof(struct _test_case));
    tcs[4]->test_case = 5;
    tcs[4]->key = (uint8_t *) malloc(20);
    memset(tcs[4]->key, 0xc, 20);
    tcs[4]->key_len = 20;
    tcs[4]->data = (uint8_t *) malloc(20);
    memcpy(tcs[4]->data, "Test With Truncation", 20);
    tcs[4]->data_len = 20;
    I2HexDecode("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", tcs[4]->digest, 20);

    tcs[5] = (struct _test_case *) malloc(sizeof(struct _test_case));
    tcs[5]->test_case = 6;
    tcs[5]->key = (uint8_t *) malloc(80);
    memset(tcs[5]->key, 0xaa, 80);
    tcs[5]->key_len = 80;
    tcs[5]->data = (uint8_t *) malloc(54);
    memcpy(tcs[5]->data, "Test Using Larger Than Block-Size Key - Hash Key First", 54);
    tcs[5]->data_len = 54;
    I2HexDecode("aa4ae5e15272d00e95705637ce8a3b55ed402112", tcs[5]->digest, 20);

    tcs[6] = (struct _test_case *) malloc(sizeof(struct _test_case));
    tcs[6]->test_case = 7;
    tcs[6]->key = (uint8_t *) malloc(80);
    memset(tcs[6]->key, 0xaa, 80);
    tcs[6]->key_len = 80;
    tcs[6]->data = (uint8_t *) malloc(73);
    memcpy(tcs[6]->data, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73);
    tcs[6]->data_len = 73;
    I2HexDecode("e8e99d0f45237d786d6bbaa7965c7808bbff1a91", tcs[6]->digest, 20);

    tcs[7] = NULL;

    return tcs;
}

/*
 * free a structure allocated by init_test_case_defs
 */
void free_test_case_defs(struct _test_case **test_case_defs) {
    struct _test_case **pptc;
    for(pptc = test_case_defs; *pptc != NULL; pptc++) {
        free((*pptc)->key);
        free((*pptc)->data);
        free(*pptc);
    }
    free(test_case_defs);
} 

/*
 * verify the hmac calculation using openssl
 *
 * returns non-zero in case of error
 */
int openssl_api_test(struct _test_case *tc) {
    HMAC_CTX *ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = HMAC_CTX_new();
#else
    HMAC_CTX _ctx;
    HMAC_CTX_init(&_ctx);
    ctx = &_ctx;
#endif

    if (! ctx)
        return -1;

    HMAC_Init_ex(ctx, tc->key, tc->key_len, EVP_sha1(), NULL);
    HMAC_Update(ctx, tc->data, tc->data_len);

    uint8_t digest[20];
    unsigned int digest_len = sizeof digest;
    HMAC_Final(ctx, digest, &digest_len);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return memcmp(tc->digest, digest, 20);
}

/*
 * verify the hmac calculation using the I2Utils api
 *
 * the OWP api assumes messages with aes block sizes, but
 * the test data doesn't satisfy this condition - so use
 * the I2Utils api directly in the same way it's used in
 * the OWP api wrappers
 *
 * returns non-zero in case of error
 */
int owp_hmac_test(struct _test_case *tc) {
    I2HMACSha1Context ctx = I2HMACSha1Alloc(NULL);

    I2HMACSha1Init(ctx, tc->key, tc->key_len);
    I2HMACSha1Append(ctx, tc->data, tc->data_len);

    uint8_t digest[20];
    I2HMACSha1Finish(ctx, digest);

    I2HMACSha1Free(ctx);

    return memcmp(tc->digest, digest, 20);
}



int main(int argc, char *argv[]) {

    int error_found = 0;
    struct _test_case **test_case_defs = init_test_case_defs();
    struct _test_case **pptc;
    for(pptc = test_case_defs; *pptc != NULL; pptc++) {
        printf("verifying test data set #%d ...\n", (*pptc)->test_case);
        if(openssl_api_test(*pptc)) {
            error_found = 1;
            printf("\topenssl hash api error\n");
        }
        if(owp_hmac_test(*pptc)) {
            error_found = 1;
            printf("\towp hash api error\n");
        }
    }
    free_test_case_defs(test_case_defs);

    printf("test %s\n", error_found ? "failed" : "passed");
    return error_found;
}

