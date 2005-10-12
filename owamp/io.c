/*
 **      $Id$
 */
/************************************************************************
 *                                                                      *
 *                             Copyright (C)  2002                      *
 *                                Internet2                             *
 *                             All Rights Reserved                      *
 *                                                                      *
 ************************************************************************/
/*
 **        File:        io.c
 **
 **        Author:      Jeff W. Boote
 **                     Anatoly Karp
 **
 **        Date:        Wed Apr  24 10:42:12  2002
 **
 **        Description: This file contains the private functions to
 **                     to facilitate IO that the library needs to do.
 */
#include <owampP.h>

int
_OWPSendBlocksIntr(
        OWPControl  cntrl,
        u_int8_t    *buf,
        int         num_blocks,
        int         *retn_on_intr
        )
{
    ssize_t n;

    if (cntrl->mode & OWP_MODE_DOCIPHER)
        _OWPEncryptBlocks(cntrl, buf, num_blocks, buf);

    n = I2Writeni(cntrl->sockfd,buf,num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE,
            retn_on_intr);
    if(n < 0){
        if(!*retn_on_intr || (errno != EINTR)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,
                    "I2Writeni(): %M");
        }
        return -1;
    } 

    return num_blocks;
}

int
_OWPReceiveBlocksIntr(
        OWPControl  cntrl,
        u_int8_t    *buf,
        int         num_blocks,
        int         *retn_on_intr
        )
{
    ssize_t n;

    n = I2Readni(cntrl->sockfd,buf,num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE,
            retn_on_intr);
    if(n < 0){
        if(!*retn_on_intr || (errno != EINTR)){
            OWPError(cntrl->ctx,OWPErrFATAL,errno,"I2Readni(): %M");
        }
        return -1;
    } 

    /*
     * Short reads mean socket was closed.
     */
    if(n != (num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE))
        return 0;

    if (cntrl->mode & OWP_MODE_DOCIPHER)
        _OWPDecryptBlocks(cntrl, buf, num_blocks, buf);

    return num_blocks;
}

int
_OWPSendBlocks(
        OWPControl  cntrl,
        u_int8_t    *buf,
        int         num_blocks
        )
{
    int intr=0;
    int *retn_on_intr = &intr;

    if(cntrl->retn_on_intr){
        retn_on_intr = cntrl->retn_on_intr;
    }

    return _OWPSendBlocksIntr(cntrl,buf,num_blocks,retn_on_intr);
}

int
_OWPReceiveBlocks(
        OWPControl  cntrl,
        u_int8_t    *buf,
        int         num_blocks
        )
{
    int intr=0;
    int *retn_on_intr = &intr;

    if(cntrl->retn_on_intr){
        retn_on_intr = cntrl->retn_on_intr;
    }

    return _OWPReceiveBlocksIntr(cntrl,buf,num_blocks,retn_on_intr);
}

/*
 ** The following two functions encrypt/decrypt a given number
 ** of (16-byte) blocks. IV is currently updated within
 ** the rijndael api (blockEncrypt/blockDecrypt).
 */
int
_OWPEncryptBlocks(
        OWPControl  cntrl,
        u_int8_t    *buf,
        int         num_blocks,
        u_int8_t    *out
        )
{
    int r;
    r = blockEncrypt(cntrl->writeIV, 
            &cntrl->encrypt_key, buf, num_blocks*16*8, out);
    if (r != num_blocks*16*8)
        return -1;
    return 0;
}


int
_OWPDecryptBlocks(
        OWPControl  cntrl,
        u_int8_t    *buf,
        int         num_blocks,
        u_int8_t    *out
        )
{
    int r;
    r = blockDecrypt(cntrl->readIV, 
            &cntrl->decrypt_key, buf, num_blocks*16*8, out);
    if (r != num_blocks*16*8)
        return -1;
    return 0;
}

/*
 ** This function sets up the key field of a OWPControl structure,
 ** using the binary key located in <binKey>.
 */

void
_OWPMakeKey(
        OWPControl  cntrl,
        u_int8_t    *binKey
        )
{
    cntrl->encrypt_key.Nr
        = rijndaelKeySetupEnc(cntrl->encrypt_key.rk, binKey, 128);
    cntrl->decrypt_key.Nr 
        = rijndaelKeySetupDec(cntrl->decrypt_key.rk, binKey, 128);
}


/* 
 ** The next two functions perform a single encryption/decryption
 ** of Token in Control protocol, using a given (binary) key and the IV of 0.
 */

#define TOKEN_BITS_LEN (2*16*8)

int
OWPEncryptToken(
        unsigned char   *binKey,
        unsigned char   *token_in,
        unsigned char   *token_out
        )
{
    int         r;
    u_int8_t    IV[16];
    keyInstance key;

    memset(IV, 0, 16);

    key.Nr = rijndaelKeySetupEnc(key.rk, binKey, 128);
    r = blockEncrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 

    if (r != TOKEN_BITS_LEN)
        return -1;

    return 0;
}

int
OWPDecryptToken(
        unsigned char   *binKey,
        unsigned char   *token_in,
        unsigned char   *token_out
        )
{
    int         r;
    u_int8_t    IV[16];
    keyInstance key;

    memset(IV, 0, 16);

    key.Nr = rijndaelKeySetupDec(key.rk, binKey, 128);
    r = blockDecrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 

    if (r != TOKEN_BITS_LEN)
        return -1;

    return 0;
}
