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

#include <I2util/pbkdf2.h>
#include <I2util/hmac-sha1.h>

int
_OWPSendBlocksIntr(
        OWPControl  cntrl,
        uint8_t     *buf,
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
        return -1;
    } 

    return num_blocks;
}

int
_OWPReceiveBlocksIntr(
        OWPControl  cntrl,
        uint8_t     *buf,
        int         num_blocks,
        int         *retn_on_intr
        )
{
    ssize_t n;

    n = I2Readni(cntrl->sockfd,buf,num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE,
            retn_on_intr);
    if(n < 0){
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
        uint8_t     *buf,
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
        uint8_t     *buf,
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
 ** of (_OWP_RIJNDAEL_BLOCK_SIZE-byte) blocks. IV is currently updated within
 ** the rijndael api (blockEncrypt/blockDecrypt).
 */
int
_OWPEncryptBlocks(
        OWPControl  cntrl,
        uint8_t     *buf,
        int         num_blocks,
        uint8_t     *out
        )
{
    int r;
    r = blockEncrypt(cntrl->writeIV,&cntrl->encrypt_key,
            (uint8_t *)buf, num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE*8,
            (uint8_t *)out);
    if (r != num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE*8)
        return -1;
    return 0;
}


int
_OWPDecryptBlocks(
        OWPControl  cntrl,
        uint8_t     *buf,
        int         num_blocks,
        uint8_t     *out
        )
{
    int r;
    r = blockDecrypt(cntrl->readIV,&cntrl->decrypt_key,
            (uint8_t *)buf, num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE*8,
            (uint8_t *)out);
    if (r != num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE*8)
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
        uint8_t     binKey[_OWP_RIJNDAEL_BLOCK_SIZE]
        )
{
    cntrl->encrypt_key.Nr = rijndaelKeySetupEnc(cntrl->encrypt_key.rk,binKey,
                _OWP_RIJNDAEL_BLOCK_SIZE*8);
    cntrl->decrypt_key.Nr = rijndaelKeySetupDec(cntrl->decrypt_key.rk,binKey,
                _OWP_RIJNDAEL_BLOCK_SIZE*8);
}


/* 
 * The next two functions perform a single encryption/decryption
 * of the Token in the SetupResponse message from the Control protocol.
 *
 * (AES CBC, IV=0) key=pbkdf2(pf,salt,count)
 */

int
OWPEncryptToken(
        const uint8_t   *pf,
        size_t          pf_len,
        const uint8_t   salt[_OWP_SALT_SIZE],
        uint32_t        count,
        const uint8_t   token_in[_OWP_TOKEN_SIZE],
        uint8_t         token_out[_OWP_TOKEN_SIZE]
        )
{
    int         r;
    uint8_t     IV[_OWP_RIJNDAEL_BLOCK_SIZE];
    uint8_t     dk[_OWP_RIJNDAEL_BLOCK_SIZE];
    keyInstance key;

    /*
     * Derive key
     */
    if( (I2pbkdf2(I2HMACSha1,(uint32_t)I2SHA1_DIGEST_SIZE,
                    pf,pf_len,salt,_OWP_SALT_SIZE,count,sizeof(dk),dk))){
        return -1;
    }

    memset(IV, 0, _OWP_RIJNDAEL_BLOCK_SIZE);

    key.Nr = rijndaelKeySetupEnc(key.rk, dk, sizeof(dk)*8);
    r = blockEncrypt(IV,&key,token_in,_OWP_TOKEN_SIZE*8,token_out); 

    if (r != (_OWP_TOKEN_SIZE*8))
        return -1;

    return 0;
}

int
OWPDecryptToken(
        const uint8_t   *pf,
        size_t          pf_len,
        const uint8_t   salt[_OWP_SALT_SIZE],
        uint32_t        count,
        const uint8_t   token_in[_OWP_TOKEN_SIZE],
        uint8_t         token_out[_OWP_TOKEN_SIZE]
        )
{
    int         r;
    uint8_t    IV[_OWP_RIJNDAEL_BLOCK_SIZE];
    uint8_t    dk[_OWP_RIJNDAEL_BLOCK_SIZE];
    keyInstance key;

    /*
     * Derive key
     */
    if( (I2pbkdf2(I2HMACSha1,(uint32_t)I2SHA1_DIGEST_SIZE,
                    pf,pf_len,salt,_OWP_SALT_SIZE,count,sizeof(dk),dk))){
        return -1;
    }

    memset(IV, 0, _OWP_RIJNDAEL_BLOCK_SIZE);

    key.Nr = rijndaelKeySetupDec(key.rk, dk, 128);
    r = blockDecrypt(IV,&key,token_in,_OWP_TOKEN_SIZE*8,token_out); 

    if (r != (_OWP_TOKEN_SIZE*8))
        return -1;

    return 0;
}

/*
 * Function:    _OWPSendHMACAdd
 *
 * Description:    
 *              Adds data to the 'send' HMAC.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
void
_OWPSendHMACAdd(
        OWPControl  cntrl,
        const char  *txt,
        uint32_t    num_blocks
        )
{
    if( !(cntrl->mode & OWP_MODE_DOCIPHER)){
        return;
    }

    I2HMACSha1Append(cntrl->send_hmac_ctx,(uint8_t *)txt,
            num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE);

    return;
}

/*
 * Function:    _OWPSendHMACDigestClear
 *
 * Description:    
 *              Fetches the digest from the 'send' HMAC and
 *              clears the digest in preparation for the next
 *              "message".
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
void
_OWPSendHMACDigestClear(
        OWPControl  cntrl,
        char        digest[_OWP_RIJNDAEL_BLOCK_SIZE]
        )
{
    uint8_t hmacd[I2HMAC_SHA1_DIGEST_SIZE];

    if( !(cntrl->mode & OWP_MODE_DOCIPHER)){
        return;
    }

    memset(digest,0,_OWP_RIJNDAEL_BLOCK_SIZE);
    memset(hmacd,0,sizeof(hmacd));

    I2HMACSha1Finish(cntrl->send_hmac_ctx,hmacd);
    memcpy(digest,hmacd,MIN(_OWP_RIJNDAEL_BLOCK_SIZE,sizeof(hmacd)));

    I2HMACSha1Init(cntrl->send_hmac_ctx,cntrl->hmac_key,
            sizeof(cntrl->hmac_key));
    return;
}

/*
 * Function:    _OWPRecvHMACAdd
 *
 * Description:    
 *              Adds data to the 'send' HMAC.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
void
_OWPRecvHMACAdd(
        OWPControl  cntrl,
        const char  *txt,
        uint32_t    num_blocks
        )
{
    if( !(cntrl->mode & OWP_MODE_DOCIPHER)){
        return;
    }

    I2HMACSha1Append(cntrl->recv_hmac_ctx,(uint8_t *)txt,
            num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE);

    return;
}

/*
 * Function:    _OWPRecvHMACCheckClear
 *
 * Description:    
 *              Determines if the hmac sent from the remote
 *              party matches the locally computed one. Then
 *              clears the hmac and prepares it for the next
 *              message.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
OWPBoolean
_OWPRecvHMACCheckClear(
        OWPControl  cntrl,
        char        check[_OWP_RIJNDAEL_BLOCK_SIZE]
        )
{
    uint8_t     hmacd[I2HMAC_SHA1_DIGEST_SIZE];
    OWPBoolean  rval;

    if( !(cntrl->mode & OWP_MODE_DOCIPHER)){
        return True;
    }

    memset(hmacd,0,sizeof(hmacd));

    I2HMACSha1Finish(cntrl->recv_hmac_ctx,hmacd);
    rval = (memcmp(check,hmacd,
                MIN(_OWP_RIJNDAEL_BLOCK_SIZE,sizeof(hmacd))) == 0);

    I2HMACSha1Init(cntrl->recv_hmac_ctx,cntrl->hmac_key,
            sizeof(cntrl->hmac_key));

    return rval;
}
