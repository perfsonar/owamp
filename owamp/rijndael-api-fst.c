/**
 * rijndael-api-fst.c
 *
 * @version 2.9 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Acknowledgements:
 *
 * We are deeply indebted to the following people for their bug reports,
 * fixes, and improvement suggestions to this implementation. Though we
 * tried to list all contributions, we apologise in advance for any
 * missing reference.
 *
 * Andrew Bales <Andrew.Bales@Honeywell.com>
 * Markus Friedl <markus.friedl@informatik.uni-erlangen.de>
 * John Skodon <skodonj@webquill.com>
 */
#include <owamp/owamp.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "rijndael-alg-fst.h"
#include "rijndael-api-fst.h"

#include <sys/param.h>

/*
 ** This function sets up a binary key based on a 32-byte
 ** hex-encoded raw key material.
 */
int 
makeKey(
        keyInstance *key,
        BYTE        direction,
        char        *keyMaterial
        )
{
    int i;
    u8  cipherKey[MAXKB];

    if (key == NULL) {
        return BAD_KEY_INSTANCE;
    }


    /* initialize key schedule: */
    /*        keyMat = key->keyMaterial; */
    for (i = 0; i < 128/8; i++) {
        int t, v;

        t = *keyMaterial++;
        if ((t >= '0') && (t <= '9')) v = (t - '0') << 4;
        else if ((t >= 'a') && (t <= 'f')) v = (t - 'a' + 10) << 4;
        else if ((t >= 'A') && (t <= 'F')) v = (t - 'A' + 10) << 4;
        else return BAD_KEY_MAT;

        t = *keyMaterial++;
        if ((t >= '0') && (t <= '9')) v ^= (t - '0');
        else if ((t >= 'a') && (t <= 'f')) v ^= (t - 'a' + 10);
        else if ((t >= 'A') && (t <= 'F')) v ^= (t - 'A' + 10);
        else return BAD_KEY_MAT;

        cipherKey[i] = (u8)v;
    }


    if (direction == DIR_ENCRYPT) {
        key->Nr = rijndaelKeySetupEnc(key->rk, cipherKey, 128);
    } else {
        key->Nr = rijndaelKeySetupDec(key->rk, cipherKey, 128);
    }

    return TRUE;
}


/*
 ** This function takes hex-encoded IV and converts it to binary.
 */
int
cipherInit(
        BYTE    *binIV,
        char    *hexIV
        )
{
    if (hexIV != NULL) {
        int i;
        for (i = 0; i < MAX_IV_SIZE; i++) {
            int t, j;

            t = hexIV[2*i];
            if ((t >= '0') && (t <= '9')) j = (t - '0') << 4;
            else if ((t >= 'a') && (t <= 'f')) j = (t - 'a' + 10) << 4;
            else if ((t >= 'A') && (t <= 'F')) j = (t - 'A' + 10) << 4;
            else return BAD_CIPHER_INSTANCE;

            t = hexIV[2*i+1];
            if ((t >= '0') && (t <= '9')) j ^= (t - '0');
            else if ((t >= 'a') && (t <= 'f')) j ^= (t - 'a' + 10);
            else if ((t >= 'A') && (t <= 'F')) j ^= (t - 'A' + 10);
            else return BAD_CIPHER_INSTANCE;

            binIV[i] = (u8)j;
        }
    } else {
        memset(binIV, 0, MAX_IV_SIZE);
    }
    return TRUE;
}

/*
 ** This function encrypts a given number of bits (= inputlen),
 ** assumed to bo divisible by 128 (= 16 bytes * 8 bits/byte).
 ** NOTICE that binIV is automatically updated in the end.
 ** NOTICE that binIV is updated! (CBC mode)
 */
int
blockEncrypt(
        BYTE        *binIV,
        keyInstance *key,
        const BYTE  *input,
        int         inputLen,
        BYTE        *outBuffer
        )
{
    int i, numBlocks;
    u8 *block, *iv, buff[16];

    if (binIV == NULL || key == NULL)
        return BAD_CIPHER_STATE;


    if (input == NULL || inputLen <= 0) {
        return 0; /* nothing to do */
    }

    numBlocks = inputLen/128;

    block = &buff[0];
    iv = binIV;
    for (i = numBlocks; i > 0; i--) {
        ((u32*)block)[0] = ((u32*)input)[0] ^ ((u32*)iv)[0];
        ((u32*)block)[1] = ((u32*)input)[1] ^ ((u32*)iv)[1];
        ((u32*)block)[2] = ((u32*)input)[2] ^ ((u32*)iv)[2];
        ((u32*)block)[3] = ((u32*)input)[3] ^ ((u32*)iv)[3];
        rijndaelEncrypt(key->rk, key->Nr, block, outBuffer);
        iv = outBuffer;
        input += 16;
        outBuffer += 16;
    }

    /* Update the IV so we don't  have to do it in owamp library. */
    memcpy(binIV, iv, 16); 

    return 128*numBlocks;
}

/*
 ** This function encrypts a given number of bits (= inputlen),
 ** assumed to be divisible by 128 (= #bits in 16 bytes).
 ** NOTICE that binIV is updated! (CBC mode)
 */
int
blockDecrypt(
        BYTE        *binIV,
        keyInstance *key,
        const BYTE  *input,
        int         inputLen,
        BYTE        *outBuffer
        )
{
    int i, numBlocks;
    u8 *block, *iv, buff[16];

    if (binIV == NULL || key == NULL) 
        return BAD_CIPHER_STATE;

    if (input == NULL || inputLen <= 0) 
        return 0; /* nothing to do */

    numBlocks = inputLen/128;

    block = &buff[0];
    iv = binIV;
    for (i = numBlocks; i > 0; i--) {
        rijndaelDecrypt(key->rk, key->Nr, input, block);
        ((u32*)block)[0] ^= ((u32*)iv)[0];
        ((u32*)block)[1] ^= ((u32*)iv)[1];
        ((u32*)block)[2] ^= ((u32*)iv)[2];
        ((u32*)block)[3] ^= ((u32*)iv)[3];
        memcpy(binIV, input, 16);
        memcpy(outBuffer, block, 16);
        input += 16;
        outBuffer += 16;
    }

    return 128*numBlocks;
}

void
bytes2Key(
        keyInstance *key,
        BYTE        *sid
        )
{
    key->Nr = rijndaelKeySetupEnc(key->rk, sid, 128);
}
