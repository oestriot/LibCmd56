#include "aes.h"
#include "aes_cbc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define block_copy(dest, src)  memcpy((dest), (src), AES_BLOCKSIZE)

inline void block_xor(uint8_t *a, uint8_t *b) {
    for(int i = 0; i < AES_BLOCKSIZE; i++)
        a[i] ^= b[i];
};

unsigned long AES_CBC_encrypt(AesContext* aes_ctx, void *input_p, void *output_p, size_t length, void *iv)
{
    uint8_t* input = input_p;
    uint8_t* output = output_p;
    uint8_t *previous_block_ciphertext = iv;
    unsigned long i;
    unsigned long output_length;

    for(i = 0; i < length; i+= AES_BLOCKSIZE)
    {
        block_copy(output, input);
        block_xor(output, previous_block_ciphertext);
        aesEncryptBlock(aes_ctx, output, output);
        previous_block_ciphertext = output;

        output += AES_BLOCKSIZE;
        input += AES_BLOCKSIZE;
    }
    output_length = (length / AES_BLOCKSIZE) * AES_BLOCKSIZE;
    i = length % AES_BLOCKSIZE;
    if (i > 0)
    {
        // puts("additional block");
        //add zero padding
        memset(output, 0, AES_BLOCKSIZE);
        memcpy(output, input, i);
        block_xor(output, previous_block_ciphertext);
        aesEncryptBlock(aes_ctx, output, output);
        output_length += AES_BLOCKSIZE;
    }

    return output_length;
}

void AES_CBC_decrypt(AesContext* aes_ctx, void *input_p, void *output_p, size_t length, void *iv)
{
    uint8_t* input = input_p;
    uint8_t* output = output_p;
    uint8_t *previous_block_ciphertext = iv;
    unsigned long i;

    for(i = 0; i < length; i+= AES_BLOCKSIZE)
    {
        block_copy(output, input);
        aesDecryptBlock(aes_ctx, output, output);
        block_xor(output, previous_block_ciphertext);

        previous_block_ciphertext = input;
        output += AES_BLOCKSIZE;
        input += AES_BLOCKSIZE;
    }

    i = length % AES_BLOCKSIZE;
    if(i > 0)
    {
        block_copy(output, input);
        aesDecryptBlock(aes_ctx, output, output);
        block_xor(output, previous_block_ciphertext);
        memset(output + i, 0, AES_BLOCKSIZE - i);
    }
}
