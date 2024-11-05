#ifndef __AES_CBC_H__
#define __AES_CBC_H__

#include <string.h>
#include <stdlib.h>
#include "aes.h"

/*
input: pointer to input data
output: ..........output....
length: length of plaintext message
key: pointer to key
keylen: 16, 24 or 32
iv: initial vector for CBC mode
*/
unsigned long AES_CBC_encrypt(AesContext* aes_ctx, void *input, void *output, size_t length, void *iv);
void AES_CBC_decrypt(AesContext* aes_ctx, void *input, void *output, size_t length, void *iv);

#endif
