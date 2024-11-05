#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCKSIZE 16

typedef struct
{
	uint32_t nr;
	uint32_t ek[60];
	uint32_t dk[60];
} AesContext;

//AES related functions
uint32_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen);

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output);

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output);

#endif
