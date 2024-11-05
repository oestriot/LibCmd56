#ifndef __AES_CMAC_H__
#define __AES_CMAC_H__

#include "aes.h"

void aes_cmac(AES_ctx* ctx, void *input, size_t length, uint8_t *mac_value);

#endif
