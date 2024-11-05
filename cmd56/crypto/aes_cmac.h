#ifndef __AES_CMAC_H__
#define __AES_CMAC_H__

#include <string.h>
#include <stdlib.h>
#include "aes.h"

void aes_cmac(AesContext* ctx, void *input, size_t length, uint8_t *mac_value);

#endif
