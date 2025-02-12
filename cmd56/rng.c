#include "compiler_defs.h"
#include "crypto/aes.h"
#include "log.h"

static uint8_t state[0x10] = { 0x54, 0x72, 0x61, 0x6E, 0x73, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x73, 0x21, 0x21, 0x21, 0x00 };

void rand_bytes(void* buf, size_t size) {
#ifdef USE_PS3_MODE
	memset(buf, 0xAA, size);
#else
	AES_CBC_encrypt_buffer_key(state, buf, size, state);
	memcpy(state, buf, sizeof(state));
#endif
}