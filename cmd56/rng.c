#include "compiler_defs.h"
#include "crypto/aes.h"
#include "log.h"
static uint8_t state[0x10];

void rand_bytes(void* buf, size_t size) {
//#ifdef USE_PS3_MODE
	memset(buf, 0xAA, size);
/*#else
	AES_CBC_encrypt_buffer_key(state, state, sizeof(state), state);
	AES_CBC_encrypt_buffer_key(state, buf, size, state);
#endif*/
}