#include "log.h"
#include "crypto/aes.h"
#include "crypto/aes_cmac.h"
#include "f00d_emu.h"

static uint8_t MASTER_KEY_0x8001[0x10] = { 0x39, 0x07, 0xA9, 0x3E, 0x6B, 0x68, 0x8C, 0x9A, 0x16, 0x8B, 0xBE, 0x3F, 0x7B, 0xD2, 0x3A, 0x6C }; // keyid = 0x8001
static uint8_t MASTER_KEY_0x1[0x10]    = { 0x16, 0x20, 0x5F, 0xA6, 0x71, 0x35, 0xD6, 0x2B, 0x29, 0x08, 0xE7, 0xEC, 0x78, 0x04, 0x1A, 0xE8 }; // keyid = 0x1

/*
(implemented as macro)
void decrypt_cbc_zero_iv(AES_ctx* aes_ctx, void* data, size_t dataLen) {
	uint8_t iv[0x10] = {0};
	AES_CBC_decrypt_buffer(aes_ctx, data, dataLen, iv);
}

void encrypt_cbc_zero_iv(AES_ctx* aes_ctx, void* data, size_t dataLen) {
	uint8_t iv[0x10] = {0};
	AES_CBC_encrypt_buffer(aes_ctx, data, dataLen, iv);
}
*/



void derive_master_key(uint8_t** masterKey_out, uint8_t* cart_random, int key_id) {
	// CART_RANDOM is used to derive the master_key
	// it is done by first decrypting bbmac 0x305 with a static key based on the key_id into bbmac 0x21.
	// then the resulting 0x21 key is used to create a AES_128_CMAC hash of the CART_RANDOM
	// -- on RETAIL_KEY_ID only, the AES_128_CMAC hash is then decrypted using bbmac 0x308 into 0x24, 
	// 
	// this is not possible to implement as the bbmac keys are not yet known.
	// so instead we have implemented a "replay attack" where we will always use the same VITA_RANDOM every time
	// this will mean the vita will derive the same 'master key' every time, and can just use it.
	// NOTE: extracting the key RETAIL_KEY_ID requires using the racoon exploit.

	if(key_id == RETAIL_KEY_ID) {
		*masterKey_out = MASTER_KEY_0x1;
		return;
	}
	if(key_id == PROTOTYPE_KEY_ID1) {
		*masterKey_out = MASTER_KEY_0x8001;
	}
	LOG("non handled keyid");
	return;
}

/*
(unused)
void decrypt_secondary_key0(uint8_t* cart_random, int key_id, uint8_t* vita_authenticity_key, uint8_t* secondary_key0) {
	uint8_t* master_key;
	derive_master_key(master_key, cart_random, key_id);
	AES_ctx master_key_ctx;
	AES_init_ctx(&master_key_ctx, master_key);
	memcpy(secondary_key0, vita_authenticity_key, 0x10);
	decrypt_cbc_zero_iv(&master_key_ctx, secondary_key0, 0x10);
}
*/
