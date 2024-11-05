#ifndef F00D_EMU_H
#define F00D_EMU_H 1

enum KEY_IDS {
	PROTOTYPE_KEY_ID1 = 0x8001,
	
	// on CEX 1.04+ 8002 and 8003 are hardcoded blocked in gcauthmgr.skprx 
	PROTOTYPE_KEY_ID2 = 0x8002, 
	PROTOTYPE_KEY_ID3 = 0x8003, 
	
	RETAIL_KEY_ID = 0x1
};

#define decrypt_cbc_zero_iv(ctx, data, len) AES_CBC_decrypt_buffer(ctx, data, len, NULL);
#define encrypt_cbc_zero_iv(ctx, data, len) AES_CBC_encrypt_buffer(ctx, data, len, NULL);

//void decrypt_cbc_zero_iv(AES_ctx* aes_ctx, void* data, size_t dataLen);
//void encrypt_cbc_zero_iv(AES_ctx* aes_ctx, void* data, size_t dataLen);
void derive_master_key(uint8_t** masterKey_out, uint8_t* cart_random, int key_id);
//void decrypt_secondary_key0(uint8_t* cart_random, int key_id, uint8_t* vita_authenticity_key, uint8_t* secondary_key0);

#endif