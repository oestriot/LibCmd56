#ifndef VITA_H
#define VITA_H 1
#include "compiler_defs.h"
#include "crypto/aes.h"
#include "cmd56.h"
#include "f00d_emu.h"

typedef void (*send_t)(const char* data, size_t* size);
typedef void (*recv_t)(const char* data, size_t* size);

typedef enum vita_error_code {
    SCE_OK = 0,
    SCE_ERROR = -1
} vita_error_code;

typedef struct vita_cmd56_state {
	// send/recv callbacks
	send_t send;
	recv_t recv;

    // cmd56 request and responses
    cmd56_request cmd56_request;
    cmd56_response cmd56_response;

    // cart lock status, unlocked after successful VITA_AUTHENTICITY_CHECK
    cmd56_lock_status lock_status;
	
    // KEY_ID to use, every gc i've ever seen uses RETAIL_KEY_ID (0x1).
    // however a PROTOTYPE_KEY_ID1 0x8001 is also allowed,

    // PROTOTYPE_KEY_ID actually has worse security in place, 
    // however sony could easily check for this in a future update
    // and can use RETAIL_KEY_ID thanks to the racoon exploit anyway. 

    // There also exists a PROTOTYPE_KEY_ID2 and 3,0x8002 and 0x8003, 
    // however these are blacklisted as of fw 1.04.
    gcauthmgr_keyid key_id;

    // per-gc keys, used to derive the rif key,
    // which is used to decrypt the game klicensee,
    // and finally PFS/EBOOT.BIN
    cmd56_keys gc_spec_key;

    // CART_RANDOM is used to derive the SECONDARY_KEY0 using bbmac 0x305
    // and 0x308 (only on RETAIL_KEY_ID) 
    uint8_t cart_random[0x20];
    uint8_t vita_random[0x20];
    AES_ctx master_key;
    AES_ctx secondary_key0;
} vita_cmd56_state;

// exposed functions:
void vita_cmd56_init(vita_cmd56_state* state, send_t send_func, recv_t recv_func);
int vita_cmd56_run(vita_cmd56_state* state);

#endif