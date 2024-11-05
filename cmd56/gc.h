#ifndef GC_H
#define GC_H 1
#include <stdint.h>
#include "compiler_defs.h"
#include "crypto/aes.h"

typedef struct gc_cmd56_state {
    // game specific keys, used to derive the rif key,
    // which is used to decrypt the game klicensee.
    char rif_key_partial[0x20];
    char klic_key_partial[0x20];

    // CART_RANDOM is used to derive the SECONDARY_KEY0 using bbmac 0x305
    // and 0x308 (only on RETAIL_KEY_ID) 
    char cart_random[0x20];
    AesContext master_key;
    AesContext secondary_key0;

    // cart lock status, unlocked after successful VITA_AUTHENTICITY_CHECK
    uint8_t cart_status;

    // KEY_ID to use, every gc i've ever seen uses RETAIL_KEY_ID (0x1).
    // however a PROTOTYPE_KEY_ID1 0x8001 is also allowed,

    // PROTOTYPE_KEY_ID actually has worse security in place, 
    // however sony could easily check for this in a future update
    // and can use RETAIL_KEY_ID thanks to the racoon exploit anyway. 

    // There also exists a PROTOTYPE_KEY_ID2 and 3,0x8002 and 0x8003, 
    // however these are blacklisted as of fw 1.04.
    uint16_t key_id;
} gc_cmd56_state;


PACK(typedef struct src_packet_header {
    uint8_t key[0x20];
    uint32_t response_code;
    uint32_t data_size;
    uint32_t response_size;
    uint8_t command;
    uint8_t unknown_host_value;
    uint8_t additional_data_size;
    uint8_t data[0x1d1];
}) src_packet_header;

PACK(typedef  struct dst_packet_header {
    uint32_t response_code;
    uint32_t additional_data_size;
    uint16_t response_size;
    uint8_t error_code;
    uint8_t data[0x1f5];
}) dst_packet_header;

enum cart_status {
    READ_WRITE_LOCK = 0xFF,
    ALL_OK = 0x00
};

enum PACKET_SUB_COMMANDS {
    START = 0xC4,
    GET_STATUS = 0xC2,
    GENERATE_RANDOM_KEYSEED = 0xA1,
    ENCRYPT_VITA_RANDOM = 0xA2,
    VITA_AUTHENTICITY_CHECK = 0xA3,
    CHALLENGE = 0xA4,
    KLIC_PART_AND_CMAC_SIGNATURE = 0xB1,
    RIFBUF_KEY_PART = 0xC1
};

// exposed functions:
void gc_cmd56_init(gc_cmd56_state* state, const char* rif_part, const char* klic_part);
void gc_cmd56_update_keyid(gc_cmd56_state* state, uint16_t key_id);
void gc_cmd56_update_keys(gc_cmd56_state* state, const char* rif_part, const char* klic_part);
void gc_cmd56_run_in_place(gc_cmd56_state* state, char* buffer);
void gc_cmd56_run(gc_cmd56_state* state, const char* buffer, char* response);

#endif