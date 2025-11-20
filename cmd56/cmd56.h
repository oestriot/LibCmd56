/*
*	LibCmd56 from the Estroit team!
*	the only functional implementation of vita gamecart authentication!
*/

#ifndef CMD56_H
#define CMD56_H 1
#include "compiler_defs.h"
#include "cmd56.h"

#define make_short(b1, b2) ((b2 << 8) | (b1 << 0))
#define make_int24(b1, b2, b3) ((b3 << 16) | (b2 << 8) | (b1 << 0))
#define make_int(b1, b2, b3, b4) ((b4 << 32) | (b3 << 16) | (b2 << 8) | (b1 << 0))

#define calc_size(type) (sizeof(type) + 0x3)

extern const uint8_t CMD56_MAGIC[0x20];

typedef uint16_t cmd56_lock_status;
enum cmd56_lock_status {
    GC_LOCKED = 0xFF,
    GC_UNLOCKED = 0x00
};

typedef uint8_t cmd56_command;
enum cmd56_commands {
    CMD_START = 0xC4,
    CMD_GET_STATUS = 0xC2,
    CMD_GENERATE_SESSION_KEY = 0xA1,
    CMD_EXCHANGE_SHARED_RANDOM = 0xA2,
    CMD_EXCHANGE_SECONDARY_KEY_AND_VERIFY_SESSION = 0xA3,
    CMD_VERIFY_SECONDARY_KEY = 0xA4,
    CMD_GET_P18_KEY_AND_CMAC_SIGNATURE = 0xB1,
    CMD_GET_P20_KEY_AND_CMAC_SIGNATURE = 0xC1
};

PACK(typedef struct cmd56_keys {
    uint8_t packet20_key[0x20];
    uint8_t packet18_key[0x20];
} cmd56_keys);

PACK(typedef struct cmd56_request {
    uint8_t magic[0x20];
    uint32_t expected_response_code;
    uint32_t request_size;
    uint32_t expected_response_size;
    cmd56_command command;
    uint8_t unknown_host_value;
    uint8_t additional_data_size;
    uint8_t data[0x1d1];
} cmd56_request);

PACK(typedef struct cmd56_response {
    uint32_t response_code;
    uint32_t additional_data_size;
    uint16_t response_size;
    uint8_t error_code;
    uint8_t data[0x1f5];
} cmd56_response);

PACK(typedef struct shared_random {
    uint8_t vita_part[0x10];
    uint8_t cart_part[0x10];
} shared_random);

/*
*   COMMAND REQUESTS
*/

PACK(typedef struct exchange_shared_random_request {
    uint16_t key_id;
    uint8_t shared_vita_part[0x10];
} exchange_shared_random_request);

PACK(typedef struct exchange_secondary_key_and_verify_session_request {
    uint8_t secondary_key[0x10];
    shared_random challenge_bytes;
} exchange_secondary_key_and_verify_session_request);

PACK(typedef struct verify_secondary_key_request {
    uint8_t challenge_bytes[0x10];
} verify_secondary_key_request);

PACK(typedef struct get_p18_key_and_cmac_signature_request {
    uint8_t challenge_bytes[0x10];
    uint8_t pad[0xF]; // !< 0x00
    uint8_t type; // 0x2 or 0x3
    uint8_t cmac_signature[0x10];
} get_p18_key_and_cmac_signature_request);

PACK(typedef struct get_p20_key_and_cmac_signature_request {
    uint8_t challenge_bytes[0x10];
} get_p20_key_and_cmac_signature_request);


/*
*   COMMAND RESPONSES 
*/

PACK(typedef struct start_response {
    uint8_t start[0x10]; // <! 00000000000000000000000000010104
} start_response);

PACK(typedef struct get_status_response {
    uint16_t status; // FFFF || 0000
} get_status_response);

PACK(typedef struct generate_session_key_response {
    uint16_t unk; //<! 0xE0
    uint16_t key_id; //<! endian swapped !
    uint16_t unk2; //<! 0x200
    uint16_t unk3; //<! 0x300
    uint8_t cart_random[0x20];
} generate_session_key_response);

PACK(typedef struct exchange_shared_random_response {
    uint8_t shared_cart_part[0x10];
    uint8_t shared_vita_part[0x10];
} exchange_shared_random_response);

PACK(typedef struct verify_secondary_key_response {
    uint8_t pad[0x8]; // rng
    uint8_t challenge_bytes[0x10];
    uint8_t cart_random[0x20];
    uint8_t pad2[0x8]; // rng
} verify_secondary_key_response);

PACK(typedef struct get_p18_and_cmac_signature_response {
    uint8_t challenge_bytes[0x10];
    uint8_t p18_key[0x20];
    uint8_t cmac_signature[0x10];
} get_p18_and_cmac_signature_response);

PACK(typedef struct get_p20_key_and_cmac_signature_response {
    uint8_t pad[8]; // rng
    uint8_t challenge_bytes[0x10];
    uint8_t p20_key[0x20];
    uint8_t pad2[0x8]; // rng
    uint8_t cmac_signature[0x10];
} get_p20_key_and_cmac_signature_response);

void cmd56_response_start(cmd56_request* packet_buffer, cmd56_response* response);
void cmd56_response_error(cmd56_response* response, uint8_t error);

void cmd56_request_start(cmd56_request* request, cmd56_command cmd, uint8_t data_size, uint32_t expected_response_size, uint32_t expected_response_code);

#endif /* CMD56_H */