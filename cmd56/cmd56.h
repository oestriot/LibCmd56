#ifndef CMD56_H
#define CMD56_H 1
#include "compiler_defs.h"
#include "cmd56.h"

#define make_short(b1, b2) ((b2 << 8) | b1)
extern const uint8_t CMD56_MAGIC[0x20];

typedef uint16_t cmd56_lock_status;
enum cmd56_lock_status {
    GC_LOCKED = 0xFF,
    GC_UNLOCKED = 0x00
};

typedef uint8_t cmd56_command;
enum cmd56_commands {
    START = 0xC4,
    GET_STATUS = 0xC2,
    GENERATE_RANDOM_KEYSEED = 0xA1,
    VERIFY_VITA_RANDOM = 0xA2,
    VITA_AUTHENTICITY_CHECK = 0xA3,
    SECONDARY_KEY0_CHALLENGE = 0xA4,
    P18_KEY_AND_CMAC_SIGNATURE = 0xB1,
    P20_KEY_AND_CMAC_SIGNATURE = 0xC1
};

typedef struct cmd56_keys {
    uint8_t packet20_key[0x20];
    uint8_t packet18_key[0x20];
} cmd56_keys;

typedef struct cmd56_request {
    uint8_t magic[0x20];
    uint32_t expected_response_code;
    uint32_t request_size;
    uint32_t expected_response_size;
    cmd56_command command;
    uint8_t unknown_host_value;
    uint8_t additional_data_size;
    uint8_t data[0x1d1];
} cmd56_request;

typedef struct cmd56_response {
    uint32_t response_code;
    uint32_t additional_data_size;
    uint16_t response_size;
    uint8_t error_code;
    uint8_t data[0x1f5];
} cmd56_response;

void cmd56_response_start(cmd56_request* packet_buffer, cmd56_response* response);
void cmd56_request_start(cmd56_request* request, cmd56_command cmd, uint8_t data_size, uint32_t expected_response_size, uint32_t expected_response_code);

#endif /* CMD56_H */