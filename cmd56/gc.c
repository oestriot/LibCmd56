#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "gc.h"
#include "f00d_emu.h"

#include "crypto/aes.h"
#include "crypto/aes_cbc.h"
#include "crypto/aes_cmac.h"

static char KEY0[0x20] = { 0xDD, 0x10, 0x25, 0x44, 0x15, 0x23, 0xFD, 0xC0, 0xF9, 0xE9, 0x15, 0x26, 0xDC, 0x2A, 0xE0, 0x84, 0xA9, 0x03, 0xA2, 0x97, 0xD4, 0xBB, 0xF8, 0x52, 0xD3, 0xD4, 0x94, 0x2C, 0x89, 0x03, 0xCC, 0x77 };

#define PACKET_RESPONSE_START(response_variable, packet_buffer, response_packet_buffer) \
	dst_packet_header* response_variable = (dst_packet_header*)response_packet_buffer; \
	memset(response_variable, 0x00, sizeof(dst_packet_header)); \
	response_variable->response_code = packet_buffer->response_code; \
	response_variable->additional_data_size = 0; \
	response_variable->response_size = __builtin_bswap16((unsigned short)packet_buffer->response_size); \
	response_variable->error_code = 0; \
	memset(response->data, 0x00, packet_buffer->response_size); \
	LOG("%s\n", "\n");

void handle_cmd_start(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response){
	PACKET_RESPONSE_START(response, packet, packet_response);

	response->data[0xD] = 0x1;
	response->data[0xE] = 0x1;
	response->data[0xF] = 0x4;
}
void handle_cmd_status(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	PACKET_RESPONSE_START(response, packet, packet_response);

	response->data[0x0] = state->cart_status;
	response->data[0x1] = 0x0;
}

void handle_vita_authenticity_check(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	PACKET_RESPONSE_START(response, packet, packet_response);
	char vita_authenticity_proof[0x30];
	char challenge[0x20];

	decrypt_cbc_zero_iv(&state->master_key, vita_authenticity_proof, packet->data, sizeof(vita_authenticity_proof));
	LOG("VITA_AUTHENTICITY_PROOF: ");
	LOG_BUFFER(vita_authenticity_proof, sizeof(vita_authenticity_proof));

	char secondary_key0[0x10];
	memcpy(secondary_key0, vita_authenticity_proof, sizeof(secondary_key0));
	LOG("secondary_key0: ");
	LOG_BUFFER(secondary_key0, sizeof(secondary_key0));
	aesInit(&state->secondary_key0, secondary_key0, sizeof(secondary_key0));

	// calculate challenge bytes ...
	memcpy(challenge, state->vita_random, sizeof(state->vita_random));
	challenge[0] |= 0x80;
	challenge[0x10] |= 0x80;

	if (memcmp(challenge, vita_authenticity_proof + 0x10, sizeof(challenge)) == 0) {
		LOG("Authenticated as real PSVita.\n");
		state->cart_status = ALL_OK;
	}
	else {
		LOG("This is not a real PSVita!\n");

		LOG("CHALLENGE: ");
		LOG_BUFFER(challenge, sizeof(challenge));

		LOG("vita_authenticity_proof+0x10: ");
		LOG_BUFFER(vita_authenticity_proof + 0x10, sizeof(challenge));

		state->cart_status = READ_WRITE_LOCK;
	}

	response->data[0x0] = 0x00;
	response->data[0x1] = 0x00;
	response->data[0x3] = 0x00;

}

void handle_generate_random_keyseed(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	PACKET_RESPONSE_START(response, packet, packet_response);

	response->data[0x0] = 0xE0;
	response->data[0x1] = 0x00;

	// specify key_id
	response->data[0x2] = (state->key_id & 0xFF00) >> 8;
	response->data[0x3] = (state->key_id & 0x00FF);

	response->data[0x4] = 0x00;
	response->data[0x5] = 0x02;

	response->data[0x6] = 0x00;
	response->data[0x7] = 0x03;

	// EXPLOIT:
	// dont actually use a random number, this way the key derived shall be the same every time.

	memset(state->cart_random, 0xAA, sizeof(state->cart_random));
	memcpy(response->data + 0x8, state->cart_random, sizeof(state->cart_random));

	// generate master key
	char master_key[0x10];
	derive_master_key(master_key, state->cart_random, state->key_id);

	LOG("Master Key: ");
	LOG_BUFFER(master_key, sizeof(master_key));

	aesInit(&state->master_key, master_key, sizeof(master_key));
}

void handle_challenge(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	PACKET_RESPONSE_START(response, packet, packet_response);

	// copy challenge data
	memcpy(response->data + 0x8, packet->data, 0x10);
	
	LOG("Challenge: ");
	LOG_BUFFER(response->data + 0x8, 0x10);

	// copy cart random
	memcpy(response->data + 0x18, state->cart_random, sizeof(state->cart_random));

	LOG("Plaintext: ");
	LOG_BUFFER(response->data, 0x40);

	encrypt_cbc_zero_iv(&state->secondary_key0, response->data, response->data, 0x40);

}
void handle_klic_part_and_cmac_signature(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	PACKET_RESPONSE_START(response, packet, packet_response);

	char cmac_input[0x40];

	// decrypt challenge value
	decrypt_cbc_zero_iv(&state->secondary_key0, response->data, packet->data, 0x20);

	LOG("challenge value: ");
	LOG_BUFFER(response->data, 0x20);

	// copy klic part of key
	memcpy(response->data + 0x10, state->klic_key_partial, sizeof(state->klic_key_partial));
	encrypt_cbc_zero_iv(&state->secondary_key0, response->data, response->data, 0x30);

	LOG("klic_key_partial: ");
	LOG_BUFFER(state->klic_key_partial, sizeof(state->klic_key_partial));

	// aes-128-cmac the whole thing
	memcpy(cmac_input, &response->response_size, 0x3);
	memset(cmac_input + 0x3, 0x00, 0xD);
	memcpy(cmac_input + 0x10, response->data, 0x30);

	aes_cmac(&state->secondary_key0, cmac_input, sizeof(cmac_input), response->data + 0x30);
	
	LOG("CMAC: ");
	LOG_BUFFER(response->data + 0x30, 0x10);
}


void handle_rif_buf_part_hash_key(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	PACKET_RESPONSE_START(response, packet, packet_response);

	char cmac_input[0x50];
	
	// copy random value
	memcpy(response->data+0x8, packet->data, 0x10);

	LOG("random value: ");
	LOG_BUFFER(response->data + 0x8, 0x10);

	// copy klic buffer
	memcpy(response->data + 0x18, state->rif_key_partial, sizeof(state->rif_key_partial));

	LOG("plaintext response: ");
	LOG_BUFFER(response->data, 0x40);

	// encrypt the response
	encrypt_cbc_zero_iv(&state->secondary_key0, response->data, response->data, 0x40);

	// aes-128-cmac the whole thing
	memcpy(cmac_input, &response->response_size, 0x3);
	memset(cmac_input + 0x3, 0x00, 0xD);
	memcpy(cmac_input + 0x10, response->data, 0x40);

	aes_cmac(&state->secondary_key0, cmac_input, sizeof(cmac_input), response->data + 0x40);
	LOG("CMAC: ");
	LOG_BUFFER(response->data + 0x40, 0x10);
}

void handle_vita_random(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	PACKET_RESPONSE_START(response, packet, packet_response);

	memcpy(state->vita_random, packet->data + 0x2, sizeof(state->vita_random));
	
	LOG("Vita Random: ");
	LOG_BUFFER(state->vita_random, sizeof(state->vita_random));

	memcpy(response->data + 0x10, state->vita_random, sizeof(state->vita_random));

	LOG("Plaintext: ");
	LOG_BUFFER(response->data, 0x20);

	encrypt_cbc_zero_iv(&state->master_key, response->data, response->data, 0x20);
}


void handle_packet(gc_cmd56_state* state, src_packet_header* packet, dst_packet_header* packet_response) {
	if(memcmp(packet->key, KEY0, sizeof(packet->key)) == 0) {
		switch(packet->command) {
			case START: //packet1, packet2
				handle_cmd_start(state, packet, packet_response);
				break;
			case GET_STATUS: // packet3, packet4
				handle_cmd_status(state, packet, packet_response);
				break;
			case GENERATE_RANDOM_KEYSEED: // packet5, packet6
				handle_generate_random_keyseed(state, packet, packet_response);
				break;
			case ENCRYPT_VITA_RANDOM: // packet7, packet8
				handle_vita_random(state, packet, packet_response);
				break;
			case VITA_AUTHENTICITY_CHECK: // packet9, packet10
				handle_vita_authenticity_check(state, packet, packet_response);
				break;
				
			// packet11, packet12 -> GET_STATUS again
			
			case CHALLENGE: // packet13, packet14
				handle_challenge(state, packet, packet_response);
				break;

			// packet15, packet16 -> CHALLENGE again

			case KLIC_PART_AND_CMAC_SIGNATURE: // packet17, packet18
				handle_klic_part_and_cmac_signature(state, packet, packet_response);
				break;
			case RIFBUF_KEY_PART: // packet19, packet20
				handle_rif_buf_part_hash_key(state, packet, packet_response);
				break;
			default:
				LOG("Unknown command: %x\n", packet->command);
				break;
		}
	}
}

// exposed functions :

void gc_cmd56_update_keyid(gc_cmd56_state* state, uint16_t key_id) {
	state->key_id = key_id;
}

void gc_cmd56_update_keys(gc_cmd56_state* state, const char* rif_part, const char* klic_part) {
	memcpy(state->rif_key_partial, rif_part, sizeof(state->rif_key_partial));
	memcpy(state->klic_key_partial, klic_part, sizeof(state->klic_key_partial));
}

void gc_cmd56_init(gc_cmd56_state* state, const char* rif_part, const char* klic_part) {
	memset(state, 0x00, sizeof(gc_cmd56_state));

	// lock "cart" for reading/writing
	state->cart_status = READ_WRITE_LOCK;

	// set default key id
	gc_cmd56_update_keyid(state, RETAIL_KEY_ID);

	// set cart specific keys
	gc_cmd56_update_keys(state, rif_part, klic_part);
}

void gc_cmd56_run_in_place(gc_cmd56_state* state, char* buffer) {
	char cmd56_packet_response[0x200];
	gc_cmd56_run(state, buffer, cmd56_packet_response);
	memcpy(buffer, cmd56_packet_response, sizeof(cmd56_packet_response));
}

void gc_cmd56_run(gc_cmd56_state* state, const char* buffer, char* response) {
	handle_packet(state, (src_packet_header*)buffer, (dst_packet_header*)response);
}