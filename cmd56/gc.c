#include "log.h"
#include "gc.h"
#include "cmd56.h"
#include "f00d_emu.h"
#include "rng.h"

#include "crypto/aes.h"
#include "crypto/aes_cmac.h"


void handle_cmd_start(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response){
	cmd56_response_start(packet, response);
	state->lock_status = GC_LOCKED;

	response->data[0xD] = 0x1;
	response->data[0xE] = 0x1;
	response->data[0xF] = 0x4;
}

void handle_cmd_status(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response) {
	cmd56_response_start(packet, response);
	response->data[0x0] = (state->lock_status & 0x00FF);
	response->data[0x1] = (state->lock_status & 0xFF00) >> 8; 
}

void handle_vita_authenticity_check(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response) {
	cmd56_response_start(packet, response);
	uint8_t* vita_authenticity_proof = packet->data;

	decrypt_cbc_zero_iv(&state->master_key, vita_authenticity_proof, 0x30);
	LOG("(GC) VITA_AUTHENTICITY_PROOF: ");
	LOG_BUFFER(vita_authenticity_proof, 0x30);

	LOG("(GC) secondary_key0: ");
	LOG_BUFFER(vita_authenticity_proof + 0x00, 0x10);
	AES_init_ctx(&state->secondary_key0, vita_authenticity_proof + 0x00);

	// calculate challenge bytes ...
	uint8_t* challenge = state->vita_random;
	challenge[0x00] |= 0x80;
	challenge[0x10] |= 0x80;

	if (memcmp(challenge, vita_authenticity_proof + 0x10, 0x20) == 0) {
		LOG("(GC) Authenticated as real PSVita.\n");
		state->lock_status = GC_UNLOCKED;
	}
	else {
		LOG("(GC) This is not a real PSVita!\n");

		LOG("(GC) SECONDARY_KEY0_CHALLENGE: ");
		LOG_BUFFER(challenge, 0x20);

		LOG("(GC) vita_authenticity_proof+0x10: ");
		LOG_BUFFER(vita_authenticity_proof + 0x10, 0x20);

		state->lock_status = GC_LOCKED;
	}

	response->data[0x0] = 0x00;
	response->data[0x1] = 0x00;
	response->data[0x3] = 0x00;
}

void handle_generate_random_keyseed(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response) {
	cmd56_response_start(packet, response);

	response->data[0x0] = 0xE0;
	response->data[0x1] = 0x00;

	// specify key_id
	LOG("(GC) Key ID %x\n", state->key_id);
	response->data[0x2] = (state->key_id & 0xFF00) >> 8;
	response->data[0x3] = (state->key_id & 0x00FF);

	response->data[0x4] = 0x00;
	response->data[0x5] = 0x02;

	response->data[0x6] = 0x00;
	response->data[0x7] = 0x03;

	
	rand_bytes(state->cart_random, sizeof(state->cart_random));
	memcpy(response->data + 0x8, state->cart_random, sizeof(state->cart_random));
	
	LOG("(GC) Cart Random: ");
	LOG_BUFFER(state->cart_random, sizeof(state->cart_random));

	// generate master key
	uint8_t master_key[0x10];
	derive_master_key(master_key, state->cart_random, state->key_id);

	LOG("(GC) Master Key: ");
	LOG_BUFFER(master_key, sizeof(master_key));

	AES_init_ctx(&state->master_key, master_key);
}

void handle_challenge(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response) {
	cmd56_response_start(packet, response);

	// copy challenge data
	memcpy(response->data + 0x8, packet->data, 0x10);
	
	LOG("(GC) Challenge: ");
	LOG_BUFFER(response->data + 0x8, 0x10);

	// copy cart random
	memcpy(response->data + 0x18, state->cart_random, sizeof(state->cart_random));

	LOG("(GC) Plaintext: ");
	LOG_BUFFER(response->data, 0x40);

	encrypt_cbc_zero_iv(&state->secondary_key0, response->data, 0x40);
}


void handle_p18key_and_cmac_signature(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response) {
	cmd56_response_start(packet, response);

	// decrypt challenge value
	memcpy(response->data, packet->data, 0x20);
	decrypt_cbc_zero_iv(&state->secondary_key0, response->data, 0x20);

	uint8_t cmac_output[0x10];
	derive_cmac_packet18_packet20(&state->secondary_key0, response->data, make_short(packet->command, packet->additional_data_size), cmac_output, 0x20);
	if (memcmp(cmac_output, packet->data + 0x20, sizeof(cmac_output)) == 0) {
		LOG("(GC) CMAC validated success\n");

		LOG("(GC) challenge random: ");
		LOG_BUFFER(response->data, 0x20);

		// copy packet18 key
		memcpy(response->data + 0x10, state->gc_spec_key.packet18_key, sizeof(state->gc_spec_key.packet18_key));

		LOG("(GC) packet18_key: ");
		LOG_BUFFER(state->gc_spec_key.packet18_key, sizeof(state->gc_spec_key.packet18_key));

		// encrypt buffer
		encrypt_cbc_zero_iv(&state->secondary_key0, response->data, 0x30);

		// aes-128-cmac the whole thing
		derive_cmac_packet18_packet20(&state->secondary_key0, response->data, response->response_size, response->data + 0x30, 0x30);
	}
	else {
		response->error_code = 0xFF;
	}

}

void handle_p20key_and_cmac_signature(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response) {
	cmd56_response_start(packet, response);
	
	// copy random value
	memcpy(response->data+0x8, packet->data, 0x10);

	LOG("(GC) random value: ");
	LOG_BUFFER(response->data + 0x8, 0x10);

	// copy p20 key
	memcpy(response->data + 0x18, state->gc_spec_key.packet20_key, sizeof(state->gc_spec_key.packet20_key));

	LOG("(GC) plaintext response: ");
	LOG_BUFFER(response->data, 0x40);

	// encrypt buffer
	encrypt_cbc_zero_iv(&state->secondary_key0, response->data, 0x40);

	// aes-128-cmac the whole thing
	derive_cmac_packet18_packet20(&state->secondary_key0, response->data, response->response_size, response->data + 0x40, 0x40);
}

void handle_vita_random(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* response) {
	cmd56_response_start(packet, response);

	memcpy(state->vita_random, packet->data + 0x2, sizeof(state->vita_random));
	
	LOG("(GC) Vita Random: ");
	LOG_BUFFER(state->vita_random, sizeof(state->vita_random));

	memcpy(response->data + 0x10, state->vita_random, sizeof(state->vita_random));

	LOG("(GC) handle_vita_random Plaintext: ");
	LOG_BUFFER(response->data, 0x20);

	encrypt_cbc_zero_iv(&state->master_key, response->data, 0x20);

	LOG("(GC) handle_vita_random Ciphertext: ");
	LOG_BUFFER(response->data, 0x20);
}

void handle_unknown_packet(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* packet_response) {
	LOG("(GC) Unknown command: %x\n", packet->command);
}

void handle_packet(gc_cmd56_state* state, cmd56_request* packet, cmd56_response* packet_response) {
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
		case VERIFY_VITA_RANDOM: // packet7, packet8
			handle_vita_random(state, packet, packet_response);
			break;
		case VITA_AUTHENTICITY_CHECK: // packet9, packet10
			handle_vita_authenticity_check(state, packet, packet_response);
			break;
			
		// packet11, packet12 -> GET_STATUS again
		
		case SECONDARY_KEY0_CHALLENGE: // packet13, packet14
			handle_challenge(state, packet, packet_response);
			break;

		case P18_KEY_AND_CMAC_SIGNATURE: // packet15, packet16
			handle_p18key_and_cmac_signature(state, packet, packet_response);
			break;

		// packet17, packet18 -> P18_KEY_AND_CMAC_SIGNATURE again

		case P20_KEY_AND_CMAC_SIGNATURE: // packet19, packet20
			handle_p20key_and_cmac_signature(state, packet, packet_response);
			break;
		default:
			handle_unknown_packet(state, packet, packet_response);
			break;
	}
}

// exposed functions :

void gc_cmd56_update_keyid(gc_cmd56_state* state, uint16_t key_id) {
	state->key_id = key_id;
}

void gc_cmd56_update_keys(gc_cmd56_state* state, const cmd56_keys* gc_spec_key) {
	memcpy(state->gc_spec_key.packet18_key, gc_spec_key->packet18_key, sizeof(state->gc_spec_key.packet18_key));
	memcpy(state->gc_spec_key.packet20_key, gc_spec_key->packet20_key, sizeof(state->gc_spec_key.packet20_key));
}

void gc_cmd56_init(gc_cmd56_state* state, const cmd56_keys* gc_spec_key) {
	memset(state, 0x00, sizeof(gc_cmd56_state)); 

	// lock "cart" for reading/writing
	state->lock_status = GC_LOCKED;

	// set default key id
	gc_cmd56_update_keyid(state, RETAIL_KEY_ID);

	// set cart specific keys
	gc_cmd56_update_keys(state, gc_spec_key);
}

void gc_cmd56_run_in_place(gc_cmd56_state* state, uint8_t* buffer) {
	uint8_t cmd56_packet_response[0x200];
	gc_cmd56_run(state, buffer, cmd56_packet_response);
	memcpy(buffer, cmd56_packet_response, sizeof(cmd56_packet_response));
}

void gc_cmd56_run(gc_cmd56_state* state, const uint8_t* buffer, uint8_t* response) {
	cmd56_request* packet = (cmd56_request*)buffer;
	if(memcmp(packet->magic, CMD56_MAGIC, sizeof(packet->magic)) != 0) {
		return;
	}
	handle_packet(state, (cmd56_request*)buffer, (cmd56_response*)response);
}