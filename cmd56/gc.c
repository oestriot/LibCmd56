#include "log.h"
#include "gc.h"
#include "cmd56.h"
#include "cmd56_sm.h"

#include "crypto/aes.h"
#include "crypto/aes_cmac.h"


void handle_cmd_start(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response){
	cmd56_response_start(request, response);
	state->lock_status = GC_LOCKED;

	response->data[0xD] = 0x1;
	response->data[0xE] = 0x1;
	response->data[0xF] = 0x4;
}

void handle_cmd_status(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_response_start(request, response);
	response->data[0x0] = (state->lock_status & 0x00FF);
	response->data[0x1] = (state->lock_status & 0xFF00) >> 8; 
}

void handle_vita_authenticity_check(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_response_start(request, response);
	// decrypt 0x30 bytes of the request ...
	decrypt_cbc_zero_iv(&state->master_key, request->data, 0x30);

	uint8_t* vita_authenticity_proof = request->data;

	// log everything
	LOG("(GC) decrypted vita_authenticity_proof buffer: ");
	LOG_BUFFER(vita_authenticity_proof, 0x30);

	LOG("(GC) secondary_key0: ");
	uint8_t* got_secondary_key0 = vita_authenticity_proof + 0x00;
	LOG_BUFFER(got_secondary_key0, 0x10);
	
	uint8_t* got_challenge = vita_authenticity_proof + 0x10;
	LOG("(GC) got_challenge: ");
	LOG_BUFFER(got_challenge, 0x20);

	AES_init_ctx(&state->secondary_key0, got_secondary_key0);

	// calculate challenge bytes ...
	uint8_t exp_challenge[0x20];
	memcpy(exp_challenge, &state->shared_random, sizeof(shared_value));

	exp_challenge[0x00] |= 0x80;
	exp_challenge[0x10] |= 0x80;


	if (memcmp(exp_challenge, got_challenge, 0x20) == 0) {
		LOG("(GC) exp_challenge == got_challenge, so authenticated as real PSVita.\n");
		state->lock_status = GC_UNLOCKED;
	}
	else {
		LOG("(GC) This is not a real PSVita!\n");

		LOG("(GC) expected: ");
		LOG_BUFFER(exp_challenge, 0x20);

		LOG("(GC) got: vita_authenticity_proof+0x10: ");
		LOG_BUFFER(vita_authenticity_proof + 0x10, 0x20);

		state->lock_status = GC_LOCKED;
		cmd56_response_error(response, 0xF1);
	}
}

void handle_generate_random_keyseed(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_response_start(request, response);

	response->data[0x0] = 0xE0;
	response->data[0x1] = 0x00;

	// specify key_id
	LOG("(GC) Key ID %x\n", state->key_id);
	response->data[0x2] = (state->key_id & 0xFF00) >> 8;
	response->data[0x3] = (state->key_id & 0x00FF);

	rand_bytes(state->cart_random, sizeof(state->cart_random));

	// unknown paramaters, copied values from "Smart As.".
	// half of it seems to extend into the CART_RANDOM even, its very strange.
	// the vita does nothing with these, so i can't easily know what there for
	// this is just included incase they decide to do something with them in a later firmware..

	response->data[0x4] = 0x00;
	response->data[0x5] = 0x02;

	response->data[0x6] = 0x00;
	response->data[0x7] = 0x03;
 
	
	state->cart_random[0x0] = 0x00;
	state->cart_random[0x1] = 0x01;

	
	state->cart_random[0x2] = 0x00;
	state->cart_random[0x3] = 0x01;
	
	
	state->cart_random[0x4] = 0x00;
	state->cart_random[0x5] = 0x00;
	state->cart_random[0x6] = 0x00;
	state->cart_random[0x7] = 0x00;


	state->cart_random[0x8] = 0x00;
	state->cart_random[0x9] = 0x00;
	state->cart_random[0xA] = 0x00;
	state->cart_random[0xB] = 0x04; // 0x3 in Superdimension Neptune vs Sega Hard Girls, 
								   // 0x4 in Smart As,
								   // (possibly: 0x3 on 4GB gc, and 0x4 on 2GB gc? needs more testing.)
	state->cart_random[0xC] = 0x00;

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

void handle_secondary_key0_challenge(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_response_start(request, response);

	// the other bytes in here are never used, but it is seemingly random on a offical cart.
	rand_bytes(response->data, 0x40);

	// copy challenge data
	memcpy(response->data + 0x8, request->data + 0x0, 0x10);
	response->data[0x00] |= 0x80; // or it w 0x80 (why does sony do this?)

	LOG("(GC) Got challenge bytes back to secondary_key0: ");
	LOG_BUFFER(response->data + 0x9, 0xF);

	// copy cart random
	memcpy(response->data + 0x18, state->cart_random, sizeof(state->cart_random));

	LOG("(GC) Plaintext of secondary_key0 challenge response request: ");
	LOG_BUFFER(response->data, 0x40);

	encrypt_cbc_zero_iv(&state->secondary_key0, response->data, 0x40);
}


void handle_p18key_and_cmac_signature(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_response_start(request, response);

	// copy challange to response
	memcpy(response->data + 0x00, request->data + 0x00, 0x20);

	// calcluate cmac and get expected cmac
	uint8_t* exp_cmac = request->data + 0x20;
	uint8_t got_cmac[0x10];
	
	derive_cmac_packet18_packet20(&state->secondary_key0, 
								  response->data,
								  make_int24(request->command, 0x0, request->additional_data_size), 
								  got_cmac, 
								  0x20);


	// check type really is 0x2 or 0x3, and its or'd by 0x80 ...
	if ((response->data[0x1F] == 0x2 || response->data[0x1F] == 0x3) && 
		(response->data[0x00] | 0x80) == response->data[0x00]) {
		LOG("(GC) invalid p18 request, 0x1F is not 0x2 or 0x3, OR 0x00 is not or'd with 0x80.\n");
		cmd56_response_error(response, 0x11);
	}
	else if (memcmp(got_cmac, exp_cmac, sizeof(got_cmac)) == 0) {
		LOG("(GC) p18 cmac validated success\n");

		uint8_t* challenge_value = response->data + 0x00;
		decrypt_cbc_zero_iv(&state->secondary_key0, challenge_value, 0x20);
		challenge_value[0x00] |= 0x80;

		LOG("(GC) decrypted p18 buffer: ");
		LOG_BUFFER(response->data, 0x30);

		LOG("(GC) exp_challenge value: ");
		LOG_BUFFER(challenge_value, 0x20);

		// copy request18 key
		memcpy(response->data + 0x10, state->per_cart_keys.packet18_key, sizeof(state->per_cart_keys.packet18_key));

		LOG("(GC) packet18_key: ");
		LOG_BUFFER(state->per_cart_keys.packet18_key, sizeof(state->per_cart_keys.packet18_key));

		// encrypt buffer
		encrypt_cbc_zero_iv(&state->secondary_key0, response->data, 0x30);

		// aes-128-cmac the whole thing
		derive_cmac_packet18_packet20(&state->secondary_key0, response->data, response->response_size, response->data + 0x30, 0x30);
	}
	else {
		LOG("(GC) p18 cmac validation failed!!\n");
		LOG("(GC) expected: ");
		LOG_BUFFER(exp_cmac, sizeof(got_cmac));
		LOG("(GC) got:");
		LOG_BUFFER(got_cmac, sizeof(got_cmac));
		cmd56_response_error(response, 0xF4);
	}

}

void handle_p20key_and_cmac_signature(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_response_start(request, response);
	
	// just to make it more accurate to what a real gamecart does.
	rand_bytes(response->data, 0x50);
	
	// copy challenge value
	uint8_t* p20_challenge_value = response->data + 0x8;

	memcpy(p20_challenge_value, request->data, 0x10);
	p20_challenge_value[0x00] |= 0x80;

	LOG("(GC) p20_challenge_value: ");
	LOG_BUFFER(p20_challenge_value, 0x10);

	// copy p20 key

	LOG("(GC) copying p20 key.\n");
	memcpy(response->data + 0x18, state->per_cart_keys.packet20_key, sizeof(state->per_cart_keys.packet20_key));

	LOG("(GC) p20 plaintext response: ");
	LOG_BUFFER(response->data, 0x40);

	// encrypt buffer
	encrypt_cbc_zero_iv(&state->secondary_key0, response->data, 0x40);

	// aes-128-cmac the whole thing
	derive_cmac_packet18_packet20(&state->secondary_key0, response->data, response->response_size, response->data + 0x40, 0x40);
}

void handle_verify_shared_random(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_response_start(request, response);

	cmd56_sm_keyid got_key_id = make_short(request->data[1], request->data[0]);

	if (got_key_id == state->key_id) {
		LOG("(GC) got_key_id == state->key_id\n");

		memcpy(state->shared_random.vita_part, request->data + 0x2, sizeof(state->shared_random.vita_part));
		LOG("(GC) read vita portion of the shared random: ");
		LOG_BUFFER(state->shared_random.vita_part, sizeof(state->shared_random.vita_part));

		// gamecart decides the lower portion of vita random ...
		rand_bytes(state->shared_random.cart_part, sizeof(state->shared_random.cart_part));
		state->shared_random.cart_part[0x00] |= 0x80;
		state->shared_random.vita_part[0x00] |= 0x80;

		LOG("(GC) generated gc portion of the shared random: ");
		LOG_BUFFER(state->shared_random.cart_part, sizeof(state->shared_random.cart_part));

		// this is sent back to the console in reverse order ...
		memcpy(response->data + 0x00, state->shared_random.cart_part, sizeof(state->shared_random.cart_part));
		memcpy(response->data + 0x10, state->shared_random.vita_part, sizeof(state->shared_random.vita_part));
		

		LOG("(GC) handle_shared_random plaintext: ");
		LOG_BUFFER(response->data, sizeof(shared_value));

		encrypt_cbc_zero_iv(&state->master_key, response->data, 0x20);

		LOG("(GC) handle_shared_random ciphertext: ");
		LOG_BUFFER(response->data, 0x20);
	}
	else {
		LOG("(GC) key_id from vita not acknowledged? (got: 0x%x, expected: 0x%x)\n", got_key_id, state->key_id);
		cmd56_response_error(response, 0x11);
	}


}

void handle_unknown_request(gc_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	LOG("(GC) Unknown command: %x\n", request->command);
	cmd56_response_start(request, response);
	cmd56_response_error(response, 0x11);
}

void handle_request(gc_cmd56_state* state, cmd56_request* request, cmd56_response* request_response) {
	switch(request->command) {
		case CMD_START: //packet1, packet2
			handle_cmd_start(state, request, request_response);
			break;
		case CMD_GET_STATUS: // packet3, packet4
			handle_cmd_status(state, request, request_response);
			break;
		case CMD_GENERATE_RANDOM_KEYSEED: // packet5, packet6
			handle_generate_random_keyseed(state, request, request_response);
			break;
		case CMD_VERIFY_SHARED_RANDOM: // packet7, packet8
			handle_verify_shared_random(state, request, request_response);
			break;
		case CMD_VITA_AUTHENTICITY_CHECK: // packet9, packet10
			handle_vita_authenticity_check(state, request, request_response);
			break;
			
		// packet11, packet12 -> CMD_GET_STATUS again
		
		case CMD_SECONDARY_KEY0_CHALLENGE: // packet13, packet14
			handle_secondary_key0_challenge(state, request, request_response);
			break;

		case CMD_P18_KEY_AND_CMAC_SIGNATURE: // packet15, packet16
			handle_p18key_and_cmac_signature(state, request, request_response);
			break;

		// packet17, packet18 -> P18_KEY_AND_CMAC_SIGNATURE again

		case CMD_P20_KEY_AND_CMAC_SIGNATURE: // packet19, packet20
			handle_p20key_and_cmac_signature(state, request, request_response);
			break;
		default:
			handle_unknown_request(state, request, request_response);
			break;
	}
}

// exposed functions :

void gc_cmd56_update_keyid(gc_cmd56_state* state, uint16_t key_id) {
	if (state == NULL) return;
	state->key_id = key_id;
}

void gc_cmd56_update_keys_ex(gc_cmd56_state* state, const uint8_t p20_key[0x20], const uint8_t p18_key[0x20]) {
	if (state == NULL) return;
	if (p20_key != NULL) memcpy(&state->per_cart_keys.packet20_key, p20_key, sizeof(state->per_cart_keys.packet20_key));
	if (p18_key != NULL) memcpy(&state->per_cart_keys.packet18_key, p18_key, sizeof(state->per_cart_keys.packet18_key));
}

void gc_cmd56_update_keys(gc_cmd56_state* state, const cmd56_keys* per_cart_keys) {
	if (state == NULL) return;
	if (per_cart_keys != NULL) gc_cmd56_update_keys_ex(state, per_cart_keys->packet20_key, per_cart_keys->packet18_key);
}

void gc_cmd56_init(gc_cmd56_state* state, const cmd56_keys* per_cart_keys) {
	if (state == NULL) return;
	memset(state, 0x00, sizeof(gc_cmd56_state)); 

	// lock "cart" for reading/writing
	state->lock_status = GC_LOCKED;

	// set default key id
	gc_cmd56_update_keyid(state, RETAIL_KEY_ID);

	// set cart specific keys
	gc_cmd56_update_keys(state, per_cart_keys);
}

void gc_cmd56_run_in_place(gc_cmd56_state* state, uint8_t* buffer) {
	if (state == NULL) return;
	uint8_t cmd56_request_response[0x200];
	gc_cmd56_run(state, buffer, cmd56_request_response);
	memcpy(buffer, cmd56_request_response, sizeof(cmd56_request_response));
}

void gc_cmd56_run(gc_cmd56_state* state, const uint8_t* buffer, uint8_t* response) {
	if (state == NULL) return;
	cmd56_request* request = (cmd56_request*)buffer;
	if(memcmp(request->magic, CMD56_MAGIC, sizeof(request->magic)) != 0) {
		return;
	}
	handle_request(state, (cmd56_request*)buffer, (cmd56_response*)response);

}