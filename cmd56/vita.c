#include "compiler_defs.h"
#include "vita.h"
#include "cmd56.h"
#include "f00d_emu.h"
#include "rng.h"
#include "log.h"

#define check_success(code) do { int ret = code; if(ret != GC_AUTH_OK) return ret; } while(0);
#define send_packet(x) do { LOG("send_packet: %s\n", __FUNCTION__); \
							x->send( ((const uint8_t*)&x->cmd56_request), sizeof(cmd56_request)); \
							x->recv( ((uint8_t*)&x->cmd56_response),      sizeof(cmd56_response)); } while(0);
#define rand_bytes_or_w_80(buf, size) do { rand_bytes(buf, size); \
									  ((uint8_t*)buf)[0] |= 0x80; } while(0);\

#define GC_AUTH_RETURN_STATUS (state->cmd56_response.error_code != 0x0) ? GC_AUTH_ERROR_REPORTED : GC_AUTH_OK;


vita_error_code start_request(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, CMD_START, 0x3, 0x13, 0x31);
	send_packet(state);

	if (state->cmd56_response.data[0xD] == 0x1 && state->cmd56_response.data[0xE] == 0x1 && state->cmd56_response.data[0xF] == 0x4) {
		return GC_AUTH_RETURN_STATUS;
	}
	return GC_AUTH_ERROR_START_FAIL;
}

vita_error_code get_status(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, CMD_GET_STATUS, 0x3, 0x5, 0x23);
	send_packet(state);

	state->lock_status = make_short(state->cmd56_response.data[0x0], state->cmd56_response.data[0x1]);

	return GC_AUTH_RETURN_STATUS;
}

vita_error_code get_cart_random(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, CMD_GENERATE_RANDOM_KEYSEED, 0x3, 0x2B, 0x2);
	send_packet(state);
	
	state->key_id = make_short(state->cmd56_response.data[0x3], state->cmd56_response.data[0x2]);
	memcpy(state->cart_random, state->cmd56_response.data + 0x8, sizeof(state->cart_random));

	LOG("(VITA) Key ID: %x\n", state->key_id);
	LOG("(VITA) CART_RANDOM: ");
	LOG_BUFFER(state->cart_random, sizeof(state->cart_random));

	if (state->allow_prototype_keys == 1 && state->key_id > PROTOTYPE_KEY_ID1) {
		LOG("(VITA) KeyID is > 0x8001, so PSVITA Firmware 1.04+ will reject this cart ...");
		return GC_AUTH_ERROR_GET_CART_RANDOM_PROTOTYPE_KEY;
	}

	// generate master key
	uint8_t master_key[0x10];
	derive_master_key(master_key, state->cart_random, state->key_id);

	LOG("(VITA) Master Key: ");
	LOG_BUFFER(master_key, 0x10);

	AES_init_ctx(&state->master_key, master_key);
	return GC_AUTH_RETURN_STATUS;
}

vita_error_code verify_vita_random(vita_cmd56_state* state) {
	
	// replicate a bug in 3.60: only first 0x10 bytes of VITA_RANDOM
	// are actually randomized, the rest is all 0's for some reason.

	rand_bytes(state->vita_random, 0x10);
	
	cmd56_request_start(&state->cmd56_request, CMD_VERIFY_VITA_RANDOM, 0x15, 0x23, 0x3);
	
	// copy random and key id into it.
	memcpy(state->cmd56_request.data + 0x2, state->vita_random, sizeof(state->vita_random));
	state->cmd56_request.data[0x1] = (state->key_id & 0x00FF);
	state->cmd56_request.data[0x0] = (state->key_id & 0xFF00) >> 8;

	send_packet(state);

	if (state->cmd56_response.error_code == GC_AUTH_OK) {
		LOG("(VITA) Ciphertext: ");
		LOG_BUFFER(state->cmd56_response.data, 0x20);

		decrypt_cbc_zero_iv(&state->master_key, state->cmd56_response.data, 0x20);
		
		LOG("(VITA) Plaintext: ");
		LOG_BUFFER(state->cmd56_response.data, 0x20);

	
		uint8_t* got_vita_random = state->cmd56_response.data + 0x10;
		if (memcmp(got_vita_random, state->vita_random, sizeof(state->vita_random)) == 0) {
			return GC_AUTH_OK;
		}
		else {
			LOG("(VITA) Invalid VITA_RANDOM! got: ");
			LOG_BUFFER(got_vita_random, sizeof(state->vita_random));
			LOG("expected: ");
			LOG_BUFFER(state->vita_random, sizeof(state->vita_random));

			return GC_AUTH_ERROR_VERIFY_CART_RANDOM_INVALID_CART_RANDOM;

			return GC_AUTH_ERROR_VERIFY_VITA_RANDOM_INVALID;
		}
		return GC_AUTH_ERROR_VERIFY_VITA_RANDOM_FAIL;
	}

	LOG("(VITA) state->cmd56_response.error_code: 0x%X\n", state->cmd56_response.error_code);
	return GC_AUTH_ERROR_REPORTED;
}

vita_error_code generate_vita_authenticity_proof(vita_cmd56_state* state) {
	uint8_t secondary_key0[0x10];
	rand_bytes_or_w_80(secondary_key0, sizeof(secondary_key0));

	LOG("(VITA) secondary_key0: ");
	LOG_BUFFER(secondary_key0, sizeof(secondary_key0));
	AES_init_ctx(&state->secondary_key0, secondary_key0);

	cmd56_request_start(&state->cmd56_request, CMD_VITA_AUTHENTICITY_CHECK, 0x33, 0x3, 0x5);

	// copy secondary_key0 to packet start
	memcpy(state->cmd56_request.data + 0x00, secondary_key0, sizeof(secondary_key0));
	
	// copy vita_random to challenge
	uint8_t* challenge = state->cmd56_request.data + 0x10;
	memcpy(challenge, state->vita_random, sizeof(state->vita_random));
	
	// or the challenge bytes with 0x80, for.. some reason?
	challenge[0x00] |= 0x80;
	challenge[0x10] |= 0x80;

	LOG("(VITA) Challenge bytes: ");
	LOG_BUFFER(challenge, sizeof(state->vita_random));

	LOG("(VITA) plaintext VITA_AUTHENTICITY_PROOF: ");
	LOG_BUFFER(state->cmd56_request.data, 0x30);

	encrypt_cbc_zero_iv(&state->master_key, state->cmd56_request.data, 0x30);

	LOG("(VITA) encrypted VITA_AUTHENTICITY_PROOF: ");
	LOG_BUFFER(state->cmd56_request.data, 0x30);
	
	send_packet(state);

	if (state->cmd56_response.error_code != GC_AUTH_OK) {
		LOG("(VITA) VITA_AUTHNETICITY_PROOF Fail (i'm not a real psvita :CCC) (error code = 0x%X)\n", state->cmd56_response.error_code);
		return GC_AUTH_ERROR_REPORTED;
	}
	else {
		return GC_AUTH_OK;
	}
}


vita_error_code verify_cart_random(vita_cmd56_state* state) {
	uint8_t* exp_challenge = state->cmd56_request.data;
	cmd56_request_start(&state->cmd56_request, CMD_SECONDARY_KEY0_CHALLENGE, 0x13, 0x43, 0x7);
	rand_bytes_or_w_80(exp_challenge, 0x10);
	
	LOG("(VITA) CHALLENGE BYTES: ");
	LOG_BUFFER(exp_challenge, 0x10);

	send_packet(state);

	decrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_response.data, 0x40);
	uint8_t* got_challenge = state->cmd56_response.data + 0x8;
	if (memcmp(got_challenge, exp_challenge, 0x10) == 0) { // Challenge check
		LOG("(VITA) CHALLENGE BYTES MATCH!\n");

		uint8_t* got_cart_random = state->cmd56_response.data + 0x18;
		if (memcmp(got_cart_random, state->cart_random, sizeof(state->cart_random)) == 0) {
			LOG("(VITA) CART_RANDOM MATCH!\n");
			return GC_AUTH_RETURN_STATUS;
		}
		else {
			LOG("(VITA) Invalid CART_RANDOM! got: ");
			LOG_BUFFER(got_cart_random, sizeof(state->cart_random));
			LOG("expected: ");
			LOG_BUFFER(state->cart_random, sizeof(state->cart_random));

			return GC_AUTH_ERROR_VERIFY_CART_RANDOM_INVALID_CART_RANDOM;
		}
	}
	else {
		LOG("(VITA) Invalid CHALLENGE BYTES! got: ");
		LOG_BUFFER(exp_challenge, 0x10);
		LOG("expected: ");
		LOG_BUFFER(got_challenge, 0x10);

		return GC_AUTH_ERROR_VERIFY_CART_RANDOM_CHALLENGE_INVALID;
	}

	return GC_AUTH_ERROR_VERIFY_CART_RANDOM_FAIL;
}

vita_error_code get_packet18_key(vita_cmd56_state* state) {
	uint8_t exp_challenge[0x20];
	cmd56_request_start(&state->cmd56_request, CMD_P18_KEY_AND_CMAC_SIGNATURE, 0x33, 0x43, 0x11);
	
	rand_bytes(exp_challenge, sizeof(exp_challenge));
	memcpy(state->cmd56_request.data + 0x00, exp_challenge, sizeof(exp_challenge));

	derive_cmac_packet18_packet20(&state->secondary_key0, state->cmd56_request.data, make_short(state->cmd56_request.command,state->cmd56_request.additional_data_size), state->cmd56_request.data + 0x20, 0x20);
	
	LOG("(VITA) CHALLENGE BYTES: ");
	LOG_BUFFER(state->cmd56_request.data, 0x30);

	encrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_request.data, 0x20);
	send_packet(state);

	if (state->cmd56_response.error_code == GC_AUTH_OK) { // check status from gc
		uint8_t exp_cmac[0x10];
		uint8_t* got_cmac = state->cmd56_response.data + 0x30;

		derive_cmac_packet18_packet20(&state->secondary_key0, state->cmd56_response.data, state->cmd56_response.response_size, exp_cmac, 0x30);
		if (memcmp(exp_cmac, got_cmac, sizeof(exp_cmac)) == 0) { // check cmac
			LOG("(VITA) CMAC Matches!\n");

			// decrypt buffer
			decrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_response.data, 0x30);
			uint8_t* got_challenge = state->cmd56_response.data + 0x00;

			if (memcmp(exp_challenge, got_challenge, 0x10) == 0) { // challenge check
				LOG("(VITA) Challenge matches!\n");

				memcpy(state->per_cart_keys.packet18_key, state->cmd56_response.data + 0x10, sizeof(state->per_cart_keys.packet18_key));
				LOG("(VITA) packet18_key: ");
				LOG_BUFFER(state->per_cart_keys.packet18_key, sizeof(state->per_cart_keys.packet18_key));

				return GC_AUTH_OK;

			}
			else {
				LOG("(VITA) Invalid Challenge Response! got: ");
				LOG_BUFFER(got_challenge, 0x10);
				LOG("expected: ");
				LOG_BUFFER(exp_challenge, 0x10);

				return GC_AUTH_ERROR_P18_KEY_CHALLANGE_FAIL;
			}
		}
		else {
			LOG("(VITA) Invalid CMAC! got: ");
			LOG_BUFFER(got_cmac, 0x10);
			LOG("expected: ");
			LOG_BUFFER(exp_cmac, 0x10);

			return GC_AUTH_ERROR_P18_KEY_INVALID_CMAC;
		}
	}
	LOG("(VITA) state->cmd56_response.error_code: 0x%X\n", state->cmd56_response.error_code);
	return GC_AUTH_ERROR_REPORTED;
}

vita_error_code get_packet20_key(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, CMD_P20_KEY_AND_CMAC_SIGNATURE, 0x13, 0x53, 0x19);
	uint8_t* exp_challange = state->cmd56_request.data + 0x00;
	rand_bytes_or_w_80(exp_challange, 0x10);
	send_packet(state);

	if (state->cmd56_response.error_code == GC_AUTH_OK) {
		uint8_t exp_cmac[0x10];
		uint8_t* got_cmac = state->cmd56_response.data + 0x40;
		
		derive_cmac_packet18_packet20(&state->secondary_key0, state->cmd56_response.data, state->cmd56_response.response_size, exp_cmac, 0x40);
		if (memcmp(exp_cmac, got_cmac, sizeof(exp_cmac)) == 0) { // cmac check
			LOG("(VITA) cmac check pass\n");

			// decrypt buffer
			decrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_response.data, 0x40);
			uint8_t* got_challange = state->cmd56_response.data + 0x8;

			if (memcmp(exp_challange, got_challange, 0x10) == 0) { // challenge check
				LOG("(VITA) Challenge matches!\n");

				memcpy(state->per_cart_keys.packet20_key, state->cmd56_response.data + 0x18, sizeof(state->per_cart_keys.packet20_key));
				LOG("(VITA) state->per_cart_keys.packet20_key: ");
				LOG_BUFFER(state->per_cart_keys.packet20_key, sizeof(state->per_cart_keys.packet20_key));

				return GC_AUTH_OK;
			}
			else {
				LOG("(VITA) Invalid Challenge Response! got: ");
				LOG_BUFFER(got_challange, 0x10);
				LOG("expected: ");
				LOG_BUFFER(exp_challange, 0x10);

				return GC_AUTH_ERROR_P20_KEY_CHALLANGE_FAIL;
			}
		}
		else {
			LOG("(VITA) Invalid CMAC! got: ");
			LOG_BUFFER(got_cmac, 0x10);
			LOG("expected: ");
			LOG_BUFFER(exp_cmac, 0x10);

			return GC_AUTH_ERROR_P20_KEY_INVALID_CMAC;
		}
	}
	LOG("(VITA) state->cmd56_response.error_code: 0x%X\n", state->cmd56_response.error_code);
	return GC_AUTH_ERROR_REPORTED;
}

// exposed functions

void vita_cmd56_init(vita_cmd56_state* state, send_t send_func, recv_t recv_func) {
	memset(state, 0x00, sizeof(vita_cmd56_state));
	state->send = send_func;
	state->recv = recv_func;

	state->allow_prototype_keys = false; // emulate 3.60 firmware
}

int vita_cmd56_run(vita_cmd56_state* state) {

	check_success(start_request(state)); // initalize gc
	check_success(get_status(state)); // check is locked
	if (state->lock_status != GC_LOCKED) return GC_AUTH_ERROR_LOCKED; // error if is locked

	check_success(get_cart_random(state)); // get cart random, and keyid 
	check_success(verify_vita_random(state)); // send vita random
	check_success(generate_vita_authenticity_proof(state)); // generate vita authenticity proof

	check_success(get_status(state)); // check is unlocked
	if (state->lock_status != GC_UNLOCKED) return GC_AUTH_ERROR_UNLOCKED; // error if is not unlocked
	
	check_success(verify_cart_random(state)); // check if secondary_key0 was obtained by the cart.
	check_success(get_packet18_key(state)); // get packet18 key, and verify cmac
	check_success(get_packet18_key(state)); // for some reason this gets sent twice,
	check_success(get_packet20_key(state)); // get packet20 key.
	return GC_AUTH_OK;
}