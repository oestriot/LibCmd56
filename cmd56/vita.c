#include "compiler_defs.h"
#include "vita.h"
#include "cmd56.h"
#include "f00d_emu.h"
#include "rng.h"
#include "log.h"

#define check_success(code) do { int ret = code; if(ret != SCE_OK) return ret; } while(0);
#define send_packet(x) do { x->send(&x->cmd56_request, sizeof(cmd56_request)); \
							x->recv(&x->cmd56_response, sizeof(cmd56_response)); } while(0);
#define rand_bytes_or_w_80(buf, size) do { rand_bytes(buf, size); \
										   ((uint8_t*)buf)[0] |= 0x80; } while(0);\



vita_error_code start_request(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, START, 0x3, 0x13, 0x31);
	send_packet(state);

	if (state->cmd56_response.data[0xD] == 0x1 && state->cmd56_response.data[0xE] == 0x1 && state->cmd56_response.data[0xF] == 0x4) {
		return SCE_OK;
	}
	return SCE_ERROR;
}

vita_error_code get_status(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, GET_STATUS, 0x3, 0x5, 0x23);
	send_packet(state);

	state->lock_status = make_short(state->cmd56_response.data[0x0], state->cmd56_response.data[0x1]);

	return state->cmd56_response.error_code;
}

vita_error_code get_cart_random(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, GENERATE_RANDOM_KEYSEED, 0x3, 0x2B, 0x2);
	send_packet(state);
	
	state->key_id = make_short(state->cmd56_response.data[0x3], state->cmd56_response.data[0x2]);
	memcpy(state->cart_random, state->cmd56_response.data + 0x8, sizeof(state->cart_random));

	LOG("(VITA) Key ID: %x\n", state->key_id);
	LOG("(VITA) CART_RANDOM: ");
	LOG_BUFFER(state->cart_random, sizeof(state->cart_random));

#ifndef ALLOW_PROTOTYPE_KEYS
	if (state->key_id > PROTOTYPE_KEY_ID1) {
		LOG("(VITA) KeyID is > 0x8001, so PSVITA Firmware 1.04+ will reject this cart ...");
		return SCE_ERROR;
	}
#endif

	// generate master key
	uint8_t master_key[0x10];
	derive_master_key(master_key, state->cart_random, state->key_id);

	LOG("(VITA) Master Key: ");
	LOG_BUFFER(master_key, 0x10);

	AES_init_ctx(&state->master_key, master_key);
	return state->cmd56_response.error_code;
}

vita_error_code verify_vita_random(vita_cmd56_state* state) {
	rand_bytes(state->vita_random, sizeof(state->vita_random));
	
	cmd56_request_start(&state->cmd56_request, VERIFY_VITA_RANDOM, 0x15, 0x23, 0x3);
	memcpy(state->cmd56_request.data + 0x2, state->vita_random, sizeof(state->vita_random));
	send_packet(state);

	LOG("(VITA) Ciphertext: ");
	LOG_BUFFER(state->cmd56_response.data, 0x20);

	decrypt_cbc_zero_iv(&state->master_key, state->cmd56_response.data, 0x20);
	
	LOG("(VITA) Plaintext: ");
	LOG_BUFFER(state->cmd56_response.data, 0x20);

	if (memcmp(state->cmd56_response.data + 0x10, state->vita_random, sizeof(state->vita_random)) == 0) {
		return SCE_OK;
	}
	else {
		LOG("(VITA) got random and sent random dont match!\n");
		return SCE_ERROR;
	}
}

vita_error_code generate_vita_authenticity_proof(vita_cmd56_state* state) {
	char secondary_key0[0x10];
	rand_bytes_or_w_80(secondary_key0, sizeof(secondary_key0));

	LOG("(VITA) secondary_key0: ");
	LOG_BUFFER(secondary_key0, sizeof(secondary_key0));
	AES_init_ctx(&state->secondary_key0, secondary_key0);

	cmd56_request_start(&state->cmd56_request, VITA_AUTHENTICITY_CHECK, 0x33, 0x3, 0x5);

	memcpy(state->cmd56_request.data + 0x00, secondary_key0, sizeof(secondary_key0));
	memcpy(state->cmd56_request.data + 0x10, state->vita_random, sizeof(state->vita_random));
	
	uint8_t* challenge = state->cmd56_request.data + 0x10;
	challenge[0x00] |= 0x80;
	challenge[0x10] |= 0x80;

	encrypt_cbc_zero_iv(&state->master_key, state->cmd56_request.data, 0x30);

	LOG("(VITA) VITA_AUTHENTICITY_PROOF: ");
	LOG_BUFFER(state->cmd56_request.data, 0x30);
	
	send_packet(state);

	if (state->cmd56_response.data[0] == 0 || state->cmd56_response.data[1] == 0 || state->cmd56_response.data[2] == 0) {
		return SCE_OK;
	}
	else {
		return SCE_ERROR;
	}
}


vita_error_code verify_cart_random(vita_cmd56_state* state) {
	uint8_t* challenge_bytes = state->cmd56_request.data;
	cmd56_request_start(&state->cmd56_request, SECONDARY_KEY0_CHALLENGE, 0x13, 0x43, 0x7);
	rand_bytes_or_w_80(challenge_bytes, 0x10);
	
	LOG("(VITA) CHALLENGE BYTES: ");
	LOG_BUFFER(challenge_bytes, 0x10);

	send_packet(state);

	decrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_response.data, 0x40);

	if (memcmp(state->cmd56_response.data + 0x8, challenge_bytes, 0x10) == 0) {
		LOG("(VITA) CHALLENGE BYTES MATCH!\n");
		if (memcmp(state->cmd56_response.data + 0x18, state->cart_random, sizeof(state->cart_random)) == 0) {
			LOG("(VITA) CART_RANDOM MATCH!\n");
			return SCE_OK;
		}
	}
	return SCE_ERROR;
}

vita_error_code get_packet18_key(vita_cmd56_state* state) {
	uint8_t challenge_bytes[0x20];
	cmd56_request_start(&state->cmd56_request, P18_KEY_AND_CMAC_SIGNATURE, 0x33, 0x43, 0x11);
	
	rand_bytes(challenge_bytes, sizeof(challenge_bytes));
	memcpy(state->cmd56_request.data + 0x00, challenge_bytes, sizeof(challenge_bytes));

	derive_cmac_packet18_packet20(&state->secondary_key0, state->cmd56_request.data, make_short(state->cmd56_request.command,state->cmd56_request.additional_data_size), state->cmd56_request.data + 0x20, 0x20);
	
	LOG("(VITA) CHALLENGE BYTES: ");
	LOG_BUFFER(state->cmd56_request.data, 0x30);

	encrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_request.data, 0x20);
	send_packet(state);

	if (state->cmd56_response.error_code == SCE_OK) {
		uint8_t exp_cmac[0x10];
		uint8_t* got_cmac = state->cmd56_response.data + 0x30;

		derive_cmac_packet18_packet20(&state->secondary_key0, state->cmd56_response.data, state->cmd56_response.response_size, exp_cmac, 0x30);
		if (memcmp(exp_cmac, got_cmac, sizeof(exp_cmac)) == 0) {
			LOG("(VITA) CMAC Matches!\n");

			// decrypt buffer
			decrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_response.data, 0x30);
			if (memcmp(state->cmd56_response.data, challenge_bytes, 0x10) == 0) {
				LOG("(VITA) Challenge matches!\n");

				memcpy(state->gc_spec_key.packet18_key, state->cmd56_response.data + 0x10, sizeof(state->gc_spec_key.packet18_key));
				LOG("(VITA) packet18_key: ");
				LOG_BUFFER(state->gc_spec_key.packet18_key, sizeof(state->gc_spec_key.packet18_key));

				return SCE_OK;

			}
			else {
				LOG("(VITA) Invalid Challenge Response! got: ");
				LOG_BUFFER(state->cmd56_response.data, 0x10);
				LOG("expected: ");
				LOG_BUFFER(challenge_bytes, 0x10);
			}
		}
	}
	
	return SCE_ERROR;
}

vita_error_code get_packet20_key(vita_cmd56_state* state) {
	cmd56_request_start(&state->cmd56_request, P20_KEY_AND_CMAC_SIGNATURE, 0x13, 0x53, 0x19);
	
	rand_bytes_or_w_80(state->cmd56_request.data, 0x10);

	send_packet(state);
	
	uint8_t cmacOut[0x10];
	derive_cmac_packet18_packet20(&state->secondary_key0, state->cmd56_response.data, state->cmd56_response.response_size, cmacOut, 0x40);
	if (memcmp(cmacOut, state->cmd56_response.data + 0x40, sizeof(cmacOut)) == 0) {
		LOG("(VITA) cmac check pass\n");

		// decrypt buffer
		decrypt_cbc_zero_iv(&state->secondary_key0, state->cmd56_response.data, 0x40);

		if (memcmp(state->cmd56_request.data, state->cmd56_response.data + 0x8, 0x10) == 0) {
			LOG("(VITA) rng check pass\n");

			memcpy(state->gc_spec_key.packet20_key, state->cmd56_response.data + 0x18, sizeof(state->gc_spec_key.packet20_key));
			LOG("(VITA) state->gc_spec_key.packet20_key: ");
			LOG_BUFFER(state->gc_spec_key.packet20_key, sizeof(state->gc_spec_key.packet20_key));

			return SCE_OK;
		}
	}
	return SCE_ERROR;
}

// exposed functions

void vita_cmd56_init(vita_cmd56_state* state, send_t send_func, recv_t recv_func) {
	memset(state, 0x00, sizeof(vita_cmd56_state));
	state->send = send_func;
	state->recv = recv_func;
}

int vita_cmd56_run(vita_cmd56_state* state) {

	check_success(start_request(state)); // initalize gc
	check_success(get_status(state)); // check is locked
	if (state->lock_status != GC_LOCKED) return SCE_ERROR; // error if is locked

	check_success(get_cart_random(state)); // get cart random, and keyid 
	check_success(verify_vita_random(state)); // send vita random
	check_success(generate_vita_authenticity_proof(state)); // generate vita authenticity proof

	check_success(get_status(state)); // check is unlocked
	if (state->lock_status != GC_UNLOCKED) return SCE_ERROR; // error if is not unlocked
	
	check_success(verify_cart_random(state)); // check if secondary_key0 was obtained by the cart.
	check_success(get_packet18_key(state)); // get packet18 key, and verify cmac
	check_success(get_packet18_key(state)); // for some reason this gets sent twice,
	check_success(get_packet20_key(state)); // get packet20 key.
	return SCE_OK;
}