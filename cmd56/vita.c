/*
*	LibCmd56 from the Estroit team!
*	the only functional implementation of vita gamecart authentication!
*/

#include "compiler_defs.h"
#include "vita.h"
#include "cmd56.h"
#include "cmd56_sm.h"
#include "log.h"

#define check_success(code) do { int ret = code; if(ret != GC_AUTH_OK) return ret; } while(0);
#define send_packet(sobj, req, resp) do { LOG("send_packet: %s\n", __FUNCTION__); \
										  sobj->send( ((const uint8_t*)req), sizeof(cmd56_request)); \
										  sobj->recv( ((uint8_t*)resp),      sizeof(cmd56_response)); } while(0);

#define get_response(type) type* resp = ((type*)response->data)
#define get_request(type) type* req = ((type*)request->data)


#define GC_AUTH_RETURN_STATUS (response->error_code != 0x0) ? GC_AUTH_ERROR_REPORTED : GC_AUTH_OK;


vita_error_code start_request(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_request_start(request, CMD_START, 0x3, calc_size(start_response), 0x31);
	send_packet(state, request, response);
	get_response(start_response);

	if (resp->start[0xD] == 0x1 && resp->start[0xE] == 0x1 && resp->start[0xF] == 0x4) {
		return GC_AUTH_RETURN_STATUS;
	}
	return GC_AUTH_ERROR_START_FAIL;
}

vita_error_code get_status(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_request_start(request, CMD_GET_STATUS, 0x3, calc_size(get_status_response), 0x23);
	send_packet(state, request, response);
	get_response(get_status_response);

	state->lock_status = resp->status;

	return GC_AUTH_RETURN_STATUS;
}

vita_error_code get_session_key(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_request_start(request, CMD_GENERATE_SESSION_KEY, 0x3, calc_size(generate_session_key_response), 0x2);
	send_packet(state, request, response);
	get_response(generate_session_key_response);

	state->key_id = __builtin_bswap16(resp->key_id);
	memcpy(state->cart_random, resp->cart_random, sizeof(state->cart_random));

	LOG("(VITA) Key ID: %x\n", state->key_id);
	LOG("(VITA) CART_RANDOM: ");
	LOG_BUFFER(state->cart_random, sizeof(state->cart_random));

	if (state->allow_prototype_keys == 1 && state->key_id > PROTOTYPE_KEY_ID1) {
		LOG("(VITA) KeyID is > 0x8001, so PSVITA Firmware 1.04+ will reject this cart ...");
		return GC_AUTH_ERROR_GET_CART_RANDOM_PROTOTYPE_KEY;
	}

	// generate session key
	uint8_t session_key[0x10];
	derive_session_key(session_key, state->cart_random, state->key_id);

	LOG("(VITA) Session key: ");
	LOG_BUFFER(session_key, 0x10);

	AES_init_ctx(&state->session_key, session_key);
	return GC_AUTH_RETURN_STATUS;
}

vita_error_code generate_shared_random(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_request_start(request, CMD_EXCHANGE_SHARED_RANDOM, calc_size(exchange_shared_random_request), calc_size(exchange_shared_random_response), 0x3);
	get_request(exchange_shared_random_request);

	// copy key id into request
	LOG("(VITA) cart key id: %x\n", state->key_id);
	req->key_id = __builtin_bswap16(state->key_id);
	
	// randomize vita portion of shared random
	rand_bytes(req->shared_vita_part, sizeof(req->shared_vita_part));
	memcpy(state->shared_random.vita_part, req->shared_vita_part, sizeof(state->shared_random.vita_part));

	LOG("(VITA) vita portion of the shared random: ");
	LOG_BUFFER(req->shared_vita_part, sizeof(req->shared_vita_part));

	LOG("(VITA) verify_shared_random (request): ");
	LOG_BUFFER(req, sizeof(exchange_shared_random_request));

	send_packet(state, request, response);
	get_response(exchange_shared_random_response);

	if (response->error_code == GC_AUTH_OK) {
		decrypt_cbc_zero_iv(&state->session_key, resp, sizeof(exchange_shared_random_response));

		LOG("(VITA) verify_shared_random (response) plaintext: ");
		LOG_BUFFER(resp, sizeof(exchange_shared_random_response));

		if (memcmp(req->shared_vita_part + 0x1, state->shared_random.vita_part + 0x1, sizeof(state->shared_random.vita_part)-0x1) == 0) {
			LOG("(VITA) cart and vita have the same shared_random.vita_part ...\n");
			
			// copy cart part into global state shared_random
			memcpy(state->shared_random.cart_part, resp->shared_cart_part, sizeof(resp->shared_cart_part));

			LOG("(VITA) shared random, cart part: ");
			LOG_BUFFER(state->shared_random.cart_part, sizeof(state->shared_random.cart_part));
			or_w_80(&state->shared_random, sizeof(state->shared_random));

			LOG("(VITA) shared random: ");
			LOG_BUFFER(&state->shared_random, sizeof(shared_random));

			return GC_AUTH_OK;
		}
		else {
			LOG("(VITA) invalid shared_random.vita_part! got: ");
			LOG_BUFFER(resp->shared_vita_part, sizeof(resp->shared_vita_part));
			LOG("(VITA) expected: ");
			LOG_BUFFER(req->shared_vita_part, sizeof(req->shared_vita_part));

			return GC_AUTH_ERROR_VERIFY_SHARED_RANDOM_INVALID;
		}
		return GC_AUTH_ERROR_VERIFY_SHARED_RANDOM_FAIL;
	}

	LOG("(VITA) response->error_code: 0x%X\n", response->error_code);
	return GC_AUTH_ERROR_REPORTED;
}

vita_error_code generate_secondary_key_and_verify_session(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_request_start(request, CMD_EXCHANGE_SECONDARY_KEY_AND_VERIFY_SESSION, calc_size(exchange_secondary_key_and_verify_session_request), 0x3, 0x5);
	get_request(exchange_secondary_key_and_verify_session_request);
	
	rand_bytes(req->secondary_key, sizeof(req->secondary_key));
	AES_init_ctx(&state->secondary_key, req->secondary_key);
	LOG("(VITA) secondary_key: ");
	LOG_BUFFER(req->secondary_key, sizeof(req->secondary_key));
	
	// copy shared_random to challenge
	memcpy(&req->challenge_bytes, &state->shared_random, sizeof(state->shared_random));
	LOG("(VITA) challenge bytes: ");
	LOG_BUFFER(&req->challenge_bytes, sizeof(req->challenge_bytes));

	LOG("(VITA) plaintext secondary_key_and_verify_session: ");
	LOG_BUFFER(req, sizeof(exchange_secondary_key_and_verify_session_request));

	encrypt_cbc_zero_iv(&state->session_key, req, sizeof(exchange_secondary_key_and_verify_session_request));

	LOG("(VITA) ciphertext secondary_key_and_verify_session: ");
	LOG_BUFFER(req, sizeof(exchange_secondary_key_and_verify_session_request));

	send_packet(state, request, response);

	if (response->error_code != GC_AUTH_OK) {
		LOG("(VITA) session_key challenge failed: (error code = 0x%X)\n", response->error_code);
		return GC_AUTH_ERROR_REPORTED;
	}
	else {
		LOG("(VITA) session_key challenge passed!!\n");
		return GC_AUTH_OK;
	}
}

vita_error_code verify_secondary_key(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_request_start(request, CMD_VERIFY_SECONDARY_KEY, calc_size(verify_secondary_key_request), calc_size(verify_secondary_key_response), 0x7);
	get_request(verify_secondary_key_request);

	// generate challenge bytes 
	rand_bytes_or_w_80(req->challenge_bytes, sizeof(req->challenge_bytes));
	LOG("(VITA) generated challenge bytes: ");
	LOG_BUFFER(req->challenge_bytes, sizeof(req->challenge_bytes));

	send_packet(state, request, response);
	get_response(verify_secondary_key_response);

	// decrypt challenge response ...
	decrypt_cbc_zero_iv(&state->secondary_key, resp, sizeof(verify_secondary_key_response));
	LOG("(VITA) decrypted secondary_key challenge: ");
	LOG_BUFFER(resp, sizeof(verify_secondary_key_response));
	
	if (memcmp(resp->challenge_bytes+0x1, req->challenge_bytes+0x1, sizeof(resp->challenge_bytes) - 1) == 0) { // for some reason, the first byte doesnt have to match.
		LOG("(VITA) decrypted secondary_key challenge matches !\n");

		if (memcmp(resp->cart_random, state->cart_random, sizeof(state->cart_random)) == 0) {
			LOG("(VITA) cart_random matches!\n");
			return GC_AUTH_RETURN_STATUS;
		}
		else {
			LOG("(VITA) cart_random invalid! got: ");
			LOG_BUFFER(resp->cart_random, sizeof(state->cart_random));
			LOG("expected: ");
			LOG_BUFFER(state->cart_random, sizeof(state->cart_random));

			return GC_AUTH_ERROR_VERIFY_CART_RANDOM_INVALID_CART_RANDOM;
		}
	}
	else {
		LOG("(VITA) invalid challenge bytes! got: ");
		LOG_BUFFER(resp->challenge_bytes+1, 0xF);
		LOG("(VITA) expected: ");
		LOG_BUFFER(req->challenge_bytes+1, 0xF);

		return GC_AUTH_ERROR_VERIFY_CART_RANDOM_CHALLENGE_INVALID;
	}

	return GC_AUTH_ERROR_VERIFY_CART_RANDOM_FAIL;
}

vita_error_code get_packet18_key(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response, uint8_t type) {
	cmd56_request_start(request, CMD_GET_P18_KEY_AND_CMAC_SIGNATURE, calc_size(get_p18_key_and_cmac_signature_request), calc_size(get_p18_and_cmac_signature_response), 0x11);
	get_request(get_p18_key_and_cmac_signature_request);

	uint8_t expected_challenge[0x10];
	rand_bytes_or_w_80(expected_challenge, sizeof(expected_challenge));
	
	memcpy(req->challenge_bytes, expected_challenge, sizeof(expected_challenge));
	memset(req->pad, 0x00, sizeof(req->pad));
	
	// i dont know what this is for, its just all that changes between the two calls to it, 
	// honestly i dont know why this is command is issued twice;
	req->type = type;
	LOG("(VITA) get_p18_key: type 0x%x\n", type);

	// log before encrypt
	LOG("(VITA) p18 exp_challenge decrypted: ");
	LOG_BUFFER(req, sizeof(get_p18_key_and_cmac_signature_request));

	encrypt_cbc_zero_iv(&state->secondary_key, req, sizeof(get_p18_key_and_cmac_signature_request));

	// create a cmac of all the p18 data, place it at the end of the request.
	do_cmd56_cmac_hash(&state->secondary_key, 
						req, 
						make_int24(request->command, 0x00, request->additional_data_size), 
						req->cmac_signature,
						offsetof(get_p18_key_and_cmac_signature_request, cmac_signature));

	// log after encrypt
	LOG("(VITA) plaintext p18 request data: ");
	LOG_BUFFER(request->data, 0x30);

	send_packet(state, request, response);
	get_response(get_p18_and_cmac_signature_response);

	if (response->error_code == GC_AUTH_OK) { // check status from gc
		uint8_t expected_cmac[0x10];

		// generate p18 cmac
		do_cmd56_cmac_hash(&state->secondary_key, 
						   resp, 
			               response->response_size, 
			               expected_cmac, 
			               offsetof(get_p18_and_cmac_signature_response, cmac_signature));

		if (memcmp(expected_cmac, resp->cmac_signature, sizeof(expected_cmac)) == 0) { // check cmac
			LOG("(VITA) CMAC Matches!\n");

			// decrypt buffer
			decrypt_cbc_zero_iv(&state->secondary_key, resp, offsetof(get_p18_and_cmac_signature_response, cmac_signature));

			LOG("(VITA) decrypted p18 response: ");
			LOG_BUFFER(resp, sizeof(get_p18_and_cmac_signature_response));

			// the first byte doesnt have to match.
			if (memcmp(expected_challenge+0x1, resp->challenge_bytes+0x1, sizeof(expected_challenge) - 0x1) == 0) { 
				LOG("(VITA) p18 challenge success!\n");

				memcpy(state->per_cart_keys.packet18_key, resp->p18_key, sizeof(state->per_cart_keys.packet18_key));
				LOG("(VITA) state->per_cart_keys.packet18_key: ");
				LOG_BUFFER(state->per_cart_keys.packet18_key, sizeof(state->per_cart_keys.packet18_key));

				return GC_AUTH_OK;

			}
			else {
				LOG("(VITA) Invalid p18 challenge response! got: ");
				LOG_BUFFER(resp->challenge_bytes+0x1, sizeof(expected_challenge)-0x1);
				LOG("(VITA) expected: ");
				LOG_BUFFER(expected_challenge+0x1, sizeof(expected_challenge)-0x1);

				return GC_AUTH_ERROR_P18_KEY_CHALLANGE_FAIL;
			}
		}
		else {
			LOG("(VITA) Invalid p18 CMAC! got: ");
			LOG_BUFFER(resp->cmac_signature, 0x10);
			LOG("(VITA) expected: ");
			LOG_BUFFER(expected_cmac, 0x10);

			return GC_AUTH_ERROR_P18_KEY_INVALID_CMAC;
		}
	}
	LOG("(VITA) response->error_code: 0x%X\n", response->error_code);
	return GC_AUTH_ERROR_REPORTED;
}

vita_error_code get_packet20_key(vita_cmd56_state* state, cmd56_request* request, cmd56_response* response) {
	cmd56_request_start(request, CMD_GET_P20_KEY_AND_CMAC_SIGNATURE, calc_size(get_p20_key_and_cmac_signature_request), calc_size(get_p20_key_and_cmac_signature_response), 0x19);
	get_request(get_p20_key_and_cmac_signature_request);
	rand_bytes_or_w_80(req->challenge_bytes, 0x10);

	LOG("(VITA) p20 request: ");
	LOG_BUFFER(req, sizeof(get_p20_key_and_cmac_signature_request));

	send_packet(state, request, response);
	get_response(get_p20_key_and_cmac_signature_response);

	if (response->error_code == GC_AUTH_OK) {
		uint8_t expected_cmac[0x10];
		
		// generate p20 cmac
		do_cmd56_cmac_hash(&state->secondary_key, 
							resp, 
							response->response_size, 
							expected_cmac, 
							offsetof(get_p20_key_and_cmac_signature_response, cmac_signature));

		if (memcmp(expected_cmac, resp->cmac_signature, sizeof(expected_cmac)) == 0) { // cmac check
			LOG("(VITA) p20 cmac check pass\n");

			// decrypt response
			decrypt_cbc_zero_iv(&state->secondary_key, resp, offsetof(get_p20_key_and_cmac_signature_response, cmac_signature));

			LOG("(VITA) decrypted p20 response data:");
			LOG_BUFFER(resp, sizeof(get_p20_key_and_cmac_signature_response));

			if (memcmp(req->challenge_bytes+0x1, resp->challenge_bytes+0x1, sizeof(resp->challenge_bytes)-1) == 0) { // challenge check
				LOG("(VITA) p20 challenge matches!\n");

				memcpy(state->per_cart_keys.packet20_key, resp->p20_key, sizeof(state->per_cart_keys.packet20_key));
				LOG("(VITA) state->per_cart_keys.packet20_key: ");
				LOG_BUFFER(state->per_cart_keys.packet20_key, sizeof(state->per_cart_keys.packet20_key));

				return GC_AUTH_OK;
			}
			else {
				LOG("(VITA) Invalid Challenge Response! got: ");
				LOG_BUFFER(resp->challenge_bytes+0x1, 0xF);
				LOG("expected: ");
				LOG_BUFFER(req->challenge_bytes+0x1, 0xF);

				return GC_AUTH_ERROR_P20_KEY_CHALLANGE_FAIL;
			}
		}
		else {
			LOG("(VITA) Invalid CMAC! got: ");
			LOG_BUFFER(resp->cmac_signature, 0x10);
			LOG("expected: ");
			LOG_BUFFER(expected_cmac, 0x10);

			return GC_AUTH_ERROR_P20_KEY_INVALID_CMAC;
		}
	}
	LOG("(VITA) response->error_code: 0x%X\n", response->error_code);
	return GC_AUTH_ERROR_REPORTED;
}

// exposed functions

void vita_cmd56_init(vita_cmd56_state* state, send_t send_func, recv_t recv_func) {
	if (state == NULL) return;

	memset(state, 0x00, sizeof(vita_cmd56_state));
	state->send = send_func;
	state->recv = recv_func;
										 // false, replicates the functionality of 1.04+ firmware, prototype carts not allowed.
	state->allow_prototype_keys = false; // true, it acts more like a prototype <1.04 console, allowing prototype carts.
}

void vita_cmd56_init_ex(vita_cmd56_state* state, send_t send_func, recv_t recv_func, bool allow_prototype_keys) {
	if (state == NULL) return;

	vita_cmd56_init(state, send_func, recv_func);
	state->allow_prototype_keys = true;
}

void vita_cmd56_get_keyid(vita_cmd56_state* state, cmd56_sm_keyid* key_id) {
	if (state == NULL) return;
	if (key_id != NULL) memcpy(key_id, &state->key_id, sizeof(state->key_id));
}

void* vita_cmd56_get_keys(vita_cmd56_state* state, cmd56_keys* per_cart_keys) {
	if (state == NULL) return;

	if (per_cart_keys != NULL) memcpy(per_cart_keys, &state->per_cart_keys, sizeof(cmd56_keys));
}
void* vita_cmd56_get_keys_ex(vita_cmd56_state* state, uint8_t p20_key[0x20], uint8_t p18_key[0x20]) {
	if (state == NULL) return;

	if (p20_key != NULL) memcpy(p20_key, state->per_cart_keys.packet20_key, sizeof(state->per_cart_keys.packet20_key));
	if (p18_key != NULL) memcpy(p18_key, state->per_cart_keys.packet18_key, sizeof(state->per_cart_keys.packet18_key));
}

int vita_cmd56_run(vita_cmd56_state* state) {
	if (state == NULL) return;

	cmd56_request request;
	cmd56_response response;

	memset(&request, 0x00, sizeof(cmd56_request));
	memset(&response, 0x00, sizeof(cmd56_response));

	check_success(start_request(state, &request, &response)); // initalize gc
	check_success(get_status(state, &request, &response)); // check is locked
	if (state->lock_status != GC_LOCKED) return GC_AUTH_ERROR_UNLOCKED; // error if is not locked

	check_success(get_session_key(state, &request, &response)); // get cart random, and keyid 
	check_success(generate_shared_random(state, &request, &response)); // send vita portion of shared random and receive gc portion.
	check_success(generate_secondary_key_and_verify_session(state, &request, &response)); // generate vita authenticity proof

	check_success(get_status(state, &request, &response)); // check is unlocked
	if (state->lock_status != GC_UNLOCKED) return GC_AUTH_ERROR_LOCKED; // error if is not unlocked
	
	check_success(verify_secondary_key(state, &request, &response)); // check if secondary_key was obtained by the cart.
	check_success(get_packet18_key(state, &request, &response, 0x2)); // get packet18 key, and verify cmac
	check_success(get_packet18_key(state, &request, &response, 0x3)); // for some reason this gets sent twice,
	check_success(get_packet20_key(state, &request, &response)); // get packet20 key.
	
	return GC_AUTH_OK;
}