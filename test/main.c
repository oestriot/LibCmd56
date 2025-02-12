#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define _DEBUG 1

#include "../cmd56/gc.h"
#include "../cmd56/vita.h"
#include "../cmd56/log.h"

// smart as ...
static cmd56_keys keys = { { 0x13, 0x29, 0x86, 0x29, 0x00, 0x63, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x42, 0x21, 0x00, 0x00, 0x00, 0x42, 0x02, 0x00, 0x86, 0x29, 0x11, 0x22, 0x63, 0x4E, 0x20, 0x11, 0x00, 0x00, 0x00, 0x00 }, { 0xA9, 0xA8, 0xC9, 0x09, 0xCF, 0xBD, 0x7F, 0xCD, 0x15, 0xB1, 0xDB, 0xCE, 0xA0, 0xFC, 0xF0, 0x5C, 0xAB, 0xF3, 0x80, 0xDB, 0xA7, 0xCB, 0x5E, 0x34, 0xD9, 0xF8, 0x5A, 0xD4, 0x1D, 0x4A, 0xF5, 0x0F } };

static gc_cmd56_state gc_state;
static vita_cmd56_state vita_state;


static uint8_t VITA_PACKET[0x200];
static uint8_t GC_PACKET[0x200];

void emu_send(char* buf, size_t size) {
	memcpy(VITA_PACKET, buf, size);
	LOG("(VITA -> GC): ");
	LOG_BUFFER(VITA_PACKET, sizeof(VITA_PACKET));
}

void emu_recv(char* buf, size_t size) {
	gc_cmd56_run(&gc_state, VITA_PACKET, GC_PACKET);
	memcpy(buf, GC_PACKET, size);
	LOG("(GC -> VITA): ");
	LOG_BUFFER(GC_PACKET, sizeof(GC_PACKET));
}

#define REPLAY_TEST 1
#ifdef REPLAY_TEST

static FILE* vRecv = NULL;
static FILE* gRecv = NULL;

int load_files(char** vitaBuffer, char** gcBuffer, size_t* vSize, size_t* gSize) {
	FILE* vRecv = fopen("from_vita.bin", "rb");
	FILE* gRecv = fopen("from_gc.bin", "rb");

	if (!vRecv || !gRecv) {
		fprintf(stderr, "Error opening files.\n");
		return 1;
	}

	fseek(vRecv, 0, SEEK_END);
	*vSize = ftell(vRecv);
	fseek(vRecv, 0, SEEK_SET);

	fseek(gRecv, 0, SEEK_END);
	*gSize = ftell(gRecv);
	fseek(gRecv, 0, SEEK_SET);

	*vitaBuffer = malloc(*vSize);
	*gcBuffer = malloc(*gSize);

	if (!*vitaBuffer || !*gcBuffer) {
		fprintf(stderr, "Memory allocation failed.\n");
		fclose(vRecv);
		fclose(gRecv);
		return 1;
	}

	fread(*vitaBuffer, 1, *vSize, vRecv);
	fread(*gcBuffer, 1, *gSize, gRecv);

	fclose(vRecv);
	fclose(gRecv);
	return 0;
}

int test_replay() {
	char* vitaBuffer;
	char* gcBuffer;
	size_t vitaSize;
	size_t gcSize;

	int res = load_files(&vitaBuffer, &gcBuffer, &vitaSize, &gcSize);
	if (res != 0) return res;
	vRecv = fopen("from_vita.bin", "rb");
	gRecv = fopen("from_gc.bin", "rb");

	
	size_t vitaPos = 0;
	size_t gcPos = 0;

	uint8_t VITA_PACKET[0x200];
	uint8_t GC_PACKET[0x200];
	uint8_t EXPECTED_GC_PACKET[0x200];

	int requestId = 0;
	int packetId = 0;
	for (; res == 0; requestId++) {
		// Copy packet data from buffers
		if (vitaPos >= vitaSize) break;
		memcpy(VITA_PACKET, vitaBuffer + vitaPos, sizeof(VITA_PACKET));
		vitaPos += sizeof(VITA_PACKET);
		LOG("\n== TESTING REQUEST %i ==\n", requestId);
		
		LOG("\n=== TESTING PACKET %i ===\n", packetId);
		packetId++;

		LOG("> ");
		LOG_BUFFER(VITA_PACKET, sizeof(VITA_PACKET));

		gc_cmd56_run(&gc_state, VITA_PACKET, GC_PACKET);
		

		LOG("\n=== TESTING PACKET %i ===\n", packetId);
		packetId++;

		LOG("< ");
		LOG_BUFFER(GC_PACKET, sizeof(GC_PACKET));

		memcpy(EXPECTED_GC_PACKET, gcBuffer + gcPos, sizeof(EXPECTED_GC_PACKET));
		gcPos += sizeof(EXPECTED_GC_PACKET);

		if (memcmp(EXPECTED_GC_PACKET, GC_PACKET, sizeof(GC_PACKET)) != 0) {
			LOG("NOT MATCH EXPECTED !!\n");
			LOG("EXPECTED: ");
			LOG_BUFFER(EXPECTED_GC_PACKET, sizeof(EXPECTED_GC_PACKET));

			res = 1;
		}
		else {
			LOG("SUCCESS!\n");
		}
	}

	LOG("GOT TO REQUEST: %i\n", requestId);
	if (requestId >= 10) {
		LOG("TESTS SUCCEEEDED\n");
	}

	free(vitaBuffer);
	free(gcBuffer);
	return res;
}

#endif

#define IMPL_TEST 1
#ifdef IMPL_TEST
int test_own_implementation() {
	int res = vita_cmd56_run(&vita_state);
	if (res != 0) {
		LOG("Authentication Failed!\n");
	}
	else {
		LOG("Authentication Success!\n");
	}

	LOG("vita_state.per_cart_keys.packet18_key\n");
	LOG_BUFFER(vita_state.per_cart_keys.packet18_key, sizeof(vita_state.per_cart_keys.packet18_key));
	LOG("gc_state.per_cart_keys.packet18_key\n");
	LOG_BUFFER(gc_state.per_cart_keys.packet18_key, sizeof(gc_state.per_cart_keys.packet18_key));

	LOG("vita_state.per_cart_keys.packet20_key\n");
	LOG_BUFFER(vita_state.per_cart_keys.packet20_key, sizeof(vita_state.per_cart_keys.packet20_key));
	LOG("gc_state.per_cart_keys.packet20_key\n");
	LOG_BUFFER(gc_state.per_cart_keys.packet20_key, sizeof(gc_state.per_cart_keys.packet20_key));
	
	return res;
}
#endif

int main(int argc, char** argv) {
	int res = 0;
	gc_cmd56_init(&gc_state, &keys); // initalize fake GC
	vita_cmd56_init(&vita_state, emu_send, emu_recv); // initalize fake VITA

#ifdef IMPL_TEST
	res = test_own_implementation();
	if (res < 0) return res;
#endif
#ifdef REPLAY_TEST
	res = test_replay();
	if (res < 0) return res;
#endif
	return res;
}