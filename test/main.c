#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../cmd56/gc.h"
#include "../cmd56/vita.h"

FILE* vRecv = NULL;
FILE* gRecv = NULL;

static cmd56_keys keys = { { 0x13, 0x29, 0x86, 0x29, 0x00, 0x63, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x42, 0x21, 0x00, 0x00, 0x00, 0x42, 0x02, 0x00, 0x86, 0x29, 0x11, 0x22, 0x63, 0x4E, 0x20, 0x11, 0x00, 0x00, 0x00, 0x00 }, { 0xA9, 0xA8, 0xC9, 0x09, 0xCF, 0xBD, 0x7F, 0xCD, 0x15, 0xB1, 0xDB, 0xCE, 0xA0, 0xFC, 0xF0, 0x5C, 0xAB, 0xF3, 0x80, 0xDB, 0xA7, 0xCB, 0x5E, 0x34, 0xD9, 0xF8, 0x5A, 0xD4, 0x1D, 0x4A, 0xF5, 0x0F } };

#define _DEBUG
#ifdef _DEBUG
#define LOG(...) printf(__VA_ARGS__)
#define LOG_BUFFER(buffer, size) for(int i = 0; i < size; i++) { LOG("%02X ", ((unsigned char*)buffer)[i]); }; LOG("\n");
#else
#define LOG(...)
#define LOG_BUFFER(buffer, size)
#endif

gc_cmd56_state gc_state;
vita_cmd56_state vita_state;

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

static uint8_t VITA_PACKET[0x200];
static uint8_t GC_PACKET[0x200];

void emu_send(char* buf, size_t size) {
	memcpy(VITA_PACKET, buf, size);
	LOG("VITA -> GC: ");
	LOG_BUFFER(VITA_PACKET, sizeof(VITA_PACKET));
}

void emu_recv(char* buf, size_t size) {
	gc_cmd56_run(&gc_state, VITA_PACKET, GC_PACKET);
	memcpy(buf, GC_PACKET, size);
	LOG("GC -> VITA: ");
	LOG_BUFFER(GC_PACKET, sizeof(GC_PACKET));
}

int main(int argc, char** argv) {
	char* vitaBuffer;
	char* gcBuffer;
	size_t vitaSize;
	size_t gcSize;
	int ret = load_files(&vitaBuffer, &gcBuffer, &vitaSize, &gcSize);
	if(ret != 0) return ret;

	gc_cmd56_init(&gc_state, &keys); // initalize fake GC
	vita_cmd56_init(&vita_state, emu_send, emu_recv);
	int res = vita_cmd56_run(&vita_state);
	if (res != 0) {
		LOG("Gc Verify Failed!\n");
	}
	return 0;



	vRecv = fopen("from_vita.bin", "rb");
	gRecv = fopen("from_gc.bin", "rb");

	for(uint32_t i = 0; i < 1; i++) {
		

		size_t vitaPos = 0;
		size_t gcPos = 0;
		
		uint8_t VITA_PACKET[0x200];
		uint8_t GC_PACKET[0x200];
		uint8_t EXPECTED_GC_PACKET[0x200];

		int packetId = 0;
		for (; ret == 0; packetId++) {
			// Copy packet data from buffers
			if(vitaPos >= vitaSize) break;
			memcpy(VITA_PACKET, vitaBuffer + vitaPos, sizeof(VITA_PACKET));
			vitaPos += sizeof(VITA_PACKET);
			LOG("\n== TESTING PACKET %i ==\n", packetId);

			LOG("> ");
			LOG_BUFFER(VITA_PACKET, sizeof(VITA_PACKET));

			gc_cmd56_run(&gc_state, VITA_PACKET, GC_PACKET);

			LOG("< ");
			LOG_BUFFER(GC_PACKET, sizeof(GC_PACKET));

			memcpy(EXPECTED_GC_PACKET, gcBuffer + gcPos, sizeof(EXPECTED_GC_PACKET));
			gcPos += sizeof(EXPECTED_GC_PACKET);

			if (memcmp(EXPECTED_GC_PACKET, GC_PACKET, sizeof(GC_PACKET)) != 0) {
				LOG("NOT MATCH EXPECTED !!\n");
				LOG("EXPECTED: ");
				LOG_BUFFER(EXPECTED_GC_PACKET, sizeof(EXPECTED_GC_PACKET));

				ret = 1;
			}
			else {
				LOG("SUCCESS!\n");
			}
		}

		LOG("GOT TO PACKET: %i\n", packetId);
		if (packetId >= 10) {
			LOG("TESTS SUCCEEEDED\n");
		}
	}
	free(vitaBuffer);
	free(gcBuffer);
	return ret;
}