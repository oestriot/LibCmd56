#include <stdint.h>
#include <stdio.h>
#include "../cmd56/gc.h"

FILE* vRecv = NULL;
FILE* gRecv = NULL;

static char gc_part1[0x20] = { 0x13, 0x29, 0x86, 0x29, 0x00, 0x63, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x42, 0x21, 0x00, 0x00, 0x00, 0x42, 0x02, 0x00, 0x86, 0x29, 0x11, 0x22, 0x63, 0x4E, 0x20, 0x11, 0x00, 0x00, 0x00, 0x00 };
static char gc_part2[0x20] = { 0xA9, 0xA8, 0xC9, 0x09, 0xCF, 0xBD, 0x7F, 0xCD, 0x15, 0xB1, 0xDB, 0xCE, 0xA0, 0xFC, 0xF0, 0x5C, 0xAB, 0xF3, 0x80, 0xDB, 0xA7, 0xCB, 0x5E, 0x34, 0xD9, 0xF8, 0x5A, 0xD4, 0x1D, 0x4A, 0xF5, 0x0F };

#define LOG(...) printf(__VA_ARGS__)
#define LOG_BUFFER(buffer, size) for(int i = 0; i < size; i++) { LOG("%02X ", ((unsigned char*)buffer)[i]); }; LOG("\n");

gc_cmd56_state gc_state;


int main(int argc, char** argv) {
	vRecv = fopen("from_vita.bin", "rb");
	gRecv = fopen("from_gc.bin", "rb");

	gc_cmd56_init(&gc_state, gc_part1, gc_part2); // initalize fake GC
	
	char VITA_PACKET[0x200];
	char GC_PACKET[0x200];
	char EXPECTED_GC_PACKET[0x200];

	int packetId = 0;
	for (;;packetId++) {
		int rd = fread(VITA_PACKET, 1, sizeof(VITA_PACKET), vRecv);
		if (rd != sizeof(VITA_PACKET)) break;
		LOG("\n== TESTING PACKET %i ==\n", packetId);

		LOG("> ");
		LOG_BUFFER(VITA_PACKET, sizeof(VITA_PACKET));

		gc_cmd56_run(&gc_state, VITA_PACKET, GC_PACKET);

		LOG("< ");
		LOG_BUFFER(GC_PACKET, sizeof(GC_PACKET));

		fread(EXPECTED_GC_PACKET, 1, sizeof(EXPECTED_GC_PACKET), gRecv);
		if (memcmp(EXPECTED_GC_PACKET, GC_PACKET, sizeof(GC_PACKET)) != 0) {
			LOG("NOT MATCH EXPECTED !!\n");
			LOG("EXPECTED: ");
			LOG_BUFFER(EXPECTED_GC_PACKET, sizeof(EXPECTED_GC_PACKET));

			break;
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