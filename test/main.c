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

int main(int argc, char** argv) {
	gc_cmd56_init(&gc_state, &keys); // initalize fake GC
	vita_cmd56_init(&vita_state, emu_send, emu_recv);
	int res = vita_cmd56_run(&vita_state);
	if (res != 0) {
		LOG("Authentication Failed!\n");
	}
	else {
		LOG("Authentication Success!\n");
	}
	return res;
}