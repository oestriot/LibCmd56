#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define _DEBUG 1

#include "../cmd56/gc.h"
#include "../cmd56/vita.h"
#include "../cmd56/log.h"

// smart as ...
static cmd56_keys keys = { { 0x12, 0x53, 0x56, 0x29, 0x00, 0x31, 0x00, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x42, 0x21, 0x00, 0x00, 0x00, 0x42, 0x02, 0x00, 0x56, 0x29, 0x05, 0x03, 0x31, 0x3D, 0x20, 0x11, 0x00, 0x00, 0x00, 0x00 },
						   { 0x7B, 0x2B, 0xA1, 0xF1, 0xB7, 0x57, 0xF0, 0x35, 0xFA, 0x93, 0x94, 0x0D, 0x1A, 0xB4, 0xD9, 0x1A, 0x18, 0x54, 0xD6, 0xC3, 0xCD, 0xCD, 0x5B, 0x67, 0xE1, 0x07, 0x70, 0xA4, 0x2B, 0x4F, 0xA9, 0x0A } };

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

int test_own_implementation() {
	int res = vita_cmd56_run(&vita_state);
	if (res != 0) {
		LOG("\nAuthentication Failed!\n\n");
	}
	else {
		LOG("\nAuthentication Success!\n\n");
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

int main(int argc, char** argv) {
	int res = 0;

	gc_cmd56_init(&gc_state, &keys); // initalize fake GC
	vita_cmd56_init(&vita_state, emu_send, emu_recv); // initalize fake VITA

	res = test_own_implementation();
	if (res < 0) return res;

	return res;
}