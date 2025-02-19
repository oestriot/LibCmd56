# Cmd56

a library to implement gamecart & vita authentication

PROGRESS:

- Gamecart side fully implemented
- Vita side fully implemented

both gamecart authenticating with a vita, and vita authenticating with a gamecart, have been tested on real hardware.

```

// gamecart side (pesudocode):

#include "cmd56/gc.h"

int main() {
	char REQU_PACKET[0x200];
	char RESP_PACKET[0x200];
	
	cmd56_keys keys = {{/*packet20 key*/}, {/*packet18 key*/}};
	gc_cmd56_state state;
	gc_cmd56_init(&state, &keys); // setup the game specific key partials..
	
	while(1) {	
		recv(REQU_PACKET); // receive packets from vita ...
		gc_cmd56_run(&state, REQU_PACKET, RESP_PACKET); // run authentication	
		send(RESP_PACKET); // send packets to vita
	}
}

// vita side (pesudocode):

#include "cmd56/vita.h"

int main() {
	vita_cmd56_state state;

	vita_cmd56_init(&state, send, recv); // functions to send/recv to sdcard ..
	int res = vita_cmd56_run(&state); // run authentication 

	// then check:
	cmd56_keys per_cart_key;
	vita_cmd56_get_keys(&state, &per_cart_key);
	
	// or alternatively

	uint8_t packet20_key[0x20];
	uint8_t packet18_key[0x20];
	vita_cmd56_get_keys_ex(&state, packet20_key, packet18_key);
	
	return res; // == 0 (or GC_AUTH_OK) = success

}



```
