# Cmd56

a library to implement gamecart & vita authentication

PROGRESS:

- Gamecart side fully implemented
- Vita side fully implemented

```

gamecart side (pesudocode):

include "cmd56/gc.h"

int main() {
	char REQU_PACKET[0x200];
	char RESP_PACKET[0x200];
	
	gc_cmd56_state state;
	gc_cmd56_init(&state, KEY_PARTIAL_1, KEY_PARTIAL_2); // setup the game specific key partials..
	
	while(1) {	
		recv(REQU_PACKET); // receive packets from vita ...
		gc_cmd56_run(&state, REQU_PACKET, RESP_PACKET); // run authentication	
		send(RESP_PACKET); // send packets to vita
	}
}

```
